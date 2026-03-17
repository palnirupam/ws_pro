# Flask + SocketIO server
"""
Dashboard Server — Flask + SocketIO
Clean architecture, concurrent scanning, .env support, session history
"""
import asyncio
import os
import sys
import json
import threading
import time
import atexit
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

# ── .env file support ────────────────────────────────────────────────────────
def load_dotenv(path=None):
    """Load .env file into environment (lightweight, no dependency)"""
    env_path = path or os.path.join(BASE_DIR, '.env')
    if os.path.isfile(env_path):
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                key, _, val = line.partition('=')
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = val

load_dotenv()

from flask import Flask, render_template, send_from_directory, request
from flask_socketio import SocketIO, emit

from core.scanner import discover_endpoints, test_connection, fingerprint
from core.findings import store, FindingsStore
from attacks.injection import run_injection_tests
from attacks.auth import test_cswsh, test_jwt_attacks, test_auth_bypass, test_rate_limit
from attacks.network import (test_encryption, test_message_size,
                              test_info_disclosure, test_graphql, test_idor)
from attacks.timing import test_timing
from attacks.subprotocol import test_subprotocol
from attacks.fuzzer import test_fuzzing
from attacks.race_condition  import test_race_condition
from attacks.ssrf            import test_ssrf
from attacks.ssti            import test_ssti
from attacks.mass_assignment import test_mass_assignment
from attacks.business_logic  import test_business_logic
from reports.generator import generate_html_report
from utils.logger import log
from core.auth_profile import auth_profile, reset_auth, AuthProfile
from core.ws_proxy import WSProxyController, validate_ws_url
import socket as _socket

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = os.environ.get('WS_SECRET_KEY', os.urandom(24).hex())
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# ── Configurable CORS ────────────────────────────────────────────────────────
cors_origins = os.environ.get('WS_CORS_ORIGINS', '*')
if cors_origins != '*':
    cors_origins = [o.strip() for o in cors_origins.split(',')]
socketio = SocketIO(app, cors_allowed_origins=cors_origins, async_mode='threading')

# ── Single-instance guard (prevents multiple :5000 dashboards) ────────────────
_LOCK_FH = None

def _acquire_single_instance_lock() -> None:
    """
    Prevent running multiple dashboard instances at once.
    On Windows, accidental multi-run causes socket events to hit a different instance,
    making proxy controls look 'randomly broken'.
    """
    global _LOCK_FH
    lock_path = os.path.join(BASE_DIR, '.dashboard.lock')
    try:
        # Keep file handle open for lifetime of process.
        _LOCK_FH = open(lock_path, 'a+')
    except Exception:
        return

    try:
        if os.name == 'nt':
            import msvcrt  # type: ignore
            try:
                msvcrt.locking(_LOCK_FH.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                print("❌ Another WS Tester Pro dashboard is already running. Close other instances first.", flush=True)
                raise SystemExit(2)
        else:
            try:
                import fcntl  # type: ignore
                fcntl.flock(_LOCK_FH.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except Exception:
                print("❌ Another WS Tester Pro dashboard is already running. Close other instances first.", flush=True)
                raise SystemExit(2)
    finally:
        try:
            _LOCK_FH.seek(0)
            _LOCK_FH.truncate(0)
            _LOCK_FH.write(str(os.getpid()))
            _LOCK_FH.flush()
        except Exception:
            pass

def _release_single_instance_lock() -> None:
    global _LOCK_FH
    try:
        if not _LOCK_FH:
            return
        if os.name == 'nt':
            import msvcrt  # type: ignore
            try:
                msvcrt.locking(_LOCK_FH.fileno(), msvcrt.LK_UNLCK, 1)
            except Exception:
                pass
        _LOCK_FH.close()
    except Exception:
        pass
    _LOCK_FH = None

_acquire_single_instance_lock()
atexit.register(_release_single_instance_lock)

# ── State ─────────────────────────────────────────────────────────────────────
scan_running   = False
scan_thread    = None
scan_paused    = False
scan_completed_endpoints = set()  # For resume capability
interceptor_messages = []
last_report_html = ''
last_report_target = ''
scan_history: list[dict] = []  # Scan session history

# ── Proxy state (real WS MITM) ────────────────────────────────────────────────
proxy_running = False
proxy_port = 8080
proxy_target_url = ''
proxy_intercept_mode = False
proxy_held_messages: list[dict] = []
proxy_controller = WSProxyController()


def emit_log(msg, level='info'):
    socketio.emit('log', {'message': msg, 'level': level})

def emit_progress(pct, text):
    socketio.emit('progress', {'percent': pct, 'text': text})

def emit_finding(finding_dict):
    socketio.emit('finding', finding_dict)


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    # Cache-bust static assets based on file mtimes (no restart required).
    try:
        js_path  = os.path.join(os.path.dirname(__file__), 'static', 'js', 'app.js')
        css_path = os.path.join(os.path.dirname(__file__), 'static', 'css', 'app.css')
        js_v  = int(os.stat(js_path).st_mtime_ns)
        css_v = int(os.stat(css_path).st_mtime_ns)
    except Exception:
        js_v = css_v = int(time.time())

    resp = render_template('index.html', js_v=js_v, css_v=css_v)
    return resp, 200, {
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'Pragma': 'no-cache',
    }

@app.route('/report')
def report_page():
    global last_report_html
    if not last_report_html:
        return '<h1>No report generated yet. Run a scan first.</h1>', 404
    return last_report_html, 200, {'Content-Type': 'text/html; charset=utf-8'}


@app.route('/download-pdf')
def download_pdf():
    from io import BytesIO
    from xhtml2pdf import pisa
    from reports.pdf_generator import generate_pdf_html

    flist = store.as_dicts()
    if not flist:
        return '<h1>No findings yet. Run a scan first.</h1>', 404

    target = last_report_target or 'Unknown'
    pdf_html = generate_pdf_html(flist, target)

    pdf_buffer = BytesIO()
    pisa_status = pisa.CreatePDF(pdf_html, dest=pdf_buffer)

    if pisa_status.err:
        return '<h1>PDF generation failed</h1>', 500

    pdf_buffer.seek(0)
    pdf_bytes = pdf_buffer.read()

    filename = f'ws_security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'

    return pdf_bytes, 200, {
        'Content-Type': 'application/pdf',
        'Content-Disposition': f'attachment; filename="{filename}"',
        'Content-Length': str(len(pdf_bytes)),
    }


@app.route('/download-html', methods=['GET', 'POST'])
def download_html():
    """Standalone HTML report export"""
    if request.method == 'POST':
        data = request.json or {}
        flist = data.get('findings', [])
        target = data.get('target', 'Unknown')
        ai_text = data.get('ai_analysis', '')
    else:
        flist = store.as_dicts()
        target = last_report_target or 'Unknown'
        ai_text = request.args.get('ai', '')
    
    html = generate_html_report(flist, target, ai_text)
    filename = f'ws_security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html'

    return html, 200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Disposition': f'attachment; filename="{filename}"',
    }


@app.route('/download-sarif', methods=['GET', 'POST'])
def download_sarif():
    """SARIF format export for CI/CD"""
    from reports.sarif_generator import generate_sarif

    if request.method == 'POST':
        data = request.json or {}
        flist = data.get('findings', [])
        target = data.get('target', 'Unknown')
    else:
        flist = store.as_dicts()
        target = last_report_target or 'Unknown'
        
    if not flist:
        return '{"error": "No findings"}', 404

    sarif_json = generate_sarif(flist, target)
    filename = f'ws_security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.sarif'

    return sarif_json, 200, {
        'Content-Type': 'application/json',
        'Content-Disposition': f'attachment; filename="{filename}"',
    }


@app.route('/download-json')
def download_json():
    """Export findings as JSON"""
    flist = store.as_dicts()
    if not flist:
        return '{"findings": []}', 200, {'Content-Type': 'application/json'}

    target = last_report_target or 'Unknown'
    data = {
        'tool': 'WS Tester Pro',
        'target': target,
        'timestamp': datetime.now().isoformat(),
        'total_findings': len(flist),
        'findings': flist,
    }
    content = json.dumps(data, indent=2, ensure_ascii=False)
    filename = f'ws_findings_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'

    return content, 200, {
        'Content-Type': 'application/json',
        'Content-Disposition': f'attachment; filename="{filename}"',
    }


@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)


# ── Socket Events ─────────────────────────────────────────────────────────────
@socketio.on('connect')
def on_connect():
    emit('status', {'status': 'idle'})
    emit_log('Connected to WS Tester Pro', 'success')

    # Warn about SSL verification
    emit_log('⚠️ SSL certificate verification is disabled for pen testing', 'warning')


# ── Finding callback (registered once at module level) ────────────────────────
def _on_finding_callback(finding):
    emit_finding(finding.to_dict())
    sev = finding.severity
    icon = {'CRITICAL':'🔴','HIGH':'🟠','MEDIUM':'🟡','LOW':'🟢'}.get(sev,'⚪')
    emit_log(f'{icon} [{sev}] {finding.title}', 'finding')

store.on_finding(_on_finding_callback)


@socketio.on('start_scan')
def on_start_scan(data):
    global scan_running, scan_thread, scan_paused, scan_completed_endpoints

    if scan_running:
        emit_log('Scan already running', 'warning')
        return

    url     = data.get('url', '').strip()
    options = data.get('options', {})
    resume  = data.get('resume', False)

    if not url:
        emit_log('No target URL provided', 'error')
        return

    # Reset state (unless resuming)
    if not resume:
        store.clear()
        interceptor_messages.clear()
        scan_completed_endpoints.clear()
    else:
        emit_log(f'🔄 Resuming scan — {len(scan_completed_endpoints)} endpoints already done', 'info')

    # ── Configure auth profile ────────────────────────────────────────
    reset_auth()
    auth_data = options.get('auth', {})
    auth_method = auth_data.get('method', '')  # 'login', 'token', 'cookie', 'headers', ''

    if auth_method:
        auth_profile.enabled    = True
        auth_profile.method     = auth_method
        auth_profile.username   = auth_data.get('username', '')
        auth_profile.password   = auth_data.get('password', '')
        auth_profile.token      = auth_data.get('token', '')
        auth_profile.cookie     = auth_data.get('cookie', '')
        auth_profile.login_url  = auth_data.get('login_url', '')

        # Parse custom headers (format: "Header-Name: value\nHeader2: value2")
        raw_headers = auth_data.get('custom_headers', '')
        if raw_headers:
            for line in raw_headers.strip().split('\n'):
                if ':' in line:
                    k, v = line.split(':', 1)
                    auth_profile.custom_headers[k.strip()] = v.strip()

        emit_log(f'🔐 Auth configured: method={auth_method}', 'info')
    else:
        emit_log('🔓 No auth — unauthenticated scan', 'info')

    scan_running = True
    scan_paused = False
    socketio.emit('status', {'status': 'running'})

    scan_thread = threading.Thread(
        target=run_scan,
        args=(url, options),
        daemon=True
    )
    scan_thread.start()


@socketio.on('stop_scan')
def on_stop_scan():
    global scan_running
    scan_running = False
    emit_log('Scan stopped by user', 'warning')
    socketio.emit('status', {'status': 'idle'})


@socketio.on('pause_scan')
def on_pause_scan():
    global scan_paused
    scan_paused = not scan_paused
    if scan_paused:
        emit_log('⏸ Scan paused', 'warning')
        socketio.emit('status', {'status': 'paused'})
    else:
        emit_log('▶ Scan resumed', 'info')
        socketio.emit('status', {'status': 'running'})


@socketio.on('generate_report')
def on_generate_report(data):
    global last_report_html, last_report_target
    findings  = data.get('findings', store.as_dicts())
    target    = data.get('target', 'Unknown')
    last_report_target = target
    ai_text   = data.get('ai_analysis', '')
    try:
        html = generate_html_report(findings, target, ai_text)
        last_report_html = html
        emit('report_ready', {'status': 'ok'})
        emit_log('Report generated — downloading PDF', 'success')
    except Exception as e:
        emit_log(f'Report error: {e}', 'error')
        log.error(f'Report generation failed: {e}')


@socketio.on('request_ai_analysis')
def on_ai_analysis(data):
    key = os.environ.get('ANTHROPIC_API_KEY', '')
    if not key:
        emit('ai_analysis', {'analysis': '⚠️ No API key set. Add your Anthropic API key in the sidebar.'})
        return

    findings = data.get('findings', store.as_dicts())
    if not findings:
        emit('ai_analysis', {'analysis': '⚠️ No findings to analyze. Run a scan first.'})
        return

    threading.Thread(target=_run_ai, args=(findings, key), daemon=True).start()


def _run_ai(findings, key):
    import urllib.request
    import urllib.error

    summary = '\n'.join(
        f"- [{f.get('severity','?')}] {f.get('title', f.get('test','?'))} on {f.get('endpoint','?')}"
        for f in findings[:20]
    )

    prompt = f"""You are a senior penetration tester. Analyze these WebSocket security findings and provide:
1. Executive summary (2-3 sentences)
2. Top 3 most critical risks and business impact
3. Attack chain analysis (how vulnerabilities can be combined)
4. Prioritized remediation roadmap

Findings:
{summary}

Be specific, technical, and actionable. Focus on real-world exploitation."""

    payload = json.dumps({
        'model': 'claude-sonnet-4-20250514',
        'max_tokens': 1000,
        'messages': [{'role': 'user', 'content': prompt}]
    }).encode()

    req = urllib.request.Request(
        'https://api.anthropic.com/v1/messages',
        data=payload,
        headers={
            'Content-Type': 'application/json',
            'x-api-key': key,
            'anthropic-version': '2023-06-01',
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            resp = json.loads(r.read())
            text = resp['content'][0]['text']
            socketio.emit('ai_analysis', {'analysis': text})
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:200]
        socketio.emit('ai_analysis', {'analysis': f'API error {e.code}: {body}'})
    except Exception as e:
        socketio.emit('ai_analysis', {'analysis': f'Error: {e}'})


@socketio.on('set_api_key')
def on_set_api_key(data):
    key = data.get('key', '').strip()
    if key and key.startswith('sk-'):
        os.environ['ANTHROPIC_API_KEY'] = key
        masked = key[:8] + '****' + key[-4:]
        emit('api_key_status', {'valid': True, 'message': f'Key set ({masked})', 'masked_key': masked})
    else:
        emit('api_key_status', {'valid': False, 'message': 'Invalid key format'})


@socketio.on('check_api_key')
def on_check_api_key():
    key = os.environ.get('ANTHROPIC_API_KEY', '')
    if key:
        masked = key[:8] + '****' + key[-4:]
        emit('api_key_status', {'valid': True, 'message': f'Key loaded ({masked})', 'masked_key': masked})
    else:
        emit('api_key_status', {'valid': False, 'message': 'No API key set'})


@socketio.on('test_auth')
def on_test_auth(data):
    """Test authentication credentials before scan"""
    url       = data.get('url', '').strip()
    auth_data = data.get('auth', {})
    method    = auth_data.get('method', '').strip()

    # ── Instant validation (no network needed) ────────────────────────
    if not method:
        emit('auth_test_result', {
            'success': False,
            'message': '⚠️ Select an auth method first'
        })
        return

    if method == 'token':
        token = auth_data.get('token', '').strip()
        if not token:
            emit('auth_test_result', {
                'success': False,
                'message': '⚠️ Enter a Bearer token'
            })
            return
        masked = token[:12] + '****' if len(token) > 12 else token
        emit('auth_test_result', {
            'success': True,
            'message': f'Token ready: {masked}',
            'headers': ['Authorization']
        })
        return

    if method == 'cookie':
        cookie = auth_data.get('cookie', '').strip()
        if not cookie:
            emit('auth_test_result', {
                'success': False,
                'message': '⚠️ Enter a session cookie'
            })
            return
        count = len([p for p in cookie.split(';') if '=' in p.strip()])
        emit('auth_test_result', {
            'success': True,
            'message': f'Cookie ready ({count} values)',
            'headers': ['Cookie']
        })
        return

    if method == 'headers':
        raw = auth_data.get('custom_headers', '').strip()
        if not raw:
            emit('auth_test_result', {
                'success': False,
                'message': '⚠️ Enter at least one header (Name: Value)'
            })
            return
        header_names = [l.split(':')[0].strip() for l in raw.split('\n') if ':' in l]
        emit('auth_test_result', {
            'success': True,
            'message': f'Headers ready: {", ".join(header_names)}',
            'headers': header_names
        })
        return

    if method == 'login':
        username  = auth_data.get('username', '').strip()
        password  = auth_data.get('password', '').strip()
        login_url = auth_data.get('login_url', '').strip()

        if not username or not password:
            emit('auth_test_result', {
                'success': False,
                'message': '⚠️ Enter username and password'
            })
            return

        if not url:
            emit('auth_test_result', {
                'success': False,
                'message': '⚠️ Enter target URL first'
            })
            return

        # Login needs network — run in thread
        # IMPORTANT: capture sid BEFORE thread, use socketio.emit() not emit()
        sid = request.sid

        def _do_login():
            test_p = AuthProfile()
            test_p.enabled   = True
            test_p.method    = 'login'
            test_p.username  = username
            test_p.password  = password
            test_p.login_url = login_url

            loop = asyncio.new_event_loop()
            try:
                ok = loop.run_until_complete(test_p.resolve(url))
                if ok:
                    h = list(test_p.get_ws_headers().keys())
                    socketio.emit('auth_test_result', {
                        'success': True,
                        'message': f'Login successful! Got: {", ".join(h)}',
                        'headers': h,
                    }, to=sid)
                else:
                    socketio.emit('auth_test_result', {
                        'success': False,
                        'message': '❌ Login failed — wrong credentials or URL',
                    }, to=sid)
            except Exception as e:
                socketio.emit('auth_test_result', {
                    'success': False,
                    'message': f'❌ Error: {str(e)[:80]}',
                }, to=sid)
            finally:
                loop.close()

        threading.Thread(target=_do_login, daemon=True).start()
        return

    emit('auth_test_result', {
        'success': False,
        'message': f'Unknown method: {method}'
    })


@socketio.on('clear_interceptor')
def on_clear_interceptor():
    interceptor_messages.clear()


# ── WebSocket Proxy (real MITM) ───────────────────────────────────────────────
def _emit_proxy_status(running: bool, port: int | None = None, target: str | None = None, intercept_mode: bool | None = None, error: str = ''):
    socketio.emit('proxy_status', {
        'running': bool(running),
        'port': int(port if port is not None else proxy_port),
        'target': target if target is not None else proxy_target_url,
        'intercept_mode': bool(intercept_mode if intercept_mode is not None else proxy_intercept_mode),
        'error': error or '',
    })

def _emit_proxy_reset(reason: str = ''):
    """Tell UI to clear stale held messages after stop/start."""
    socketio.emit('proxy_reset', {'reason': reason or ''})


def _on_proxy_message(msg: dict):
    """Callback from core.ws_proxy — forward to dashboard UI."""
    global proxy_held_messages
    try:
        if msg.get('held'):
            proxy_held_messages.append(msg)
        socketio.emit('proxy_message', msg)
    except Exception:
        # Avoid crashing proxy thread on UI emit issues
        pass


@socketio.on('start_proxy')
def on_start_proxy(data):
    global proxy_running, proxy_port, proxy_target_url, proxy_intercept_mode, proxy_held_messages

    if proxy_running:
        emit_log('⚠️ Proxy already running', 'warning')
        _emit_proxy_status(True)
        return

    ws_url = (data.get('ws_url') or '').strip()
    port = int(data.get('port') or 8080)
    intercept_mode = bool(data.get('intercept_mode', False))

    try:
        print(f"[Proxy] start_proxy ws_url={ws_url} port={port} intercept={intercept_mode}", flush=True)
    except Exception:
        pass

    ok, err = validate_ws_url(ws_url)
    if not ok:
        emit_log(f'❌ Invalid WS URL: {err}', 'error')
        _emit_proxy_status(False, port=port, target=ws_url, intercept_mode=intercept_mode, error=err)
        return

    if port < 1 or port > 65535:
        emit_log('❌ Invalid proxy port', 'error')
        _emit_proxy_status(False, port=port, target=ws_url, intercept_mode=intercept_mode, error='Invalid port')
        return

    # Preflight: ensure we can bind the local listen port.
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        try:
            s.bind(('127.0.0.1', port))
        finally:
            try:
                s.close()
            except Exception:
                pass
    except OSError as e:
        proxy_running = False
        msg = f'Local port {port} unavailable: {e}'
        emit_log(f'❌ {msg}', 'error')
        _emit_proxy_status(False, port=port, target=ws_url, intercept_mode=intercept_mode, error=str(e)[:200])
        return

    proxy_running = True
    proxy_port = port
    proxy_target_url = ws_url
    proxy_intercept_mode = intercept_mode
    proxy_held_messages = []
    _emit_proxy_reset('start_proxy')

    emit_log(f'🧲 Starting WS proxy on ws://localhost:{port} → {ws_url}', 'info')
    emit_log('ℹ️ Point your browser/app to the local proxy URL instead of the real server', 'info')

    # Emit immediately so UI doesn't stick on "Starting..." without feedback.
    _emit_proxy_status(False, port=port, target=ws_url, intercept_mode=intercept_mode, error='starting')

    def _starter():
        global proxy_running
        try:
            proxy_controller.start(
                target_url=ws_url,
                listen_host='127.0.0.1',
                listen_port=port,
                intercept_mode=intercept_mode,
                on_message=_on_proxy_message,
            )
            _emit_proxy_status(True, port=port, target=ws_url, intercept_mode=intercept_mode)
            emit_log(f'✅ Proxy running on ws://localhost:{port}', 'success')
        except Exception as e:
            proxy_running = False
            err = str(e)[:200]
            emit_log(f'❌ Proxy start failed: {err}', 'error')
            _emit_proxy_status(False, port=port, target=ws_url, intercept_mode=intercept_mode, error=err)

    threading.Thread(target=_starter, daemon=True).start()


@socketio.on('stop_proxy')
def on_stop_proxy(data=None):
    global proxy_running
    if not proxy_running:
        _emit_proxy_status(False)
        return
    proxy_running = False
    _emit_proxy_status(False, error='stopping')
    _emit_proxy_reset('stop_proxy')

    def _stopper():
        try:
            proxy_controller.stop()
        except Exception as e:
            emit_log(f'❌ Proxy stop failed: {str(e)[:200]}', 'error')
        emit_log('🧲 Proxy stopped', 'info')
        _emit_proxy_status(False)
        _emit_proxy_reset('stopped')

    threading.Thread(target=_stopper, daemon=True).start()

@socketio.on('get_proxy_status')
def on_get_proxy_status(data=None):
    """Allow UI to refresh proxy status on demand."""
    try:
        print(f"[Proxy] get_proxy_status running={proxy_running} port={proxy_port} target={proxy_target_url}", flush=True)
    except Exception:
        pass
    _emit_proxy_status(bool(proxy_running))


@socketio.on('forward_message')
def on_forward_message(data):
    mid = (data.get('message_id') or '').strip()
    modified = data.get('modified_content', None)
    sid = request.sid
    try:
        print(f"[Proxy] forward_message id={mid} modified_len={len(modified) if isinstance(modified, str) else 0}", flush=True)
    except Exception:
        pass
    if not mid:
        emit_log('❌ Missing message_id to forward', 'error')
        res = {'ok': False, 'action': 'forward', 'id': mid, 'error': 'missing_id'}
        socketio.emit('proxy_action_result', res, to=sid)
        return res
    try:
        ok = proxy_controller.forward_held(mid, modified_content=modified)
    except Exception as e:
        err = str(e)[:200]
        emit_log(f'❌ Forward failed: {err}', 'error')
        res = {'ok': False, 'action': 'forward', 'id': mid, 'error': err}
        socketio.emit('proxy_action_result', res, to=sid)
        return res
    if not ok:
        emit_log('⚠️ Failed to forward — not held / proxy not running', 'warning')
        res = {'ok': False, 'action': 'forward', 'id': mid, 'error': 'not_held_or_not_running'}
        socketio.emit('proxy_action_result', res, to=sid)
        return res

    # Update UI immediately (otherwise held items look stuck).
    try:
        global proxy_held_messages
        proxy_held_messages = [m for m in proxy_held_messages if m.get('id') != mid]
    except Exception:
        pass
    socketio.emit('proxy_held_resolved', {'id': mid, 'action': 'forward'}, to=sid)
    res = {'ok': True, 'action': 'forward', 'id': mid}
    socketio.emit('proxy_action_result', res, to=sid)
    return res


@socketio.on('drop_message')
def on_drop_message(data):
    mid = (data.get('message_id') or '').strip()
    sid = request.sid
    try:
        print(f"[Proxy] drop_message id={mid}", flush=True)
    except Exception:
        pass
    if not mid:
        emit_log('❌ Missing message_id to drop', 'error')
        res = {'ok': False, 'action': 'drop', 'id': mid, 'error': 'missing_id'}
        socketio.emit('proxy_action_result', res, to=sid)
        return res
    try:
        ok = proxy_controller.drop_held(mid)
    except Exception as e:
        err = str(e)[:200]
        emit_log(f'❌ Drop failed: {err}', 'error')
        res = {'ok': False, 'action': 'drop', 'id': mid, 'error': err}
        socketio.emit('proxy_action_result', res, to=sid)
        return res
    if not ok:
        emit_log('⚠️ Failed to drop — not held / proxy not running', 'warning')
        res = {'ok': False, 'action': 'drop', 'id': mid, 'error': 'not_held_or_not_running'}
        socketio.emit('proxy_action_result', res, to=sid)
        return res

    try:
        global proxy_held_messages
        proxy_held_messages = [m for m in proxy_held_messages if m.get('id') != mid]
    except Exception:
        pass
    socketio.emit('proxy_held_resolved', {'id': mid, 'action': 'drop'}, to=sid)
    res = {'ok': True, 'action': 'drop', 'id': mid}
    socketio.emit('proxy_action_result', res, to=sid)
    return res


@socketio.on('replay_via_proxy')
def on_replay_via_proxy(data):
    msg = (data.get('message') or '').strip()
    direction = (data.get('direction') or 'client_to_server').strip()
    if not msg:
        emit_log('❌ Missing message to replay', 'error')
        return {'ok': False, 'error': 'missing_message'}
    ok = proxy_controller.replay(msg, direction=direction)
    if not ok:
        emit_log('❌ Replay failed — proxy not running or no active client session', 'error')
        return {'ok': False, 'error': 'proxy_not_running_or_no_session'}
    emit_log('🔄 Replayed message via proxy', 'info')
    return {'ok': True}


@socketio.on('client_error')
def on_client_error(data):
    """JS runtime errors from browser (debugging UI not updating)."""
    try:
        msg = (data or {}).get('message', '')
        src = (data or {}).get('source', '')
        stack = (data or {}).get('stack', '')
        emit_log(f'🧯 UI error: {msg} @ {src}', 'error')
        if stack:
            log.error(f'UI error stack: {stack}')
    except Exception:
        pass


# ── Scan History ──────────────────────────────────────────────────────────────
@socketio.on('save_session')
def on_save_session(data):
    """Save current scan session to history"""
    session = {
        'id': len(scan_history),
        'target': data.get('target', 'Unknown'),
        'timestamp': datetime.now().isoformat(),
        'findings': store.as_dicts(),
        'total': len(store.all()),
        'counts': store.count_by_severity(),
    }
    scan_history.append(session)
    emit('session_saved', {'id': session['id'], 'total': session['total']})
    emit_log(f'💾 Session saved (#{session["id"]}, {session["total"]} findings)', 'success')


@socketio.on('load_session')
def on_load_session(data):
    """Load a saved session"""
    sid = data.get('id', -1)
    if 0 <= sid < len(scan_history):
        session = scan_history[sid]
        emit('session_loaded', session)
        emit_log(f'📂 Loaded session #{sid} ({session["total"]} findings)', 'success')
    else:
        emit_log('❌ Session not found', 'error')


@socketio.on('get_history')
def on_get_history():
    """Return scan history list"""
    history = [{
        'id': s['id'],
        'target': s['target'],
        'timestamp': s['timestamp'],
        'total': s['total'],
        'counts': s['counts'],
    } for s in scan_history]
    emit('history_list', history)


@socketio.on('compare_sessions')
def on_compare_sessions(data):
    """Compare two scan sessions"""
    id_a = data.get('session_a', -1)
    id_b = data.get('session_b', -1)

    if not (0 <= id_a < len(scan_history) and 0 <= id_b < len(scan_history)):
        emit_log('❌ Invalid session IDs for comparison', 'error')
        return

    a = scan_history[id_a]
    b = scan_history[id_b]

    titles_a = {f['title'] for f in a['findings']}
    titles_b = {f['title'] for f in b['findings']}

    comparison = {
        'session_a': {'id': id_a, 'target': a['target'], 'total': a['total'], 'timestamp': a['timestamp']},
        'session_b': {'id': id_b, 'target': b['target'], 'total': b['total'], 'timestamp': b['timestamp']},
        'only_in_a': [f for f in a['findings'] if f['title'] not in titles_b],
        'only_in_b': [f for f in b['findings'] if f['title'] not in titles_a],
        'common': [f for f in a['findings'] if f['title'] in titles_b],
        'new_count': len(titles_b - titles_a),
        'fixed_count': len(titles_a - titles_b),
    }
    emit('comparison_result', comparison)
    emit_log(f'📊 Compared sessions #{id_a} vs #{id_b}: '
             f'{comparison["new_count"]} new, {comparison["fixed_count"]} fixed', 'success')


@socketio.on('import_findings')
def on_import_findings(data):
    """Import findings from JSON"""
    findings = data.get('findings', [])
    if not findings:
        emit_log('❌ No findings data to import', 'error')
        return

    store.clear()
    from utils.evidence import Evidence
    for f in findings:
        ev = Evidence.make(**f.get('evidence', {})) if f.get('evidence') else Evidence()
        store.add(
            endpoint=f.get('endpoint', ''),
            title=f.get('title', ''),
            severity=f.get('severity', 'LOW'),
            description=f.get('description', ''),
            evidence=ev,
        )

    emit_log(f'📂 Imported {len(findings)} findings', 'success')
    socketio.emit('scan_complete', {'count': len(store.all())})


# ── Async helper ──────────────────────────────────────────────────────────────
def _run_async(coro):
    """Run a coroutine safely from a synchronous thread using a fresh event loop."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ── Scan Runner (with concurrency + resume) ───────────────────────────────────
def run_scan(target_url: str, options: dict):
    global scan_running, scan_paused, scan_completed_endpoints

    fast_mode     = options.get('fast_mode', False)
    run_jwt       = options.get('jwt', True)
    run_ai        = options.get('ai', True)
    run_timing_   = options.get('timing', False)
    run_fuzzer_   = options.get('fuzzing', False)
    run_race      = options.get('race_condition', True)
    run_ssrf      = options.get('ssrf', True)
    run_ssti      = options.get('ssti', True)
    run_mass      = options.get('mass_assignment', True)
    run_logic     = options.get('business_logic', True)
    # Baseline (previously always-on) tests — now user-controllable.
    run_enc       = options.get('enc_check', True)
    run_inj       = options.get('injection_tests', True)
    run_cswsh     = options.get('cswsh_check', True)
    run_rate      = options.get('rate_limit_check', True)
    run_msg_size  = options.get('msg_size_check', True)
    run_info_disc = options.get('info_disc_check', True)
    run_graphql   = options.get('graphql_check', True)
    run_idor      = options.get('idor_check', True)
    run_subproto  = options.get('subproto_check', True)
    # Auth bypass used to run only when fast_mode is OFF. Keep that as default,
    # but allow explicit enabling via checkbox.
    run_auth_bypass = options.get('auth_bypass', not fast_mode)
    concurrent    = min(int(options.get('concurrent_count', 5)), 10)

    try:
        emit_log(f'🚀 Starting scan: {target_url}', 'info')
        emit_log(f'   Concurrent: {concurrent} threads | Mode: {"Fast" if fast_mode else "Deep"}', 'info')

        # ── Resolve auth (do login if needed) ────────────────────────────
        if auth_profile.is_configured():
            emit_log('🔐 Resolving authentication...', 'info')
            loop = asyncio.new_event_loop()
            try:
                auth_ok = loop.run_until_complete(auth_profile.resolve(target_url))
            finally:
                loop.close()

            if auth_ok:
                emit_log('✅ Authentication successful', 'success')
            else:
                emit_log('⚠️ Authentication failed — continuing without auth', 'warning')
                auth_profile.enabled = False

        emit_progress(5, 'Discovering endpoints...')

        # 1. Discover endpoints
        endpoints = _run_async(discover_endpoints(target_url))
        emit_log(f'Found {len(endpoints)} potential endpoints', 'info')
        emit_progress(15, f'Found {len(endpoints)} endpoints — testing...')

        # 2. Filter alive endpoints
        emit_log('Testing connectivity...', 'info')
        alive = []
        for ep in endpoints:
            if not scan_running:
                break
            result = _run_async(test_connection(ep, timeout=4))
            if result['alive']:
                alive.append(ep)
                emit_log(f'  ✅ Alive: {ep}', 'success')
            else:
                emit_log(f'  ⬜ Dead: {ep}', 'info')

        if not alive:
            emit_log('⚠️ No live WebSocket endpoints found', 'warning')
            emit_progress(100, 'Complete — no live endpoints')
            socketio.emit('scan_complete', {})
            socketio.emit('status', {'status': 'complete'})
            return

        emit_log(f'🎯 {len(alive)} live endpoints to test', 'success')
        emit_progress(25, f'Testing {len(alive)} endpoints...')

        # 3. Run attacks on each alive endpoint (with concurrency)
        # Filter out already-completed endpoints for resume
        remaining = [ep for ep in alive if ep not in scan_completed_endpoints]
        total = len(remaining)

        def run_tests_on_endpoint(i_ep_tuple):
            """Run all tests on a single endpoint using asyncio.run() per coroutine"""
            i, ep = i_ep_tuple

            while scan_paused and scan_running:
                time.sleep(0.5)

            if not scan_running:
                return

            pct = 25 + int((i / max(total, 1)) * 65)
            emit_progress(pct, f'[{i+1}/{total}] {ep[:50]}')
            emit_log(f'\n▶ Testing: {ep}', 'info')

            # Fingerprint
            try:
                info = _run_async(fingerprint(ep))
                emit_log(f'  Framework: {info["framework"]} | Server: {info["server_header"]}', 'info')
            except Exception as e:
                emit_log(f'  ⚠️ Fingerprint failed: {e}', 'warning')

            # Build test list as (label, factory) — factory creates fresh coroutine each call
            tests = []
            if run_enc:
                tests.append(('Encryption check', lambda: test_encryption(ep)))
            if run_inj:
                tests.append(('Injection tests', lambda: run_injection_tests(ep, fast_mode=fast_mode)))
            if run_cswsh:
                tests.append(('CSWSH check', lambda: test_cswsh(ep)))
            if run_rate:
                tests.append(('Rate limit check', lambda: test_rate_limit(ep, fast_mode=fast_mode)))
            if run_msg_size:
                tests.append(('Message size check', lambda: test_message_size(ep)))
            if run_info_disc:
                tests.append(('Info disclosure check', lambda: test_info_disclosure(ep)))
            if run_graphql:
                tests.append(('GraphQL check', lambda: test_graphql(ep)))
            if run_idor:
                tests.append(('IDOR check', lambda: test_idor(ep)))
            if run_subproto:
                tests.append(('Subprotocol check', lambda: test_subprotocol(ep)))

            if run_race:
                tests.append(('Race condition check',  lambda ep=ep: test_race_condition(ep, fast_mode=fast_mode)))
            if run_ssrf:
                tests.append(('SSRF check',            lambda ep=ep: test_ssrf(ep, fast_mode=fast_mode)))
            if run_ssti:
                tests.append(('SSTI check',            lambda ep=ep: test_ssti(ep, fast_mode=fast_mode)))
            if run_mass:
                tests.append(('Mass assignment check', lambda ep=ep: test_mass_assignment(ep, fast_mode=fast_mode)))
            if run_logic:
                tests.append(('Business logic check',  lambda ep=ep: test_business_logic(ep, fast_mode=fast_mode)))

            if run_auth_bypass:
                tests.append(('Auth bypass check', lambda: test_auth_bypass(ep)))

            if run_jwt:
                tests.append(('JWT attacks', lambda: test_jwt_attacks(ep, fast_mode=fast_mode)))

            if run_timing_:
                tests.append(('Timing attacks', lambda: test_timing(ep, fast_mode=fast_mode)))

            if run_fuzzer_:
                tests.append(('WebSocket fuzzing', lambda: test_fuzzing(ep, fast_mode=fast_mode)))

            for label, coro_factory in tests:
                if not scan_running:
                    break
                while scan_paused and scan_running:
                    time.sleep(0.5)
                try:
                    emit_log(f'  ⏳ {label}...', 'info')
                    loop = asyncio.new_event_loop()
                    try:
                        loop.run_until_complete(
                            asyncio.wait_for(coro_factory(), timeout=20)
                        )
                    finally:
                        loop.close()
                except asyncio.TimeoutError:
                    emit_log(f'  ⏱ Timeout: {label}', 'warning')
                except Exception as e:
                    emit_log(f'  ❌ Error in {label}: {e}', 'warning')
                    log.error(f'Attack error [{label}] on {ep}: {e}')

            scan_completed_endpoints.add(ep)

        # Use ThreadPoolExecutor for concurrent scanning
        if concurrent > 1 and total > 1:
            futures = []
            with ThreadPoolExecutor(max_workers=concurrent) as executor:
                for item in enumerate(remaining):
                    if not scan_running:
                        break
                    futures.append(executor.submit(run_tests_on_endpoint, item))
                for future in futures:
                    if not scan_running:
                        future.cancel()
        else:
            for item in enumerate(remaining):
                run_tests_on_endpoint(item)

        emit_progress(95, 'Finalizing...')

        # 4. AI Analysis
        if run_ai and scan_running:
            key = os.environ.get('ANTHROPIC_API_KEY', '')
            if key and store.all():
                emit_log('🤖 Running AI analysis...', 'info')
                threading.Thread(
                    target=_run_ai,
                    args=(store.as_dicts(), key),
                    daemon=True
                ).start()

        counts = store.count_by_severity()
        summary = ' | '.join(f'{k}:{v}' for k, v in counts.items() if v > 0) or 'None'
        emit_log(f'\n✅ Scan complete — {len(store.all())} findings: {summary}', 'success')
        emit_progress(100, f'Complete — {len(store.all())} findings')

        # Send browser notification
        socketio.emit('scan_notification', {
            'title': 'Scan Complete',
            'body': f'{len(store.all())} findings: {summary}',
        })

    except Exception as e:
        emit_log(f'❌ Scan error: {e}', 'error')
        log.error(f'Scan error: {e}', exc_info=True)
    finally:
        scan_running = False
        socketio.emit('scan_complete', {'count': len(store.all())})
        socketio.emit('status', {'status': 'complete'})


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    try:
        # Windows terminals may default to cp1252; prefer UTF-8 for banner output.
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

    banner = """
╔══════════════════════════════════════╗
║     WS Tester Pro — Dashboard        ║
║     http://localhost:5000            ║
╚══════════════════════════════════════╝
"""
    try:
        print(banner)
    except UnicodeEncodeError:
        print("WS Tester Pro — Dashboard\nhttp://localhost:5000\n")

    if cors_origins != '*':
        print(f'  CORS: {cors_origins}')
    if os.environ.get('ANTHROPIC_API_KEY'):
        print('  API Key: loaded from .env')
    print()

    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)