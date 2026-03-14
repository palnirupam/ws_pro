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
from reports.generator import generate_html_report
from utils.logger import log

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = os.environ.get('WS_SECRET_KEY', os.urandom(24).hex())
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# ── Configurable CORS ────────────────────────────────────────────────────────
cors_origins = os.environ.get('WS_CORS_ORIGINS', '*')
if cors_origins != '*':
    cors_origins = [o.strip() for o in cors_origins.split(',')]
socketio = SocketIO(app, cors_allowed_origins=cors_origins, async_mode='threading')

# ── State ─────────────────────────────────────────────────────────────────────
scan_running   = False
scan_thread    = None
scan_paused    = False
scan_completed_endpoints = set()  # For resume capability
interceptor_messages = []
last_report_html = ''
last_report_target = ''
scan_history: list[dict] = []  # Scan session history


def emit_log(msg, level='info'):
    socketio.emit('log', {'message': msg, 'level': level})

def emit_progress(pct, text):
    socketio.emit('progress', {'percent': pct, 'text': text})

def emit_finding(finding_dict):
    socketio.emit('finding', finding_dict)


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    resp = render_template('index.html')
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

    # Register finding callback
    def on_finding(finding):
        emit_finding(finding.to_dict())
        sev = finding.severity
        icon = {'CRITICAL':'🔴','HIGH':'🟠','MEDIUM':'🟡','LOW':'🟢'}.get(sev,'⚪')
        emit_log(f'{icon} [{sev}] {finding.title}', 'finding')

    store.on_finding(on_finding)

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


@socketio.on('clear_interceptor')
def on_clear_interceptor():
    interceptor_messages.clear()


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


# ── Interceptor ───────────────────────────────────────────────────────────────
interceptor_running = False
interceptor_thread = None

SUSPICIOUS_PATTERNS = [
    (r'(?i)(select|insert|update|delete|drop|union).*?(from|into|table|where)', '🔴 SQL Pattern'),
    (r'(?i)<\s*script', '🔴 XSS Pattern'),
    (r'(?i)(password|passwd|secret|token|api.?key)', '🟡 Sensitive Data'),
    (r'(?i)(eyJ[A-Za-z0-9_-]+\.eyJ)', '🟡 JWT Token'),
    (r'(?i)(admin|root|sudo|superuser)', '🟠 Privilege Keyword'),
    (r'(?i)(\.\./|\.\.\\|%2e%2e)', '🟠 Path Traversal'),
    (r'(?i)(;|\||\&\&)\s*(ls|cat|id|whoami|ping|curl)', '🔴 Command Injection'),
]

import re as _re

def _check_suspicious(msg_text):
    """Check message for suspicious patterns, return list of flags."""
    flags = []
    for pattern, label in SUSPICIOUS_PATTERNS:
        if _re.search(pattern, str(msg_text)):
            flags.append(label)
    return flags


@socketio.on('start_interceptor')
def on_start_interceptor(data):
    global interceptor_running, interceptor_thread

    ws_url = data.get('ws_url', '').strip()
    if not ws_url:
        emit_log('❌ No WebSocket URL provided for interceptor', 'error')
        return

    if interceptor_running:
        emit_log('⚠️ Interceptor already running', 'warning')
        return

    interceptor_running = True
    emit_log(f'🕵️ Interceptor connecting to {ws_url}', 'info')

    interceptor_thread = threading.Thread(
        target=_run_interceptor,
        args=(ws_url,),
        daemon=True
    )
    interceptor_thread.start()


@socketio.on('stop_interceptor')
def on_stop_interceptor():
    global interceptor_running
    interceptor_running = False
    emit_log('🕵️ Interceptor stopped', 'info')


@socketio.on('replay_message')
def on_replay_message(data):
    msg = data.get('message', '')
    ws_url = data.get('ws_url', '')
    if not msg or not ws_url:
        emit_log('❌ Missing message or URL for replay', 'error')
        return
    threading.Thread(target=_replay_msg, args=(ws_url, msg), daemon=True).start()


def _replay_msg(ws_url, message):
    import asyncio as _asyncio
    import websockets as _ws

    async def _do_replay():
        try:
            async with _ws.connect(ws_url, open_timeout=5) as conn:
                await conn.send(message)
                emit_log(f'🔄 Replayed: {message[:80]}', 'info')
                try:
                    resp = await asyncio.wait_for(conn.recv(), timeout=3)
                    _emit_interceptor_msg('SERVER→CLIENT', resp, '🔄 Replay response')
                except asyncio.TimeoutError:
                    pass
                except websockets.exceptions.ConnectionClosed:
                    emit_log('Connection closed during replay', 'warning')
        except ConnectionRefusedError:
            emit_log(f'❌ Connection refused: {ws_url}', 'error')
        except Exception as e:
            emit_log(f'❌ Replay failed: {e}', 'error')

    loop = _asyncio.new_event_loop()
    try:
        loop.run_until_complete(_do_replay())
    finally:
        loop.close()


def _emit_interceptor_msg(direction, message, extra=''):
    ts = datetime.now().strftime('%H:%M:%S')
    msg_str = str(message)[:500]
    flags = _check_suspicious(msg_str)
    flagged = len(flags) > 0

    entry = {
        'time': ts,
        'direction': direction,
        'message': msg_str,
        'flagged': flagged,
        'flags': flags,
        'extra': extra,
    }
    interceptor_messages.append(entry)
    socketio.emit('interceptor_message', entry)


def _run_interceptor(ws_url):
    global interceptor_running
    import websockets as _ws

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def _intercept():
        global interceptor_running
        import ssl as _ssl

        ssl_ctx = None
        if ws_url.startswith('wss://'):
            ssl_ctx = _ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = _ssl.CERT_NONE

        try:
            async with _ws.connect(ws_url, ssl=ssl_ctx, open_timeout=10) as ws:
                emit_log(f'✅ Interceptor connected to {ws_url}', 'success')

                test_payloads = [
                    '{"type":"ping"}',
                    '{"type":"auth","token":"test"}',
                    '{"query":"SELECT * FROM users"}',
                    '<script>alert(1)</script>',
                    '{"cmd":"id"}',
                    '{"type":"subscribe","channel":"notifications"}',
                    '{"action":"get_profile","user_id":"1"}',
                    '{"action":"get_profile","user_id":"../../etc/passwd"}',
                ]

                for payload in test_payloads:
                    if not interceptor_running:
                        break

                    _emit_interceptor_msg('CLIENT→SERVER', payload)

                    try:
                        await ws.send(payload)
                        try:
                            resp = await asyncio.wait_for(ws.recv(), timeout=3)
                            _emit_interceptor_msg('SERVER→CLIENT', resp)
                        except asyncio.TimeoutError:
                            _emit_interceptor_msg('SERVER→CLIENT', '(no response — timeout)', '⏱')
                    except websockets.exceptions.ConnectionClosed:
                        _emit_interceptor_msg('SERVER→CLIENT', '(connection closed)', '❌')
                        break
                    except Exception as e:
                        _emit_interceptor_msg('SERVER→CLIENT', f'(error: {e})', '❌')

                    await asyncio.sleep(0.3)

                emit_log(f'🕵️ Interceptor captured {len(interceptor_messages)} messages', 'success')

        except ConnectionRefusedError:
            emit_log(f'❌ Connection refused: {ws_url}', 'error')
        except Exception as e:
            emit_log(f'❌ Interceptor connection failed: {e}', 'error')
        finally:
            interceptor_running = False

    try:
        loop.run_until_complete(_intercept())
    except Exception as e:
        emit_log(f'❌ Interceptor error: {e}', 'error')
    finally:
        interceptor_running = False
        loop.close()


# ── Async helper ──────────────────────────────────────────────────────────────
def _run_async(coro):
    """Run a coroutine safely from a synchronous thread using a fresh event loop."""
    return asyncio.run(coro)


# ── Scan Runner (with concurrency + resume) ───────────────────────────────────
def run_scan(target_url: str, options: dict):
    global scan_running, scan_paused, scan_completed_endpoints

    fast_mode     = options.get('fast_mode', False)
    run_jwt       = options.get('jwt', True)
    run_ai        = options.get('ai', True)
    run_timing_   = options.get('timing', False)
    run_fuzzer_   = options.get('fuzzing', False)
    concurrent    = min(int(options.get('concurrent_count', 5)), 10)

    try:
        emit_log(f'🚀 Starting scan: {target_url}', 'info')
        emit_log(f'   Concurrent: {concurrent} threads | Mode: {"Fast" if fast_mode else "Deep"}', 'info')
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
            tests = [
                ('Encryption check',      lambda: test_encryption(ep)),
                ('Injection tests',       lambda: run_injection_tests(ep, fast_mode=fast_mode)),
                ('CSWSH check',           lambda: test_cswsh(ep)),
                ('Rate limit check',      lambda: test_rate_limit(ep, fast_mode=fast_mode)),
                ('Message size check',    lambda: test_message_size(ep)),
                ('Info disclosure check', lambda: test_info_disclosure(ep)),
                ('GraphQL check',         lambda: test_graphql(ep)),
                ('IDOR check',            lambda: test_idor(ep)),
                ('Subprotocol check',     lambda: test_subprotocol(ep)),
            ]

            if not fast_mode:
                tests.append(('Auth bypass check', lambda: test_auth_bypass(ep)))

            if run_jwt:
                tests.append(('JWT attacks', lambda: test_jwt_attacks(ep)))

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
                    _run_async(asyncio.wait_for(coro_factory(), timeout=20))
                except asyncio.TimeoutError:
                    emit_log(f'  ⏱ Timeout: {label}', 'warning')
                except Exception as e:
                    emit_log(f'  ❌ Error in {label}: {e}', 'warning')
                    log.error(f'Attack error [{label}] on {ep}: {e}')

            scan_completed_endpoints.add(ep)

        # Use ThreadPoolExecutor for concurrent scanning
        if concurrent > 1 and total > 1:
            with ThreadPoolExecutor(max_workers=concurrent) as executor:
                list(executor.map(run_tests_on_endpoint, enumerate(remaining)))
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
    print("""
╔══════════════════════════════════════╗
║     WS Tester Pro — Dashboard        ║
║     http://localhost:5000            ║
╚══════════════════════════════════════╝
""")

    if cors_origins != '*':
        print(f'  CORS: {cors_origins}')
    if os.environ.get('ANTHROPIC_API_KEY'):
        print('  API Key: loaded from .env')
    print()

    socketio.run(app, host='0.0.0.0', port=5000, debug=False)