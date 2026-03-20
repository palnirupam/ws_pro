"""
Enhanced Mock Vulnerable WebSocket Server
Simulates various vulnerability scenarios for testing WS Tester Pro
"""
import asyncio
import json
import time
import base64
import websockets
import sys
import os
import threading
import hmac as _hmac
import hashlib as _hashlib
from http.server import HTTPServer, BaseHTTPRequestHandler
import socket


# Fake JWT (unsigned)
def make_fake_jwt(payload):
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b'=').decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
    return f"{header}.{body}."


FAKE_USERS = {
    '1': {'id': 1, 'username': 'admin', 'email': 'admin@corp.com', 'role': 'admin'},
    '2': {'id': 2, 'username': 'user',  'email': 'user@corp.com',  'role': 'user'},
    '999': {'id': 999, 'username': 'secret', 'email': 'secret@corp.com', 'role': 'superadmin'},
}

REQUEST_COUNT = {}
MAX_REQUESTS = 200  # No real rate limit — simulate missing rate limiting


# ── Auth test users ───────────────────────────────────────────────────────────
MOCK_USERS = {
    'admin': {'password': 'admin123', 'role': 'admin',  'id': 1},
    'alice': {'password': 'alice123', 'role': 'user',   'id': 2},
    'bob':   {'password': 'bob123',   'role': 'user',   'id': 3},
    'test':  {'password': 'test',     'role': 'tester', 'id': 4},
}


def _make_jwt(username, role):
    """Create a signed JWT for testing"""
    h = base64.urlsafe_b64encode(
        b'{"alg":"HS256","typ":"JWT"}'
    ).rstrip(b'=').decode()
    p = base64.urlsafe_b64encode(
        json.dumps({'user': username, 'role': role,
                    'exp': 9999999999, 'iat': int(time.time())}).encode()
    ).rstrip(b'=').decode()
    sig = base64.urlsafe_b64encode(
        _hmac.new(b'secret', f'{h}.{p}'.encode(), _hashlib.sha256).digest()
    ).rstrip(b'=').decode()
    return f"{h}.{p}.{sig}"


class _LoginHandler(BaseHTTPRequestHandler):
    """HTTP login endpoint — http://localhost:8766/api/login"""

    LOGIN_PATHS = {'/api/login', '/login', '/api/auth/login',
                   '/api/token', '/api/authenticate', '/api/v1/login'}

    def do_POST(self):
        if self.path not in self.LOGIN_PATHS:
            self._send(404, {'error': 'Not found'})
            return

        length = int(self.headers.get('Content-Length', 0))
        try:
            body = json.loads(self.rfile.read(length))
        except Exception:
            self._send(400, {'error': 'Invalid JSON'})
            return

        username = (body.get('username') or body.get('email') or
                    body.get('user') or '').strip()
        password = (body.get('password') or body.get('pass') or '').strip()

        if username in MOCK_USERS and MOCK_USERS[username]['password'] == password:
            user  = MOCK_USERS[username]
            token = _make_jwt(username, user['role'])
            self._send(200, {
                'success':      True,
                'access_token': token,
                'token':        token,
                'user': {
                    'id':       user['id'],
                    'username': username,
                    'role':     user['role'],
                },
                'message': f'Welcome, {username}!'
            })
        else:
            self._send(401, {
                'success': False,
                'error':   'Invalid credentials'
            })

    def do_GET(self):
        if self.path == '/health':
            self._send(200, {'status': 'ok', 'server': 'VulnServer', 'version': '3.2.1'})
        else:
            self._send(404, {'error': 'Not found'})

    def _send(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type',   'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # Suppress logs


def _start_http(port=8766, host='127.0.0.1'):
    """
    Start HTTP login endpoint.
    Bind to 127.0.0.1 by default to avoid IPv6/dual-stack surprises on Windows.
    """
    server = HTTPServer((host, port), _LoginHandler)
    server.serve_forever()

async def handler(websocket):
    client_id = id(websocket)
    REQUEST_COUNT[client_id] = 0

    try:
        # ── Parse auth credentials ────────────────────────────────────
        # websockets v16 passes a ServerConnection object; headers are available via
        # websocket.request.headers (older versions used websocket.request_headers).
        try:
            headers = websocket.request_headers  # type: ignore[attr-defined]
        except Exception:
            headers = getattr(getattr(websocket, 'request', None), 'headers', {}) or {}
        auth_hdr     = headers.get('Authorization', '')
        cookie_hdr   = headers.get('Cookie', '')

        # Detect custom headers (any non-standard header = user is testing)
        custom_hdrs  = {k: v for k, v in headers.items()
                        if k.lower() not in {
                            'host', 'upgrade', 'connection', 'sec-websocket-key',
                            'sec-websocket-version', 'sec-websocket-extensions',
                            'origin', 'user-agent', 'authorization', 'cookie'
                        }}
        has_custom   = len(custom_hdrs) > 0

        # Determine auth method and user
        token        = auth_hdr.replace('Bearer ', '').strip()
        auth_method  = None
        auth_user    = None
        auth_role    = 'guest'

        if token and len(token) > 10:
            auth_method = 'bearer'
            # Try to decode JWT payload (base64)
            try:
                import base64 as _b64
                parts = token.split('.')
                if len(parts) == 3:
                    pad = parts[1] + '=' * (4 - len(parts[1]) % 4)
                    import json as _json
                    payload = _json.loads(_b64.urlsafe_b64decode(pad))
                    auth_user = payload.get('user', 'token_user')
                    auth_role = payload.get('role', 'user')
                else:
                    auth_user = 'token_user'
                    auth_role = 'user'
            except Exception:
                auth_user = 'token_user'
                auth_role = 'user'

        elif 'session=' in cookie_hdr:
            auth_method = 'cookie'
            auth_user   = 'cookie_user'
            auth_role   = 'user'

        elif has_custom:
            auth_method = 'custom_headers'
            auth_user   = 'custom_header_user'
            auth_role   = 'user'
            # Log which custom headers were received
            print(f"[MockServer] Custom headers received: {list(custom_hdrs.keys())}")

        is_auth = auth_method is not None

        # Send welcome — includes framework fingerprint for CVE matching
        await websocket.send(json.dumps({
            'type':           'welcome',
            'message':        'Connected to VulnServer v3.2.1',
            'server':         'VulnServer',
            'version':        '3.2.1',
            'framework':      'Engine.IO',
            'framework_version': '4.1.0',
            'engine':         'Socket.IO/4.5.0',
            'powered_by':     'ws/8.2.0',
            'debug':          True,
            'authenticated':  is_auth,
            'auth_method':    auth_method,
            'custom_headers_received': list(custom_hdrs.keys()) if has_custom else [],
            'user': {
                'id':       1 if auth_role == 'admin' else 2,
                'username': auth_user,
                'role':     auth_role,
                'email':    f'{auth_user}@corp.com',
                'session':  'sess_abc123',
                'balance':  9999 if auth_role == 'admin' else 500,
            } if is_auth else None,
        }))

        async for message in websocket:
            REQUEST_COUNT[client_id] = REQUEST_COUNT.get(client_id, 0) + 1

            # ── Fuzzer vulnerability: crash on null bytes ─────────────
            if '\x00' in message:
                await websocket.send(json.dumps({
                    'error': 'Internal server error',
                    'stack_trace': 'Traceback (most recent call last):\n  File "app.py", line 127, in handle_ws\n    data = msg.decode("utf-8")\nUnicodeDecodeError: \'utf-8\' codec can\'t decode byte 0x00',
                    'internal_path': '/opt/app/server/handlers/ws_handler.py',
                }))
                await websocket.close(1011, 'Internal error')
                return

            # ── Fuzzer vulnerability: crash on oversized payloads ─────
            if len(message) > 40000:
                await websocket.send(json.dumps({
                    'error': 'FATAL ERROR: Out of memory',
                    'detail': 'Buffer overflow in message handler',
                    'stack': 'at MessageHandler.process (node_modules/ws/lib/receiver.js:473:22)',
                }))
                await websocket.close(1009, 'Message too big')
                return

            # ── SSTI vulnerability: template execution ────────────────
            if '{{' in message and '}}' in message:
                import re
                tpl = message
                # Simulate Jinja2/SSTI — evaluate simple expressions
                for match in re.finditer(r'\{\{(.+?)\}\}', message):
                    expr = match.group(1).strip()
                    try:
                        result = str(eval(expr, {'__builtins__': {}}, {'config': {'SECRET_KEY': 'super-secret-2024', 'DEBUG': True}}))
                        tpl = tpl.replace(match.group(0), result)
                    except Exception:
                        tpl = tpl.replace(match.group(0), f'Error: {expr}')
                await websocket.send(json.dumps({
                    'output': tpl,
                    'template_engine': 'jinja2',
                    'evaluated': True,
                }))
                continue

            # ── Fuzzer: format string vulnerability ───────────────────
            if '%s' in message or '%x' in message or '%n' in message:
                await websocket.send(json.dumps({
                    'error': f'Format string processed: {message[:100]}',
                    'leaked': '0x7fffffffde80 0x400 0x7ffff7a42300',
                    'stack_info': 'Partial stack dump from format string',
                }))
                continue

            try:
                data = json.loads(message)
            except json.JSONDecodeError:
                # Echo back raw text — XSS reflection vulnerability
                await websocket.send(message)
                continue

            msg_type = data.get('type', '')
            action = data.get('action', '')

            # ── Auth endpoint (timing vulnerability) ──────────────────
            # Trigger auth flow only when it looks like an auth request, not when
            # other endpoints include a "username" field (e.g. profile updates).
            if msg_type == 'auth' or (data.get('username') and data.get('password')):
                username = data.get('username', '')
                password = data.get('password', '')

                if data.get('test'):
                    # Auth bypass: accepts test=true
                    await websocket.send(json.dumps({
                        'status': 'ok',
                        'message': 'authenticated success',
                        'user': {'username': 'admin', 'role': 'admin'},
                    }))
                    continue

                # Timing: valid username = slower (simulate DB lookup)
                if username == 'admin':
                    await asyncio.sleep(0.08)  # Simulate slower lookup
                    await websocket.send(json.dumps({
                        'status': 'error',
                        'message': 'Invalid password',
                    }))
                else:
                    await asyncio.sleep(0.02)  # Quick rejection
                    await websocket.send(json.dumps({
                        'status': 'error',
                        'message': 'Invalid credentials',
                    }))
                continue

            # ── JWT endpoint ──────────────────────────────────────────
            if data.get('token') or data.get('authorization'):
                token = data.get('token', data.get('authorization', ''))
                # Accept ANY token including alg=none
                if token and ('eyJ' in token or token == 'test'):
                    await websocket.send(json.dumps({
                        'status': 'ok',
                        'message': 'token accepted, authenticated',
                        'user': {'role': 'admin', 'logged_in': True},
                    }))
                else:
                    await websocket.send(json.dumps({
                        'status': 'error',
                        'message': 'Invalid token',
                    }))
                continue

            # ── SQL Injection (error-based) ───────────────────────────
            # Note: some other lab endpoints legitimately include "username"
            # (e.g., mass assignment/profile updates). Don't route those here.
            if (data.get('query') or data.get('search') or data.get('username')) and action not in (
                'update_profile', 'register', 'create_user', 'edit_account', 'update_settings'
            ) and msg_type not in ('profile_update', 'user_update'):
                payload = data.get('query', data.get('search', data.get('username', '')))
                if any(c in payload for c in ["'", '"', ';', '--', 'UNION', 'SELECT']):
                    await websocket.send(json.dumps({
                        'error': f"mysql syntax error near '{payload}' at line 1",
                        'detail': 'You have an error in your SQL syntax',
                    }))
                else:
                    await websocket.send(json.dumps({
                        'results': [],
                        'count': 0,
                    }))
                continue

            # ── Command Injection ─────────────────────────────────────
            if data.get('cmd') or data.get('host') or data.get('exec') or data.get('ping'):
                cmd = data.get('cmd', data.get('host', data.get('exec', data.get('ping', ''))))
                if any(c in cmd for c in [';', '|', '`', '&&', '$(']):
                    await websocket.send(json.dumps({
                        'output': f'uid=0(root) gid=0(root) groups=0(root) - from {cmd}',
                    }))
                else:
                    await websocket.send(json.dumps({
                        'output': f'ping {cmd}: 64 bytes, time=1ms',
                    }))
                continue

            # ── IDOR (access other users' data) ──────────────────────
            if action in ['get_user', 'get_account', 'get_profile'] or data.get('user_id') or data.get('userId'):
                user_id = str(data.get('user_id', data.get('userId', data.get('id', '1'))))
                if user_id in FAKE_USERS:
                    user = FAKE_USERS[user_id]
                    await websocket.send(json.dumps({
                        'user': user,
                        'email': user['email'],
                        'token': make_fake_jwt({'user': user['username'], 'role': user['role']}),
                    }))
                else:
                    await websocket.send(json.dumps({
                        'error': 'User not found',
                    }))
                continue

            # ── GraphQL endpoint ──────────────────────────────────────
            if data.get('payload') and data['payload'].get('query'):
                query = data['payload']['query']
                if '__schema' in query:
                    await websocket.send(json.dumps({
                        'id': data.get('id', '1'),
                        'type': 'data',
                        'payload': {
                            'data': {
                                '__schema': {
                                    'types': [
                                        {'name': 'Query'},
                                        {'name': 'User'},
                                        {'name': 'String'},
                                        {'name': 'Int'},
                                    ]
                                }
                            }
                        }
                    }))
                else:
                    await websocket.send(json.dumps({
                        'id': data.get('id', '1'),
                        'type': 'data',
                        'payload': {'data': {}}
                    }))
                continue

            if msg_type == 'connection_init':
                await websocket.send(json.dumps({
                    'type': 'connection_ack',
                    'payload': {'graphql': True, 'server': 'graphql-ws/5.11.2'},
                }))
                continue

            # ── GraphQL WS Subscription attacks (Mod #5) ─────────────
            if msg_type == 'subscribe':
                sub_id = data.get('id', '1')
                payload = data.get('payload', {})
                query = payload.get('query', '') if isinstance(payload, dict) else ''

                # Subscription flooding: accept unlimited subs (no limit)
                await websocket.send(json.dumps({
                    'id': sub_id,
                    'type': 'next',
                    'payload': {
                        'data': {
                            'onUpdate': {
                                'id': sub_id,
                                'message': f'Subscription {sub_id} active',
                                'user': auth_user or 'anonymous',
                                'timestamp': time.time(),
                            }
                        }
                    }
                }))
                continue

            # ── GraphQL batch query abuse ─────────────────────────────
            if isinstance(data, list) and all(isinstance(d, dict) and 'query' in d for d in data):
                results = []
                for q in data:
                    results.append({
                        'data': {'result': f'Batch {len(results)+1} processed'},
                    })
                await websocket.send(json.dumps(results))
                continue

            # ── GraphQL field suggestion leak ─────────────────────────
            if data.get('payload', {}).get('query', '') if isinstance(data.get('payload'), dict) else False:
                query = data['payload']['query']
                if 'userz' in query or 'passwrd' in query or '__' in query:
                    await websocket.send(json.dumps({
                        'errors': [{
                            'message': f"Cannot query field 'userz'. Did you mean 'users', 'user', 'userRole'?",
                            'extensions': {
                                'code': 'GRAPHQL_VALIDATION_FAILED',
                                'suggestions': ['users', 'user', 'userRole', 'userEmail', 'userToken'],
                            },
                        }]
                    }))
                    continue

            # ── Deep nesting DoS (accepts deeply nested queries) ─────
            if msg_type == 'start' or (data.get('payload', {}).get('query', '') if isinstance(data.get('payload'), dict) else ''):
                query = ''
                if isinstance(data.get('payload'), dict):
                    query = data['payload'].get('query', '')
                nesting = query.count('{') if query else 0
                if nesting > 5:
                    # Simulate slow response from deep nesting (vulnerable)
                    await asyncio.sleep(0.5)
                    await websocket.send(json.dumps({
                        'data': {'deeply': {'nested': {'query': {'accepted': True, 'depth': nesting}}}},
                        'extensions': {'complexity': nesting * 10, 'processingTime': nesting * 100},
                    }))
                    continue

            # ── Prototype Pollution ───────────────────────────────────
            if '__proto__' in message or 'constructor' in message:
                # Reflect back the injected properties (vulnerable behavior)
                try:
                    injected = json.loads(message)
                    proto = injected.get('__proto__', injected.get('constructor', {}).get('prototype', {}))
                    response = {'status': 'ok', 'config': {}}
                    response['config'].update(proto)
                    await websocket.send(json.dumps(response))
                except Exception:
                    await websocket.send(json.dumps({'status': 'ok'}))
                continue

            # ── Info/Debug probes ─────────────────────────────────────
            if msg_type in ['version', 'info', 'debug'] or data.get('debug'):
                await websocket.send(json.dumps({
                    'version': '3.2.1',
                    'debug': True,
                    'api_key': 'sk-test-fake-key-do-not-use',
                    'database': 'mongodb://admin:password123@db.internal:27017',
                    'environment': 'development',
                    'stack': 'at Server.handler (server.js:42)',
                    'secret_key': 'super-secret-signing-key-2024',
                }))
                continue

            if msg_type == 'error':
                await websocket.send(json.dumps({
                    'error': 'Internal server error',
                    'stack_trace': 'Traceback (most recent call last):\n  File "app.py", line 42\nTypeError: unsupported operand',
                    'sql_syntax_error': 'near "WHERE" at line 1',
                }))
                continue

            # ── Subscribe — auth-aware ────────────────────────────────
            if msg_type == 'subscribe':
                channel = data.get('channel', 'default')
                if is_auth:
                    await websocket.send(json.dumps({
                        'type':    'subscribed',
                        'channel': channel,
                        'message': f'Subscribed to {channel}',
                        'data': {
                            'user':    auth_user,
                            'role':    auth_role,
                            'session': 'sess_abc123',
                            'email':   f'{auth_user}@corp.com',
                        },
                    }))
                else:
                    await websocket.send(json.dumps({
                        'type':    'subscribed',
                        'channel': 'public_only',
                        'message': 'Subscribed to public channel (limited data)',
                        'note':    'Authenticate to access private channels',
                    }))
                continue

            # ── My Profile — authenticated only ──────────────────────
            if action in ('get_my_profile', 'my_profile', 'profile') or msg_type == 'profile':
                if is_auth:
                    await websocket.send(json.dumps({
                        'action': 'profile',
                        'user': {
                            'id':       1 if auth_role == 'admin' else 2,
                            'username': auth_user,
                            'role':     auth_role,
                            'email':    f'{auth_user}@corp.com',
                            'balance':  9999 if auth_role == 'admin' else 500,
                            'token':    token if token else 'n/a',
                            'created':  '2024-01-01',
                        }
                    }))
                else:
                    await websocket.send(json.dumps({
                        'error':   'Authentication required',
                        'message': 'Please provide a Bearer token or session cookie',
                        'hint':    'Use Authorization: Bearer <token> header',
                    }))
                continue

            # ── Admin panel — admin role only ─────────────────────────
            if action in ('admin', 'admin_panel', 'get_all_users', 'list_users') or \
               msg_type == 'admin':
                if is_auth and auth_role == 'admin':
                    await websocket.send(json.dumps({
                        'action':     'admin_panel',
                        'authorized': True,
                        'users': [
                            {'id': 1, 'username': 'admin',
                             'email': 'admin@corp.com', 'role': 'admin',
                             'password': 'admin123'},   # Intentional vuln!
                            {'id': 2, 'username': 'alice',
                             'email': 'alice@corp.com', 'role': 'user',
                             'password': 'alice123'},   # Intentional vuln!
                            {'id': 3, 'username': 'bob',
                             'email': 'bob@corp.com',   'role': 'user',
                             'password': 'bob123'},     # Intentional vuln!
                        ],
                        'server_config': {
                            'db_host':    'db.internal',
                            'db_pass':    'super_secret_db_pass',
                            'secret_key': 'super-secret-signing-key-2024',
                        }
                    }))
                elif is_auth and auth_role != 'admin':
                    await websocket.send(json.dumps({
                        'error':        'Forbidden',
                        'message':      f'Admin access required. Your role: {auth_role}',
                        'your_role':    auth_role,
                        'required_role':'admin',
                    }))
                else:
                    await websocket.send(json.dumps({
                        'error':   'Authentication required',
                        'message': 'Login as admin to access admin panel',
                    }))
                continue

            # ── Notification — auth shows personal data ───────────────
            if action in ('get_notifications', 'notifications') or \
               msg_type == 'notifications':
                if is_auth:
                    await websocket.send(json.dumps({
                        'notifications': [
                            {'id': 1, 'message': f'Welcome back, {auth_user}!',
                             'type': 'welcome'},
                            {'id': 2, 'message': 'Your account balance: $500',
                             'type': 'balance', 'amount': 500},
                            {'id': 3, 'message': 'New login from 192.168.1.1',
                             'type': 'security', 'ip': '192.168.1.1'},
                        ],
                        'user':  auth_user,
                        'email': f'{auth_user}@corp.com',
                        'role':  auth_role,
                    }))
                else:
                    await websocket.send(json.dumps({
                        'notifications': [
                            {'id': 1, 'message': 'Login to see your notifications',
                             'type': 'info'},
                        ],
                        'authenticated': False,
                    }))
                continue

            # ── Mass Assignment lab endpoints (intentionally vulnerable) ───────
            # These endpoints simulate servers that blindly accept and reflect
            # user-provided fields (no allowlist), enabling privilege escalation.
            if action in ('update_profile', 'register', 'create_user', 'edit_account', 'update_settings') or \
               msg_type in ('profile_update', 'user_update'):
                # Blindly reflect all fields back (vulnerable behavior).
                resp = dict(data)
                resp.update({
                    'success': True,
                    'updated': True,
                    'note': 'Profile updated (no field allowlist)',
                })
                await websocket.send(json.dumps(resp))
                continue

            # ── Business Logic lab endpoints (intentionally vulnerable) ───────
            # Accepts logically invalid inputs (negative/zero/overflow/workflow bypass).
            if action in ('purchase', 'transfer', 'withdraw', 'apply_discount',
                          'complete_payment', 'checkout', 'claim_bonus', 'use_coupon', 'get_items'):
                resp = {'success': True, 'action': action, 'echo': data}

                if action == 'purchase':
                    qty = data.get('quantity', 1)
                    price = data.get('price', 100)
                    resp['order'] = {
                        'item_id': data.get('item_id', '1'),
                        'quantity': qty,
                        'price': price,
                        'total': qty * price if isinstance(qty, (int, float)) and isinstance(price, (int, float)) else 0,
                        'purchased': True,
                    }
                    resp['total'] = resp['order']['total']

                elif action == 'transfer':
                    amt = data.get('amount', 0)
                    resp['transferred'] = True
                    resp['balance'] = 500 - amt if isinstance(amt, (int, float)) else 500

                elif action == 'withdraw':
                    amt = data.get('amount', 0)
                    resp['withdrawn'] = True
                    resp['balance'] = 500 - amt if isinstance(amt, (int, float)) else 500

                elif action == 'apply_discount':
                    pct = data.get('percent', 0)
                    resp['price'] = 100
                    resp['total'] = 100 * (1 - (pct / 100)) if isinstance(pct, (int, float)) else 100

                elif action == 'complete_payment':
                    resp['completed'] = True
                    resp['confirmed'] = True

                elif action == 'checkout':
                    resp['order'] = {'id': '1', 'status': 'paid' if data.get('payment_status') == 'success' else 'pending'}

                elif action == 'claim_bonus':
                    resp['bonus'] = {'id': data.get('bonus_id', 'welcome_bonus'), 'credited': True}

                elif action == 'use_coupon':
                    resp['discount'] = {'code': data.get('code', 'SAVE50'), 'applied': True}

                elif action == 'get_items':
                    limit = data.get('limit', 10)
                    offset = data.get('offset', 0)
                    resp['items'] = [{'id': i} for i in range(1, 6)]
                    resp['limit'] = limit
                    resp['offset'] = offset

                await websocket.send(json.dumps(resp))
                continue

            # ── SSRF lab endpoint (intentionally vulnerable) ───────────────────
            if action in ('fetch', 'webhook', 'ping_server', 'download', 'check_status') or \
               msg_type in ('fetch', 'test_webhook') or data.get('url') or data.get('webhook') or data.get('callback'):
                target_url = data.get('url', data.get('webhook', data.get('callback', data.get('uri', data.get('href', '')))))
                if target_url and target_url.startswith('http'):
                    import urllib.request
                    try:
                        req = urllib.request.Request(target_url, headers={'User-Agent': 'MockServer-SSRF-Vuln'})
                        with urllib.request.urlopen(req, timeout=2) as r:
                            r.read()
                        await websocket.send(json.dumps({
                            'action': action, 'status': 'fetched', 'url': target_url
                        }))
                    except Exception as e:
                        await websocket.send(json.dumps({
                            'action': action, 'status': 'error fetching', 'url': target_url, 'error': str(e)
                        }))
                    continue

            # ── Heartbeat / ping — auth-aware pong ─────────────────────
            if msg_type == 'ping' or action == 'ping' or not action:
                pong = {
                    'type':           'pong',
                    'message':        'pong',
                    'server':         'Engine.IO/4.1.0',
                    'framework':      'Socket.IO/4.5.0',
                    'authenticated':  is_auth,
                    'auth_method':    auth_method,
                    'custom_headers': list(custom_hdrs.keys()) if has_custom else [],
                    'request_number': REQUEST_COUNT.get(client_id, 0),
                    'time':           time.time(),
                }
                # Auth users get extra sensitive data (intentional leak for diff testing)
                if is_auth:
                    pong['user']        = auth_user
                    pong['role']        = auth_role
                    pong['email']       = f'{auth_user}@corp.com'
                    pong['balance']     = 9999 if auth_role == 'admin' else 500
                    pong['token']       = token[:20] + '...' if token else 'n/a'
                    pong['session']     = 'sess_abc123'
                    pong['internal_ip'] = '10.0.0.42'
                    pong['api_key']     = 'sk-live-4f3a8b2c1d0e9f7a6b5c4d3e2f1a0b9c'
                    pong['admin_panel'] = '/admin/dashboard'
                    pong['database']    = 'mongodb://prod-db:27017/users'
                    pong['permissions'] = ['read', 'write', 'delete', 'admin']
                else:
                    pong['tip'] = 'Not authenticated. Try Bearer Token or Session Cookie auth.'
                await websocket.send(json.dumps(pong))
                continue

            # ── Default: echo — shows auth context + framework info ───
            response = {
                'response':       'echo',
                'echo':           message[:200],
                'server':         'Engine.IO/4.1.0',
                'request_number': REQUEST_COUNT.get(client_id, 0),
                'authenticated':  is_auth,
                'auth_method':    auth_method,
            }
            # Authenticated users get extra context (for diff tool testing)
            if is_auth:
                response['user']           = auth_user
                response['role']           = auth_role
                response['email']          = f'{auth_user}@corp.com'
                response['balance']        = 9999 if auth_role == 'admin' else 500
                response['token']          = token[:20] + '...' if token else 'n/a'
                response['session']        = 'sess_abc123'
                response['internal_ip']    = '10.0.0.42'
                response['api_key']        = 'sk-live-4f3a8b2c1d0e9f7a6b5c4d3e2f1a0b9c'
                response['admin_panel']    = '/admin/dashboard'
                response['database']       = 'mongodb://prod-db:27017/users'
                response['permissions']    = ['read', 'write', 'delete', 'admin']
                response['custom_headers'] = list(custom_hdrs.keys())
                response['tip']            = 'You are authenticated! Try: get_my_profile, admin, notifications'
            else:
                response['tip'] = 'Not authenticated. Try Bearer Token or Session Cookie auth.'
            await websocket.send(json.dumps(response))

    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as e:
        try:
            await websocket.send(json.dumps({
                'error': str(e),
                'type': 'exception',
                'exception_at': 'handler',
            }))
        except Exception:
            pass
    finally:
        REQUEST_COUNT.pop(client_id, None)


async def main():
    # Bind WS on all interfaces so ws://localhost works on Windows
    # even when localhost resolves to IPv6 (::1).
    ws_host = None
    http_host = '127.0.0.1'

    # Tests and docs expect fixed defaults:
    # - WebSocket: ws://localhost:8765
    # - HTTP login: http://localhost:8766/api/login
    #
    # Allow overriding via env vars for local usage, but keep defaults stable.
    ws_port = int((os.environ.get('MOCK_WS_PORT') or os.environ.get('WS_PORT') or '8765').strip())
    http_port = int((os.environ.get('MOCK_HTTP_PORT') or os.environ.get('HTTP_PORT') or '8766').strip())

    # Start HTTP login server in background thread.
    http_thread = threading.Thread(target=_start_http, args=(http_port, http_host), daemon=True)
    http_thread.start()

    # Start WebSocket server.
    # Framework fingerprint (Engine.IO/4.1.0, Socket.IO/4.5.0, ws/8.2.0)
    # is embedded in welcome, pong, and echo JSON responses for CVE detection.
    ws_server = await websockets.serve(
        handler, ws_host, ws_port, max_size=1024 * 1024,
    )

    try:
        try:
            # Windows terminals may default to cp1252; prefer UTF-8 for banner output.
            sys.stdout.reconfigure(encoding='utf-8')
        except Exception:
            pass

        # Try to enable ANSI colors on Windows CMD/PowerShell
        if os.name == 'nt':
            os.system('')

        width = 68
        C = "\033[36m"  # Cyan border
        G = "\033[92m"  # Green success
        Y = "\033[93m"  # Yellow titles
        M = "\033[95m"  # Magenta highlights
        R = "\033[0m"   # Reset
        B = "\033[1m"   # Bold
        D = "\033[90m"  # Dark gray
        W = "\033[97m"  # White text

        def box_line(text="", color=""):
            visible_len = len(text)
            padding = " " * ((width - 4) - visible_len)
            content = f"{color}{text}{R}" if color else f"{W}{text}{R}"
            return f"{C}║{R} {content}{padding} {C}║{R}"

        def section(title):
            return box_line(title, B+Y)

        lines = [
            f"{C}╔" + "═" * (width - 2) + f"╗{R}",
            box_line("           WS Tester Pro — Vulnerable Lab Server", B+G),
            f"{C}╠" + "═" * (width - 2) + f"╣{R}",
            section(" [ ENDPOINTS ]"),
            box_line(f"   > WebSocket:   ws://localhost:{ws_port}"),
            box_line(f"   > HTTP Login:  http://localhost:{http_port}/api/login"),
            f"{C}╠" + "═" * (width - 2) + f"╣{R}",
            section(" [ TEST USERS ]"),
            box_line("   > admin / admin123   (Role: admin)", G),
            box_line("   > alice / alice123   (Role: user)"),
            box_line("   > bob   / bob123     (Role: user)"),
            box_line("   > test  / test       (Role: tester)", D),
            f"{C}╠" + "═" * (width - 2) + f"╣{R}",
            section(" [ HOW TO TEST AUTH (Dashboard) ]"),
            box_line(f"   1. Target URL : ws://localhost:{ws_port}"),
            box_line("   2. Auth Mode  : Username + Password"),
            box_line("        - User: admin   |  Pass: admin123", M),
            box_line(f"        - URL : http://localhost:{http_port}/api/login", M),
            box_line("   3. Click 'Test Auth' to verify connection"),
            f"{C}╠" + "═" * (width - 2) + f"╣{R}",
            section(" [ HOW TO TEST OOB - BLIND SSRF ]"),
            box_line("   1. Start OOB Server : python oob_server.py"),
            box_line("   2. In Dashboard     : Enable 'OOB Proof'"),
            box_line("        - Base URL: http://127.0.0.1:7000/", M),
            box_line("        - API Key : change-me", M),
            box_line("   3. For CLI Scans    :"),
            box_line("        --oob http://127.0.0.1:7000/ --oob-key change-me", M),
            f"{C}╠" + "═" * (width - 2) + f"╣{R}",
            section(" [ NEW VULN MODULES (v2.0) ]"),
            box_line("   > WS Smuggling  : Accepts malformed Upgrade", G),
            box_line("   > GraphQL WS    : Sub flooding, deep nesting", G),
            box_line("   > SSTI          : {{7*7}} template injection", G),
            box_line("   > CVE Fingerprint: Engine.IO/4.1.0 header", G),
            box_line("   > Diff Vuln     : Auth vs unauth data leak", G),
            box_line("   > Format String : %s %x %n processed", G),
            f"{C}╚" + "═" * (width - 2) + f"╝{R}"
        ]
        banner = "\n" + "\n".join(lines) + "\n"

        try:
            print(banner)
        except UnicodeEncodeError:
            print(
                "WS Tester Pro — Vulnerable Lab Server\n"
                f"WebSocket:  ws://localhost:{ws_port}\n"
                f"HTTP Login: http://localhost:{http_port}/api/login\n"
                "Users: admin/admin123, alice/alice123, bob/bob123, test/test\n"
                "OOB Testing:\n"
                "  URL: http://127.0.0.1:7000/\n"
                "  Key: change-me\n"
            )

        await asyncio.Future()
    finally:
        try:
            ws_server.close()
            await ws_server.wait_closed()
        except Exception:
            pass


if __name__ == "__main__":
    asyncio.run(main())
