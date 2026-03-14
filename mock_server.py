"""
Enhanced Mock Vulnerable WebSocket Server
Simulates various vulnerability scenarios for testing WS Tester Pro
"""
import asyncio
import json
import time
import base64
import websockets


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


async def handler(websocket):
    client_id = id(websocket)
    REQUEST_COUNT[client_id] = 0

    try:
        # Send welcome with server info (info disclosure)
        await websocket.send(json.dumps({
            'type': 'welcome',
            'message': 'Connected to VulnServer v3.2.1',
            'server': 'VulnServer',
            'version': '3.2.1',
            'debug': True,
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

            try:
                data = json.loads(message)
            except json.JSONDecodeError:
                # Echo back raw text — XSS reflection vulnerability
                await websocket.send(message)
                continue

            msg_type = data.get('type', '')
            action = data.get('action', '')

            # ── Auth endpoint (timing vulnerability) ──────────────────
            if msg_type == 'auth' or data.get('username'):
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
            if data.get('query') or data.get('search') or data.get('username'):
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
                    'payload': {'graphql': True},
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

            # ── Subscribe (no auth check) ─────────────────────────────
            if msg_type == 'subscribe':
                channel = data.get('channel', 'default')
                await websocket.send(json.dumps({
                    'type': 'subscribed',
                    'channel': channel,
                    'message': f'Subscribed to {channel}',
                    'data': {'user': 'admin', 'session': 'abc123'},
                }))
                continue

            # ── Default: echo with server info ────────────────────────
            await websocket.send(json.dumps({
                'response': 'data',
                'echo': message[:200],
                'request_number': REQUEST_COUNT.get(client_id, 0),
            }))

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
    async with websockets.serve(handler, "localhost", 8765, max_size=1024*1024):
        print("""
╔══════════════════════════════════════════════════╗
║   🎯 Mock Vulnerable WebSocket Server            ║
║   ws://localhost:8765                             ║
║                                                  ║
║   Simulated vulnerabilities:                     ║
║   • SQL Injection (error-based)                  ║
║   • XSS (reflection)                             ║
║   • Command Injection                            ║
║   • IDOR (user data access)                      ║
║   • JWT bypass (accepts alg=none)                ║
║   • Auth bypass (test=true)                      ║
║   • Info Disclosure (debug, stack traces)         ║
║   • GraphQL Introspection                        ║
║   • Prototype Pollution                          ║
║   • Timing side-channel (auth)                   ║
║   • No Rate Limiting                             ║
║   • No Encryption (ws://)                        ║
║   • Large message acceptance (1MB)               ║
╚══════════════════════════════════════════════════╝
""")
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
