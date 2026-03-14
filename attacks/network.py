"""
Network & Protocol Attack Module
Encryption, CSWSH, Message Size, Info Disclosure, GraphQL
"""
import asyncio
import json
import re
from core.scanner import ws_connect, send_recv
from core.findings import store
from utils.evidence import Evidence
from utils.logger import log


SENSITIVE_PATTERNS = [
    (r'version\s*[:\=]\s*[\d\.]+',       'version number'),
    (r'"debug"\s*:\s*true',               'debug mode enabled'),
    (r'secret[_-]?key\s*:',              'secret key'),
    (r'api[_-]?key\s*:',                 'API key'),
    (r'password\s*:',                     'password field'),
    (r'stack\s*trace|traceback',          'stack trace'),
    (r'exception\s+at|at\s+\w+\.\w+\(',  'exception details'),
    (r'internal\s+server\s+error',        'internal error'),
    (r'sql\s+syntax\s+error',             'SQL in error message'),
    (r'mongodb://|mysql://|postgresql://', 'DB connection string'),
    (r'[A-Za-z0-9+/]{32,}={0,2}(?=["\s])', 'possible secret/token'),
]

GRAPHQL_INTROSPECTION = '{"query":"{__schema{types{name}}}"}'
GRAPHQL_CONFIRMED = r'"__schema"'


async def test_encryption(ws_url: str):
    """Flag unencrypted ws:// connections"""
    if ws_url.startswith('ws://'):
        ev = Evidence.make(
            proof='Connection uses ws:// — all traffic sent in plaintext',
            reproduce=(
                "1. Intercept network traffic (Wireshark/Burp)\n"
                "2. Connect to the WebSocket endpoint\n"
                "3. All messages visible in plaintext"
            )
        )
        store.add(ws_url, 'Unencrypted WebSocket (ws://)', 'HIGH',
            "Connection uses ws:// instead of wss://.\n"
            "All WebSocket traffic transmitted in plaintext.\n"
            "Vulnerable to MITM interception.", ev)


async def test_message_size(ws_url: str):
    """Check for missing message size limits"""
    try:
        import websockets
        async with await ws_connect(ws_url, timeout=5) as ws:
            # Start small and escalate
            for size_kb in [64, 256, 512]:
                payload = 'A' * (size_kb * 1024)
                try:
                    await ws.send(payload)
                    resp = await asyncio.wait_for(ws.recv(), timeout=3)
                    if resp:
                        ev = Evidence.make(
                            proof=f'Server accepted {size_kb}KB message without rejection',
                            reproduce=(
                                f"1. Connect to {ws_url}\n"
                                f"2. Send {size_kb}KB of data\n"
                                f"3. Server accepts without error"
                            ),
                            size_tested=f'{size_kb}KB'
                        )
                        store.add(ws_url, 'No Message Size Limit', 'MEDIUM',
                            f"Server accepted messages up to {size_kb}KB.\n"
                            f"Large message floods can exhaust server memory.", ev)
                        return
                except Exception:
                    return  # Server rejected — good
    except Exception as e:
        log.debug(f"Size test error: {e}")


async def test_info_disclosure(ws_url: str):
    """Probe for sensitive information leakage"""
    probes = [
        ('{"type":"version"}',          'version probe'),
        ('{"action":"debug"}',          'debug probe'),
        ('{"type":"info"}',             'info probe'),
        ('{"debug":true}',              'debug flag'),
        ('{"type":"error","cause":"x"}','error probe'),
        ('INVALID_JSON{{{{',            'malformed JSON'),
        ('{}',                          'empty object'),
    ]
    try:
        async with await ws_connect(ws_url, timeout=5) as ws:
            for msg, label in probes:
                resp = await send_recv(ws, msg, timeout=2)
                if not resp:
                    continue
                for pattern, desc in SENSITIVE_PATTERNS:
                    if re.search(pattern, resp, re.IGNORECASE):
                        ev = Evidence.make(
                            payload=msg,
                            request=f'Probe: {label}',
                            response=resp[:400],
                            proof=f'Sensitive info leaked: {desc} (pattern: {pattern})',
                            reproduce=(
                                f"1. Connect to {ws_url}\n"
                                f"2. Send: {msg}\n"
                                f"3. Response contains {desc}"
                            )
                        )
                        store.add(ws_url, 'Information Disclosure', 'MEDIUM',
                            f"Sensitive information leaked in response.\n"
                            f"Leaked: {desc}\n"
                            f"Probe: {label}", ev)
                        return  # One finding per endpoint
    except Exception as e:
        log.debug(f"Info disclosure test error: {e}")


async def test_graphql(ws_url: str):
    """Test for GraphQL over WebSocket + introspection"""
    try:
        async with await ws_connect(ws_url, timeout=5) as ws:
            # Check if it's a GraphQL endpoint
            init = json.dumps({"type": "connection_init"})
            resp = await send_recv(ws, init, timeout=3)
            if not resp:
                return
            if '"connection_ack"' not in resp and 'graphql' not in resp.lower():
                return

            # Try introspection
            query = json.dumps({
                "id": "1",
                "type": "start",
                "payload": {"query": "{__schema{types{name}}}"}
            })
            resp2 = await send_recv(ws, query, timeout=4)
            if resp2 and re.search(GRAPHQL_CONFIRMED, resp2, re.IGNORECASE):
                ev = Evidence.make(
                    payload=query,
                    response=resp2[:400],
                    proof='GraphQL introspection enabled — full schema exposed',
                    reproduce=(
                        f"1. Connect to {ws_url}\n"
                        f"2. Send: {init}\n"
                        f"3. Send: {query}\n"
                        f"4. Response contains full GraphQL schema"
                    )
                )
                store.add(ws_url, 'GraphQL Introspection Enabled', 'MEDIUM',
                    "GraphQL introspection is enabled in production.\n"
                    "Attacker can enumerate all types, queries, mutations, fields.", ev)
    except Exception as e:
        log.debug(f"GraphQL test error: {e}")


async def test_idor(ws_url: str):
    """Test for IDOR — access other users' resources"""
    try:
        async with await ws_connect(ws_url, timeout=5) as ws:
            baseline = await send_recv(ws, '{"type":"ping"}', timeout=2)
            if not baseline:
                return

            found_ids = re.findall(r'"(?:id|user_id|userId|account_id)"\s*:\s*(\d+)', str(baseline))

            for test_id in ['1', '2', '0', '999999', '../../etc']:
                for fmt in [
                    json.dumps({'action': 'get_user', 'user_id': test_id}),
                    json.dumps({'action': 'get_account', 'id': test_id}),
                    json.dumps({'type': 'fetch', 'resource': f'/user/{test_id}'}),
                    json.dumps({'type': 'get_profile', 'userId': test_id}),
                ]:
                    resp = await send_recv(ws, fmt, timeout=2)
                    if not resp:
                        continue
                    resp_lower = resp.lower()

                    # Only flag if sensitive data is returned
                    if (any(s in resp_lower for s in ['"email":', '"password":', '"token":', '"phone":'])
                            and 'error' not in resp_lower and 'not found' not in resp_lower):
                        ev = Evidence.make(
                            payload=fmt,
                            response=resp[:300],
                            proof=f'Sensitive user data returned for resource ID: {test_id}',
                            reproduce=(
                                f"1. Connect to {ws_url}\n"
                                f"2. Send: {fmt}\n"
                                f"3. Response contains another user's sensitive data"
                            )
                        )
                        store.add(ws_url, 'IDOR via WebSocket', 'HIGH',
                            f"Access to other users' data without authorization.\n"
                            f"Resource ID: {test_id}", ev)
                        return
    except Exception as e:
        log.debug(f"IDOR test error: {e}")
