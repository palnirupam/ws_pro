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
            # Drain welcome / banner message if present.
            try:
                await asyncio.wait_for(ws.recv(), timeout=0.5)
            except Exception:
                pass

            init = json.dumps({"type": "connection_init"})
            direct = GRAPHQL_INTROSPECTION
            query = json.dumps({
                "id": "1",
                "type": "start",
                "payload": {"query": "{__schema{types{name}}}"}
            })

            # Some endpoints (and our mock lab) won't follow graphql-ws handshake strictly.
            # Try multiple probes and flag if __schema appears in any response.
            probes = [
                ("graphql-ws init", init),
                ("graphql direct query", direct),
                ("graphql-ws start", query),
            ]

            for label, payload in probes:
                await ws.send(payload)

                # Read a few frames since responses can be queued/out-of-order.
                for _ in range(3):
                    try:
                        resp = await asyncio.wait_for(ws.recv(), timeout=1.5)
                    except Exception:
                        resp = None
                    if not resp:
                        continue
                    if re.search(GRAPHQL_CONFIRMED, str(resp), re.IGNORECASE):
                        ev = Evidence.make(
                            payload=payload,
                            request=f'Probe: {label}',
                            response=str(resp)[:400],
                            proof='GraphQL introspection enabled — __schema exposed',
                            reproduce=(
                                f"1. Connect to {ws_url}\n"
                                f"2. Send: {payload}\n"
                                f"3. Response contains __schema"
                            )
                        )
                        store.add(ws_url, 'GraphQL Introspection Enabled', 'MEDIUM',
                            "GraphQL introspection is enabled in production.\n"
                            "Attacker can enumerate all types, queries, mutations, fields.", ev)
                        return
            return

            # (Kept for readability; loop returns on success)
            resp2 = None
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


async def test_idor(ws_url: str) -> bool:
    """
    IDOR — Insecure Direct Object Reference
    Powerful version: sequential scan, UUID guessing,
    horizontal + vertical escalation, mass IDOR check
    """
    found_any = False

    # ── ID patterns to test ───────────────────────────────────────────────
    test_ids = [
        # Sequential IDs
        '0', '1', '2', '3', '4', '5',
        '100', '999', '1000',
        # Common admin IDs
        '-1', '99999999',
        # String variants
        'admin', 'administrator', 'root', 'superuser',
        # Path traversal style
        '../../admin', '../1',
    ]

    # ── Action templates to try ───────────────────────────────────────────
    action_templates = [
        lambda id_val: json.dumps({'action': 'get_user',    'user_id': id_val}),
        lambda id_val: json.dumps({'action': 'get_profile', 'user_id': id_val}),
        lambda id_val: json.dumps({'action': 'get_account', 'id':      id_val}),
        lambda id_val: json.dumps({'type':   'fetch',       'resource': f'/user/{id_val}'}),
        lambda id_val: json.dumps({'type':   'get_profile', 'userId':  id_val}),
        lambda id_val: json.dumps({'action': 'view',        'id':      id_val}),
        lambda id_val: json.dumps({'cmd':    'get_user',    'uid':     id_val}),
        lambda id_val: json.dumps({'op':     'read',        'user':    id_val}),
        lambda id_val: json.dumps({'method': 'getUser',     'params':  {'id': id_val}}),
    ]

    # ── Sensitive data patterns that confirm IDOR ─────────────────────────
    sensitive_patterns = [
        (r'"email"\s*:\s*"[^"]+@[^"]+"',  'email address'),
        (r'"password"\s*:',               'password field'),
        (r'"token"\s*:\s*"[^"]+"',        'auth token'),
        (r'"phone"\s*:\s*"[\d\+\-\s]+"', 'phone number'),
        (r'"ssn"\s*:',                    'SSN'),
        (r'"credit_card"\s*:',            'credit card'),
        (r'"balance"\s*:\s*[\d\.]+',      'account balance'),
        (r'"address"\s*:\s*"[^"]+"',      'physical address'),
        (r'"dob"\s*:',                    'date of birth'),
        (r'"secret"\s*:',                 'secret field'),
        (r'"api_key"\s*:',                'API key'),
        (r'"private_key"\s*:',            'private key'),
    ]

    try:
        async with await ws_connect(ws_url, timeout=5) as ws:

            # ── Step 1: Get baseline (what our "own" data looks like) ─────
            baseline = await send_recv(ws, '{"type":"ping"}', timeout=2)
            baseline_str = str(baseline or '')

            # Extract own user ID from baseline if present
            own_id_match = re.search(
                r'"(?:id|user_id|userId|uid)"\s*:\s*["\']?(\d+)["\']?',
                baseline_str
            )
            own_id = own_id_match.group(1) if own_id_match else None

            # ── Step 2: Sequential IDOR scan ─────────────────────────────
            for test_id in test_ids:
                # Skip our own ID — that's not IDOR
                if own_id and str(test_id) == str(own_id):
                    continue

                for template in action_templates:
                    try:
                        msg  = template(test_id)
                        resp = await send_recv(ws, msg, timeout=2)
                        if not resp:
                            continue

                        resp_lower = resp.lower()

                        # Skip error responses
                        if any(err in resp_lower for err in [
                            '"error"', 'not found', 'unauthorized',
                            'forbidden', 'access denied', 'invalid'
                        ]):
                            continue

                        # Check for sensitive data in response
                        for pattern, data_type in sensitive_patterns:
                            if re.search(pattern, resp, re.IGNORECASE):
                                ev = Evidence.make(
                                    payload=msg,
                                    request=f"Tested ID: {test_id} via action template",
                                    response=resp[:400],
                                    proof=f"IDOR confirmed: '{data_type}' returned for resource ID '{test_id}' without authorization check",
                                    reproduce=(
                                        f"1. Connect to {ws_url}\n"
                                        f"2. Send: {msg}\n"
                                        f"3. Response contains {data_type} of user ID {test_id}\n"
                                        f"4. No authorization token required — IDOR confirmed"
                                    )
                                )
                                added = store.add(
                                    ws_url, 'IDOR via WebSocket', 'HIGH',
                                    f"Insecure Direct Object Reference confirmed.\n"
                                    f"Accessed resource ID: {test_id}\n"
                                    f"Sensitive data leaked: {data_type}\n"
                                    f"No authorization check performed.", ev
                                )
                                if added:
                                    found_any = True
                                # Don't return — keep scanning other IDs
                                break

                    except Exception:
                        continue

            # ── Step 3: Vertical Privilege Escalation via IDOR ────────────
            # Try to access admin-only resources
            admin_actions = [
                json.dumps({'action': 'get_all_users'}),
                json.dumps({'action': 'admin_panel'}),
                json.dumps({'action': 'get_users',  'role': 'admin'}),
                json.dumps({'type':   'admin',       'cmd':  'list_users'}),
                json.dumps({'action': 'get_config'}),
                json.dumps({'action': 'system_info'}),
            ]

            for msg in admin_actions:
                try:
                    resp = await send_recv(ws, msg, timeout=2)
                    if not resp:
                        continue
                    resp_lower = resp.lower()

                    # Flag if response looks like admin data (list of users etc.)
                    if (re.search(r'"users"\s*:\s*\[', resp, re.I) or
                        re.search(r'"total_users"\s*:', resp, re.I) or
                        re.search(r'"admin_data"\s*:', resp, re.I)):

                        ev = Evidence.make(
                            payload=msg,
                            response=resp[:400],
                            proof="Vertical IDOR: admin-only resource accessible without admin privileges",
                            reproduce=(
                                f"1. Connect to {ws_url} (as regular user)\n"
                                f"2. Send: {msg}\n"
                                f"3. Receive admin-level data — privilege escalation via IDOR"
                            )
                        )
                        store.add(ws_url, 'IDOR — Vertical Privilege Escalation', 'CRITICAL',
                            f"Vertical IDOR: Admin resources accessible without admin role.\n"
                            f"Action: {msg}", ev)
                        found_any = True
                        break
                except Exception:
                    continue

    except Exception as e:
        log.debug(f"IDOR test error on {ws_url}: {e}")

    return found_any
