"""
Core Scanner — Smart, reliable, zero false positives
"""
import asyncio
import re
import ssl
import time
from urllib.parse import urlparse
import httpx
import websockets
from utils.logger import log
from utils.evidence import Evidence


# ── Endpoint Discovery ────────────────────────────────────────────────────────

COMMON_WS_PATHS = [
    '/ws', '/websocket', '/socket', '/socket.io/',
    '/sockjs/websocket', '/cable', '/push', '/live',
    '/realtime', '/stream', '/events', '/api/ws',
    '/api/v1/ws', '/api/websocket', '/chat', '/notify',
    '/connect', '/hub', '/graphql', '/subscriptions',
]

async def discover_endpoints(target_url: str, timeout: int = 8) -> list:
    endpoints = []
    parsed = urlparse(target_url)
    scheme = 'wss' if parsed.scheme in ('https', 'wss') else 'ws'
    base_ws = f"{scheme}://{parsed.netloc}"

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
            r = await client.get(target_url)
            html = r.text

            # Regex: find WS URLs in source
            patterns = [
                r'["\`](wss?://[^\s"\`>\']+)',
                r'new\s+WebSocket\s*\(\s*["\`](.*?)["\`]',
                r'WebSocket\s*\(\s*["\`](.*?)["\`]',
                r'socketUrl\s*[=:]\s*["\`](.*?)["\`]',
                r'wsUrl\s*[=:]\s*["\`](.*?)["\`]',
                r'ws[_-]?endpoint\s*[=:]\s*["\`](.*?)["\`]',
            ]
            for pat in patterns:
                for m in re.finditer(pat, html, re.IGNORECASE):
                    url = m.group(1)
                    if url.startswith('ws'):
                        endpoints.append(url)
                    elif url.startswith('/'):
                        endpoints.append(base_ws + url)

            # Scan linked JS files
            js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html, re.I)
            for js_url in js_urls[:5]:
                full = js_url if js_url.startswith('http') else target_url.rstrip('/') + '/' + js_url.lstrip('/')
                try:
                    jr = await client.get(full, timeout=4)
                    for pat in patterns:
                        for m in re.finditer(pat, jr.text, re.IGNORECASE):
                            url = m.group(1)
                            if url.startswith('ws'):
                                endpoints.append(url)
                            elif url.startswith('/'):
                                endpoints.append(base_ws + url)
                except Exception:
                    pass

    except Exception as e:
        log.warning(f"Discovery HTTP error: {e}")

    # Always test the base URL root and the target's own path
    endpoints.insert(0, base_ws + '/')
    if parsed.path and parsed.path != '/':
        endpoints.insert(1, base_ws + parsed.path)

    # Add common paths
    for path in COMMON_WS_PATHS:
        endpoints.append(base_ws + path)

    # Deduplicate, limit
    seen = set()
    result = []
    for ep in endpoints:
        if ep not in seen and ep.startswith('ws'):
            seen.add(ep)
            result.append(ep)

    return result[:25]


# ── Connection Test ───────────────────────────────────────────────────────────

async def test_connection(ws_url: str, timeout: int = 5) -> dict:
    """Check if endpoint actually accepts WS connections"""
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    try:
        async with websockets.connect(
            ws_url,
            open_timeout=timeout,
            ssl=ssl_ctx if ws_url.startswith('wss') else None,
        ) as ws:
            # Get initial server message
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=2)
                return {'alive': True, 'initial_msg': str(msg)[:300]}
            except asyncio.TimeoutError:
                return {'alive': True, 'initial_msg': None}
            except websockets.exceptions.ConnectionClosed:
                return {'alive': True, 'initial_msg': None}
    except Exception as e:
        exc_name = type(e).__name__
        err_str = str(e).lower()

        # Handle HTTP rejections (e.g., Auth required, Rate limited)
        # These indicate the endpoint is a valid target but restricted
        if 'invalidstatus' in exc_name.lower():
            status = getattr(e, 'status_code', None)
            if status in [401, 403, 429, 500, 502, 503]:
                return {'alive': True, 'initial_msg': None}
            elif '401' in err_str or '403' in err_str or '429' in err_str:
                return {'alive': True, 'initial_msg': None}

        # Handle premature connection closures (often auth/subprotocol related)
        if exc_name in ('ConnectionClosedError', 'ConnectionClosedOK', 'ConnectionClosed'):
            return {'alive': True, 'initial_msg': None}

        return {'alive': False, 'error': str(e)}


# ── Smart WS Connection helper ────────────────────────────────────────────────

async def ws_connect(ws_url: str, headers: dict = None, timeout: int = 5):
    """Create WS connection with proper SSL + headers"""
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    kwargs = {
        'open_timeout': timeout,
        'ssl': ssl_ctx if ws_url.startswith('wss') else None,
    }
    if headers:
        kwargs['additional_headers'] = headers

    return await websockets.connect(ws_url, **kwargs)


async def send_recv(ws, message: str, timeout: float = 3.0) -> str | None:
    """Send message and receive response with timeout"""
    await ws.send(message)
    try:
        return await asyncio.wait_for(ws.recv(), timeout=timeout)
    except asyncio.TimeoutError:
        return None


# ── Fingerprint server ────────────────────────────────────────────────────────

async def fingerprint(ws_url: str) -> dict:
    """Detect server framework, auth type, message format"""
    info = {
        'framework':    'unknown',
        'auth_type':    'unknown',
        'msg_format':   'unknown',
        'server_header': None,
    }

    parsed = urlparse(ws_url)
    http_url = ('https' if ws_url.startswith('wss') else 'http') + '://' + parsed.netloc

    try:
        async with httpx.AsyncClient(timeout=5, verify=False) as client:
            r = await client.get(http_url)
            info['server_header'] = r.headers.get('server', 'unknown')
    except Exception:
        pass

    try:
        result = await test_connection(ws_url)
        if result['alive'] and result['initial_msg']:
            msg = result['initial_msg'].lower()
            if 'socket.io' in msg or '0{"sid"' in msg:
                info['framework'] = 'Socket.IO'
            elif 'sockjs' in msg:
                info['framework'] = 'SockJS'
            elif 'actioncable' in msg or '"type":"welcome"' in msg:
                info['framework'] = 'ActionCable (Rails)'
            elif '"type":"connection_ack"' in msg:
                info['framework'] = 'GraphQL Subscriptions'
            elif '{' in msg:
                info['msg_format'] = 'JSON'
            else:
                info['msg_format'] = 'Text'
    except Exception:
        pass

    return info
