"""
WebSocket Subprotocol Attack Module
Tests for subprotocol negotiation vulnerabilities
"""
import asyncio
import json
import ssl
import websockets
from core.scanner import ws_connect, send_recv
from core.findings import store
from utils.evidence import Evidence
from utils.logger import log

# Common subprotocols to test
SUBPROTOCOLS = [
    'graphql-ws', 'graphql-transport-ws',
    'wamp.2.json', 'wamp.2.msgpack',
    'mqtt', 'stomp', 'v10.stomp', 'v11.stomp', 'v12.stomp',
    'soap', 'xmpp',
    'chat', 'superchat',
    'binary', 'base64',
    'actioncable-v1-json', 'actioncable-unsupported',
]


async def test_subprotocol(ws_url: str) -> bool:
    """Test for subprotocol negotiation issues"""

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    accepted = []
    all_tested = []

    for proto in SUBPROTOCOLS:
        try:
            async with websockets.connect(
                ws_url,
                subprotocols=[proto],
                open_timeout=5,
                ssl=ssl_ctx if ws_url.startswith('wss') else None,
            ) as ws:
                negotiated = ws.subprotocol
                if negotiated:
                    accepted.append(negotiated)
                    all_tested.append((proto, negotiated, True))
                else:
                    all_tested.append((proto, None, True))

                # Try sending a message to see if the subprotocol changes behavior
                resp = await send_recv(ws, '{"type":"ping"}', timeout=2)

        except websockets.exceptions.InvalidHandshake:
            all_tested.append((proto, None, False))
        except Exception:
            all_tested.append((proto, None, False))

    # ── Check 1: Accepts too many subprotocols ────────────────────────
    if len(accepted) >= 3:
        ev = Evidence.make(
            proof=f'Server accepted {len(accepted)} subprotocols: {", ".join(accepted)}',
            reproduce=(
                f"1. Connect to {ws_url} with various Sec-WebSocket-Protocol headers\n"
                f"2. Server accepts: {', '.join(accepted)}\n"
                f"3. Excessive protocol support increases attack surface"
            ),
            accepted_protocols=accepted,
        )
        store.add(ws_url, 'Excessive Subprotocol Support', 'LOW',
            f"Server accepts {len(accepted)} WebSocket subprotocols.\n"
            f"Supported: {', '.join(accepted)}\n"
            f"Large protocol surface area may expose vulnerabilities.", ev)
        return True

    # ── Check 2: Protocol confusion — accepts unexpected protocols ─────
    unexpected = [p for p in accepted if p in [
        'actioncable-unsupported', 'soap', 'xmpp', 'binary'
    ]]
    if unexpected:
        ev = Evidence.make(
            proof=f'Server accepts unexpected subprotocols: {", ".join(unexpected)}',
            reproduce=(
                f"1. Connect to {ws_url}\n"
                f"2. Set Sec-WebSocket-Protocol: {unexpected[0]}\n"
                f"3. Server accepts unexpected protocol"
            ),
        )
        store.add(ws_url, 'Subprotocol Confusion', 'MEDIUM',
            f"Server accepts unexpected subprotocols: {', '.join(unexpected)}.\n"
            f"May allow protocol downgrade/confusion attacks.", ev)
        return True

    # ── Check 3: No subprotocol validation ─────────────────────────────
    connected_without = sum(1 for _, _, connected in all_tested if connected)
    if connected_without == len(all_tested) and len(all_tested) > 3:
        ev = Evidence.make(
            proof=f'Server accepted connection for all {len(all_tested)} tested subprotocols',
            reproduce=(
                f"1. Connect to {ws_url} with any Sec-WebSocket-Protocol\n"
                f"2. Server always accepts — no validation"
            ),
        )
        store.add(ws_url, 'No Subprotocol Validation', 'LOW',
            f"Server accepts connections regardless of requested subprotocol.\n"
            f"No protocol validation may lead to unexpected behavior.", ev)
        return True

    return False
