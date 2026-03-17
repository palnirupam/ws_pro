"""
Real WebSocket MITM proxy (asyncio + websockets).

Browser -> ws://localhost:PORT -> [this proxy] -> ws(s)://real-target

Key features:
- Multiple concurrent client sessions
- Bidirectional bridging with per-message callback for dashboard streaming
- Optional intercept/hold mode with Forward / Modify / Drop decisions
- SSL verification disabled for pentest usage
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import re
import ssl
import time
import uuid
import concurrent.futures
import threading
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

import websockets
from websockets.server import WebSocketServerProtocol


MessageCallback = Callable[[dict], None]


SUSPICIOUS_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)(select|insert|update|delete|drop|union).*?(from|into|table|where)", "SQL Pattern"),
    (r"(?i)<\s*script", "XSS Pattern"),
    (r"(?i)(password|passwd|secret|token|api.?key)", "Sensitive Data"),
    (r"(?i)(eyJ[A-Za-z0-9_-]+\.eyJ)", "JWT Token"),
    (r"(?i)(admin|root|sudo|superuser)", "Privilege Keyword"),
    (r"(?i)(\.\./|\.\.\\|%2e%2e)", "Path Traversal"),
    (r"(?i)(;|\||\&\&)\s*(ls|cat|id|whoami|ping|curl|powershell|cmd)", "Command Injection"),
    (r"(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", "Email"),
]


def _now_hms() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _flags_for_text(text: str) -> list[str]:
    flags: list[str] = []
    for pat, label in SUSPICIOUS_PATTERNS:
        try:
            if re.search(pat, text):
                flags.append(label)
        except re.error:
            # Shouldn't happen, but never crash the proxy for a bad regex.
            continue
    return flags


def _is_jsonish(s: str) -> bool:
    s = s.strip()
    return (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]"))


def _to_text_and_meta(payload: Any) -> tuple[str, str, int]:
    """
    Return (text, message_type, size_bytes).
    websockets delivers either str or bytes.
    """
    if isinstance(payload, bytes):
        size = len(payload)
        b64 = base64.b64encode(payload[:2048]).decode("ascii")
        suffix = "" if size <= 2048 else f"...(+{size-2048} bytes)"
        return f"<binary:{size} bytes> base64:{b64}{suffix}", "binary", size
    if payload is None:
        return "", "text", 0
    text = str(payload)
    return text, ("json" if _is_jsonish(text) else "text"), len(text.encode("utf-8", "replace"))


@dataclass
class HeldMessage:
    id: str
    created_ts: float
    session_id: str
    direction: str  # "CLIENT→SERVER" or "SERVER→CLIENT"
    original_payload: Any
    message_text: str
    message_type: str
    size: int
    flags: list[str]
    decision: asyncio.Future  # resolves to {"action": "forward"|"drop", "payload": Any}


@dataclass
class SessionStats:
    start_time: float = dataclasses.field(default_factory=time.time)
    total_intercepted: int = 0
    c2s_count: int = 0
    s2c_count: int = 0
    flagged_count: int = 0


@dataclass
class ProxySession:
    id: str
    client_ws: WebSocketServerProtocol
    server_ws: websockets.WebSocketClientProtocol
    stats: SessionStats = dataclasses.field(default_factory=SessionStats)


class WSProxyServer:
    """
    WebSocket MITM proxy server.

    This object is asyncio-native, but it's designed to be started/stopped from a
    different thread (dashboard uses SocketIO threading mode).
    """

    def __init__(
        self,
        target_url: str,
        listen_host: str = "127.0.0.1",
        listen_port: int = 8080,
        intercept_mode: bool = False,
        on_message: Optional[MessageCallback] = None,
    ) -> None:
        self.target_url = (target_url or "").strip()
        self.listen_host = listen_host
        self.listen_port = int(listen_port)
        self.intercept_mode = bool(intercept_mode)
        self.on_message = on_message

        self._ws_server: Any = None  # websockets.server.Serve
        self._running = asyncio.Event()

        self._sessions: dict[str, ProxySession] = {}
        self._held: dict[str, HeldMessage] = {}

    # ── Public (async) control ─────────────────────────────────────────
    async def start(self) -> None:
        await self._start_async()

    async def stop(self) -> None:
        await self._stop_async()

    def forward_held(self, message_id: str, modified_content: Optional[str] = None) -> bool:
        """Forward a held message (must be called from the proxy loop thread)."""
        hm = self._held.get(message_id)
        if not hm or hm.decision.done():
            return False
        payload: Any = hm.original_payload if modified_content is None else modified_content
        hm.decision.set_result({"action": "forward", "payload": payload})
        return True

    def drop_held(self, message_id: str) -> bool:
        """Drop a held message (must be called from the proxy loop thread)."""
        hm = self._held.get(message_id)
        if not hm or hm.decision.done():
            return False
        hm.decision.set_result({"action": "drop", "payload": None})
        return True

    def replay(self, message: str, direction: str = "client_to_server") -> bool:
        """
        Replay a message via the proxy. Picks the most recent active session.
        direction: "client_to_server" or "server_to_client"
        """
        if not message:
            return False

        async def _do() -> None:
            sess = next(iter(self._sessions.values()), None)
            if not sess:
                return
            if direction == "server_to_client":
                # Not generally meaningful for a MITM replay UI; keep for completeness.
                await sess.client_ws.send(message)
                return
            await sess.server_ws.send(message)

        # If there is no active session, nothing can be replayed.
        if not self._sessions:
            return False

        asyncio.create_task(_do())
        return True

    # ── Async internals ───────────────────────────────────────────────
    async def _start_async(self) -> None:
        if not self.target_url:
            raise ValueError("No target_url set")

        # websockets.serve returns a Serve object; awaiting it starts listening.
        self._ws_server = await websockets.serve(
            self._handle_client,
            self.listen_host,
            self.listen_port,
            max_size=None,
            ping_interval=20,
            ping_timeout=20,
        )
        self._running.set()

    async def _stop_async(self) -> None:
        self._running.clear()

        # Close held message decisions to avoid deadlocks.
        for mid, hm in list(self._held.items()):
            if not hm.decision.done():
                hm.decision.set_result({"action": "drop", "payload": None})
            self._held.pop(mid, None)

        # Close sessions
        for sid, sess in list(self._sessions.items()):
            try:
                await sess.client_ws.close()
            except Exception:
                pass
            try:
                await sess.server_ws.close()
            except Exception:
                pass
            self._sessions.pop(sid, None)

        # Stop server
        try:
            if self._ws_server is not None:
                self._ws_server.close()
                await self._ws_server.wait_closed()
        finally:
            self._ws_server = None

    def _ssl_ctx_for_target(self) -> Optional[ssl.SSLContext]:
        if not self.target_url.lower().startswith("wss://"):
            return None
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    async def _handle_client(self, client_ws: WebSocketServerProtocol) -> None:
        session_id = uuid.uuid4().hex[:12]
        ssl_ctx = self._ssl_ctx_for_target()

        try:
            server_ws = await websockets.connect(
                self.target_url,
                ssl=ssl_ctx,
                open_timeout=10,
                max_size=None,
                ping_interval=20,
                ping_timeout=20,
            )
        except Exception as e:
            # Tell client why it failed, then close.
            self._emit_message(
                {
                    "id": uuid.uuid4().hex,
                    "time": _now_hms(),
                    "direction": "SYSTEM",
                    "message": f"Proxy error: failed to connect to target {self.target_url}: {str(e)[:200]}",
                    "flagged": True,
                    "flags": ["Target Unreachable"],
                    "held": False,
                    "size": 0,
                    "message_type": "text",
                    "session_id": session_id,
                    "stats": {
                        "total": 0,
                        "c2s": 0,
                        "s2c": 0,
                        "flagged": 1,
                        "start_time": time.time(),
                    },
                }
            )
            try:
                await client_ws.send(f"Proxy error: failed to connect to target: {e}")
            except Exception:
                pass
            try:
                await client_ws.close()
            except Exception:
                pass
            return

        sess = ProxySession(id=session_id, client_ws=client_ws, server_ws=server_ws)
        self._sessions[session_id] = sess

        async def _bridge(
            src: Any,
            dst: Any,
            direction: str,
        ) -> None:
            # direction is display direction used by dashboard
            is_c2s = direction == "CLIENT→SERVER"
            try:
                async for payload in src:
                    text, mtype, size = _to_text_and_meta(payload)
                    flags = _flags_for_text(text)
                    flagged = bool(flags)

                    sess.stats.total_intercepted += 1
                    if is_c2s:
                        sess.stats.c2s_count += 1
                    else:
                        sess.stats.s2c_count += 1
                    if flagged:
                        sess.stats.flagged_count += 1

                    held = False
                    msg_id = uuid.uuid4().hex

                    if self.intercept_mode:
                        held = True
                        decision: asyncio.Future = asyncio.get_running_loop().create_future()
                        hm = HeldMessage(
                            id=msg_id,
                            created_ts=time.time(),
                            session_id=session_id,
                            direction=direction,
                            original_payload=payload,
                            message_text=text,
                            message_type=mtype,
                            size=size,
                            flags=flags,
                            decision=decision,
                        )
                        self._held[msg_id] = hm

                    self._emit_message(
                        {
                            "id": msg_id,
                            "time": _now_hms(),
                            "direction": direction,
                            "message": text,
                            "flagged": flagged,
                            "flags": flags,
                            "held": held,
                            "size": size,
                            "message_type": mtype,
                            "session_id": session_id,
                            "stats": {
                                "total": sess.stats.total_intercepted,
                                "c2s": sess.stats.c2s_count,
                                "s2c": sess.stats.s2c_count,
                                "flagged": sess.stats.flagged_count,
                                "start_time": sess.stats.start_time,
                            },
                        }
                    )

                    if not self.intercept_mode:
                        await dst.send(payload)
                        continue

                    # Wait for user decision.
                    try:
                        res = await asyncio.wait_for(decision, timeout=None)
                    finally:
                        # Remove held entry once decided.
                        self._held.pop(msg_id, None)

                    if not isinstance(res, dict):
                        continue
                    if res.get("action") == "drop":
                        continue
                    if res.get("action") == "forward":
                        await dst.send(res.get("payload"))
            except websockets.exceptions.ConnectionClosed:
                return
            except Exception:
                return

        t1 = asyncio.create_task(_bridge(client_ws, server_ws, "CLIENT→SERVER"))
        t2 = asyncio.create_task(_bridge(server_ws, client_ws, "SERVER→CLIENT"))

        try:
            await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in (t1, t2):
                if not t.done():
                    t.cancel()
            self._sessions.pop(session_id, None)
            try:
                await client_ws.close()
            except Exception:
                pass
            try:
                await server_ws.close()
            except Exception:
                pass

    def _emit_message(self, data: dict) -> None:
        cb = self.on_message
        if not cb:
            return
        try:
            cb(data)
        except Exception:
            # Never let dashboard callback crash proxy.
            return


def validate_ws_url(ws_url: str) -> tuple[bool, str]:
    u = (ws_url or "").strip()
    if not u:
        return False, "Empty URL"
    if not (u.startswith("ws://") or u.startswith("wss://")):
        return False, "URL must start with ws:// or wss://"
    return True, ""


class WSProxyController:
    """
    Real-world style proxy runtime:
    - One dedicated asyncio loop thread
    - Start/stop are acknowledged (sync wait with timeout)
    - All actions are marshalled onto the proxy loop
    """

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._ready = threading.Event()
        self._server: WSProxyServer | None = None
        self._lock = threading.Lock()

    def _ensure_loop(self) -> asyncio.AbstractEventLoop:
        with self._lock:
            if self._loop and self._loop.is_running():
                return self._loop

            self._ready.clear()

            def _run_loop() -> None:
                loop = asyncio.new_event_loop()
                self._loop = loop
                asyncio.set_event_loop(loop)
                self._ready.set()
                loop.run_forever()
                # cleanup
                try:
                    loop.close()
                except Exception:
                    pass

            self._thread = threading.Thread(target=_run_loop, daemon=True)
            self._thread.start()

        if not self._ready.wait(timeout=3):
            raise TimeoutError("Proxy controller loop failed to start")
        assert self._loop is not None
        return self._loop

    def start(
        self,
        *,
        target_url: str,
        listen_host: str,
        listen_port: int,
        intercept_mode: bool,
        on_message: Optional[MessageCallback],
        timeout_s: float = 6.0,
    ) -> None:
        loop = self._ensure_loop()

        # Stop any existing server first (real-world tools do clean restarts).
        if self._server is not None:
            self.stop(timeout_s=timeout_s)

        self._server = WSProxyServer(
            target_url=target_url,
            listen_host=listen_host,
            listen_port=listen_port,
            intercept_mode=intercept_mode,
            on_message=on_message,
        )

        fut = asyncio.run_coroutine_threadsafe(self._server.start(), loop)
        fut.result(timeout=timeout_s)

    def stop(self, timeout_s: float = 6.0) -> None:
        if not self._loop or not self._loop.is_running():
            self._server = None
            return
        if not self._server:
            return
        fut = asyncio.run_coroutine_threadsafe(self._server.stop(), self._loop)
        fut.result(timeout=timeout_s)
        self._server = None

    def forward_held(self, message_id: str, modified_content: Optional[str] = None) -> bool:
        if not self._loop or not self._loop.is_running() or not self._server:
            return False
        async def _do() -> bool:
            return self._server.forward_held(message_id, modified_content=modified_content)
        fut = asyncio.run_coroutine_threadsafe(_do(), self._loop)
        return bool(fut.result(timeout=6))

    def drop_held(self, message_id: str) -> bool:
        if not self._loop or not self._loop.is_running() or not self._server:
            return False
        async def _do() -> bool:
            return self._server.drop_held(message_id)
        fut = asyncio.run_coroutine_threadsafe(_do(), self._loop)
        return bool(fut.result(timeout=6))

    def replay(self, message: str, direction: str) -> bool:
        if not self._loop or not self._loop.is_running() or not self._server:
            return False
        async def _do() -> bool:
            return self._server.replay(message, direction=direction)
        fut = asyncio.run_coroutine_threadsafe(_do(), self._loop)
        return bool(fut.result(timeout=6))

