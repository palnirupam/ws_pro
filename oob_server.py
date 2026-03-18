"""
WS Tester Pro — OOB (Out-of-Band) Callback Server

Self-host this on a VPS / public domain to confirm blind SSRF/XXE-style issues.

Endpoints:
  - /c/<token>          records HTTP callbacks (GET/POST/PUT/...)
  - /api/events/<token> returns recorded events for a token (optional API key)

Security:
  - Set OOB_API_KEY to require X-OOB-Key header for the API endpoints (recommended).
  - Callback endpoint (/c/<token>) remains unauthenticated by design.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import time
from datetime import datetime

from flask import Flask, jsonify, request


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

EVENTS_PATH = os.path.join(LOG_DIR, "oob_events.jsonl")  # optional append-only audit
DB_PATH = os.path.join(LOG_DIR, "oob_events.sqlite3")

API_KEY = os.environ.get("OOB_API_KEY", "").strip()
API_OPEN = (os.environ.get("OOB_API_OPEN", "").strip().lower() in ("1", "true", "yes"))
MAX_BODY_BYTES = int(os.environ.get("OOB_MAX_BODY_BYTES", "4096"))
MAX_EVENTS_PER_TOKEN = int(os.environ.get("OOB_MAX_EVENTS_PER_TOKEN", "50"))
TOKEN_TTL_SECONDS = int(os.environ.get("OOB_TOKEN_TTL_SECONDS", str(60 * 60 * 24 * 7)))  # default: 7d
RATE_LIMIT_PER_MIN = int(os.environ.get("OOB_RATE_LIMIT_PER_MIN", "120"))  # per IP, callback endpoint
TRUST_PROXY = (os.environ.get("OOB_TRUST_PROXY", "").strip().lower() in ("1", "true", "yes"))

app = Flask(__name__)

_lock = threading.Lock()
_events: dict[str, list[dict]] = {}
_rl: dict[str, list[float]] = {}  # ip -> timestamps (rolling 60s)


def _db() -> sqlite3.Connection:
    # check_same_thread=False because Flask may handle requests in multiple threads
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          token TEXT NOT NULL,
          ts INTEGER NOT NULL,
          method TEXT,
          path TEXT,
          query TEXT,
          remote_addr TEXT,
          user_agent TEXT,
          headers_json TEXT,
          body_preview TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_token_ts ON events(token, ts)")
    return conn


_DB = _db()


def _now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"

def _now_ts() -> int:
    return int(time.time())


def _write_jsonl(obj: dict) -> None:
    try:
        with open(EVENTS_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _clean_token(token: str) -> str:
    token = (token or "").strip()
    # keep tokens short/URL-safe to prevent log abuse
    token = token[:80]
    token = re.sub(r"[^a-zA-Z0-9_\-\.]", "", token)
    return token


def _get_remote_ip() -> str:
    if TRUST_PROXY:
        xf = request.headers.get("X-Forwarded-For", "")
        if xf:
            return xf.split(",")[0].strip()
    return request.remote_addr or ""


def _rate_limit_ok(ip: str) -> bool:
    if not ip:
        return True
    now = time.time()
    window_start = now - 60.0
    with _lock:
        lst = _rl.get(ip) or []
        lst = [t for t in lst if t >= window_start]
        if len(lst) >= RATE_LIMIT_PER_MIN:
            _rl[ip] = lst
            return False
        lst.append(now)
        _rl[ip] = lst
    return True


def _record_event(token: str) -> dict:
    body = b""
    try:
        body = request.get_data(cache=False) or b""
    except Exception:
        body = b""
    if len(body) > MAX_BODY_BYTES:
        body = body[:MAX_BODY_BYTES]

    token = _clean_token(token)
    ev = {
        "token": token,
        "ts": _now_iso(),
        "method": request.method,
        "path": request.path,
        "query": request.query_string.decode(errors="ignore"),
        "remote_addr": _get_remote_ip(),
        "user_agent": request.headers.get("User-Agent", ""),
        "headers": {k: v for k, v in request.headers.items() if k.lower() not in ("cookie",)},
        "body_preview": body.decode(errors="replace"),
    }

    with _lock:
        lst = _events.get(token) or []
        lst.append(ev)
        if len(lst) > MAX_EVENTS_PER_TOKEN:
            lst = lst[-MAX_EVENTS_PER_TOKEN:]
        _events[token] = lst

    # Persist
    try:
        _DB.execute(
            "INSERT INTO events(token, ts, method, path, query, remote_addr, user_agent, headers_json, body_preview) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (
                token,
                _now_ts(),
                ev.get("method"),
                ev.get("path"),
                ev.get("query"),
                ev.get("remote_addr"),
                ev.get("user_agent"),
                json.dumps(ev.get("headers", {}), ensure_ascii=False),
                ev.get("body_preview"),
            ),
        )
        _DB.commit()
    except Exception:
        pass
    _write_jsonl(ev)  # audit trail (best-effort)
    return ev


def _require_api_key() -> bool:
    if API_OPEN:
        return True
    # Default: require API key for /api/*
    if not API_KEY:
        return False
    given = (request.headers.get("X-OOB-Key") or "").strip()
    return bool(given and given == API_KEY)


@app.route("/health")
def health():
    return jsonify(
        {
            "ok": True,
            "time": int(time.time()),
            "api_protected": (not API_OPEN),
            "token_ttl_seconds": TOKEN_TTL_SECONDS,
        }
    )


@app.route("/c/<token>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
def callback(token: str):
    ip = _get_remote_ip()
    if not _rate_limit_ok(ip):
        return ("", 429)
    _record_event(token)
    # Return a tiny 204 so targets don't waste time downloading a body.
    return ("", 204)


@app.route("/api/events/<token>", methods=["GET"])
def events(token: str):
    if not _require_api_key():
        return jsonify({"error": "unauthorized"}), 401

    token = _clean_token(token)
    since = request.args.get("since", "").strip()
    since_ts = 0
    try:
        if since:
            since_ts = int(since)
    except Exception:
        since_ts = 0

    try:
        cur = _DB.execute(
            "SELECT ts, method, path, query, remote_addr, user_agent, headers_json, body_preview "
            "FROM events WHERE token=? AND ts>=? ORDER BY ts ASC LIMIT ?",
            (token, since_ts, MAX_EVENTS_PER_TOKEN),
        )
        rows = cur.fetchall()
        out = []
        for ts, method, path, query, remote_addr, ua, headers_json, body_preview in rows:
            out.append(
                {
                    "token": token,
                    "ts": datetime.utcfromtimestamp(int(ts)).isoformat() + "Z",
                    "method": method,
                    "path": path,
                    "query": query,
                    "remote_addr": remote_addr,
                    "user_agent": ua,
                    "headers": json.loads(headers_json or "{}"),
                    "body_preview": body_preview,
                }
            )
        return jsonify({"token": token, "count": len(out), "events": out, "since": since_ts})
    except Exception:
        # Fallback to in-memory if DB read fails
        with _lock:
            lst = list(_events.get(token) or [])
        return jsonify({"token": token, "count": len(lst), "events": lst})


@app.route("/api/last", methods=["GET"])
def last_events():
    if not _require_api_key():
        return jsonify({"error": "unauthorized"}), 401
    n = int(request.args.get("n", "30"))
    n = max(1, min(n, 200))

    # Best-effort: scan JSONL from disk (keeps memory small if server runs long).
    out = []
    try:
        with open(EVENTS_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()[-n:]
        for ln in lines:
            try:
                out.append(json.loads(ln))
            except Exception:
                pass
    except Exception:
        pass

    return jsonify({"count": len(out), "events": out})


def _cleanup_loop() -> None:
    # Purge old events to keep DB/logs bounded.
    while True:
        try:
            if TOKEN_TTL_SECONDS > 0:
                cutoff = _now_ts() - TOKEN_TTL_SECONDS
                _DB.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
                _DB.commit()
        except Exception:
            pass
        time.sleep(60)


if __name__ == "__main__":
    host = os.environ.get("OOB_HOST", "0.0.0.0")
    port = int(os.environ.get("OOB_PORT", "7000"))
    print(f"🛰️  OOB server listening on http://{host}:{port}")
    if API_OPEN:
        print("⚠️  OOB_API_OPEN=1 — /api/* is open (not recommended on the Internet).")
    elif API_KEY:
        print("🔐 API key protection enabled for /api/*")
    else:
        print("❌ No OOB_API_KEY set — /api/* will be locked. Set OOB_API_KEY to use polling/auto-confirm.")

    threading.Thread(target=_cleanup_loop, daemon=True).start()
    app.run(host=host, port=port, debug=False)

