"""
WebSocket Fuzzer Module
Sends malformed/unexpected data to discover crashes, error leaks, and anomalies.
Real-world bug bounty grade — detects DoS, stack trace leaks, and unhandled exceptions.
"""
import asyncio
import json
import re
import struct
import time
import websockets
from core.scanner import ws_connect, send_recv
from core.findings import store
from utils.evidence import Evidence
from utils.logger import log
from utils.evidence import Evidence
from utils.logger import log


# ── Fuzzer Payload Categories ─────────────────────────────────────────────────

OVERSIZED_PAYLOADS = [
    ('A' * 50000,                           'Large string (50KB)'),
    ('A' * 200000,                          'Very large string (200KB)'),
    ('{' * 10000,                           'Nested braces (10K)'),
    ('[' * 10000,                           'Nested brackets (10K)'),
    ('{"x":"' + 'B' * 100000 + '"}',        'Large JSON value (100KB)'),
]

MALFORMED_JSON_PAYLOADS = [
    ('{"id":',                              'Truncated JSON'),
    ('{{{',                                 'Triple braces'),
    ('[null',                               'Unclosed array'),
    ('{"a":undefined}',                     'JS undefined in JSON'),
    ('{"a":NaN}',                           'NaN in JSON'),
    ('{"a":Infinity}',                      'Infinity in JSON'),
    ('{' + '"a":1,' * 5000 + '"z":0}',      'Deeply nested keys'),
    ('[]' * 5000,                           'Repeated arrays'),
    ('{"key": "\\"\\"\\""}',                'Escaped quote chaos'),
    ('',                                    'Empty string'),
    (' ',                                   'Whitespace only'),
]

SPECIAL_BYTE_PAYLOADS = [
    ('\x00',                                'Null byte'),
    ('\x00' * 100,                          'Null byte flood'),
    ('\xff\xfe',                            'UTF-16 BOM'),
    ('\xef\xbb\xbf',                        'UTF-8 BOM'),
    ('\r\n' * 1000,                         'CRLF flood'),
    ('\x1b[31mRED\x1b[0m',                  'ANSI escape sequence'),
    ('%00%0d%0a',                            'URL-encoded control chars'),
]

TYPE_CONFUSION_PAYLOADS = [
    ('{"id": true}',                        'Boolean as ID'),
    ('{"id": null}',                        'Null as ID'),
    ('{"id": [1,2,3]}',                     'Array as ID'),
    ('{"id": {"nested": true}}',            'Object as ID'),
    ('{"id": 1.7976931348623157e+308}',     'Max float'),
    ('{"id": -1}',                          'Negative ID'),
    ('{"id": 0}',                           'Zero ID'),
    ('{"id": 99999999999999999999}',        'Huge integer'),
    ('{"id": -99999999999999999999}',       'Huge negative integer'),
    ('{"amount": 0.1, "repeat": 999999}',   'Float precision + large repeat'),
]

BOUNDARY_PAYLOADS = [
    ('{"id": 2147483647}',                  'INT32 MAX'),
    ('{"id": 2147483648}',                  'INT32 MAX + 1'),
    ('{"id": -2147483648}',                 'INT32 MIN'),
    ('{"id": -2147483649}',                 'INT32 MIN - 1'),
    ('{"id": 9007199254740991}',            'JS MAX_SAFE_INTEGER'),
    ('{"id": 9007199254740992}',            'JS MAX_SAFE_INTEGER + 1'),
    ('{"length": -1}',                      'Negative length'),
    ('{"offset": -1}',                      'Negative offset'),
    ('{"page": 0}',                         'Zero page'),
    ('{"limit": 999999999}',                'Absurd limit'),
]

# ── Error/Crash Detection Patterns ────────────────────────────────────────────

ERROR_LEAK_PATTERNS = [
    (r'traceback\s*\(most recent call',     'Python Stack Trace'),
    (r'at\s+\S+\s*\([\w./\\]+:\d+:\d+\)',   'Node.js Stack Trace'),
    (r'java\.\w+\.(\w+Exception)',           'Java Exception'),
    (r'System\.\w+Exception',               'C#/.NET Exception'),
    (r'panic:\s',                           'Go Panic'),
    (r'FATAL\s+ERROR',                      'Fatal Error'),
    (r'Segmentation fault',                 'Segfault'),
    (r'stack overflow',                     'Stack Overflow'),
    (r'internal server error',             'Internal Server Error'),
    (r'unhandled\s+(exception|error|rejection)', 'Unhandled Exception'),
    (r'undefined\s+is\s+not\s+(a\s+function|an\s+object)', 'JS TypeError'),
    (r'cannot read propert',               'JS Property Error'),
    (r'maximum call stack',                'Recursion Overflow'),
    (r'out of memory',                     'Out of Memory'),
    (r'killed',                            'Process Killed'),
]

SENSITIVE_LEAK_PATTERNS = [
    (r'(?:/[\w.]+)+\.\w{1,4}:\d+',         'File Path Leak'),
    (r'(?:password|passwd|secret|api.?key)\s*[=:]\s*\S+', 'Credential Leak'),
    (r'mongodb://\S+',                     'MongoDB Connection String'),
    (r'postgres://\S+',                    'PostgreSQL Connection String'),
    (r'mysql://\S+',                       'MySQL Connection String'),
    (r'(?:SELECT|INSERT|UPDATE|DELETE)\s+', 'SQL Query Leak'),
    (r'node_modules/',                     'Node.js Path Leak'),
    (r'site-packages/',                    'Python Path Leak'),
]


async def test_fuzzing(ws_url: str, fast_mode: bool = False) -> list:
    """
    WebSocket Fuzzer — sends malformed data to discover crashes,
    error leaks, and unexpected server behavior.
    Returns list of confirmed finding types.
    """
    results = []

    # Select payload sets based on mode
    if fast_mode:
        payload_sets = [
            ('Malformed JSON',     MALFORMED_JSON_PAYLOADS[:5]),
            ('Type Confusion',     TYPE_CONFUSION_PAYLOADS[:4]),
            ('Boundary Values',    BOUNDARY_PAYLOADS[:4]),
        ]
    else:
        payload_sets = [
            ('Oversized',          OVERSIZED_PAYLOADS),
            ('Malformed JSON',     MALFORMED_JSON_PAYLOADS),
            ('Special Bytes',      SPECIAL_BYTE_PAYLOADS),
            ('Type Confusion',     TYPE_CONFUSION_PAYLOADS),
            ('Boundary Values',    BOUNDARY_PAYLOADS),
        ]

    # ── Get baseline response ─────────────────────────────────────────────
    baseline_len = 0
    try:
        async with await ws_connect(ws_url, timeout=5) as ws:
            baseline = await send_recv(ws, '{"type":"ping"}', timeout=3)
            baseline_len = len(baseline) if baseline else 0
    except Exception:
        pass

    crashes = []
    error_leaks = []
    sensitive_leaks = []
    anomalies = []

    for category_name, payloads in payload_sets:
        for payload, label in payloads:
            try:
                async with await ws_connect(ws_url, timeout=5) as ws:
                    # Consume welcome/initial message if any
                    try:
                        await asyncio.wait_for(ws.recv(), timeout=1)
                    except (asyncio.TimeoutError, Exception):
                        pass

                    # Send the fuzz payload
                    try:
                        await ws.send(payload)
                    except Exception as send_err:
                        # Connection dropped on send — possible crash
                        crashes.append({
                            'category': category_name,
                            'label': label,
                            'payload': payload[:200],
                            'error': f'Send failed: {send_err}',
                        })
                        continue

                    # Try to receive response
                    try:
                        resp = await asyncio.wait_for(ws.recv(), timeout=3)
                    except asyncio.TimeoutError:
                        # No response — possible hang/crash
                        crashes.append({
                            'category': category_name,
                            'label': label,
                            'payload': payload[:200],
                            'error': 'No response (timeout — possible server hang)',
                        })
                        continue
                    except websockets.exceptions.ConnectionClosed as cc:
                        # Server closed connection after payload — crash indicator
                        crashes.append({
                            'category': category_name,
                            'label': label,
                            'payload': payload[:200],
                            'error': f'Connection closed: code={cc.code} reason={cc.reason}',
                        })
                        continue

                    resp_str = str(resp)

                    # ── Check for error/stack trace leaks ─────────────────
                    for pattern, leak_type in ERROR_LEAK_PATTERNS:
                        if re.search(pattern, resp_str, re.IGNORECASE):
                            error_leaks.append({
                                'category': category_name,
                                'label': label,
                                'payload': payload[:200],
                                'response': resp_str[:400],
                                'leak_type': leak_type,
                            })
                            break

                    # ── Check for sensitive data leaks ────────────────────
                    for pattern, leak_type in SENSITIVE_LEAK_PATTERNS:
                        if re.search(pattern, resp_str, re.IGNORECASE):
                            sensitive_leaks.append({
                                'category': category_name,
                                'label': label,
                                'payload': payload[:200],
                                'response': resp_str[:400],
                                'leak_type': leak_type,
                            })
                            break

                    # ── Check for response size anomaly ───────────────────
                    if baseline_len > 0 and len(resp_str) > baseline_len * 5:
                        anomalies.append({
                            'category': category_name,
                            'label': label,
                            'payload': payload[:200],
                            'response_size': len(resp_str),
                            'baseline_size': baseline_len,
                        })

            except websockets.exceptions.ConnectionClosed:
                crashes.append({
                    'category': category_name,
                    'label': label,
                    'payload': payload[:200],
                    'error': 'Connection refused/closed before send',
                })
            except Exception as e:
                log.debug(f"Fuzzer error [{label}]: {e}")

    # ── Report Findings ───────────────────────────────────────────────────

    # Finding 1: Server crashes (DoS)
    if crashes:
        crash_summary = '\n'.join(
            f"  • [{c['category']}] {c['label']}: {c['error']}"
            for c in crashes[:10]
        )
        crash_payloads = [c['label'] for c in crashes[:5]]
        ev = Evidence.make(
            proof=f"Server crashed/hung on {len(crashes)} fuzz payloads",
            reproduce=(
                f"1. Connect to {ws_url}\n"
                f"2. Send payload: {crashes[0]['payload'][:80]}\n"
                f"3. Server closes connection or stops responding"
            ),
            crash_count=len(crashes),
            crash_payloads=crash_payloads,
        )
        severity = 'HIGH' if len(crashes) >= 3 else 'MEDIUM'
        store.add(ws_url, 'WebSocket Denial of Service (Fuzz Crash)', severity,
            f"Server crashed or became unresponsive when sent {len(crashes)} malformed payloads.\n"
            f"Indicates missing input validation and DoS vulnerability.\n\n"
            f"Crash triggers:\n{crash_summary}", ev)
        results.append('fuzz_crash')

    # Finding 2: Error/Stack trace leaks
    if error_leaks:
        leak_summary = '\n'.join(
            f"  • [{e['leak_type']}] via {e['label']}"
            for e in error_leaks[:10]
        )
        unique_types = list(set(e['leak_type'] for e in error_leaks))
        ev = Evidence.make(
            payload=error_leaks[0]['payload'][:100],
            response=error_leaks[0]['response'][:300],
            proof=f"Server leaked {len(error_leaks)} error details: {', '.join(unique_types)}",
            reproduce=(
                f"1. Connect to {ws_url}\n"
                f"2. Send: {error_leaks[0]['payload'][:80]}\n"
                f"3. Observe stack trace / error details in response"
            ),
            leak_count=len(error_leaks),
            leak_types=unique_types,
        )
        store.add(ws_url, 'Error Information Disclosure (Fuzzer)', 'MEDIUM',
            f"Server leaked internal error details for {len(error_leaks)} fuzz payloads.\n"
            f"Error types exposed: {', '.join(unique_types)}\n\n"
            f"Details:\n{leak_summary}", ev)
        results.append('fuzz_error_leak')

    # Finding 3: Sensitive data leaks
    if sensitive_leaks:
        leak_summary = '\n'.join(
            f"  • [{s['leak_type']}] via {s['label']}"
            for s in sensitive_leaks[:10]
        )
        unique_types = list(set(s['leak_type'] for s in sensitive_leaks))
        ev = Evidence.make(
            payload=sensitive_leaks[0]['payload'][:100],
            response=sensitive_leaks[0]['response'][:300],
            proof=f"Sensitive data leaked: {', '.join(unique_types)}",
            reproduce=(
                f"1. Connect to {ws_url}\n"
                f"2. Send malformed payload: {sensitive_leaks[0]['payload'][:80]}\n"
                f"3. Server responds with sensitive internal data"
            ),
            leak_count=len(sensitive_leaks),
            leak_types=unique_types,
        )
        store.add(ws_url, 'Sensitive Data Leak via Fuzzing', 'HIGH',
            f"Server exposed sensitive information for {len(sensitive_leaks)} fuzz payloads.\n"
            f"Data types leaked: {', '.join(unique_types)}\n\n"
            f"Details:\n{leak_summary}", ev)
        results.append('fuzz_sensitive_leak')

    # Finding 4: Response size anomalies
    if anomalies:
        anom = anomalies[0]
        ev = Evidence.make(
            payload=anom['payload'][:100],
            proof=f"Response size {anom['response_size']} bytes vs baseline {anom['baseline_size']} bytes",
            reproduce=(
                f"1. Connect to {ws_url}\n"
                f"2. Send: {anom['payload'][:80]}\n"
                f"3. Response is {anom['response_size'] // anom['baseline_size']}x larger than normal"
            ),
            anomaly_count=len(anomalies),
        )
        store.add(ws_url, 'Abnormal Response Size (Fuzzer)', 'LOW',
            f"Server returned abnormally large responses for {len(anomalies)} payloads.\n"
            f"Largest: {anom['response_size']} bytes (baseline: {anom['baseline_size']} bytes).\n"
            f"May indicate data leak or buffer over-read.", ev)
        results.append('fuzz_anomaly')

    return results
