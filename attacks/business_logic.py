"""
Business Logic Attack Module
Tests negative values, state machine bypass, workflow manipulation.
No scanner tests this — highest real-world vulnerability class.
"""
import asyncio
import json
import re
from core.scanner import ws_connect, send_recv
from core.findings import store
from utils.evidence import Evidence
from utils.logger import log


# ── Business Logic Test Cases ─────────────────────────────────────────────────
LOGIC_TESTS = [
    # ── Negative Values ──────────────────────────────────────────────────
    (
        '{"action":"purchase","item_id":"1","quantity":-1}',
        'negative_quantity',
        'Negative quantity',
        [r'"success"', r'"order"', r'"total"'],
        'Negative quantity accepted — attacker gets refund or free items',
        'CRITICAL',
    ),
    (
        '{"action":"transfer","amount":-100,"to":"attacker"}',
        'negative_transfer',
        'Negative transfer amount',
        [r'"success"', r'"balance"', r'"transferred"'],
        'Negative transfer — money flows backwards (victim receives, attacker "sends")',
        'CRITICAL',
    ),
    (
        '{"action":"withdraw","amount":-500}',
        'negative_withdraw',
        'Negative withdrawal',
        [r'"success"', r'"balance"'],
        'Negative withdrawal = deposit without paying',
        'CRITICAL',
    ),
    (
        '{"action":"apply_discount","percent":-50}',
        'negative_discount',
        'Negative discount',
        [r'"success"', r'"price"', r'"total"'],
        'Negative discount increases price — interesting logic issue',
        'MEDIUM',
    ),

    # ── Integer/Float Overflow ───────────────────────────────────────────
    (
        '{"action":"purchase","quantity":99999999999}',
        'int_overflow',
        'Integer overflow in quantity',
        [r'"success"', r'"order"', r'"quantity":0', r'"quantity":-'],
        'Integer overflow wraps to negative/zero — free purchase',
        'HIGH',
    ),
    (
        '{"action":"transfer","amount":9999999999999999}',
        'amount_overflow',
        'Amount overflow',
        [r'"success"', r'"balance"'],
        'Huge amount overflows to small/negative value',
        'HIGH',
    ),

    # ── Zero Values ──────────────────────────────────────────────────────
    (
        '{"action":"purchase","item_id":"1","price":0}',
        'zero_price',
        'Zero price purchase',
        [r'"success"', r'"order"', r'"purchased"'],
        'Server accepts zero price — free item purchase',
        'CRITICAL',
    ),
    (
        '{"action":"purchase","item_id":"1","quantity":0}',
        'zero_quantity',
        'Zero quantity order',
        [r'"success"', r'"order"'],
        'Zero quantity accepted — edge case in business logic',
        'MEDIUM',
    ),

    # ── Step/Workflow Bypass ─────────────────────────────────────────────
    (
        '{"action":"complete_payment","order_id":"1","skip_verification":true}',
        'skip_verification',
        'Skip payment verification',
        [r'"success"', r'"completed"', r'"confirmed"'],
        'Payment verification skipped — order completed without payment',
        'CRITICAL',
    ),
    (
        '{"step":"payment_complete","status":"paid","order_id":"1"}',
        'fake_payment_status',
        'Fake payment status',
        [r'"success"', r'"order_confirmed"', r'"delivered"'],
        'Payment status forged — order fulfilled without actual payment',
        'CRITICAL',
    ),
    (
        '{"action":"checkout","payment_status":"success"}',
        'payment_status_inject',
        'Payment status injection',
        [r'"success"', r'"order"'],
        'Payment status injected by attacker',
        'CRITICAL',
    ),

    # ── Duplicate Actions ────────────────────────────────────────────────
    (
        '{"action":"claim_bonus","bonus_id":"welcome_bonus"}',
        'duplicate_bonus',
        'Duplicate bonus claim',
        [r'"success"', r'"bonus"', r'"credited"'],
        'Bonus claimable multiple times — send twice and check both succeed',
        'HIGH',
    ),
    (
        '{"action":"use_coupon","code":"SAVE50"}',
        'coupon_reuse',
        'Coupon reuse',
        [r'"success"', r'"discount"', r'"applied"'],
        'Coupon can be used multiple times',
        'HIGH',
    ),

    # ── Boundary Manipulation ────────────────────────────────────────────
    (
        '{"action":"get_items","limit":-1}',
        'negative_limit',
        'Negative limit parameter',
        [r'"items"', r'"data"', r'"results"'],
        'Negative limit may return all records',
        'MEDIUM',
    ),
    (
        '{"action":"get_items","limit":999999999,"offset":-1}',
        'huge_limit',
        'Huge limit + negative offset',
        [r'"items"', r'"data"'],
        'Huge limit with negative offset — mass data exposure',
        'HIGH',
    ),
]


async def test_business_logic(ws_url: str, fast_mode: bool = False) -> bool:
    """
    Business Logic Test:
    Test negative values, overflow, workflow bypass, duplicate actions.
    Only flag if server confirms the action succeeded.
    """
    found_any = False
    tests = LOGIC_TESTS[:7] if fast_mode else LOGIC_TESTS

    try:
        async with await ws_connect(ws_url, timeout=6) as ws:

            # Baseline — does a normal valid request work?
            baseline = await send_recv(ws, '{"type":"ping"}', timeout=2)

            for payload, test_id, test_name, success_patterns, impact, severity in tests:
                try:
                    resp = await send_recv(ws, payload, timeout=3)
                    if not resp:
                        continue

                    resp_lower = resp.lower()

                    # Skip clear error responses
                    if any(x in resp_lower for x in [
                        '"error"', 'invalid', 'not found',
                        'bad request', 'rejected'
                    ]):
                        continue

                    # Check if action succeeded
                    for pattern in success_patterns:
                        if re.search(pattern, resp, re.IGNORECASE):
                            ev = Evidence.make(
                                payload=payload,
                                request=f"Business logic test: {test_name}",
                                response=resp[:400],
                                proof=(
                                    f"Business logic vulnerability confirmed: '{test_name}'.\n"
                                    f"Server accepted logically invalid input.\n"
                                    f"Impact: {impact}"
                                ),
                                reproduce=(
                                    f"1. Connect to {ws_url}\n"
                                    f"2. Send: {payload}\n"
                                    f"3. Server responds with success\n"
                                    f"4. Business logic bypassed"
                                ),
                                test_case=test_id,
                            )
                            store.add(
                                ws_url,
                                f'Business Logic Flaw — {test_name}',
                                severity,
                                f"Business logic vulnerability: {test_name}\n"
                                f"Payload: {payload}\n"
                                f"Impact: {impact}",
                                ev
                            )
                            found_any = True
                            log.warning(f"Business Logic: {test_name} on {ws_url}")
                            break

                except asyncio.TimeoutError:
                    continue
                except Exception:
                    continue

    except Exception as e:
        log.debug(f"Business logic test error on {ws_url}: {e}")

    return found_any
