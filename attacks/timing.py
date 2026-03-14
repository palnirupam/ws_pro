"""
Timing Attack Module
Detects timing-based side channels in WebSocket endpoints
"""
import asyncio
import json
import time
from core.scanner import ws_connect, send_recv
from core.findings import store
from utils.evidence import Evidence
from utils.logger import log


async def test_timing(ws_url: str, fast_mode: bool = False) -> bool:
    """Detect timing-based side channels (auth, search, etc.)"""
    iterations = 5 if fast_mode else 10

    try:
        async with await ws_connect(ws_url, timeout=6) as ws:
            # ── Test 1: Auth timing (valid vs invalid username) ────────────
            valid_times = []
            invalid_times = []

            for _ in range(iterations):
                # Valid-looking username
                t0 = time.perf_counter()
                await send_recv(ws, json.dumps({
                    'type': 'auth', 'username': 'admin', 'password': 'wrong'
                }), timeout=4)
                valid_times.append(time.perf_counter() - t0)

                # Invalid username
                t0 = time.perf_counter()
                await send_recv(ws, json.dumps({
                    'type': 'auth', 'username': 'xyznonexistent99', 'password': 'wrong'
                }), timeout=4)
                invalid_times.append(time.perf_counter() - t0)

            if valid_times and invalid_times:
                avg_valid = sum(valid_times) / len(valid_times)
                avg_invalid = sum(invalid_times) / len(invalid_times)
                diff = abs(avg_valid - avg_invalid)

                # Significant timing difference (>50ms) suggests user enumeration
                if diff > 0.05:
                    ev = Evidence.make(
                        proof=(
                            f'Timing difference detected: '
                            f'valid username avg={avg_valid*1000:.1f}ms, '
                            f'invalid username avg={avg_invalid*1000:.1f}ms, '
                            f'delta={diff*1000:.1f}ms'
                        ),
                        reproduce=(
                            f"1. Connect to {ws_url}\n"
                            f"2. Send auth with known username + wrong password\n"
                            f"3. Send auth with random username + wrong password\n"
                            f"4. Compare response times over {iterations} iterations\n"
                            f"5. Observe {diff*1000:.1f}ms timing difference"
                        ),
                        avg_valid_ms=round(avg_valid * 1000, 2),
                        avg_invalid_ms=round(avg_invalid * 1000, 2),
                        delta_ms=round(diff * 1000, 2),
                        iterations=iterations,
                    )
                    store.add(ws_url, 'Timing-Based User Enumeration', 'MEDIUM',
                        f"Authentication response time differs by {diff*1000:.1f}ms "
                        f"between valid and invalid usernames.\n"
                        f"Attacker can enumerate valid usernames via timing oracle.", ev)
                    return True

            # ── Test 2: Search/query timing oracle ────────────────────────
            short_times = []
            long_times = []

            for _ in range(iterations):
                t0 = time.perf_counter()
                await send_recv(ws, json.dumps({'query': 'a'}), timeout=4)
                short_times.append(time.perf_counter() - t0)

                t0 = time.perf_counter()
                await send_recv(ws, json.dumps({
                    'query': 'a' * 100 + "' AND SLEEP(0)--"
                }), timeout=4)
                long_times.append(time.perf_counter() - t0)

            if short_times and long_times:
                avg_short = sum(short_times) / len(short_times)
                avg_long = sum(long_times) / len(long_times)
                diff = abs(avg_long - avg_short)

                if diff > 0.1:  # >100ms difference
                    ev = Evidence.make(
                        proof=(
                            f'Query timing difference: '
                            f'short={avg_short*1000:.1f}ms, '
                            f'long={avg_long*1000:.1f}ms, '
                            f'delta={diff*1000:.1f}ms'
                        ),
                        reproduce=(
                            f"1. Connect to {ws_url}\n"
                            f"2. Send short query and measure time\n"
                            f"3. Send long/complex query and measure time\n"
                            f"4. Observe {diff*1000:.1f}ms timing difference"
                        ),
                    )
                    store.add(ws_url, 'Timing Side Channel (Query)', 'LOW',
                        f"Query processing time varies by {diff*1000:.1f}ms.\n"
                        f"May indicate backend processing leakage.", ev)
                    return True

    except asyncio.TimeoutError:
        log.debug(f"Timeout on timing test: {ws_url}")
    except Exception as e:
        log.debug(f"Timing test error on {ws_url}: {e}")

    return False
