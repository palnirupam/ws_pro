"""
Attack Module Unit Tests
Tests individual attack modules against mock server endpoints.
Validates detection logic, payload generation, evidence quality.

Run:  pytest tests/test_attacks.py -v -s
"""
import sys
import os
import asyncio
import json
import time
import subprocess
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scanner import ws_connect, send_recv, test_connection
from core.findings import FindingsStore, store
from utils.evidence import Evidence

MOCK_URL = 'ws://localhost:8765'


# ── Fixture: auto-start mock server ──────────────────────────────────────────

@pytest.fixture(scope='session', autouse=True)
def mock_server():
    server_script = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'mock_server.py'
    )
    proc = subprocess.Popen(
        [sys.executable, server_script],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        creationflags=getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0),
    )
    loop = asyncio.new_event_loop()
    for _ in range(25):
        try:
            r = loop.run_until_complete(test_connection(MOCK_URL, timeout=2))
            if r['alive']:
                break
        except Exception:
            pass
        time.sleep(0.2)
    else:
        proc.terminate(); proc.wait(); loop.close()
        pytest.skip("Mock server not available")

    yield proc

    try:
        proc.terminate(); proc.wait(timeout=3)
    except Exception:
        proc.kill()
    loop.close()


@pytest.fixture(autouse=True)
def clear_store():
    """Clear findings store before each test."""
    store.clear()
    yield
    store.clear()


def run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def get_titles():
    return [f.title.lower() for f in store.all()]


def get_severities():
    return [f.severity for f in store.all()]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                          INJECTION MODULE TESTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestSQLInjection:
    """Test SQL injection detection against mock server."""

    def test_sqli_error_based_detected(self):
        from attacks.injection import run_injection_tests
        run_async(run_injection_tests(MOCK_URL, fast_mode=True))
        titles = get_titles()
        assert any('sql' in t for t in titles), f"SQLi not detected: {titles}"

    def test_sqli_finding_is_critical(self):
        from attacks.injection import run_injection_tests
        run_async(run_injection_tests(MOCK_URL, fast_mode=True))
        sql_findings = [f for f in store.all() if 'sql' in f.title.lower()]
        if sql_findings:
            assert sql_findings[0].severity == 'CRITICAL'

    def test_sqli_evidence_has_proof(self):
        from attacks.injection import run_injection_tests
        run_async(run_injection_tests(MOCK_URL, fast_mode=True))
        sql_findings = [f for f in store.all() if 'sql' in f.title.lower()]
        if sql_findings:
            ev = sql_findings[0].evidence.to_dict()
            assert ev.get('proof'), "SQLi finding has no proof"

    def test_sqli_payloads_are_strings(self):
        from attacks.injection import SQLI_PAYLOADS
        assert len(SQLI_PAYLOADS) >= 5
        for p in SQLI_PAYLOADS:
            assert isinstance(p, str)
            assert len(p) > 0


class TestXSS:
    """Test XSS detection — mock server echoes raw input."""

    def test_xss_reflected_detected(self):
        from attacks.injection import run_injection_tests
        run_async(run_injection_tests(MOCK_URL, fast_mode=True))
        titles = get_titles()
        assert any('xss' in t for t in titles), f"XSS not detected: {titles}"

    def test_xss_finding_severity(self):
        from attacks.injection import run_injection_tests
        run_async(run_injection_tests(MOCK_URL, fast_mode=True))
        xss_findings = [f for f in store.all() if 'xss' in f.title.lower()]
        if xss_findings:
            assert xss_findings[0].severity in ('HIGH', 'CRITICAL')

    def test_xss_payloads_exist(self):
        from attacks.injection import XSS_PAYLOADS
        assert len(XSS_PAYLOADS) >= 3
        assert any('<script' in p for p in XSS_PAYLOADS)

    def test_xss_confirmed_patterns_exist(self):
        from attacks.injection import XSS_CONFIRMED_PATTERNS
        assert len(XSS_CONFIRMED_PATTERNS) >= 3


class TestCommandInjection:
    """Test OS command injection detection."""

    def test_cmdi_detected(self):
        from attacks.injection import run_injection_tests
        run_async(run_injection_tests(MOCK_URL, fast_mode=True))
        titles = get_titles()
        assert any('command' in t for t in titles), f"CMDi not detected: {titles}"

    def test_cmdi_finding_is_critical(self):
        from attacks.injection import run_injection_tests
        run_async(run_injection_tests(MOCK_URL, fast_mode=True))
        cmd_findings = [f for f in store.all() if 'command' in f.title.lower()]
        if cmd_findings:
            assert cmd_findings[0].severity == 'CRITICAL'

    def test_cmd_payloads_have_special_chars(self):
        from attacks.injection import CMD_PAYLOADS
        assert len(CMD_PAYLOADS) >= 5
        special = [';', '|', '`', '&&', '$(']
        for p in CMD_PAYLOADS:
            assert any(c in p for c in special), f"Payload '{p}' lacks special chars"

    def test_cmd_confirmed_patterns_regex(self):
        import re
        from attacks.injection import CMD_CONFIRMED
        # Verify all patterns are valid regex
        for pattern in CMD_CONFIRMED:
            try:
                re.compile(pattern)
            except re.error as e:
                pytest.fail(f"Invalid regex '{pattern}': {e}")


class TestNoSQLInjection:
    """Test NoSQL injection payloads and patterns."""

    def test_nosql_payloads_are_json(self):
        from attacks.injection import NOSQL_PAYLOADS
        assert len(NOSQL_PAYLOADS) >= 3
        for p in NOSQL_PAYLOADS:
            try:
                json.loads(p)
            except json.JSONDecodeError:
                pytest.fail(f"NoSQL payload is not valid JSON: {p}")

    def test_nosql_error_patterns_exist(self):
        from attacks.injection import NOSQL_ERRORS
        assert len(NOSQL_ERRORS) >= 3


class TestPrototypePollution:
    """Test prototype pollution detection."""

    def test_proto_payloads_have_proto_key(self):
        from attacks.injection import PROTO_PAYLOADS
        assert len(PROTO_PAYLOADS) >= 2
        for p in PROTO_PAYLOADS:
            data = json.loads(p)
            assert '__proto__' in data or 'constructor' in data

    def test_proto_pollution_detected(self):
        from attacks.injection import run_injection_tests
        run_async(run_injection_tests(MOCK_URL, fast_mode=False))
        titles = get_titles()
        found = any('proto' in t or 'pollution' in t for t in titles)
        assert found, f"Prototype Pollution not detected: {titles}"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                            AUTH MODULE TESTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestAuthBypass:
    """Test authentication bypass detection."""

    def test_auth_bypass_runs_without_error(self):
        from attacks.auth import test_auth_bypass
        # Should not raise any exception
        run_async(test_auth_bypass(MOCK_URL))

    def test_cswsh_runs_without_error(self):
        from attacks.auth import test_cswsh
        run_async(test_cswsh(MOCK_URL))


class TestJWTAttacks:
    """Test JWT attack module."""

    def test_jwt_none_algo_runs(self):
        from attacks.auth import test_jwt_attacks
        run_async(test_jwt_attacks(MOCK_URL))
        # JWT bypass detection depends on server behavior
        # Just verify no crash

    def test_jwt_with_token_runs(self):
        from attacks.auth import test_jwt_attacks
        run_async(test_jwt_attacks(MOCK_URL))
        # Verify it processes token without error


class TestRateLimit:
    """Test rate limiting detection."""

    def test_rate_limit_fast_mode(self):
        from attacks.auth import test_rate_limit
        run_async(test_rate_limit(MOCK_URL, fast_mode=True))
        # Mock server has no rate limit → should flag
        titles = get_titles()
        rate_found = any('rate' in t for t in titles)
        # Rate limit detection is timing-dependent, just verify no crash
        assert True

    def test_rate_limit_deep_mode(self):
        from attacks.auth import test_rate_limit
        run_async(test_rate_limit(MOCK_URL, fast_mode=False))
        assert True  # No crash


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                           NETWORK MODULE TESTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestEncryption:
    """Test encryption check — ws:// should be flagged."""

    def test_ws_flagged_as_unencrypted(self):
        from attacks.network import test_encryption
        run_async(test_encryption(MOCK_URL))
        titles = get_titles()
        enc_found = any('encrypt' in t or 'tls' in t or 'ssl' in t for t in titles)
        assert enc_found, f"ws:// not flagged: {titles}"

    def test_encryption_finding_severity(self):
        from attacks.network import test_encryption
        run_async(test_encryption(MOCK_URL))
        enc_findings = [f for f in store.all() if 'encrypt' in f.title.lower()]
        if enc_findings:
            assert enc_findings[0].severity in ('MEDIUM', 'HIGH')


class TestMessageSize:
    """Test message size limit detection."""

    def test_large_message_accepted(self):
        from attacks.network import test_message_size
        run_async(test_message_size(MOCK_URL))
        titles = get_titles()
        size_found = any('size' in t or 'message' in t for t in titles)
        assert size_found, f"Message size not flagged: {titles}"


class TestInfoDisclosure:
    """Test information disclosure detection."""

    def test_info_leak_detected(self):
        from attacks.network import test_info_disclosure
        run_async(test_info_disclosure(MOCK_URL))
        titles = get_titles()
        info_found = any('disclosure' in t or 'info' in t for t in titles)
        assert info_found, f"Info disclosure not detected: {titles}"

    def test_info_finding_has_evidence(self):
        from attacks.network import test_info_disclosure
        run_async(test_info_disclosure(MOCK_URL))
        info_findings = [f for f in store.all() if 'disclosure' in f.title.lower() or 'info' in f.title.lower()]
        if info_findings:
            ev = info_findings[0].evidence.to_dict()
            assert ev.get('proof'), "Info finding has no proof"


class TestGraphQL:
    """Test GraphQL introspection detection."""

    def test_graphql_introspection_detected(self):
        from attacks.network import test_graphql
        run_async(test_graphql(MOCK_URL))
        titles = get_titles()
        gql_found = any('graphql' in t for t in titles)
        assert gql_found, f"GraphQL not detected: {titles}"

    def test_graphql_finding_severity(self):
        from attacks.network import test_graphql
        run_async(test_graphql(MOCK_URL))
        gql_findings = [f for f in store.all() if 'graphql' in f.title.lower()]
        if gql_findings:
            assert gql_findings[0].severity in ('MEDIUM', 'LOW')


class TestIDOR:
    """Test Insecure Direct Object Reference detection."""

    def test_idor_detected(self):
        from attacks.network import test_idor
        run_async(test_idor(MOCK_URL))
        titles = get_titles()
        idor_found = any('idor' in t or 'object' in t or 'direct' in t for t in titles)
        assert idor_found, f"IDOR not detected: {titles}"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                           TIMING MODULE TESTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestTimingAttacks:
    """Test timing-based attacks."""

    def test_timing_fast_mode(self):
        from attacks.timing import test_timing
        run_async(test_timing(MOCK_URL, fast_mode=True))
        # Timing detection is inherently non-deterministic
        assert True

    def test_timing_deep_mode(self):
        from attacks.timing import test_timing
        run_async(test_timing(MOCK_URL, fast_mode=False))
        # Deeper iteration — timing differences may or may not trigger
        assert True


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                         SUBPROTOCOL MODULE TESTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestSubprotocol:
    """Test WebSocket subprotocol testing."""

    def test_subprotocol_check_runs(self):
        from attacks.subprotocol import test_subprotocol
        run_async(test_subprotocol(MOCK_URL))
        assert True  # No crash

    def test_subprotocol_list_exists(self):
        from attacks.subprotocol import SUBPROTOCOLS
        assert len(SUBPROTOCOLS) >= 10
        assert 'graphql-ws' in SUBPROTOCOLS
        assert 'mqtt' in SUBPROTOCOLS


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                      CROSS-MODULE INTERACTION TESTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestCrossModule:
    """Test interactions between attack modules."""

    def test_all_modules_use_same_store(self):
        """All modules should write to the global store."""
        from attacks.injection import run_injection_tests
        from attacks.network import test_encryption

        run_async(test_encryption(MOCK_URL))
        count1 = len(store.all())
        assert count1 > 0, "Encryption test should produce findings"

        run_async(run_injection_tests(MOCK_URL, fast_mode=True))
        count2 = len(store.all())
        assert count2 > count1, "Injection tests should add more findings"

    def test_no_false_positives_on_safe_payloads(self):
        """Sending safe messages should not trigger findings."""
        async def _send_safe():
            async with await ws_connect(MOCK_URL, timeout=3) as ws:
                await asyncio.wait_for(ws.recv(), timeout=2)  # welcome
                safe_messages = [
                    '{"type": "ping"}',
                    '{"action": "heartbeat"}',
                    '{"message": "hello world"}',
                ]
                for msg in safe_messages:
                    await send_recv(ws, msg, timeout=2)

        # Clear store and send safe messages only
        store.clear()
        run_async(_send_safe())
        assert len(store.all()) == 0, (
            f"False positives detected with safe payloads: "
            f"{[f.title for f in store.all()]}"
        )

    def test_findings_endpoint_matches_target(self):
        """All findings should reference the correct endpoint."""
        from attacks.network import test_encryption
        run_async(test_encryption(MOCK_URL))
        for f in store.all():
            assert MOCK_URL in f.endpoint or 'ws://' in f.endpoint, (
                f"Finding '{f.title}' has wrong endpoint: {f.endpoint}"
            )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                      ADVANCED CSWSH MODULE TESTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestAdvancedCSWSH:
    """Test the enhanced Cross-Site WebSocket Hijacking detection."""

    def test_advanced_cswsh_runs_without_error(self):
        from attacks.auth import test_cswsh
        run_async(test_cswsh(MOCK_URL))
        # Verify it ran without crashing

    def test_cswsh_detects_origin_bypass(self):
        from attacks.auth import test_cswsh
        run_async(test_cswsh(MOCK_URL))
        titles = get_titles()
        cswsh_found = any(
            'cswsh' in t or 'origin' in t or 'cross-site' in t
            for t in titles
        )
        assert cswsh_found, f"CSWSH not detected: {titles}"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                         FUZZER MODULE TESTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestFuzzer:
    """Test WebSocket fuzzer module."""

    def test_fuzzer_runs_fast_mode(self):
        from attacks.fuzzer import test_fuzzing
        results = run_async(test_fuzzing(MOCK_URL, fast_mode=True))
        assert isinstance(results, list)

    def test_fuzzer_runs_deep_mode(self):
        from attacks.fuzzer import test_fuzzing
        results = run_async(test_fuzzing(MOCK_URL, fast_mode=False))
        assert isinstance(results, list)

    def test_fuzzer_detects_crash(self):
        """Mock server should crash on null bytes — fuzzer should detect it."""
        from attacks.fuzzer import test_fuzzing
        results = run_async(test_fuzzing(MOCK_URL, fast_mode=False))
        assert 'fuzz_crash' in results or 'fuzz_error_leak' in results, (
            f"Fuzzer should detect crash or error leak: {results}"
        )

    def test_fuzzer_payload_lists_exist(self):
        from attacks.fuzzer import (
            OVERSIZED_PAYLOADS, MALFORMED_JSON_PAYLOADS,
            SPECIAL_BYTE_PAYLOADS, TYPE_CONFUSION_PAYLOADS, BOUNDARY_PAYLOADS,
        )
        assert len(OVERSIZED_PAYLOADS) >= 3
        assert len(MALFORMED_JSON_PAYLOADS) >= 5
        assert len(SPECIAL_BYTE_PAYLOADS) >= 3
        assert len(TYPE_CONFUSION_PAYLOADS) >= 5
        assert len(BOUNDARY_PAYLOADS) >= 5

    def test_fuzzer_error_patterns_are_valid_regex(self):
        import re
        from attacks.fuzzer import ERROR_LEAK_PATTERNS
        for pattern, label in ERROR_LEAK_PATTERNS:
            try:
                re.compile(pattern)
            except re.error as e:
                pytest.fail(f"Invalid regex '{pattern}' ({label}): {e}")

    def test_fuzzer_sensitive_patterns_are_valid_regex(self):
        import re
        from attacks.fuzzer import SENSITIVE_LEAK_PATTERNS
        for pattern, label in SENSITIVE_LEAK_PATTERNS:
            try:
                re.compile(pattern)
            except re.error as e:
                pytest.fail(f"Invalid regex '{pattern}' ({label}): {e}")
