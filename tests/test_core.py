"""
Unit Tests for WS Tester Pro
Run: pytest tests/ -v
"""
import sys
import os
import json
import time
import pytest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.findings import Finding, FindingsStore, CVSS_DB, REMEDIATION_DB
from utils.evidence import Evidence
from reports.sarif_generator import generate_sarif


# ── Evidence Tests ────────────────────────────────────────────────────────────

class TestEvidence:
    def test_default_evidence(self):
        ev = Evidence()
        assert ev.proof == "Evidence pending"
        assert ev.payload is None
        assert ev.to_dict() == {'proof': 'Evidence pending'}

    def test_evidence_with_fields(self):
        ev = Evidence(proof="XSS confirmed", payload="<script>alert(1)</script>",
                      response="HTTP 200")
        d = ev.to_dict()
        assert d['proof'] == "XSS confirmed"
        assert d['payload'] == "<script>alert(1)</script>"
        assert d['response'] == "HTTP 200"
        assert 'request' not in d  # None fields omitted

    def test_evidence_make_with_extras(self):
        ev = Evidence.make(proof="test", payload="x", size_tested="512KB")
        d = ev.to_dict()
        assert d['proof'] == 'test'
        assert d['payload'] == 'x'
        assert d['size_tested'] == '512KB'

    def test_evidence_empty_fields_omitted(self):
        ev = Evidence(proof="test", payload=None, request=None, response=None)
        d = ev.to_dict()
        assert 'payload' not in d
        assert 'request' not in d
        assert 'response' not in d


# ── Finding Tests ─────────────────────────────────────────────────────────────

class TestFinding:
    def test_finding_auto_cvss(self):
        f = Finding(
            endpoint='ws://test:8765',
            title='SQL Injection (Error-Based)',
            severity='CRITICAL',
            description='SQL error found',
            evidence=Evidence(proof="MySQL error"),
        )
        assert f.cvss_score == 9.8
        assert 'CVSS:3.1' in f.cvss_vector

    def test_finding_auto_remediation(self):
        f = Finding(
            endpoint='ws://test:8765',
            title='SQL Injection',
            severity='CRITICAL',
            description='test',
            evidence=Evidence(),
        )
        assert 'parameterized' in f.remediation.lower()

    def test_finding_timestamp_generated(self):
        f = Finding(
            endpoint='ws://test:8765',
            title='Test',
            severity='LOW',
            description='test',
            evidence=Evidence(),
        )
        assert f.timestamp  # Not empty

    def test_finding_to_dict(self):
        f = Finding(
            endpoint='ws://test:8765',
            title='XSS',
            severity='HIGH',
            description='XSS found',
            evidence=Evidence(proof="Script tag reflected"),
        )
        d = f.to_dict()
        assert d['endpoint'] == 'ws://test:8765'
        assert d['title'] == 'XSS'
        assert d['severity'] == 'HIGH'
        assert isinstance(d['evidence'], dict)

    def test_finding_default_cvss_for_unknown(self):
        f = Finding(
            endpoint='ws://test:8765',
            title='Unknown Vulnerability XYZ',
            severity='HIGH',
            description='test',
            evidence=Evidence(),
        )
        assert f.cvss_score == 7.5  # Default for HIGH

    def test_finding_default_remediation_for_unknown(self):
        f = Finding(
            endpoint='ws://test:8765',
            title='Unknown Issue',
            severity='LOW',
            description='test',
            evidence=Evidence(),
        )
        assert 'OWASP' in f.remediation


# ── FindingsStore Tests ───────────────────────────────────────────────────────

class TestFindingsStore:
    def test_add_finding(self):
        store = FindingsStore()
        added = store.add('ws://test', 'SQL Injection', 'CRITICAL', 'test')
        assert added is True
        assert len(store.all()) == 1

    def test_dedup(self):
        store = FindingsStore()
        store.add('ws://test', 'SQL Injection', 'CRITICAL', 'test')
        added = store.add('ws://test', 'SQL Injection', 'CRITICAL', 'test duplicate')
        assert added is False
        assert len(store.all()) == 1

    def test_different_endpoints_no_dedup(self):
        store = FindingsStore()
        store.add('ws://test1', 'SQL Injection', 'CRITICAL', 'test')
        store.add('ws://test2', 'SQL Injection', 'CRITICAL', 'test')
        assert len(store.all()) == 2

    def test_clear(self):
        store = FindingsStore()
        store.add('ws://test', 'Test', 'LOW', 'test')
        store.clear()
        assert len(store.all()) == 0

    def test_count_by_severity(self):
        store = FindingsStore()
        store.add('ws://t1', 'A', 'CRITICAL', 'test')
        store.add('ws://t2', 'B', 'CRITICAL', 'test')
        store.add('ws://t3', 'C', 'HIGH', 'test')
        store.add('ws://t4', 'D', 'LOW', 'test')
        counts = store.count_by_severity()
        assert counts['CRITICAL'] == 2
        assert counts['HIGH'] == 1
        assert counts['MEDIUM'] == 0
        assert counts['LOW'] == 1

    def test_as_dicts(self):
        store = FindingsStore()
        store.add('ws://test', 'Test', 'LOW', 'test')
        dicts = store.as_dicts()
        assert isinstance(dicts, list)
        assert len(dicts) == 1
        assert dicts[0]['title'] == 'Test'

    def test_callback(self):
        store = FindingsStore()
        results = []
        store.on_finding(lambda f: results.append(f.title))
        store.add('ws://test', 'Callback Test', 'LOW', 'test')
        assert results == ['Callback Test']


# ── CVSS & Remediation DB Tests ──────────────────────────────────────────────

class TestCVSSDB:
    def test_all_entries_have_valid_scores(self):
        for name, (score, vector) in CVSS_DB.items():
            assert 0 <= score <= 10.0, f"{name} has invalid score: {score}"
            if vector:
                assert vector.startswith('CVSS:3.1'), f"{name} has invalid vector format"

    def test_remediation_entries_exist(self):
        assert len(REMEDIATION_DB) > 10
        for key, fix in REMEDIATION_DB.items():
            assert isinstance(fix, str)
            assert len(fix) > 10, f"Remediation for '{key}' is too short"


# ── SARIF Generator Tests ────────────────────────────────────────────────────

class TestSARIF:
    def test_basic_sarif_output(self):
        findings = [{
            'title': 'SQL Injection',
            'severity': 'CRITICAL',
            'description': 'SQL error found',
            'endpoint': 'ws://test:8765',
            'cvss_score': 9.8,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            'evidence': {'proof': 'MySQL error matched'},
            'remediation': 'Use parameterized queries',
            'timestamp': '12:00:00',
        }]
        sarif = generate_sarif(findings, 'ws://test:8765')
        data = json.loads(sarif)

        assert data['version'] == '2.1.0'
        assert len(data['runs']) == 1
        assert len(data['runs'][0]['results']) == 1
        assert data['runs'][0]['tool']['driver']['name'] == 'WS Tester Pro'

    def test_severity_mapping(self):
        for sev, expected in [('CRITICAL', 'error'), ('HIGH', 'error'),
                               ('MEDIUM', 'warning'), ('LOW', 'note')]:
            findings = [{'title': 'test', 'severity': sev, 'description': 'x',
                         'endpoint': 'ws://test', 'evidence': {}}]
            data = json.loads(generate_sarif(findings))
            assert data['runs'][0]['results'][0]['level'] == expected

    def test_empty_findings(self):
        sarif = generate_sarif([], 'ws://test')
        data = json.loads(sarif)
        assert data['runs'][0]['results'] == []

    def test_sarif_valid_json(self):
        findings = [
            {'title': 'A', 'severity': 'HIGH', 'description': 'desc1',
             'endpoint': 'ws://a', 'evidence': {'proof': 'p1'}},
            {'title': 'B', 'severity': 'LOW', 'description': 'desc2',
             'endpoint': 'ws://b', 'evidence': {'proof': 'p2', 'reproduce': 'step1'}},
        ]
        sarif = generate_sarif(findings, 'ws://test')
        data = json.loads(sarif)  # Should not raise
        assert len(data['runs'][0]['results']) == 2
        assert len(data['runs'][0]['tool']['driver']['rules']) == 2
