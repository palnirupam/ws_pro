"""
Central findings store — shared across all attack modules
Dedup, CVSS scoring, remediation built-in
"""
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Optional
from utils.evidence import Evidence


CVSS_DB = {
    'SQL Injection':              (9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    'Command Injection':          (9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    'Auth Bypass':                (9.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'),
    'JWT None Algorithm':         (9.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'),
    'Privilege Escalation':       (8.8, 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N'),
    'IDOR':                       (8.1, 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N'),
    'Mass Assignment':            (8.1, 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N'),
    'CSWSH':                      (8.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N'),
    'Deserialization':            (8.1, 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    'XSS':                        (6.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'),
    'Prototype Pollution':        (7.3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'),
    'GraphQL Introspection':      (5.3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'),
    'Rate Limit':                 (5.3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L'),
    'Information Disclosure':     (5.3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'),
    'No Encryption':              (5.9, 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'),
    'Message Size':               (5.3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L'),
}

REMEDIATION_DB = {
    'SQL':         'Use parameterized queries. Never concatenate user input into SQL strings.',
    'Command':     'Never pass user input to shell. Use subprocess with list args, not shell=True.',
    'Auth':        'Validate auth token on every WS message, not just on connection.',
    'JWT':         'Always verify signature. Reject alg=none. Use RS256 with 2048-bit keys.',
    'CSWSH':       'Validate Origin header on WS handshake. Use anti-CSRF tokens.',
    'XSS':         'Sanitize all output. Use Content-Security-Policy. Never use innerHTML.',
    'Rate':        'Implement per-IP rate limiting. Disconnect clients exceeding threshold.',
    'Prototype':   'Block __proto__, constructor, prototype keys. Use Object.create(null).',
    'IDOR':        'Check authorization on every object access, not just authentication.',
    'Mass':        'Use allowlist for accepted fields. Never blindly assign user input to objects.',
    'GraphQL':     'Disable introspection in production. Use query depth/complexity limits.',
    'Encryption':  'Use wss:// with valid TLS certificate. Enforce HSTS.',
    'Disclosure':  'Remove debug info, stack traces, version numbers from responses.',
    'Deserial':    'Validate and sanitize all deserialized data. Use safe deserializers.',
    'Size':        'Set maximum WS message size (e.g. websockets max_size=65536).',
}


@dataclass
class Finding:
    endpoint:     str
    title:        str
    severity:     str
    description:  str
    evidence:     Evidence
    cvss_score:   float = 0.0
    cvss_vector:  str   = ''
    remediation:  str   = ''
    timestamp:    str   = ''

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.strftime('%H:%M:%S')
        if not self.cvss_score:
            self.cvss_score, self.cvss_vector = self._calc_cvss()
        if not self.remediation:
            self.remediation = self._get_remediation()

    def _calc_cvss(self):
        for key, (score, vector) in CVSS_DB.items():
            if key.lower() in self.title.lower():
                return score, vector
        defaults = {'CRITICAL': (9.0, ''), 'HIGH': (7.5, ''),
                    'MEDIUM': (5.0, ''), 'LOW': (3.1, '')}
        s, v = defaults.get(self.severity, (0.0, ''))
        return s, v

    def _get_remediation(self):
        for key, fix in REMEDIATION_DB.items():
            if key.lower() in self.title.lower():
                return fix
        return 'Review OWASP WebSocket Security Cheat Sheet.'

    def to_dict(self):
        return {
            'endpoint':    self.endpoint,
            'title':       self.title,
            'severity':    self.severity,
            'description': self.description,
            'cvss_score':  self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'remediation': self.remediation,
            'timestamp':   self.timestamp,
            'evidence':    self.evidence.to_dict(),
        }


class FindingsStore:
    """Thread-safe, deduplicated findings storage"""

    def __init__(self):
        self._findings: list[Finding] = []
        self._seen: set = set()
        self._lock = threading.Lock()
        self._callbacks: list = []

    def add(self, endpoint: str, title: str, severity: str,
            description: str, evidence: Evidence = None) -> bool:
        """Add finding. Returns True if new, False if duplicate."""
        key = f"{title}|{endpoint}"
        with self._lock:
            if key in self._seen:
                return False
            self._seen.add(key)
            finding = Finding(
                endpoint=endpoint,
                title=title,
                severity=severity,
                description=description,
                evidence=evidence or Evidence(),
            )
            self._findings.append(finding)

        # Fire callbacks outside lock
        for cb in self._callbacks:
            try:
                cb(finding)
            except Exception:
                pass
        return True

    def on_finding(self, callback):
        """Register callback for new findings"""
        self._callbacks.append(callback)

    def clear(self):
        with self._lock:
            self._findings.clear()
            self._seen.clear()

    def all(self) -> list[Finding]:
        with self._lock:
            return list(self._findings)

    def as_dicts(self) -> list[dict]:
        return [f.to_dict() for f in self.all()]

    def count_by_severity(self) -> dict:
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for f in self.all():
            if f.severity in counts:
                counts[f.severity] += 1
        return counts


# Global store instance
store = FindingsStore()