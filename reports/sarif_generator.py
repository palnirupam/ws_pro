"""
SARIF Report Generator
Generates Static Analysis Results Interchange Format (SARIF) v2.1.0 reports
for CI/CD integration (GitHub Actions, Azure DevOps, etc.)
"""
import json
from datetime import datetime, timezone


def generate_sarif(findings: list, target: str = 'Unknown') -> str:
    """Generate SARIF v2.1.0 JSON report from findings list."""

    rules = {}
    results = []

    severity_map = {
        'CRITICAL': 'error',
        'HIGH': 'error',
        'MEDIUM': 'warning',
        'LOW': 'note',
    }

    for idx, f in enumerate(findings):
        rule_id = f.get('title', 'unknown').replace(' ', '-').lower()

        # Build rule if not seen
        if rule_id not in rules:
            rules[rule_id] = {
                'id': rule_id,
                'name': f.get('title', 'Unknown'),
                'shortDescription': {
                    'text': f.get('title', 'Unknown Vulnerability'),
                },
                'fullDescription': {
                    'text': f.get('description', ''),
                },
                'helpUri': 'https://owasp.org/www-project-web-security-testing-guide/',
                'properties': {
                    'security-severity': str(f.get('cvss_score', 0.0)),
                },
                'defaultConfiguration': {
                    'level': severity_map.get(f.get('severity', 'LOW'), 'note'),
                },
            }
            if f.get('remediation'):
                rules[rule_id]['help'] = {
                    'text': f['remediation'],
                    'markdown': f"**Remediation:** {f['remediation']}",
                }

        # Build result
        evidence = f.get('evidence', {})
        message_parts = [f.get('description', '')]
        if evidence.get('proof'):
            message_parts.append(f"Proof: {evidence['proof']}")
        if evidence.get('payload'):
            message_parts.append(f"Payload: {evidence['payload']}")

        result = {
            'ruleId': rule_id,
            'level': severity_map.get(f.get('severity', 'LOW'), 'note'),
            'message': {
                'text': '\n'.join(message_parts),
            },
            'locations': [{
                'physicalLocation': {
                    'artifactLocation': {
                        'uri': f.get('endpoint', target),
                        'uriBaseId': 'WEBSOCKET',
                    },
                },
                'logicalLocations': [{
                    'name': f.get('endpoint', target),
                    'kind': 'url',
                }],
            }],
            'properties': {
                'severity': f.get('severity', 'LOW'),
                'cvss_score': f.get('cvss_score', 0.0),
                'cvss_vector': f.get('cvss_vector', ''),
                'timestamp': f.get('timestamp', ''),
            },
        }

        if evidence.get('reproduce'):
            result['codeFlows'] = [{
                'message': {'text': 'Reproduction steps'},
                'threadFlows': [{
                    'locations': [{
                        'location': {
                            'message': {'text': evidence['reproduce']},
                            'physicalLocation': {
                                'artifactLocation': {
                                    'uri': f.get('endpoint', target),
                                },
                            },
                        },
                    }],
                }],
            }]

        results.append(result)

    sarif = {
        '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {
                'driver': {
                    'name': 'WS Tester Pro',
                    'version': '1.0.0',
                    'informationUri': 'https://github.com/ws-tester-pro',
                    'rules': list(rules.values()),
                },
            },
            'results': results,
            'invocations': [{
                'executionSuccessful': True,
                'endTimeUtc': datetime.now(timezone.utc).isoformat(),
                'properties': {
                    'target': target,
                    'totalFindings': len(findings),
                },
            }],
        }],
    }

    return json.dumps(sarif, indent=2, ensure_ascii=False)
