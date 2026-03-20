"""
WebSocket Response Diff Engine
Compares WebSocket responses between different contexts
(e.g., authenticated vs unauthenticated) to detect authorization bypasses.
"""
import json
from typing import Optional


def diff_responses(resp_a: str, resp_b: str,
                   label_a: str = 'Unauthenticated',
                   label_b: str = 'Authenticated') -> dict:
    """
    Compare two WebSocket responses, return structured diff.
    Supports JSON and plain text responses.
    """
    result = {
        'added': [],
        'removed': [],
        'changed': [],
        'same': [],
        'type': 'unknown',
        'label_a': label_a,
        'label_b': label_b,
        'summary': '',
    }

    try:
        a = json.loads(resp_a)
        b = json.loads(resp_b)
        result['type'] = 'json'

        if isinstance(a, dict) and isinstance(b, dict):
            _diff_dicts(a, b, '', result, label_a, label_b)
        elif isinstance(a, list) and isinstance(b, list):
            _diff_lists(a, b, result, label_a, label_b)
        else:
            if a == b:
                result['same'].append({'path': '$', 'value': str(a)[:200]})
            else:
                result['changed'].append({
                    'path': '$',
                    label_a: str(a)[:200],
                    label_b: str(b)[:200],
                })
    except (json.JSONDecodeError, TypeError):
        result['type'] = 'text'
        _diff_text(resp_a, resp_b, result, label_a, label_b)

    # Generate summary
    total_diffs = len(result['added']) + len(result['removed']) + len(result['changed'])
    if total_diffs == 0:
        result['summary'] = 'Responses are identical'
    else:
        parts = []
        if result['added']:
            parts.append(f"{len(result['added'])} added")
        if result['removed']:
            parts.append(f"{len(result['removed'])} removed")
        if result['changed']:
            parts.append(f"{len(result['changed'])} changed")
        result['summary'] = f'{total_diffs} differences: {", ".join(parts)}'

    return result


def _diff_dicts(a: dict, b: dict, path: str, result: dict,
                label_a: str, label_b: str):
    """Recursively diff two dictionaries."""
    all_keys = set(list(a.keys()) + list(b.keys()))

    for key in sorted(all_keys):
        key_path = f'{path}.{key}' if path else key

        if key in a and key not in b:
            result['removed'].append({
                'path': key_path,
                'value': _truncate(a[key]),
            })
        elif key not in a and key in b:
            result['added'].append({
                'path': key_path,
                'value': _truncate(b[key]),
            })
        elif isinstance(a[key], dict) and isinstance(b[key], dict):
            _diff_dicts(a[key], b[key], key_path, result, label_a, label_b)
        elif isinstance(a[key], list) and isinstance(b[key], list):
            if a[key] != b[key]:
                result['changed'].append({
                    'path': key_path,
                    label_a: _truncate(a[key]),
                    label_b: _truncate(b[key]),
                })
            else:
                result['same'].append(key_path)
        elif a[key] != b[key]:
            result['changed'].append({
                'path': key_path,
                label_a: _truncate(a[key]),
                label_b: _truncate(b[key]),
            })
        else:
            result['same'].append(key_path)


def _diff_lists(a: list, b: list, result: dict,
                label_a: str, label_b: str):
    """Diff two lists."""
    max_len = max(len(a), len(b))
    for i in range(max_len):
        if i < len(a) and i < len(b):
            if a[i] != b[i]:
                result['changed'].append({
                    'path': f'[{i}]',
                    label_a: _truncate(a[i]),
                    label_b: _truncate(b[i]),
                })
            else:
                result['same'].append(f'[{i}]')
        elif i < len(a):
            result['removed'].append({
                'path': f'[{i}]',
                'value': _truncate(a[i]),
            })
        else:
            result['added'].append({
                'path': f'[{i}]',
                'value': _truncate(b[i]),
            })


def _diff_text(a: str, b: str, result: dict,
               label_a: str, label_b: str):
    """Line-by-line diff for plain text responses."""
    lines_a = a.splitlines()
    lines_b = b.splitlines()

    max_len = max(len(lines_a), len(lines_b))
    for i in range(max_len):
        la = lines_a[i] if i < len(lines_a) else None
        lb = lines_b[i] if i < len(lines_b) else None

        if la == lb:
            result['same'].append(f'line:{i+1}')
        elif la is None:
            result['added'].append({'path': f'line:{i+1}', 'value': lb[:200]})
        elif lb is None:
            result['removed'].append({'path': f'line:{i+1}', 'value': la[:200]})
        else:
            result['changed'].append({
                'path': f'line:{i+1}',
                label_a: la[:200],
                label_b: lb[:200],
            })


def _truncate(value, max_len: int = 200) -> str:
    """Truncate value for display."""
    s = str(value)
    return s[:max_len] + '...' if len(s) > max_len else s


# ── Sensitive field detection ─────────────────────────────────────────────────

SENSITIVE_FIELDS = {
    'password', 'passwd', 'secret', 'token', 'api_key', 'apikey',
    'api-key', 'auth', 'authorization', 'credit_card', 'creditcard',
    'ssn', 'social_security', 'bank_account', 'account_number',
    'private_key', 'privatekey', 'session', 'cookie', 'jwt',
    'access_token', 'refresh_token', 'phone', 'email', 'address',
    'balance', 'salary', 'dob', 'date_of_birth', 'medical',
}


def analyze_auth_bypass(diff_result: dict) -> dict:
    """
    Analyze diff result to detect potential authorization bypass.
    Returns analysis dict with severity and description.
    """
    analysis = {
        'is_bypass': False,
        'severity': 'LOW',
        'description': '',
        'sensitive_fields': [],
        'extra_data': [],
    }

    # Check if unauthenticated response has more data than expected
    for item in diff_result.get('added', []):
        path = item.get('path', '').lower()
        value = str(item.get('value', '')).lower()

        for field in SENSITIVE_FIELDS:
            if field in path or field in value:
                analysis['sensitive_fields'].append(item['path'])
                analysis['is_bypass'] = True

    for item in diff_result.get('changed', []):
        path = item.get('path', '').lower()
        for field in SENSITIVE_FIELDS:
            if field in path:
                analysis['sensitive_fields'].append(item['path'])
                analysis['is_bypass'] = True

    if analysis['is_bypass']:
        if len(analysis['sensitive_fields']) >= 3:
            analysis['severity'] = 'CRITICAL'
        elif len(analysis['sensitive_fields']) >= 1:
            analysis['severity'] = 'HIGH'
        analysis['description'] = (
            f"Authorization bypass detected. "
            f"Sensitive fields accessible without auth: "
            f"{', '.join(analysis['sensitive_fields'][:5])}"
        )
    elif len(diff_result.get('added', [])) > 5:
        analysis['is_bypass'] = True
        analysis['severity'] = 'MEDIUM'
        analysis['description'] = (
            f"Unauthenticated response contains {len(diff_result['added'])} "
            f"additional fields that may require authorization."
        )

    return analysis
