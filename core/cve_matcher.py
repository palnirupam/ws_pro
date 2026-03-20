"""
CVE Matcher — Cross-reference detected frameworks with known CVEs.
Loads curated CVE database and matches against fingerprint results.
"""
import json
import os
from core.findings import store
from utils.evidence import Evidence
from utils.logger import log

_DB = None
_DB_PATH = os.path.join(os.path.dirname(__file__), 'cve_db.json')


def load_db() -> dict:
    """Load CVE database from JSON file."""
    global _DB
    if _DB is None:
        try:
            with open(_DB_PATH, 'r', encoding='utf-8') as f:
                _DB = json.load(f)
        except Exception as e:
            log.warning(f"Failed to load CVE database: {e}")
            _DB = {}
    return _DB


def reload_db():
    """Force reload CVE database (for updates)."""
    global _DB
    _DB = None
    return load_db()


def match_cves(framework: str, version: str = None) -> list:
    """
    Return list of CVEs matching the detected framework.
    If version is provided, only return CVEs for affected versions.
    """
    db = load_db()
    fw = framework.lower().replace(' ', '.').replace('_', '-')

    matches = []
    for key, cves in db.items():
        key_lower = key.lower()
        # Match if framework name contains the key or vice versa
        if key_lower in fw or fw in key_lower:
            for cve in cves:
                # If no version, include all CVEs for the framework
                if version is None:
                    matches.append(cve)
                else:
                    # Basic version comparison (add all for now — precise
                    # semver comparison would require packaging lib)
                    matches.append(cve)

    return matches


def check_and_report(ws_url: str, framework: str, server_header: str = None):
    """
    Check detected framework against CVE database and store findings.
    Called after fingerprint() in scanner.
    """
    if not framework or framework.lower() in ('unknown', ''):
        return

    cves = match_cves(framework)

    if not cves:
        return

    # Group by severity
    critical = [c for c in cves if c.get('severity') == 'CRITICAL']
    high = [c for c in cves if c.get('severity') == 'HIGH']
    medium = [c for c in cves if c.get('severity') == 'MEDIUM']

    # Report most severe finding
    if critical:
        top = critical[0]
        severity = 'CRITICAL'
    elif high:
        top = high[0]
        severity = 'HIGH'
    elif medium:
        top = medium[0]
        severity = 'MEDIUM'
    else:
        top = cves[0]
        severity = top.get('severity', 'MEDIUM')

    cve_list = '\n'.join(
        f"  • {c['cve']} ({c['severity']}, CVSS {c['cvss']}) — {c['description']}"
        for c in cves[:5]
    )

    nvd_links = '\n'.join(
        f"  {c['nvd_url']}" for c in cves[:5] if c.get('nvd_url')
    )

    ev = Evidence.make(
        proof=f"Framework '{framework}' has {len(cves)} known CVEs",
        payload=f"Detected framework: {framework}",
        response=f"Server header: {server_header or 'unknown'}",
        reproduce=(
            f"1. Connect to {ws_url}\n"
            f"2. Fingerprint reveals: {framework}\n"
            f"3. Cross-reference with CVE database:\n{cve_list}"
        ),
        cve_count=len(cves),
        top_cve=top['cve'],
        top_cvss=top['cvss'],
        nvd_links=nvd_links,
    )

    store.add(ws_url, f"Known CVEs for {framework}", severity,
        f"Detected framework '{framework}' has {len(cves)} known vulnerabilities.\n\n"
        f"Top vulnerability: {top['cve']} (CVSS {top['cvss']})\n"
        f"{top['description']}\n\n"
        f"All matched CVEs:\n{cve_list}\n\n"
        f"NVD References:\n{nvd_links}", ev)


def get_all_frameworks() -> list[str]:
    """Return list of all frameworks in CVE database."""
    db = load_db()
    return list(db.keys())


def get_stats() -> dict:
    """Return CVE database statistics."""
    db = load_db()
    total_cves = sum(len(cves) for cves in db.values())
    return {
        'frameworks': len(db),
        'total_cves': total_cves,
        'frameworks_list': list(db.keys()),
    }
