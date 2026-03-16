"""
WS Tester Pro — CLI Entry Point
Run scans from the command line without the dashboard
"""
import argparse
import asyncio
import json
import os
import sys
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from core.scanner import discover_endpoints, test_connection, fingerprint
from core.findings import store
from attacks.injection import run_injection_tests
from attacks.auth import test_cswsh, test_jwt_attacks, test_auth_bypass, test_rate_limit
from attacks.network import (test_encryption, test_message_size,
                              test_info_disclosure, test_graphql, test_idor)
from attacks.timing import test_timing
from attacks.subprotocol import test_subprotocol
from attacks.race_condition  import test_race_condition
from attacks.ssrf            import test_ssrf
from attacks.ssti            import test_ssti
from attacks.mass_assignment import test_mass_assignment
from attacks.business_logic  import test_business_logic
from utils.logger import log


def print_banner():
    print("""
╔══════════════════════════════════════════╗
║         🔐 WS Tester Pro — CLI           ║
║    Advanced WebSocket Security Scanner    ║
╚══════════════════════════════════════════╝
""")


def run_cli_scan(args):
    """Run scan from CLI arguments"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    target = args.target
    fast_mode = args.fast
    run_jwt = not args.no_jwt
    run_timing = args.timing

    try:
        print(f'🚀 Target: {target}')
        print(f'   Mode: {"Fast" if fast_mode else "Deep"}')
        print(f'   JWT: {"On" if run_jwt else "Off"}')
        print(f'   Timing: {"On" if run_timing else "Off"}')
        print()

        # 1. Discover endpoints
        print('🔍 Discovering endpoints...')
        endpoints = loop.run_until_complete(discover_endpoints(target))
        print(f'   Found {len(endpoints)} potential endpoints')

        # 2. Test connectivity
        print('🔌 Testing connectivity...')
        alive = []
        for ep in endpoints:
            result = loop.run_until_complete(test_connection(ep, timeout=4))
            if result['alive']:
                alive.append(ep)
                print(f'   ✅ {ep}')
            else:
                print(f'   ⬜ {ep}')

        if not alive:
            print('\n⚠️  No live WebSocket endpoints found')
            return

        print(f'\n🎯 {len(alive)} live endpoints')

        # 3. Run attacks
        total = len(alive)
        for i, ep in enumerate(alive):
            print(f'\n▶ [{i+1}/{total}] Testing: {ep}')

            info = loop.run_until_complete(fingerprint(ep))
            print(f'  Framework: {info["framework"]} | Server: {info["server_header"]}')

            tests = [
                ('Encryption', lambda ep=ep: test_encryption(ep)),
                ('Injection', lambda ep=ep: run_injection_tests(ep, fast_mode=fast_mode)),
                ('CSWSH', lambda ep=ep: test_cswsh(ep)),
                ('Rate Limit', lambda ep=ep: test_rate_limit(ep, fast_mode=fast_mode)),
                ('Message Size', lambda ep=ep: test_message_size(ep)),
                ('Info Disclosure', lambda ep=ep: test_info_disclosure(ep)),
                ('GraphQL', lambda ep=ep: test_graphql(ep)),
                ('IDOR', lambda ep=ep: test_idor(ep)),
                ('Subprotocol', lambda ep=ep: test_subprotocol(ep)),
                ('Race Condition', lambda ep=ep: test_race_condition(ep, fast_mode=fast_mode)),
                ('SSRF', lambda ep=ep: test_ssrf(ep, fast_mode=fast_mode)),
                ('SSTI', lambda ep=ep: test_ssti(ep, fast_mode=fast_mode)),
                ('Mass Assignment', lambda ep=ep: test_mass_assignment(ep, fast_mode=fast_mode)),
                ('Business Logic', lambda ep=ep: test_business_logic(ep, fast_mode=fast_mode)),
            ]

            if not fast_mode:
                tests.append(('Auth Bypass', lambda ep=ep: test_auth_bypass(ep)))

            if run_jwt:
                tests.append(('JWT Attacks', lambda ep=ep: test_jwt_attacks(ep)))

            if run_timing:
                tests.append(('Timing', lambda ep=ep: test_timing(ep, fast_mode=fast_mode)))

            for label, coro_factory in tests:
                try:
                    print(f'  ⏳ {label}...', end=' ', flush=True)
                    loop.run_until_complete(asyncio.wait_for(coro_factory(), timeout=20))
                    print('✓')
                except asyncio.TimeoutError:
                    print('⏱ timeout')
                except Exception as e:
                    print(f'✗ {e}')

        # 4. Summary
        counts = store.count_by_severity()
        total_findings = len(store.all())

        print('\n' + '═' * 50)
        print(f'  SCAN COMPLETE — {total_findings} findings')
        print('═' * 50)
        for sev, cnt in counts.items():
            if cnt > 0:
                icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}[sev]
                print(f'  {icon} {sev}: {cnt}')

        # 5. Export
        if args.output:
            findings_data = store.as_dicts()
            ext = os.path.splitext(args.output)[1].lower()

            if ext == '.sarif' or args.format == 'sarif':
                from reports.sarif_generator import generate_sarif
                content = generate_sarif(findings_data, target)
            else:
                content = json.dumps(findings_data, indent=2, ensure_ascii=False)

            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f'\n📄 Report saved: {args.output}')

        if args.json:
            print('\n' + json.dumps(store.as_dicts(), indent=2, ensure_ascii=False))

    except KeyboardInterrupt:
        print('\n\n⏹ Scan cancelled')
    except Exception as e:
        print(f'\n❌ Error: {e}')
        log.error(f'CLI scan error: {e}', exc_info=True)
    finally:
        loop.close()


def main():
    parser = argparse.ArgumentParser(
        prog='ws_tester_pro',
        description='🔐 WS Tester Pro — Advanced WebSocket Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --target https://example.com
  python main.py --target wss://example.com/ws --fast
  python main.py --target https://example.com --output report.json
  python main.py --target https://example.com --output report.sarif --format sarif
  python main.py --target https://example.com --no-jwt --timing
  python main.py --dashboard    (start the web dashboard instead)
""",
    )

    parser.add_argument('--target', '-t', type=str,
                        help='Target URL (https:// or wss://)')
    parser.add_argument('--fast', '-f', action='store_true',
                        help='Fast mode — skip deep tests')
    parser.add_argument('--no-jwt', action='store_true',
                        help='Skip JWT attacks')
    parser.add_argument('--timing', action='store_true',
                        help='Enable timing attack tests')
    parser.add_argument('--output', '-o', type=str,
                        help='Save report to file (JSON or SARIF)')
    parser.add_argument('--format', choices=['json', 'sarif'],
                        default='json', help='Output format (default: json)')
    parser.add_argument('--json', action='store_true',
                        help='Print findings as JSON to stdout')
    parser.add_argument('--dashboard', '-d', action='store_true',
                        help='Start the web dashboard instead of CLI scan')

    args = parser.parse_args()

    print_banner()

    if args.dashboard:
        print('Starting web dashboard...\n')
        from dashboard.app import app, socketio
        socketio.run(app, host='0.0.0.0', port=5000, debug=False)
        return

    if not args.target:
        parser.print_help()
        print('\n⚠️  Use --target to specify a URL, or --dashboard to start the web UI')
        sys.exit(1)

    # Register finding callback for CLI output
    def on_finding(finding):
        sev = finding.severity
        icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(sev, '⚪')
        print(f'\n  {icon} [{sev}] {finding.title}')

    store.on_finding(on_finding)
    run_cli_scan(args)


if __name__ == '__main__':
    main()
