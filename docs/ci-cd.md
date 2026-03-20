# CI/CD Integration Guide — WS Tester Pro

## GitHub Actions

WS Tester Pro includes a ready-to-use GitHub Actions workflow at `.github/workflows/ws-security.yml`.

### Quick Setup

1. **Add secrets** to your GitHub repo:
   - `WS_TARGET_URL` — Your WebSocket target URL (e.g., `wss://app.example.com/ws`)
   - `ANTHROPIC_API_KEY` — (Optional) For AI analysis

2. **Copy the workflow** file to your repo:
   ```bash
   mkdir -p .github/workflows
   cp .github/workflows/ws-security.yml your-repo/.github/workflows/
   ```

3. **Trigger manually** via Actions tab → "Run workflow"

### Automatic Scanning

The workflow runs automatically on:
- Push to `main`
- Pull requests to `main`
- Manual trigger (workflow_dispatch)

### Fail Threshold

Use `--fail-on` to block PRs with findings:

```bash
# Fail on CRITICAL findings only
python main.py --target wss://example.com --fail-on=critical

# Fail on HIGH or above
python main.py --target wss://example.com --fail-on=high

# Fail on any finding
python main.py --target wss://example.com --fail-on=low
```

Exit codes:
- `0` — No findings at or above threshold
- `1` — Findings found at or above threshold

### SARIF Output

Results are uploaded to GitHub Security tab automatically:
```bash
python main.py --target wss://example.com --output results.sarif --format sarif
```

---

## GitLab CI

```yaml
ws-security:
  image: python:3.11-slim
  stage: test
  script:
    - pip install -r requirements.txt
    - python main.py --target $WS_TARGET_URL --output results.sarif --format sarif --fast --fail-on=critical
  artifacts:
    reports:
      sast: results.sarif
    paths:
      - results.sarif
```

---

## Docker

```bash
# Build
docker build -t ws-tester-pro .

# CLI scan
docker run --rm ws-tester-pro python main.py --target wss://example.com --fast

# Dashboard
docker run --rm -p 5000:5000 ws-tester-pro
```

### Docker Compose (with OOB server)
```bash
docker-compose up -d
# Dashboard: http://localhost:5000
# OOB Server: http://localhost:7000
```

---

## Scan Profiles

Use pre-built profiles for common scenarios:

| Profile | File | Use Case |
|---------|------|----------|
| Bug Bounty Quick | `profiles/bug_bounty.json` | Fast scan for bug bounty targets |
| Deep Audit | `profiles/deep_audit.json` | Full security audit (all tests) |
| CI/CD Safe | `profiles/ci_cd.json` | Non-destructive, safe for pipelines |
| JWT Focus | `profiles/jwt_focus.json` | JWT and auth-specific testing |

Load profiles via the dashboard UI or API:
```bash
curl http://localhost:5000/load-profile?name=ci_cd
```
