# Contributing to WS Tester Pro

Thank you for your interest in contributing to **WS Tester Pro**! 🎉

## 🚀 Getting Started

1. **Fork** the repository
2. **Clone** your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/ws_pro.git
   cd ws_pro
   ```
3. **Create a virtual environment** and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate  # or venv\Scripts\activate on Windows
   pip install -r requirements.txt
   pip install pytest  # for running tests
   ```

## 🏗️ Project Structure

```
ws_pro/
├── core/           # Scanner, findings store, CVSS scoring
├── attacks/        # Attack modules (injection, auth, network, timing, subprotocol)
├── dashboard/      # Flask + SocketIO web dashboard
├── reports/        # Report generators (HTML, PDF, SARIF)
├── utils/          # Evidence collector, logger
├── tests/          # Unit tests (pytest)
├── main.py         # CLI entry point
└── mock_server.py  # Vulnerable test server
```

## 📝 How to Contribute

### Adding a New Attack Module

1. Create a new file in `attacks/` (e.g., `attacks/my_attack.py`)
2. Follow the pattern of existing modules:
   - Import from `core.scanner`, `core.findings`, `utils.evidence`
   - Create an `async` test function
   - Use `store.add()` to register findings with proper evidence
   - Only report **confirmed** vulnerabilities (no guessing)
3. Register your attack in `dashboard/app.py` → `run_scan()` function
4. Add it to `main.py` CLI if applicable
5. Add test scenarios to `mock_server.py`
6. Write unit tests in `tests/`

### Code Style

- Python 3.9+ features OK
- Use type hints where practical
- Async functions for all WebSocket operations
- Thread-safe access to shared `store` (uses `threading.Lock`)
- Include evidence in all findings (proof, payload, reproduce steps)

### Testing

```bash
# Run all tests
pytest tests/ -v

# Run with mock server
python mock_server.py  # Terminal 1
pytest tests/ -v       # Terminal 2
```

### Commit Messages

Use clear, descriptive commit messages:
- `feat: add SSRF attack module`
- `fix: correct CVSS score for NoSQL injection`
- `docs: update README with new attack list`

## 🔒 Security

If you discover a security vulnerability in this tool itself (not in the targets it scans), please report it privately via GitHub Security Advisories.

## ⚖️ License

By contributing, you agree that your contributions will be licensed under the MIT License.
