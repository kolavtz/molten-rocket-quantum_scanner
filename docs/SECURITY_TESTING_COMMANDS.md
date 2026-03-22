# Security Testing Commands

Use these commands in your local environment or CI pipeline.

## Static security analysis

- `python -m pip install bandit pip-audit`
- `bandit -r web src -x tests,tmp`
- `pip-audit -r requirements.txt`

## Test suite with security-focused markers

- `pytest tests/security -q`

## Full regression with coverage

- `pytest -q --maxfail=1 --disable-warnings --cov=src --cov=web --cov-report=term-missing`

## Optional API fuzz sanity (quick)

- `pytest tests/smoke/test_smoke_dashboard_apis.py -q`
