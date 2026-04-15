# 🔒 QuantumShield — Quantum-Safe TLS Scanner

> **PNB Cybersecurity Hackathon 2026** — Post-Quantum Cryptography Readiness Platform

A comprehensive scanner that discovers cryptographic assets on public-facing systems, generates a **Cryptographic Bill of Materials (CBOM)**, validates **NIST PQC compliance** (FIPS 203/204/205), and issues **Quantum-Safe labels** with actionable migration recommendations.

---

## 🚀 Quick Start

```bash
# Clone & setup
cd quantum-safe-scanner
pip install -r requirements.txt

# Run the web dashboard
python web/app.py

# Open http://127.0.0.1:5000
```

## 🎯 Features

| Feature | Description |
|---------|-------------|
| **🔍 Crypto Discovery** | Concurrent port scanning, TLS handshake analysis, cipher suite & key exchange detection |
| **📋 CBOM Generation** | CycloneDX 1.6 JSON format — industry-standard cryptographic inventory |
| **🛡️ PQC Validation** | ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205) compliance checks |
| **🏷️ Quantum-Safe Labels** | Digital certificates with SHA-256 integrity checksums |
| **📊 HNDL Risk Scoring** | Harvest Now, Decrypt Later risk assessment (High/Medium/Low) |
| **🔧 Migration Guidance** | Server-specific configs for Nginx, Apache, HAProxy, AWS ALB |
| **🌐 Unified Dashboard API** | `/api/dashboard` for all in-app dashboard + scan actions |
| **🤖 CI/CD Scan API** | `/api/scan?target=example.com` for automation pipelines |
| **📈 Visual Dashboard** | Chart.js charts, glassmorphism dark-mode UI, responsive design |
| **🎨 UI Accessibility** | Improved login page text contrast for light/dark/system theme modes |

## 🏗️ Architecture

```
src/
├── scanner/
│   ├── network_discovery.py    # Concurrent port scanner (no nmap needed)
│   ├── tls_analyzer.py         # TLS handshake + certificate extraction
│   └── pqc_detector.py         # NIST PQC algorithm classification
├── cbom/
│   ├── builder.py              # Crypto asset → CBOM assembly
│   └── cyclonedx_generator.py  # CycloneDX 1.6 JSON export
├── validator/
│   ├── quantum_safe_checker.py # NIST compliance validation
│   └── certificate_issuer.py   # PQC Ready label issuance
└── reporting/
    ├── report_generator.py     # Executive summary builder
    └── recommendation_engine.py # Server-specific migration configs
web/
├── app.py                      # Flask web app (5 routes + REST API)
├── templates/                  # Jinja2 templates (base, index, results, error)
└── static/                     # CSS design system + JS particle animation
tests/
├── test_network_discovery.py   # 9 tests
├── test_tls_analyzer.py        # 12 tests
├── test_pqc_detector.py        # 18 tests
├── test_cbom_builder.py        # 9 tests
├── test_validator.py           # 14 tests
└── test_web_app.py             # 6 tests (68 total)
```

## 📡 API Usage

### Authentication
- This API supports API key auth with `X-API-Key` request header (preferred) and fallback via `?api_key=...` query string or `api_key` in JSON body.
- Missing/wrong key returns 401 + JSON: `{"error": "API key required"}` or `{"error": "Invalid or revoked API key"}`.

### Two-Factor Authentication (2FA)
The web application supports TOTP-based two-factor authentication (2FA) for user accounts.

- Endpoints (web UI / form-backed):
  - `GET /2fa/setup` — Show QR and one-time secret for provisioning an authenticator app (after password verification).
  - `POST /2fa/setup` — Verify the first TOTP code and enable 2FA; returns one-time backup codes (shown once).
  - `GET /2fa/login` — Show TOTP/backup-code form when a user has 2FA enabled.
  - `POST /2fa/login` — Verify TOTP or one-time backup code to complete login. This endpoint is rate-limited server-side (default 10/min per IP).
  - `POST /admin/users/<user_id>/reset-2fa` — Admin action to clear a user's 2FA configuration; forces re-setup on next login.

- Environment / secrets:
  - `QSS_ENCRYPTION_KEY` — REQUIRED in production: a 32-url-safe-base64-encoded Fernet key used to encrypt per-user TOTP secrets and backup code blobs. Generate with:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Then add to your .env: QSS_ENCRYPTION_KEY=<generated_key>
```

  - `QSS_REQUIRE_2FA` — Optional boolean (`true|false`) to force all users to configure 2FA on next login when enabled (default: false).

Security notes: backup codes are hashed (SHA-256) and stored encrypted; plaintext backup codes are displayed only once during setup. Do not commit `QSS_ENCRYPTION_KEY` to public repos.

### Examples (API key required for non-browser endpoints)
```bash
# Unified dashboard payload (session-authenticated app clients)
# If using API key:
# -H "X-API-Key: sk_..."

curl -X GET "https://127.0.0.1:5000/api/dashboard" \
  -H "X-API-Key: sk_your_api_key_here"

# Unified action API (example: refresh)
curl -X POST https://127.0.0.1:5000/api/dashboard \
  -H "X-API-Key: sk_your_api_key_here" \
  -H "Content-Type: application/json" \
  -d '{"action":"dashboard.refresh"}'

# REST API scan (GET)
curl -X GET "https://127.0.0.1:5000/api/scan?target=google.com" \
  -H "X-API-Key: sk_your_api_key_here"

# POST scan (JSON body)
curl -X POST https://127.0.0.1:5000/api/scan \
  -H "X-API-Key: sk_your_api_key_here" \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'

# Download CBOM
curl -X GET "https://127.0.0.1:5000/cbom/<scan_id>" \
  -H "X-API-Key: sk_your_api_key_here" \
  -o cbom.json

# Admin: list API keys
curl -X GET "https://127.0.0.1:5000/api/admin/api-keys" \
  -H "X-API-Key: sk_your_admin_api_key_here"
```

### Useful query parameters
- `page`, `page_size` — pagination
- `sort`, `order` — sorting field and direction
- `q` — full-text search filter (if supported)
- `tab=domains|ssl|ips|software` — discovery modes (e.g., `/api/discovery`)

### Sample dashboard response structure
```json
{
  "success": true,
  "data": {
    "items": [...],
    "total": 150,
    "page": 1,
    "page_size": 25,
    "total_pages": 6,
    "kpis": {...}
  },
  "filters": {
    "sort": "field",
    "order": "asc",
    "search": "query"
  }
}
```

## 🧪 Testing

```bash
# Run all tests
python -m pytest tests/ -v

# With coverage
python -m pytest tests/ --cov=src --cov-report=term-missing
```

## ☁️ Free Remote Hosting + Remote MySQL

For deploying this app with a remote SQL host and free web hosting, see:

- `FREE_REMOTE_HOSTING_SETUP.md`

Helper scripts included:

- `scripts/remote_db_check.py` — verify remote MySQL connectivity
- `scripts/push_sql_to_remote.py` — apply schema/migration SQL to remote MySQL

## CI/CD and Auto-update

This repository includes a GitHub Actions workflow to run tests and deploy to a production server when changes land on `main`.

Configuration (set these as GitHub repository secrets):

- `PRODUCTION_HOST` — production server SSH host (e.g. `prod.example.com`)
- `PRODUCTION_SSH_USER` — SSH user (e.g. `deploy`)
- `PRODUCTION_SSH_KEY` — private SSH key used by Actions to connect (keep secret)
- `PRODUCTION_SSH_PORT` — optional SSH port (default `22`)
- `PRODUCTION_DEPLOY_PATH` — absolute path on the server where the repo is checked out
- `PRODUCTION_BRANCH` — branch to deploy (default `main`)

The workflow file is `.github/workflows/ci-cd-deploy.yml` and will:

1. Run tests (pytest)
2. If tests pass, SSH into the production server, `git fetch` and `git reset --hard origin/<branch>`, install requirements, and attempt to restart `quantumshield.service` (or use Docker Compose if present).

Note: The deployment commands are intentionally conservative — replace `quantumshield.service` with your systemd service name or adjust the restart commands to match your environment.

Auto-update on start or schedule

If you want the running app process itself to check GitHub Releases for updates, enable the following environment variables on the server (in the app's runtime environment):

- `QSS_GITHUB_REPO_OWNER=your-github-org-or-user`
- `QSS_GITHUB_REPO_NAME=your-repository-name`
- `QSS_GITHUB_UPDATE_ON_START=true` — check for a newer release before boot
- `QSS_ALLOW_AUTO_UPDATE=true` — allow the process to install the newer wheel/archive

Optional scheduler:

- `QSS_GITHUB_UPDATE_SCHEDULED=true` — keep checking in a background thread
- `QSS_GITHUB_UPDATE_INTERVAL_MINUTES=60` — how often to poll GitHub Releases
- `QSS_GITHUB_RELEASE_ASSET_NAME=` — pin a specific release asset if desired
- `QSS_GITHUB_TOKEN=` — optional token for private repos or rate-limit relief

Behavior: if enabled and GitHub has a newer release tag, the process installs the latest package asset with `pip` and then re-execs the current process so the new code is used.

Security and safety

- Do NOT store private SSH keys or production secrets in the repository. Use GitHub Secrets for the Actions workflow.
- Use GitHub Releases or PyPI as the source of truth for updates; keep the release tag/version in sync with the package version.
- Only enable auto-update on servers where an automatic restart is acceptable.

## 🔬 NIST PQC Standards Validated

| Standard | Algorithm Family | Replaces |
|----------|-----------------|----------|
| **FIPS 203** | ML-KEM (Kyber) — 512/768/1024 | RSA, ECDH key exchange |
| **FIPS 204** | ML-DSA (Dilithium) — 44/65/87 | RSA, ECDSA signatures |
| **FIPS 205** | SLH-DSA (SPHINCS+) | Hash-based fallback signatures |
| *Draft* | FN-DSA (Falcon), HQC | Backup KEM/signature standards |

## 📦 Tech Stack

- **Python 3.10+** — Core language
- **Flask** — Web framework
- **pyOpenSSL + cryptography** — TLS/certificate analysis
- **CycloneDX** — CBOM standard format
- **Chart.js** — Interactive dashboard charts
- **Pure CSS** — Glassmorphism dark-mode design (no Tailwind)



## Built for the PNB Cybersecurity Hackathon 2026
