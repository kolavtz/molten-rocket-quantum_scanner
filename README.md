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

This repository includes a GitHub Actions workflow to run tests and package a production-ready release when a GitHub Release is published (or when manually dispatched).
The release job attaches a source bundle ZIP to the GitHub Release instead of deploying to a server.

No production SSH secrets are needed for the packaging workflow itself — GitHub Actions uses the built-in token to create the release asset.

The workflow file is `.github/workflows/release-package.yml` and will:

1. Check out the release tag/ref
2. Copy only runtime files needed to run the app (`web/`, `src/`, `middleware/`, `migrations/`, `config.py`, `Procfile`, `requirements.txt`)
3. Exclude tests, docs, GitHub workflow files, temp files, and other development-only content
4. Publish a ZIP bundle to the GitHub Release and upload the same bundle as a workflow artifact

To package a new release manually, run the workflow from the Actions tab and provide the release tag you want to publish.

Auto-update on start

If you want the running app process itself to check for updates when the process starts, enable the following environment variables on the server (in the app's runtime environment):

- `QSS_AUTO_UPDATE_ON_START=true` — enable startup update check
- `QSS_AUTO_UPDATE_SOURCE=release` — follow the newest Git tag/release instead of branch HEAD
- `QSS_ALLOW_AUTO_PULL=true` — allow the process to perform a hard reset or tag checkout (dangerous if local changes exist)
- `QSS_GIT_BRANCH=main` — branch to compare/checkout when `QSS_AUTO_UPDATE_SOURCE=branch`
- `QSS_RELEASE_TAG_PREFIX=v` — optional tag prefix when following releases (defaults to `v`)

Important: for auto-update to work reliably in private repositories, configure server-side git credentials (typically SSH deploy key and a git remote URL the app can fetch from).

Behavior:

- In `branch` mode, if the local HEAD differs from `origin/<branch>`, the process will (when `QSS_ALLOW_AUTO_PULL=true` and the working tree is clean) reset to the remote and re-exec the Python process.
- In `release` mode, if the latest release tag differs from the current checked-out tag, the process will fetch tags, checkout the newest tag, and re-exec the Python process so the new code is used.

Security and safety

- Do NOT store private SSH keys or production secrets in the repository. Use GitHub Secrets for the Actions workflow.
- Auto-pulling from a remote may overwrite local changes. Only enable `QSS_ALLOW_AUTO_PULL=true` on servers where the repo directory is managed by CI or otherwise safe to overwrite.

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
