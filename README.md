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

```bash
# Unified dashboard payload (session-authenticated app clients)
curl -X GET "http://127.0.0.1:5000/api/dashboard"

# Unified action API (example: refresh)
curl -X POST http://127.0.0.1:5000/api/dashboard \
  -H "Content-Type: application/json" \
  -d '{"action":"dashboard.refresh"}'

# REST API scan
curl "http://127.0.0.1:5000/api/scan?target=google.com"

# POST scan
curl -X POST http://127.0.0.1:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'

# Download CBOM
curl "http://127.0.0.1:5000/cbom/<scan_id>" -o cbom.json
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

## 📄 License

MIT — Built for the PNB Cybersecurity Hackathon 2026
