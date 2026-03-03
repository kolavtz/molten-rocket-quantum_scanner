# QuantumShield User Guide

## What Is QuantumShield?

QuantumShield is a **Quantum-Safe TLS Scanner** that checks whether your public-facing systems (websites, APIs, VPNs) are protected against future quantum computer attacks.

It scans your endpoints, identifies what cryptography they use, and tells you:
- ✅ Which systems are **quantum-safe** (using NIST-approved PQC algorithms)
- ❌ Which systems are **vulnerable** (using RSA, ECDHE, ECDSA — breakable by quantum computers)
- 🔧 **Exactly what to change** to fix them — with copy-paste server configs

---

## How to Use

### 1. Open the Dashboard
Navigate to `http://127.0.0.1:5000` in your browser.

### 2. Enter a Target
Type a hostname (e.g., `google.com`), IP address, or CIDR range into the scan box.

**Quick scan buttons** are available for common test targets:
- `google.com` — typical quantum-vulnerable endpoint
- `cloudflare.com` — may have partial PQC support
- `test.openquantumsafe.org` — PQC test server by the Open Quantum Safe project

### 3. Click "Scan Now"
The scanner will:
1. Discover TLS-enabled ports
2. Perform a TLS handshake and extract cipher suite, key exchange, protocol version
3. Parse the X.509 certificate (subject, issuer, key type, expiry, signature algorithm)
4. Classify all algorithms as quantum-safe or quantum-vulnerable
5. Generate a CBOM (Cryptographic Bill of Materials)
6. Validate NIST PQC compliance and issue a label
7. Generate server-specific migration recommendations

### 4. Review Results
The results page shows:

| Section | What It Tells You |
|---------|-------------------|
| **Overview Cards** | Total assets, safe vs vulnerable count, compliance score |
| **Charts** | Visual asset distribution, severity breakdown, risk distribution |
| **Quantum-Safe Labels** | PQC Ready / Partial / Non-Compliant badge with validity period |
| **Security Findings** | Each vulnerability with severity, current value, and recommended fix |
| **Migration Recommendations** | Prioritized actions (P1–P5) with Nginx/Apache/HAProxy/ALB configs |
| **TLS Details** | Full endpoint data — cipher suite, key exchange, cert details, fingerprint |

### 5. Download CBOM
Click **"Download CBOM (JSON)"** to get a CycloneDX 1.6 file — the industry-standard format for cryptographic inventories.

### 6. Use the API
Integrate scanning into your CI/CD pipeline:
```bash
curl "http://127.0.0.1:5000/api/scan?target=your-app.com"
```

---

## Understanding the Compliance Score

| Score | Label | Meaning |
|-------|-------|---------|
| **90–100%** | 🛡️ PQC Ready | All algorithms are NIST-approved PQC. Fully quantum-safe. |
| **50–89%** | ⚡ Partial | Mix of quantum-safe and classical algorithms. Migration needed. |
| **0–49%** | ❌ Non-Compliant | No PQC algorithms detected. Vulnerable to quantum attacks. |

---

## HNDL Risk Levels

**HNDL** = Harvest Now, Decrypt Later. Attackers record encrypted traffic today, planning to decrypt it when quantum computers arrive.

| Risk | Examples | Why It Matters |
|------|----------|----------------|
| **HIGH** | Banking APIs, auth endpoints, payment systems | Financial/PII data has long-term value |
| **MEDIUM** | Customer portals, internal tools | Sensitive but time-limited data |
| **LOW** | Public CDNs, marketing sites, blogs | Data has no long-term confidentiality value |

---

## NIST Standards Reference

| Standard | Algorithm | What It Replaces |
|----------|-----------|------------------|
| **FIPS 203** | ML-KEM (Kyber) 512/768/1024 | RSA, ECDH key exchange |
| **FIPS 204** | ML-DSA (Dilithium) 44/65/87 | RSA, ECDSA digital signatures |
| **FIPS 205** | SLH-DSA (SPHINCS+) | Hash-based backup signatures |

**NIST Deadline:** All federal systems must transition to PQC by **2035**.

---

## FAQ

**Q: Is it safe to scan production systems?**
A: Yes — the scanner only performs standard TLS handshakes (the same thing a browser does). It does not attempt to exploit vulnerabilities.

**Q: Why does google.com show as "Non-Compliant"?**
A: As of 2026, most public websites still use classical key exchange (ECDHE). Google has been experimenting with hybrid PQC but hasn't fully deployed it on all endpoints.

**Q: Can it detect PQC algorithms like ML-KEM?**
A: Yes — the scanner checks key exchange groups, cipher suites, and certificate signature algorithms for all NIST-approved PQC algorithms.

**Q: What is a CBOM?**
A: A Cryptographic Bill of Materials — a standardized inventory of all cryptographic assets on your systems, similar to an SBOM (Software Bill of Materials) but focused on cryptography.
