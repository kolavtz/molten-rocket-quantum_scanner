# QuantumShield API Reference

## Base URL

```
http://127.0.0.1:5000
```

---

## Endpoints

### `POST /scan`

**Run a TLS scan via the web form.**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | string (form) | ✅ | Hostname, IP, or CIDR range |

**Response:** `302` redirect to `/results/<scan_id>`

---

### `GET /results/<scan_id>`

**View scan results in the dashboard.**

| Parameter | Type | Description |
|-----------|------|-------------|
| `scan_id` | string (path) | 8-char UUID prefix from scan |

**Response:** HTML results page with charts, findings, labels, and recommendations.

---

### `GET /cbom/<scan_id>`

**Download CBOM in CycloneDX 1.6 JSON format.**

```bash
curl http://127.0.0.1:5000/cbom/abc12345 -o cbom.json
```

**Response:** `application/json` file attachment.

---

### `GET /api/scan` or `POST /api/scan`

**REST API — run a scan and get JSON results.**

**GET:**
```bash
curl "http://127.0.0.1:5000/api/scan?target=google.com"
```

**POST:**
```bash
curl -X POST http://127.0.0.1:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

**Response (200):**
```json
{
  "scan_id": "abc12345",
  "target": "google.com",
  "status": "complete",
  "overview": {
    "total_assets": 1,
    "quantum_safe": 0,
    "quantum_vulnerable": 1,
    "average_compliance_score": 33
  },
  "severity_breakdown": {
    "CRITICAL": 1, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "INFO": 1
  },
  "risk_distribution": { "HIGH": 1, "MEDIUM": 0, "LOW": 0 },
  "label_distribution": { "PQC Ready": 0, "Partial": 0, "Non-Compliant": 1 },
  "top_recommendations": [...],
  "findings": [...],
  "labels": [...],
  "tls_results": [...],
  "pqc_assessments": [...],
  "recommendations_detailed": [...]
}
```

**Error (400):**
```json
{ "error": "Missing 'target' parameter" }
```

---

### `GET /api/scans`

**List all stored scan results.**

```bash
curl http://127.0.0.1:5000/api/scans
```

**Response (200):**
```json
[
  {
    "scan_id": "abc12345",
    "target": "google.com",
    "status": "complete",
    "generated_at": "2026-03-02T04:49:48+00:00",
    "overview": { "total_assets": 1, "quantum_safe": 0, "quantum_vulnerable": 1 }
  }
]
```

---

## Data Models

### CBOM Asset
```json
{
  "asset_id": "uuid",
  "host": "example.com",
  "port": 443,
  "protocol_version": "TLSv1.3",
  "cipher_suite": "TLS_AES_256_GCM_SHA384",
  "key_exchange": "TLS1.3-ECDHE",
  "cipher_bits": 256,
  "cert_subject": "example.com",
  "cert_public_key_type": "RSA",
  "cert_public_key_bits": 2048,
  "is_quantum_safe": false,
  "pqc_status": "quantum_vulnerable",
  "risk_level": "HIGH"
}
```

### Quantum-Safe Label
```json
{
  "label_id": "uuid",
  "host": "example.com",
  "port": 443,
  "label": "PQC Ready | Partial | Non-Compliant",
  "compliance_score": 95,
  "standard": "FIPS 203 (ML-KEM) | FIPS 204 (ML-DSA)",
  "issued_at": "2026-03-02T04:49:48+00:00",
  "valid_until": "2027-03-02T04:49:48+00:00",
  "badge_color": "#22c55e",
  "checksum": "sha256-hex-string"
}
```

### Validation Finding
```json
{
  "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
  "category": "key_exchange | signature | certificate | protocol | pqc",
  "title": "Quantum-vulnerable key exchange",
  "description": "Key exchange 'ECDHE' is vulnerable to Shor's algorithm.",
  "current_value": "ECDHE",
  "recommended_value": "ML-KEM-768 or ML-KEM-1024",
  "nist_reference": "FIPS 203 (ML-KEM)"
}
```
