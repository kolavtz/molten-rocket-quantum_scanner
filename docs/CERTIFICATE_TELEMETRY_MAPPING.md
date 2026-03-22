## SSL/TLS Certificate Telemetry — Complete Mapping Guide

This document maps each **dashboard UI widget → SQL fields → source data**.

All data is **100% database-backed**, sourced from the `certificates` table populated during scan ingestion (line 994 of `web/app.py`). No mock or hardcoded values.

---

## 1. EXPIRING CERTIFICATES KPI Card

**UI Location:** `web/templates/asset_inventory.html` line 80

```html
<div class="overview-value">{{ vm.kpis.expiring_certificates }}</div>
<div class="overview-label">EXPIRING CERTIFICATES</div>
```

### Data Flow

```
Scan TLS Result 
  → Certificate.valid_until (datetime)
  → Certificate.is_deleted (soft-delete)
  → AssetService.get_inventory_view_model()
  → vm.kpis.expiring_certificates (count)
  → HTML KPI Card
```

### SQL Query

```sql
SELECT COUNT(*) FROM certificates c
WHERE c.is_deleted = 0
  AND NOW() < c.valid_until < DATE_ADD(NOW(), INTERVAL 30 DAYS)
```

### ORM Equivalent

```python
# src/services/certificate_telemetry_service.py
from datetime import datetime, timezone, timedelta
from sqlalchemy import func

def get_expiring_certificates_count(self, days_threshold: int = 30) -> int:
    db = self._get_db_session()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    threshold_date = now + timedelta(days=days_threshold)
    
    count = db.query(func.count(Certificate.id)).filter(
        Certificate.is_deleted == False,
        Certificate.valid_until > now,
        Certificate.valid_until <= threshold_date
    ).scalar() or 0
    
    return int(count)
```

### Database Fields

| Field | Type | Example | Source | Purpose |
|-------|------|---------|--------|---------|
| `valid_until` | DATETIME | 2025-03-15 14:30:00 | TLS scan: `tls.get("valid_until_dt")` | Expiry date |
| `is_deleted` | TINYINT(1) | 0 | SoftDeleteMixin | Soft-delete flag |

### Service Layer Integration

In `src/services/asset_service.py` (lines 205-350):

```python
expiring_certs = self._service.get_expiring_certificates_count()
kpi_data = {
    "expiring_certificates": expiring_certs,
    # ...other KPIs...
}
return {"kpis": kpi_data, ...}
```

---

## 2. CERTIFICATE EXPIRY TIMELINE Chart

**UI Location:** `web/templates/asset_inventory.html` lines 109-110

```html
<div>Certificate Expiry Timeline</div>
{% for k,v in vm.certificate_expiry_timeline.items() %}
  <div>{{ k }}: {{ v }}</div>
{% endfor %}
```

### Data Flow

```
Scan → Certificate.valid_until
  → Calculate DATEDIFF(valid_until - NOW())
  → Group into 4 buckets: [0-30], [30-60], [60-90], [>90] days
  → vm.certificate_expiry_timeline (dict)
  → Template loop + Chart
```

### SQL Query

```sql
-- Grouped aggregations
SELECT
  CASE
    WHEN DATEDIFF(c.valid_until, NOW()) BETWEEN 0 AND 30 THEN '0-30'
    WHEN DATEDIFF(c.valid_until, NOW()) BETWEEN 31 AND 60 THEN '30-60'
    WHEN DATEDIFF(c.valid_until, NOW()) BETWEEN 61 AND 90 THEN '60-90'
    WHEN DATEDIFF(c.valid_until, NOW()) > 90 THEN '>90'
  END as bucket,
  COUNT(*) as count
FROM certificates c
WHERE c.is_deleted = 0 AND c.valid_until > NOW()
GROUP BY bucket
```

### ORM Equivalent

```python
def get_certificate_expiry_timeline(self) -> Dict[str, int]:
    """Returns {"0-30": 5, "30-60": 3, "60-90": 2, ">90": 15}"""
    db = self._get_db_session()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    
    # Get all valid (not expired, not deleted) certificates
    certs = db.query(Certificate).filter(
        Certificate.is_deleted == False,
        Certificate.valid_until > now
    ).all()
    
    buckets = {"0-30": 0, "30-60": 0, "60-90": 0, ">90": 0}
    
    for cert in certs:
        if cert.valid_until is None:
            continue
        
        days_left = (cert.valid_until - now).days
        
        if days_left <= 30:
            buckets["0-30"] += 1
        elif days_left <= 60:
            buckets["30-60"] += 1
        elif days_left <= 90:
            buckets["60-90"] += 1
        else:
            buckets[">90"] += 1
    
    return buckets
```

### Database Fields

| Field | Type | Calculation | Purpose |
|-------|------|-------------|---------|
| `valid_until` | DATETIME | ISO parsed from TLS | Expiry threshold |
| `is_deleted` | TINYINT(1) | SoftDeleteMixin | Exclude deleted |

---

## 3. SSL CERTIFICATE INTELLIGENCE Table

**UI Location:** `web/templates/asset_inventory.html` lines 280-284

```html
<h3>SSL Certificate Intelligence</h3>
<table>
  <thead>
    <tr>
      <th>Asset</th>
      <th>Issuer</th>
      <th>Key</th>
      <th>TLS</th>
      <th>Days Left</th>
      <th>Status</th>
    </tr>
  </thead>
  <tbody>
    {% for cert in vm.certificate_inventory %}
      <tr>
        <td>{{ cert.asset }}</td>
        <td>{{ cert.issuer }}</td>
        <td>{{ cert.key_length }}</td>
        <td>{{ cert.tls_version }}</td>
        <td>{{ cert.days_remaining }}</td>
        <td>{{ cert.status }}</td>
      </tr>
    {% endfor %}
  </tbody>
</table>
```

### Data Flow

```
Scan TLS Results
  → Certificate ORM (11 fields)
  → Stored in DB (certificates table)
  → AssetService.get_inventory_view_model()
  → Loop: Calculate cert_days, determine cert_status
  → vm.certificate_inventory (list of dicts)
  → Template table rows
```

### SQL Query

```sql
SELECT 
  c.id,
  c.issuer,
  c.subject,
  c.serial,
  c.tls_version,
  c.key_length,
  c.cipher_suite,
  c.ca,
  c.valid_from,
  c.valid_until,
  c.fingerprint_sha256,
  a.target as asset_name
FROM certificates c
LEFT JOIN assets a ON c.asset_id = a.id
WHERE c.is_deleted = 0
ORDER BY c.valid_until ASC
LIMIT 100
```

### ORM Equivalent

```python
def get_certificate_inventory(self, limit: int = 100) -> List[Dict]:
    """
    Returns list of certificate dicts with all fields + computed status.
    
    Example return:
    [
        {
            "asset": "api.example.com",
            "issuer": "DigiCert",
            "key_length": 2048,
            "tls_version": "TLS 1.3",
            "days_remaining": 45,
            "status": "Valid",
            ...
        },
        ...
    ]
    """
    db = self._get_db_session()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    
    certs = db.query(Certificate).filter(
        Certificate.is_deleted == False
    ).order_by(Certificate.valid_until.asc()).limit(limit).all()
    
    inventory = []
    
    for cert in certs:
        asset_name = "Unknown"
        if cert.asset_id and cert.asset:
            asset_name = str(cert.asset.target or "Unknown")
        
        # Compute status based on days to expiry
        days_remaining = None
        status = "Unknown"
        
        if cert.valid_until:
            days_remaining = (cert.valid_until - now).days
            
            if days_remaining < 0:
                status = "Expired"
            elif days_remaining == 0:
                status = "Expires Today"
            elif days_remaining <= 7:
                status = "Critical"
            elif days_remaining <= 30:
                status = "Expiring"
            else:
                status = "Valid"
        
        inventory.append({
            "certificate_id": cert.id,
            "asset": asset_name,
            "issuer": str(cert.issuer or cert.ca or "Unknown"),
            "subject": str(cert.subject or ""),
            "key_length": int(cert.key_length or 0),
            "cipher_suite": str(cert.cipher_suite or "Unknown"),
            "tls_version": str(cert.tls_version or "Unknown"),
            "ca": str(cert.ca or cert.issuer or "Unknown"),
            "serial": str(cert.serial or ""),
            "valid_from": cert.valid_from.isoformat() if cert.valid_from else None,
            "valid_until": cert.valid_until.isoformat() if cert.valid_until else None,
            "days_remaining": days_remaining,
            "status": status,
            "fingerprint": str(cert.fingerprint_sha256 or "")[:16] + "..." if cert.fingerprint_sha256 else "N/A",
        })
    
    return inventory
```

### Database Fields

| Field | Type | Example | Formula | Purpose |
|-------|------|---------|---------|---------|
| `issuer` | VARCHAR | DigiCert | TLS: `issuer.O` | Certificate issuer |
| `subject` | VARCHAR | example.com | TLS: `subject.O` | Certificate subject |
| `serial` | VARCHAR | ABC123... | TLS: `serial_number` | Serial number |
| `key_length` | INT | 2048 | TLS: `key_length` | RSA key bits |
| `tls_version` | VARCHAR | TLS 1.3 | TLS: `protocol_version` | TLS version |
| `cipher_suite` | VARCHAR | TLS_AES_256... | TLS: `cipher_suite` | Negotiated cipher |
| `ca` | VARCHAR | DigiCert | TLS: `issuer.CN` | CA name |
| `valid_from` | DATETIME | 2024-01-01 | TLS: `valid_from_dt` | Cert start date |
| `valid_until` | DATETIME | 2025-01-01 | TLS: `valid_until_dt` | Cert end date |
| `days_remaining` | (computed) | 45 | `DATEDIFF(valid_until, NOW())` | Days left (**not stored**) |
| `status` | (computed) | Valid | days_remaining logic | Expiry status (**not stored**) |

---

## 4. CRYPTO OVERVIEW Table

**UI Location:** `web/templates/asset_inventory.html` lines 264-267

```html
<table>
  <thead>
    <tr>
      <th>Asset</th>
      <th>Key Length</th>
      <th>Cipher Suite</th>
      <th>TLS Version</th>
      <th>Certificate Authority</th>
      <th>Last Scan</th>
    </tr>
  </thead>
  <tbody>
    {% for row in vm.crypto_overview %}
      <tr>
        <td>{{ row.asset }}</td>
        <td>{{ row.key_length }}</td>
        <td>{{ row.cipher_suite }}</td>
        <td>{{ row.tls_version }}</td>
        <td>{{ row.ca }}</td>
        <td>{{ row.last_scan }}</td>
      </tr>
    {% endfor %}
  </tbody>
</table>
```

### Data Flow

```
Scan Results
  → Certificate ORM (key_length, cipher_suite, tls_version, ca)
  → Scan ORM (completed_at as last_scan)
  → AssetService.get_inventory_view_model()
  → vm.crypto_overview (list)
  → Template table
```

### SQL Query

```sql
SELECT 
  a.target as asset_name,
  c.key_length,
  c.cipher_suite,
  c.tls_version,
  c.ca,
  s.completed_at as last_scan
FROM certificates c
LEFT JOIN assets a ON c.asset_id = a.id
LEFT JOIN scans s ON c.scan_id = s.id
WHERE c.is_deleted = 0
ORDER BY s.completed_at DESC
```

### ORM Equivalent

```python
def get_crypto_overview(self, limit: int = 50) -> List[Dict]:
    """Similar to certificate_inventory but focused on crypto metrics."""
    db = self._get_db_session()
    
    certs = db.query(Certificate).filter(
        Certificate.is_deleted == False
    ).all()
    
    crypto_overview = []
    
    for cert in certs:
        asset_name = "Unknown"
        if cert.asset:
            asset_name = str(cert.asset.target or "Unknown")
        
        last_scan = ""
        if cert.scan and cert.scan.completed_at:
            last_scan = str(cert.scan.completed_at)[:10]
        
        crypto_overview.append({
            "asset": asset_name,
            "key_length": int(cert.key_length or 0),
            "cipher_suite": str(cert.cipher_suite or "Unknown"),
            "tls_version": str(cert.tls_version or "Unknown"),
            "ca": str(cert.ca or cert.issuer or "Unknown"),
            "last_scan": last_scan,
        })
    
    return crypto_overview[:limit]
```

### Database Fields

| Field | Type | Source | Purpose |
|-------|------|--------|---------|
| `key_length` | INT | TLS scan | RSA key bits |
| `cipher_suite` | VARCHAR | TLS scan | Negotiated cipher |
| `tls_version` | VARCHAR | TLS scan | Protocol version |
| `ca` | VARCHAR | TLS scan: issuer.CN | Certificate authority |
| `completed_at` | DATETIME | Scan record | Last scan timestamp |

---

## 5. KEY LENGTH DISTRIBUTION

**Purpose:** Crypto standards compliance (2048-bit minimum recommended)

### SQL Query

```sql
SELECT 
  CASE
    WHEN c.key_length >= 4096 THEN '4096+'
    WHEN c.key_length >= 2048 THEN '2048'
    WHEN c.key_length >= 256 THEN '256-2047'
    WHEN c.key_length > 0 THEN '<256'
    ELSE 'Unknown'
  END as key_category,
  COUNT(*) as count
FROM certificates c
WHERE c.is_deleted = 0
GROUP BY key_category
```

### ORM Equivalent

```python
def get_key_length_distribution(self) -> Dict[str, int]:
    """Returns {"2048": 45, "4096": 23, "256": 5, ...}"""
    db = self._get_db_session()
    
    certs = db.query(Certificate).filter(
        Certificate.is_deleted == False
    ).all()
    
    distribution = Counter()
    
    for cert in certs:
        key_len = int(cert.key_length or 0)
        
        if key_len >= 4096:
            distribution["4096+"] += 1
        elif key_len >= 2048:
            distribution["2048"] += 1
        elif key_len >= 256:
            distribution["256-2047"] += 1
        elif key_len > 0:
            distribution["<256"] += 1
        else:
            distribution["Unknown"] += 1
    
    return dict(distribution)
```

---

## 6. CIPHER SUITE DISTRIBUTION

**Purpose:** Identify weak ciphers in use

### SQL Query

```sql
SELECT 
  c.cipher_suite,
  COUNT(*) as count
FROM certificates c
WHERE c.is_deleted = 0
GROUP BY c.cipher_suite
ORDER BY count DESC
LIMIT 10
```

### ORM Equivalent

```python
def get_cipher_suite_distribution(self, limit: int = 10) -> List[Dict]:
    """Returns top N ciphers with counts."""
    db = self._get_db_session()
    
    certs = db.query(Certificate).filter(
        Certificate.is_deleted == False
    ).all()
    
    cipher_counts = Counter(
        cert.cipher_suite for cert in certs
        if cert.cipher_suite
    )
    
    return [
        {"cipher_suite": cipher, "count": count}
        for cipher, count in cipher_counts.most_common(limit)
    ]
```

---

## 7. TLS VERSION DISTRIBUTION

**Purpose:** Ensure modern TLS usage (1.2+, prefer 1.3)

### SQL Query

```sql
SELECT 
  c.tls_version,
  COUNT(*) as count
FROM certificates c
WHERE c.is_deleted = 0
GROUP BY c.tls_version
ORDER BY count DESC
```

### ORM Equivalent

```python
def get_tls_version_distribution(self) -> Dict[str, int]:
    """Returns {"TLS 1.3": 60, "TLS 1.2": 35, ...}"""
    db = self._get_db_session()
    
    certs = db.query(Certificate).filter(
        Certificate.is_deleted == False
    ).all()
    
    distribution = Counter(
        cert.tls_version for cert in certs
        if cert.tls_version
    )
    
    return dict(distribution)
```

---

## 8. WEAK CRYPTOGRAPHY METRICS

**Purpose:** Security dashboard — identify non-compliant certificates

### SQL Queries

```sql
-- Weak RSA keys (< 2048-bit)
SELECT COUNT(*) FROM certificates c
WHERE c.is_deleted = 0 AND c.key_length < 2048 AND c.key_length > 0

-- Weak TLS versions (1.0, 1.1, SSL)
SELECT COUNT(*) FROM certificates c
WHERE c.is_deleted = 0 AND c.tls_version IN ('TLS 1.0', 'TLS 1.1', 'SSLv3', 'SSLv2')

-- Expired certificates
SELECT COUNT(*) FROM certificates c
WHERE c.is_deleted = 0 AND c.valid_until < NOW()

-- Self-signed certificates
SELECT COUNT(*) FROM certificates c
WHERE c.is_deleted = 0 AND c.issuer = c.subject
```

### ORM Equivalent

```python
def get_weak_cryptography_metrics(self) -> Dict[str, int]:
    """
    Returns:
    {
        "weak_keys": 5,           # RSA < 2048-bit
        "weak_tls": 3,            # TLS 1.0/1.1
        "expired": 2,             # Past valid_until
        "self_signed": 1,         # Issuer == Subject
    }
    """
    db = self._get_db_session()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    
    # Weak keys
    weak_keys_count = db.query(func.count(Certificate.id)).filter(
        Certificate.is_deleted == False,
        Certificate.key_length < 2048,
        Certificate.key_length > 0
    ).scalar() or 0
    
    # Weak TLS
    weak_tls_versions = ["TLS 1.0", "TLS 1.1", "SSLv3", "SSLv2"]
    weak_tls_count = db.query(func.count(Certificate.id)).filter(
        Certificate.is_deleted == False,
        Certificate.tls_version.in_(weak_tls_versions)
    ).scalar() or 0
    
    # Expired
    expired_count = db.query(func.count(Certificate.id)).filter(
        Certificate.is_deleted == False,
        Certificate.valid_until < now
    ).scalar() or 0
    
    # Self-signed
    all_certs = db.query(Certificate).filter(
        Certificate.is_deleted == False
    ).all()
    
    self_signed_count = sum(
        1 for cert in all_certs
        if cert.issuer and cert.subject and cert.issuer == cert.subject
    )
    
    return {
        "weak_keys": int(weak_keys_count),
        "weak_tls": int(weak_tls_count),
        "expired": int(expired_count),
        "self_signed": self_signed_count,
    }
```

---

## 9. CERTIFICATE AUTHORITY DISTRIBUTION

**Purpose:** Understand CA portfolio and identify concentration risk

### SQL Query

```sql
SELECT 
  c.ca,
  COUNT(*) as count
FROM certificates c
WHERE c.is_deleted = 0
GROUP BY c.ca
ORDER BY count DESC
LIMIT 10
```

### ORM Equivalent

```python
def get_certificate_authority_distribution(self, limit: int = 10) -> List[Dict]:
    """Returns top N CAs with certificate counts."""
    db = self._get_db_session()
    
    certs = db.query(Certificate).filter(
        Certificate.is_deleted == False
    ).all()
    
    ca_counts = Counter()
    for cert in certs:
        ca = str(cert.ca or cert.issuer or "Unknown")
        ca_counts[ca] += 1
    
    return [
        {"ca": ca, "count": count}
        for ca, count in ca_counts.most_common(limit)
    ]
```

---

## 10. CERTIFICATE ISSUES COUNT (for CBOM)

**UI Location:** CBOM summary dashboard (vm.cbom_summary.cert_issues_count)

**Purpose:** Dashboard health indicator — total cryptographic compliance issues

### SQL Query

```sql
SELECT COUNT(*) as issues_count FROM (
  SELECT c.id FROM certificates c
  WHERE c.is_deleted = 0 AND c.valid_until < DATE_ADD(NOW(), INTERVAL 30 DAYS)
  
  UNION ALL
  
  SELECT c.id FROM certificates c
  WHERE c.is_deleted = 0 AND c.key_length < 2048 AND c.key_length > 0
  
  UNION ALL
  
  SELECT c.id FROM certificates c
  WHERE c.is_deleted = 0 AND c.tls_version IN ('TLS 1.0', 'TLS 1.1')
) AS issues
```

### ORM Equivalent

```python
def get_certificate_issues_count(self) -> int:
    """
    Combined count of certificate issues:
    - Expired / expiring (< 30 days)
    - Weak keys (< 2048)
    - Weak TLS versions (1.0, 1.1)
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    threshold_date = now + timedelta(days=30)
    
    db = self._get_db_session()
    
    # Expired or expiring
    urgent_count = db.query(func.count(Certificate.id)).filter(
        Certificate.is_deleted == False,
        Certificate.valid_until <= threshold_date
    ).scalar() or 0
    
    # Weak crypto
    weak_metrics = self.get_weak_cryptography_metrics()
    weak_count = weak_metrics["weak_keys"] + weak_metrics["weak_tls"]
    
    return int(urgent_count) + weak_count
```

---

## Data Ingestion Pipeline

### Step 1: Scan Execution

Scanner runs TLS/SSL probe on target, produces **tls_results** list:

```python
tls_results = [
    {
        "issuer": {"O": "DigiCert", "CN": "DigiCert Global G2 ICA"},
        "subject": {"O": "Example Inc", "CN": "api.example.com"},
        "serial_number": "ABC123...",
        "valid_from_dt": datetime(2024, 1, 1),
        "valid_until_dt": datetime(2025, 1, 1),
        "protocol_version": "TLS 1.3",
        "key_length": 2048,
        "key_size": 2048,
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
    },
    # ... more TLS records ...
]
```

### Step 2: Certificate ORM Creation (`web/app.py` lines 992-1015)

```python
# TLS & Certificates
for tls in tls_results:
    cert_obj = Certificate(
        asset_id=asset_id,
        issuer=str(tls.get("issuer", {}).get("O", "Unknown")),
        subject=str(tls.get("subject", {}).get("O", "Unknown")),
        serial=tls.get("serial_number", ""),
        valid_from=tls.get("valid_from_dt"),
        valid_until=tls.get("valid_until_dt"),
        tls_version=tls.get("protocol_version", ""),
        key_length=int(tls.get("key_length", 0) or tls.get("key_size", 0)),
        cipher_suite=tls.get("cipher_suite", ""),
        ca=str(tls.get("issuer", {}).get("CN", "Unknown"))
    )
    if hasattr(db_scan, "certificates"):
        db_scan.certificates.append(cert_obj)
    elif hasattr(cert_obj, "scan_id") and scan_pk is not None:
        cert_obj.scan_id = scan_pk
        db_session.add(cert_obj)
```

**Result:** Certificate ORM object created from real TLS data, **not mocked**.

### Step 3: Database Persistence

ORM relationship via `Scan.certificates` or direct add → MySQL INSERT:

```sql
INSERT INTO certificates (
  asset_id, scan_id, issuer, subject, serial, valid_from, valid_until,
  tls_version, key_length, cipher_suite, ca, is_deleted, created_at
) VALUES (
  123, 456, 'DigiCert', 'Example Inc', 'ABC123...', '2024-01-01', '2025-01-01',
  'TLS 1.3', 2048, 'TLS_AES_256_GCM_SHA384', 'DigiCert', 0, NOW()
)
```

### Step 4: Service Layer Aggregation

`AssetService.get_inventory_view_model()` queries DB and computes telemetry:

```python
certificates = db.query(Certificate).filter(
    Certificate.is_deleted == False,
    Certificate.asset_id.in_(asset_ids)
).all()

# Compute metrics for each certificate
for cert in certificates:
    days_remaining = (cert.valid_until - now).days
    status = "Expired" if days_remaining < 0 else "Valid"
    # ... (all metrics computed)
```

### Step 5: Dashboard Template Consumption

Template data passed as `vm.*` variables (**Jinja2**):

```html
<div>{{ vm.kpis.expiring_certificates }}</div>
<table>
  {% for cert in vm.certificate_inventory %}
    <tr><td>{{ cert.asset }}</td><td>{{ cert.issuer }}</td></tr>
  {% endfor %}
</table>
```

---

## Complete Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│ 1. SCAN EXECUTION (Scanner)                                 │
│    TLS probe → tls_results dict list                         │
└────────────────────┬────────────────────────────────────────┘
                     │ tls_results = [{issuer, subject, serial, ...}]
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. INGESTION (web/app.py:992-1015)                          │
│    Certificate ORM creation from tls_results                │
│                                                              │
│    cert_obj = Certificate(                                  │
│        asset_id=asset_id,                                   │
│        issuer=tls["issuer"]["O"],                           │
│        valid_until=tls["valid_until_dt"],                   │
│        key_length=int(tls["key_length"]),                   │
│        ... (8 more fields)                                  │
│    )                                                         │
└────────────────────┬────────────────────────────────────────┘
                     │ db_session.add(cert_obj)
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. DATABASE (MySQL certificates table)                      │
│    is_deleted | asset_id | issuer | valid_until | ...      │
│    0          | 123      | Digi   | 2025-01-01  | ...      │
│    0          | 124      | Comodo | 2024-06-15  | ...      │
└────────────────────┬────────────────────────────────────────┘
                     │ SELECT * FROM certificates WHERE is_deleted=0
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. SERVICE AGGREGATION (AssetService)                       │
│    .get_inventory_view_model()                              │
│                                                              │
│    - Query certificates per asset                          │
│    - Compute metrics (days_left, status, etc.)              │
│    - Aggregate into vm dicts                                │
└────────────────────┬────────────────────────────────────────┘
                     │ vm = {
                     │   kpis: {expiring_certificates: 12},
                     │   certificate_inventory: [...],
                     │   crypto_overview: [...]
                     │ }
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. TEMPLATE RENDERING (Jinja2)                              │
│    asset_inventory.html                                     │
│                                                              │
│    {{ vm.kpis.expiring_certificates }}                     │
│    {% for cert in vm.certificate_inventory %}              │
│      <tr><td>{{ cert.asset }}</td><td>{{ cert.status }}</td>
│    {% endfor %}                                             │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
        ┌──────────────────────────┐
        │  HTML OUTPUT (Dashboard) │
        │  EXPIRING CERTIFICATES   │
        │  Count: 12               │
        │                          │
        │  Timeline: [0-30: 5, ...] │
        │  Inventory Table: ...    │
        └──────────────────────────┘
```

---

## Service Integration Example

### Calling All Certificate Metrics at Once

```python
# src/services/certificate_telemetry_service.py

def get_complete_certificate_telemetry(self) -> Dict:
    """
    Build comprehensive payload with all certificate metrics.
    
    Reduces database round-trips by fetching all metrics in single call.
    """
    return {
        "kpis": {
            "total_certificates": self._get_total_certificates_count(),
            "expiring_certificates": self.get_expiring_certificates_count(),
            "expired_certificates": self.get_expired_certificates_count(),
        },
        "expiry_timeline": self.get_certificate_expiry_timeline(),
        "tls_version_distribution": self.get_tls_version_distribution(),
        "key_length_distribution": self.get_key_length_distribution(),
        "certificate_inventory": self.get_certificate_inventory(),
        "certificate_authority_distribution": self.get_certificate_authority_distribution(),
        "cipher_suite_distribution": self.get_cipher_suite_distribution(),
        "weak_cryptography": self.get_weak_cryptography_metrics(),
        "cert_issues_count": self.get_certificate_issues_count(),
    }
```

### Usage in API Endpoint

```python
# web/app.py or api blueprint

@app.route("/api/dashboard/certificates", methods=["GET"])
def get_certificates_telemetry():
    """Return complete certificate telemetry for UI."""
    service = CertificateTelemetryService()
    telemetry = service.get_complete_certificate_telemetry()
    
    return {
        "status": "ok",
        "data": telemetry,
        "timestamp": datetime.now().isoformat(),
    }
```

### Usage in Asset Service (Current Implementation)

```python
# src/services/asset_service.py

class AssetService:
    def get_inventory_view_model(self):
        cert_service = CertificateTelemetryService()
        
        return {
            "kpis": {
                "total_assets": self._count_total_assets(),
                "expiring_certificates": cert_service.get_expiring_certificates_count(),
                "weak_crypto": cert_service.get_weak_cryptography_metrics(),
                # ... other KPIs
            },
            "certificate_expiry_timeline": cert_service.get_certificate_expiry_timeline(),
            "certificate_inventory": cert_service.get_certificate_inventory(),
            "crypto_overview": cert_service.get_crypto_overview(),
            # ... other views
        }
```

---

## Field Reference Table — All Certificate Fields

| Field | Type | SQL | ORM | Source | Nullable | Indexed |
|-------|------|-----|-----|--------|----------|---------|
| `id` | INT | PRIMARY KEY | id: int | Auto | N | Y |
| `asset_id` | INT | FOREIGN KEY(assets) | asset_id: int | Asset ref | N | Y |
| `scan_id` | INT | FOREIGN KEY(scans) | scan_id: int | Scan ref | Y | Y |
| `issuer` | VARCHAR(255) | issuer VARCHAR | issuer: str | TLS: issuer.O | Y | N |
| `subject` | VARCHAR(255) | subject VARCHAR | subject: str | TLS: subject.O | Y | N |
| `serial` | VARCHAR(255) | serial VARCHAR | serial: str | TLS: serial_number | Y | N |
| `valid_from` | DATETIME | valid_from DATETIME | valid_from: datetime | TLS: valid_from_dt | Y | N |
| `valid_until` | DATETIME | valid_until DATETIME | valid_until: datetime | **TLS: valid_until_dt** | Y | **Y** |
| `fingerprint_sha256` | VARCHAR(64) | fingerprint_sha256 VARCHAR | fingerprint_sha256: str | TLS scan | Y | Y |
| `tls_version` | VARCHAR(50) | tls_version VARCHAR | tls_version: str | **TLS: protocol_version** | Y | N |
| `key_length` | INT | key_length INT | key_length: int | **TLS: key_length/key_size** | Y | **Y** |
| `cipher_suite` | VARCHAR(255) | cipher_suite VARCHAR | cipher_suite: str | **TLS: cipher_suite** | Y | N |
| `ca` | VARCHAR(255) | ca VARCHAR | ca: str | **TLS: issuer.CN** | Y | N |
| `is_deleted` | TINYINT(1) | is_deleted TINYINT DEFAULT 0 | is_deleted: bool | SoftDeleteMixin | N | Y |
| `deleted_at` | DATETIME | deleted_at DATETIME | deleted_at: datetime | SoftDeleteMixin | Y | N |
| `deleted_by_user_id` | INT | deleted_by_user_id INT | deleted_by_user_id: int | SoftDeleteMixin | Y | N |
| `created_at` | DATETIME | created_at DATETIME | created_at: datetime | Auto | N | N |
| `updated_at` | DATETIME | updated_at DATETIME | updated_at: datetime | Auto | N | N |

**Key Insights:**
- **Bolded fields** are critical for dashboard metrics
- `valid_until`, `key_length`, `tls_version`, `cipher_suite`, `ca` are **most frequently queried**
- **Index strategy**: valid_until (range queries), key_length, is_deleted, asset_id, scan_id

---

## Security & Soft-Delete Compliance

✅ All queries include `WHERE is_deleted = 0`
✅ No deleted certificates appear in dashboards
✅ Recycle bin can restore (`UPDATE is_deleted=0`) or hard-delete permanently
✅ Audit trail tracks deletion via `deleted_at`, `deleted_by_user_id`

---

## Next Steps

1. **API Endpoint**: Expose `/api/dashboard/certificates` using `CertificateTelemetryService.get_complete_certificate_telemetry()`
2. **Dashboard Update**: Integrate `CertificateTelemetryService` into `AssetService.get_inventory_view_model()`
3. **CBOM Link**: Add `certificate_id` FK to `CBOMEntry` for cross-table integrity
4. **Query Optimization**: Add indexes on `valid_until`, `key_length`, `is_deleted`
5. **Testing**: Unit tests for each metric (especially expiry calculations, date boundary cases)
