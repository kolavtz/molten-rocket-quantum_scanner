# AssetService Integration Guide for CertificateTelemetryService

**Document Date**: 2026-03-21  
**Purpose**: Complete analysis of AssetService structure and CertificateTelemetryService integration points

---

## Table of Contents

1. [AssetService Architecture](#assetservice-architecture)
2. [Data Flow Overview](#data-flow-overview)
3. [The get_inventory_view_model() Method](#the-get_inventory_view_model-method)
4. [Current KPI Structure](#current-kpi-structure)
5. [Existing Certificate-Related Code](#existing-certificate-related-code)
6. [CertificateTelemetryService Overview](#certificatetelemetryservice-overview)
7. [Integration Points & Strategy](#integration-points--strategy)
8. [Code Examples](#code-examples)

---

## AssetService Architecture

### Class Structure

```
AssetService
├── __init__()                        # Empty initializer
├── load_combined_assets()            # Core data loader (lines 18-156)
├── get_inventory_view_model()        # Main view builder (lines 158-328)
├── get_dashboard_summary()           # Dashboard KPI builder (lines 330-381)
├── _score_to_risk()                  # Risk calculation helper (lines 383-387)
└── _as_list()                        # Utility for list conversion (lines 20-26)
```

### Key Characteristics

- **No dependency injection**: Services instantiate in methods, uses `from src.db import db_session`
- **MySQL-only data**: All data sourced from relational tables (assets, scans, certificates, dns_records)
- **Stateless design**: Methods are largely stateless with minimal class state
- **Direct SQL access**: Uses SQLAlchemy ORM + raw SQL (`text()`) for complex queries
- **Certificate-aware**: Already loads and processes certificate telemetry directly

---

## Data Flow Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│  Database Tables: assets, scans, certificates, asset_dns_records   │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
                   ┌───────────────┴────────────────┐
                   ▼                                ▼
        ┌──────────────────────┐      ┌─────────────────────────┐
        │ AssetService         │      │ CertificateTelemetry    │
        │ .load_combined_      │      │ Service                 │
        │  assets()            │      │ (separate service)      │
        │                      │      │                         │
        │ Returns:             │      │ Returns:                │
        │ - Asset basic info   │      │ - Expiring count        │
        │ - Latest cert per    │      │ - Expiry timeline       │
        │   asset             │      │ - Full inventory        │
        │ - Latest scan per    │      │ - Key length dist.      │
        │   asset             │      │ - Cipher suite dist.    │
        │ - Risk score        │      │ - TLS version dist.     │
        │ - Cert status       │      │ - CA distribution       │
        └──────────┬───────────┘      │ - Weak crypto metrics   │
                   │                  │ - Issues count          │
                   │                  └───────────┬─────────────┘
                   │                              │
                   └──────────────┬───────────────┘
                                  │
                                  ▼
                   ┌──────────────────────────────┐
                   │ get_inventory_view_model()   │
                   │                              │
                   │ Returns complete dict with:  │
                   │ - kpis{}                     │
                   │ - asset_type_distribution    │
                   │ - asset_risk_distribution    │
                   │ - risk_heatmap               │
                   │ - certificate_expiry_       │
                   │   timeline                   │
                   │ - ip_version_breakdown       │
                   │ - assets[]                   │
                   │ - nameserver_records[]       │
                   │ - crypto_overview[]          │
                   │ - asset_locations[]          │
                   │ - certificate_inventory[]    │
                   └──────────────┬───────────────┘
                                  │
                                  ▼
                   ┌──────────────────────────────┐
                   │ web/templates/               │
                   │ asset_inventory.html         │
                   │                              │
                   │ Jinja2 template loops over   │
                   │ vm variables to render UI    │
                   └──────────────────────────────┘
```

---

## The get_inventory_view_model() Method

### Method Signature

```python
def get_inventory_view_model(self, testing_mode: bool = False) -> dict:
    """Build full asset inventory page view-model from MySQL tables only."""
```

### Processing Pipeline

**Phase 1: Data Loading (lines 169-175)**
```python
if testing_mode:
    return {...}  # Return mock structure for testing
    
assets = self.load_combined_assets()  # Load all assets with related data
```

**Phase 2: Asset List Aggregation (lines 176-181)**
- Calls `load_combined_assets()` to fetch assets with certificates/scans
- Creates Counter objects for type, risk, and certificate expiry distributions
- Returns list of dicts: `[{"id": 1, "asset_name": "...", "risk": "Medium", "cert_status": "Valid", ...}, ...]`

**Phase 3: Certificate Timeline Bucketing (lines 183-192)**
```python
cert_bucket = Counter({"0-30": 0, "30-60": 0, "60-90": 0, ">90": 0})
for row in assets:
    days = row.get("cert_days")  # From load_combined_assets()
    if not isinstance(days, (int, float)): continue
    if days <= 30: cert_bucket["0-30"] += 1
    ...
```

**Phase 4: IP Version Breakdown (lines 194-199)**
```python
ipv4_count = sum(1 for a in assets if str(a.get("ipv4") or "").strip())
ipv6_count = sum(1 for a in assets if str(a.get("ipv6") or "").strip())
total_ip_assets = max(1, ipv4_count + ipv6_count)
```

**Phase 5: Risk Heatmap by Owner (lines 201-210)**
```python
owners = sorted({str(a.get("owner") or "Unassigned") for a in assets})
heatmap = []
for owner in owners:
    owner_rows = [a for a in assets if str(a.get("owner") or "Unassigned") == owner]
    for band in ("Critical", "High", "Medium", "Low"):
        value = sum(1 for a in owner_rows if str(a.get("risk") or "") == band)
        heatmap.append({"x": owner, "y": band, "value": value})
```

**Phase 6: Certificate Inventory Building (lines 212-234)**
```python
certificate_inventory = []
for a in assets:
    cert_status = str(a.get("cert_status") or "")
    if cert_status and cert_status != "Not Scanned":
        certificate_inventory.append({
            "asset": a.get("asset_name"),
            "issuer": a.get("ca") or "Unknown",
            "key_length": int(a.get("key_length") or 0),
            "tls_version": a.get("tls_version") or "Unknown",
            "days_remaining": a.get("cert_days"),
            "status": cert_status,
        })
```

**Phase 7: Crypto Overview Building (lines 236-245)**
```python
crypto_overview = []
for a in assets:
    if int(a.get("key_length") or 0) > 0:
        crypto_overview.append({
            "asset": a.get("asset_name"),
            "key_length": int(a.get("key_length") or 0),
            "cipher_suite": a.get("cipher_suite") or "Unknown",
            "tls_version": a.get("tls_version") or "Unknown",
            "ca": a.get("ca") or "Unknown",
            "last_scan": str(a.get("last_scan") or "")[:10],
        })
```

**Phase 8: DNS Records Query (lines 247-281)**
- Raw SQL join: `asset_dns_records → scans → assets`
- Soft-delete aware filtering
- Type classification (A, AAAA, MX, NS, PTR, CNAME, TXT)

**Phase 9: Return Complete View Model (lines 283-311)**
```python
return {
    "empty": len(assets) == 0,
    "kpis": {...},
    "asset_type_distribution": {...},
    "asset_risk_distribution": {...},
    "risk_heatmap": [...],
    "certificate_expiry_timeline": {...},
    "ip_version_breakdown": {...},
    "assets": [...],
    "nameserver_records": [...],
    "crypto_overview": [...],
    "asset_locations": [],
    "certificate_inventory": [...],
}
```

---

## Current KPI Structure

### KPI Dictionary (lines 285-292)

```python
"kpis": {
    "total_assets": len(assets),
    "public_web_apps": sum(1 for a in assets if a.get("type") == "Web App"),
    "apis": sum(1 for a in assets if a.get("type") == "API"),
    "servers": sum(1 for a in assets if a.get("type") == "Server"),
    "expiring_certificates": sum(1 for a in assets if a.get("cert_status") == "Expiring"),
    "high_risk_assets": sum(1 for a in assets if a.get("risk") in {"Critical", "High"}),
}
```

### Current KPI Sources

| KPI | Source | Calculation |
|-----|--------|-------------|
| `total_assets` | len(assets) | Count of non-deleted assets |
| `public_web_apps` | asset loop | Counts where type == "Web App" |
| `apis` | asset loop | Counts where type == "API" |
| `servers` | asset loop | Counts where type == "Server" |
| `expiring_certificates` | asset loop | Counts where cert_status == "Expiring" |
| `high_risk_assets` | asset loop | Counts where risk in {Critical, High} |

### Missing KPIs (Opportunity)

These KPIs are NOT currently in the dictionary but are available in CertificateTelemetryService:

- ❌ `expired_certificates_count` — Available via `get_expired_certificates_count()`
- ❌ `weak_cryptography_count` — Available via `get_weak_cryptography_metrics()`
- ❌ `total_certificates` — Available via `_get_total_certificates_count()`
- ❌ `certificate_issues_count` — Available via `get_certificate_issues_count()`

---

## Existing Certificate-Related Code

### In load_combined_assets() (lines 74-98)

**Certificate Lookup**
```python
# Get latest cert per asset (by valid_until date)
latest_cert_by_asset: Dict[int, Certificate] = {}
certs = []
if asset_ids:
    cert_query = _db_session.query(Certificate)
    if hasattr(cert_query, "filter"):
        cert_query = cert_query.filter(
            Certificate.is_deleted == False,
            Certificate.asset_id.in_(asset_ids)
        )
        certs = self._as_list(cert_query.all()) if hasattr(cert_query, "all") else []

for cert in certs:
    asset_id = int(getattr(cert, "asset_id", 0) or 0)
    if asset_id <= 0:
        continue
    prev = latest_cert_by_asset.get(asset_id)
    if prev is None:
        latest_cert_by_asset[asset_id] = cert
        continue
    prev_ts = getattr(prev, "valid_until", None) or datetime.min
    cur_ts = getattr(cert, "valid_until", None) or datetime.min
    if cur_ts >= prev_ts:
        latest_cert_by_asset[asset_id] = cert  # Keep most recent
```

**Certificate Field Extraction (lines 128-147)**
```python
if latest_cert:
    key_length = int(getattr(latest_cert, "key_length", 0) or 0)
    tls_version = str(getattr(latest_cert, "tls_version", "") or "Unknown")
    cipher_suite = str(getattr(latest_cert, "cipher_suite", "") or "Unknown")
    ca_name = str(getattr(latest_cert, "ca", "") or getattr(latest_cert, "issuer", "") or "Unknown")
    
    valid_until = getattr(latest_cert, "valid_until", None)
    if valid_until:
        cert_days = int((valid_until - now_naive_utc).days)
        if cert_days < 0:
            cert_status = "Expired"
        elif cert_days <= 30:
            cert_status = "Expiring"
        else:
            cert_status = "Valid"
    else:
        cert_status = "Unknown"
```

**Per-Asset Output Structure (lines 149-169)**
```python
assets_out.append({
    "id": meta.id,
    "asset_name": str(meta.name or ""),
    "url": meta.url or (...),
    "ipv4": str(getattr(meta, "ipv4", "") or ""),
    "ipv6": str(getattr(meta, "ipv6", "") or ""),
    "type": str(meta.asset_type or "Web App"),
    "asset_class": str(getattr(latest_scan, "asset_class", "") or "Inventory"),
    "risk": risk_level or "Medium",
    "risk_score": risk_score,
    "cert_status": cert_status,              # ← Certificate field
    "cert_days": cert_days,                  # ← Certificate field
    "key_length": key_length,                # ← Certificate field
    "tls_version": tls_version,              # ← Certificate field
    "cipher_suite": cipher_suite,            # ← Certificate field
    "ca": ca_name,                           # ← Certificate field
    "last_scan": last_scan_ts.strftime(...) if last_scan_ts else "Pending",
    "owner": str(meta.owner or "Unassigned"),
    "notes": str(getattr(meta, "notes", "") or ""),
    "overview": {},
})
```

### In get_inventory_view_model() (lines 212-234)

**Certificate Inventory Table**
```python
certificate_inventory = []
crypto_overview = []
for a in assets:
    cert_status = str(a.get("cert_status") or "")
    if cert_status and cert_status != "Not Scanned":
        certificate_inventory.append({
            "asset": a.get("asset_name"),
            "issuer": a.get("ca") or "Unknown",
            "key_length": int(a.get("key_length") or 0),
            "tls_version": a.get("tls_version") or "Unknown",
            "days_remaining": a.get("cert_days"),
            "status": cert_status,
        })
```

**Crypto Overview Table**
```python
    if int(a.get("key_length") or 0) > 0:
        crypto_overview.append({
            "asset": a.get("asset_name"),
            "key_length": int(a.get("key_length") or 0),
            "cipher_suite": a.get("cipher_suite") or "Unknown",
            "tls_version": a.get("tls_version") or "Unknown",
            "ca": a.get("ca") or "Unknown",
            "last_scan": str(a.get("last_scan") or "")[:10],
        })
```

---

## CertificateTelemetryService Overview

### Complete Method Inventory

| Method | Purpose | Return Type | Used By |
|--------|---------|-------------|---------|
| `get_expiring_certificates_count(days_threshold=30)` | KPI card | `int` | Dashboard widget |
| `get_expired_certificates_count()` | Health metric | `int` | Status indicator |
| `get_certificate_expiry_timeline()` | 4-bucket distribution | `Dict[str, int]` | Timeline chart |
| `get_certificate_inventory(limit=100)` | Full cert list | `List[Dict]` | Cert inventory table |
| `get_key_length_distribution()` | Key size breakdown | `Dict[str, int]` | Crypto metrics |
| `get_cipher_suite_distribution(limit=10)` | Cipher ranking | `List[Dict]` | Security analysis |
| `get_tls_version_distribution()` | Protocol version counts | `Dict[str, int]` | Compliance check |
| `get_certificate_authority_distribution(limit=10)` | CA portfolio | `List[Dict]` | CA analysis |
| `get_weak_cryptography_metrics()` | Weak crypto detection | `Dict[str, int]` | CBOM health |
| `get_certificate_issues_count()` | Combined issues | `int` | CBOM dashboard |
| `get_latest_certificate_for_asset(asset_id)` | Per-asset cert | `Optional[Dict]` | Asset detail view |
| `get_complete_certificate_telemetry()` | All metrics | `Dict` | API endpoint |

### Key Metrics (get_weak_cryptography_metrics)

```python
{
    "weak_keys": int,           # Count of key_length < 2048
    "weak_tls": int,            # Count of TLS 1.0, 1.1, SSLv3, SSLv2
    "expired": int,             # Count of valid_until < NOW()
    "self_signed": int,         # Count where issuer == subject
}
```

### Sample Return Value: get_certificate_expiry_timeline()

```python
{
    "0-30": 5,      # 5 certs expiring in 0–30 days
    "30-60": 3,     # 3 certs expiring in 30–60 days
    "60-90": 2,     # 2 certs expiring in 60–90 days
    ">90": 15,      # 15 certs valid >90 days
}
```

### Sample Return Value: get_certificate_inventory(limit=5)

```python
[
    {
        "certificate_id": 42,
        "asset": "api.example.com",
        "issuer": "Let's Encrypt Authority X3",
        "subject": "CN=api.example.com",
        "key_length": 2048,
        "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "tls_version": "TLS 1.3",
        "ca": "Let's Encrypt",
        "valid_from": "2024-01-15T00:00:00",
        "valid_until": "2025-04-15T00:00:00",
        "days_remaining": 25,
        "status": "Expiring",
        "fingerprint": "A1B2C3D4E5F6...",
    },
    ...
]
```

---

## Integration Points & Strategy

### ✅ **Integration Point 1: KPI Enrichment**

**Current State**: 6 KPIs in get_inventory_view_model().kpis

**New Opportunity**: Add 4 more KPIs using CertificateTelemetryService

```python
# In get_inventory_view_model() around line 285-292
cert_service = CertificateTelemetryService()

"kpis": {
    # Existing
    "total_assets": len(assets),
    "public_web_apps": ...,
    "apis": ...,
    "servers": ...,
    "expiring_certificates": ...,  # Can stay or be replaced
    "high_risk_assets": ...,
    
    # NEW: Add these
    "expired_certificates": cert_service.get_expired_certificates_count(),
    "weak_cryptography": cert_service.get_weak_cryptography_metrics(),
    "total_certificates": cert_service._get_total_certificates_count(),
    "cert_issues_count": cert_service.get_certificate_issues_count(),
}
```

**Why**: Centralizes certificate calculations, reduces code duplication, ensures consistency.

---

### ✅ **Integration Point 2: Dashboard Summary Enhancement**

**Current State**: get_dashboard_summary() uses asset loop for KPIs

**Location**: `src/services/asset_service.py:330-381`

**Current Metrics**:
```python
{
    "total_assets": total,
    "api_count": api_count,
    "vpn_count": vpn_count,
    "server_count": server_count,
    "expiring_certs": expiring,
    "overall_risk_score": risk_percent,
    "risk_distribution": dict(dist),
    "type_distribution": type_array,
    "ssl_expiry": [bucket values],
    "ip_breakdown": [ipv4_cnt, ipv6_cnt],
}
```

**Add Certificate Metrics**:
```python
def get_dashboard_summary(self, assets: list) -> dict:
    """Compute top-level statistics dynamically."""
    # ... existing code ...
    
    cert_service = CertificateTelemetryService()
    weak_metrics = cert_service.get_weak_cryptography_metrics()
    
    return {
        # ... existing ...
        "certificate_summary": {
            "total": cert_service._get_total_certificates_count(),
            "expiring": cert_service.get_expiring_certificates_count(),
            "expired": cert_service.get_expired_certificates_count(),
            "weak_crypto": weak_metrics,
        }
    }
```

---

### ✅ **Integration Point 3: Crypto Overview Replacement**

**Current**: Lines 236-245 build crypto_overview by looping assets

**Replacement**:
```python
# Instead of looping assets and extracting cert fields:
cert_service = CertificateTelemetryService()

# New structure
crypto_overview = cert_service.get_certificate_inventory()

# OR build custom structure with TLS version distribution
crypto_overview = {
    "inventory": cert_service.get_certificate_inventory(limit=20),
    "tls_distribution": cert_service.get_tls_version_distribution(),
    "key_distribution": cert_service.get_key_length_distribution(),
    "cipher_distribution": cert_service.get_cipher_suite_distribution(),
}
```

**Why**: Moves certificate expertise into the dedicated service, reduces AssetService complexity.

---

### ✅ **Integration Point 4: Certificate Inventory View**

**Current**: Lines 212-234 build certificate_inventory manually

**Replacement**:
```python
cert_service = CertificateTelemetryService()
certificate_inventory = cert_service.get_certificate_inventory(limit=500)
```

**Result**: Simpler, more maintainable, consistent with CertificateTelemetryService logic.

---

### ✅ **Integration Point 5: Weak Cryptography Dashboard Widget**

**Current**: No weak cryptography indicator in KPIs or view model

**New**:
```python
cert_service = CertificateTelemetryService()
weak_metrics = cert_service.get_weak_cryptography_metrics()

# In view model, add:
"weak_cryptography_metrics": {
    "weak_keys": weak_metrics["weak_keys"],
    "weak_tls": weak_metrics["weak_tls"],
    "expired": weak_metrics["expired"],
    "self_signed": weak_metrics["self_signed"],
    "total_issues": sum(weak_metrics.values()),
}
```

---

### ✅ **Integration Point 6: Per-Asset Certificate Detail**

**Current**: AssetService loads latest cert per asset but doesn't expose it cleanly

**New Method**:
```python
def get_asset_certificate_detail(self, asset_id: int) -> Optional[Dict]:
    """Get detailed certificate info for single asset."""
    cert_service = CertificateTelemetryService()
    return cert_service.get_latest_certificate_for_asset(asset_id)
```

**Use Case**: Asset detail page shows full certificate chain/validity info.

---

## Code Examples

### Example 1: Minimal Integration (KPI Only)

**File**: `src/services/asset_service.py`  
**Location**: Around line 285 in get_inventory_view_model()

```python
def get_inventory_view_model(self, testing_mode: bool = False) -> dict:
    """Build full asset inventory page view-model from MySQL tables only."""
    from src.db import db_session as _db_session
    from src.services.certificate_telemetry_service import CertificateTelemetryService

    if testing_mode:
        return {...}  # existing mock structure

    assets = self.load_combined_assets()
    
    # ... existing aggregation code ...
    
    # Instantiate cert service (MINIMAL CHANGE)
    cert_service = CertificateTelemetryService()
    
    # Build KPIs with new cert metrics
    return {
        "empty": len(assets) == 0,
        "kpis": {
            "total_assets": len(assets),
            "public_web_apps": sum(1 for a in assets if a.get("type") == "Web App"),
            "apis": sum(1 for a in assets if a.get("type") == "API"),
            "servers": sum(1 for a in assets if a.get("type") == "Server"),
            "expiring_certificates": cert_service.get_expiring_certificates_count(),
            "expired_certificates": cert_service.get_expired_certificates_count(),
            "high_risk_assets": sum(1 for a in assets if a.get("risk") in {"Critical", "High"}),
            "cert_issues_count": cert_service.get_certificate_issues_count(),
        },
        # ... rest of structure ...
    }
```

---

### Example 2: Full Integration (All Certificate Views)

```python
def get_inventory_view_model(self, testing_mode: bool = False) -> dict:
    """Build full asset inventory page view-model from MySQL tables only."""
    from src.services.certificate_telemetry_service import CertificateTelemetryService
    
    if testing_mode:
        return {...}  # existing mock structure

    assets = self.load_combined_assets()
    
    # ... existing aggregation code for assets, type_dist, risk_dist, etc. ...
    
    # NEW: Instantiate specialized service
    cert_service = CertificateTelemetryService()
    
    # Get all certificate metrics at once (single call)
    cert_telemetry = cert_service.get_complete_certificate_telemetry()
    
    return {
        "empty": len(assets) == 0,
        "kpis": {
            "total_assets": len(assets),
            "public_web_apps": sum(1 for a in assets if a.get("type") == "Web App"),
            "apis": sum(1 for a in assets if a.get("type") == "API"),
            "servers": sum(1 for a in assets if a.get("type") == "Server"),
            # Replace manual cert counting with service call
            "expiring_certificates": cert_telemetry["kpis"]["expiring_certificates"],
            "expired_certificates": cert_telemetry["kpis"]["expired_certificates"],
            "total_certificates": cert_telemetry["kpis"]["total_certificates"],
            "high_risk_assets": sum(1 for a in assets if a.get("risk") in {"Critical", "High"}),
        },
        "asset_type_distribution": dict(type_dist),
        "asset_risk_distribution": dict(risk_dist),
        "risk_heatmap": heatmap,
        
        # REPLACE: Use cert service directly
        "certificate_expiry_timeline": cert_telemetry["expiry_timeline"],
        
        "ip_version_breakdown": {
            "IPv4": round((ipv4_count * 100) / total_ip_assets),
            "IPv6": round((ipv6_count * 100) / total_ip_assets),
        },
        
        "assets": assets,
        "nameserver_records": nameserver_records,
        
        # REPLACE: Use cert service directly
        "crypto_overview": {
            "inventory": cert_telemetry["certificate_inventory"][:20],
            "tls_distribution": cert_telemetry["tls_version_distribution"],
            "key_distribution": cert_telemetry["key_length_distribution"],
        },
        
        "asset_locations": [],
        
        # REPLACE: Use cert service directly
        "certificate_inventory": cert_telemetry["certificate_inventory"],
        
        # NEW: Add weak crypto metrics
        "weak_cryptography": cert_telemetry["weak_cryptography"],
        
        # NEW: Add CA distribution
        "certificate_authority_distribution": cert_telemetry["certificate_authority_distribution"],
    }
```

---

### Example 3: New Helper Method

```python
def get_asset_certificate_detail(self, asset_id: int) -> Optional[Dict]:
    """Get detailed certificate information for a specific asset."""
    cert_service = CertificateTelemetryService()
    return cert_service.get_latest_certificate_for_asset(asset_id)
```

**Use in web/blueprints/dashboard.py**:
```python
@dashboard_bp.route('/asset/<int:asset_id>/certificate')
def asset_certificate_detail(asset_id):
    asset_service = AssetService()
    cert_detail = asset_service.get_asset_certificate_detail(asset_id)
    return render_template('asset_certificate_detail.html', certificate=cert_detail)
```

---

## Integration Checklist

### Phase 1: Add KPI Metrics (Minimal)
- [ ] Import CertificateTelemetryService in get_inventory_view_model()
- [ ] Instantiate cert_service
- [ ] Add expired_certificates KPI
- [ ] Add cert_issues_count KPI
- [ ] Test in unit tests

### Phase 2: Replace Certificate Data Building (Medium)
- [ ] Replace manual certificate_inventory loop with cert_service.get_certificate_inventory()
- [ ] Replace manual crypto_overview loop with cert_service methods
- [ ] Update certificate_expiry_timeline to use cert_service
- [ ] Test in unit tests

### Phase 3: Add New Metrics (Enhanced)
- [ ] Add weak_cryptography to view model
- [ ] Add certificate_authority_distribution
- [ ] Add cipher_suite_distribution
- [ ] Update get_dashboard_summary() to use cert service
- [ ] Test in unit tests

### Phase 4: Create New Views (Optional)
- [ ] Create get_asset_certificate_detail() method
- [ ] Create /api/asset/<id>/certificate endpoint
- [ ] Create asset certificate detail template
- [ ] Integrate with asset detail page

---

## Current State Summary

| Aspect | Status | Details |
|--------|--------|---------|
| AssetService exists | ✅ | Complete implementation in `src/services/asset_service.py` |
| CertificateTelemetryService exists | ✅ | Complete implementation in `src/services/certificate_telemetry_service.py` |
| No cross-dependencies | ✅ | Services can be used independently |
| Certificate data in AssetService | ✅ | Loads and partially processes certificates |
| Opportunity for consolidation | ⚠️ | Code duplication between services - consolidation recommended |
| Unit tests for both services | ✅ | Both have comprehensive test suites |
| Integration examples documented | ✅ | This guide + CERTIFICATE_TELEMETRY_MAPPING.md |

---

## Recommended Integration Strategy

**Priority 1 (Week 1)**:
1. Add KPI metrics (Example 1)
2. Run existing unit tests to verify
3. Small PR to main branch

**Priority 2 (Week 2)**:
1. Replace certificate_inventory and crypto_overview (Example 2 parts)
2. Add weak_cryptography metrics
3. Update tests

**Priority 3 (Week 3)**:
1. Create per-asset certificate detail method
2. Implement /api/certificate/issues endpoint
3. Update templates to use new data structures

---

## Files to Modify

```
src/services/asset_service.py
  ├── get_inventory_view_model() — Add cert_service calls
  ├── get_dashboard_summary() — Add weak crypto metrics
  └── [optional] get_asset_certificate_detail() — New method

tests/test_asset_service.py
  ├── Test KPI structure with cert metrics
  ├── Test certificate_inventory via cert_service
  └── Test crypto_overview structure

web/templates/asset_inventory.html
  └── [optional] Update to use new metrics

web/blueprints/dashboard.py
  └── [optional] Add /api/asset/<id>/certificate endpoint
```

---

## Key Takeaways

1. **AssetService is data aggregator**, not certificate expert — should use CertificateTelemetryService for cert logic
2. **CertificateTelemetryService is singleton pattern** — instantiate per method call or cache in blueprint
3. **Current integration points**: KPIs, certificate_inventory, crypto_overview, weak crypto detection
4. **No breaking changes** — Integration is additive; can be done incrementally
5. **Database efficiency**: Use `get_complete_certificate_telemetry()` to reduce round-trips
6. **Soft-delete safe**: Both services filter `WHERE is_deleted=0`

---

**End of Guide**
