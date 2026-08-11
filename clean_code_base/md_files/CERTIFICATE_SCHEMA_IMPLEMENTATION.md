# QuantumShield - Complete Asset → Certificate → PQC Schema Implementation

## Overview

Complete production-ready database schema and application code for managing:
- **Assets** (inventory of targets)
- **Certificates** (TLS certificate details with full metadata)
- **PQC Classification** (post-quantum cryptography analysis)
- **Compliance Scores** (aggregate security ratings)

All with soft-delete support, audit trails, and proper foreign key relationships.

---

## What Was Delivered

### 1. **Enhanced SQLAlchemy Models** (`src/models.py`)

#### Certificate Model
```python
class Certificate(Base, SoftDeleteMixin):
    # Updated columns:
    - subject_cn: Common Name extracted from subject
    - company_name: Organization name for reporting
    - expiry_days: Calculated days remaining (updated on save)
    - key_algorithm: Algorithm type (RSA, ECDSA, etc.)
    - signature_algorithm: Signature method
    - ca_name: Issuer canonical name
    - is_self_signed: Boolean flag
    - is_expired: Boolean flag
    - created_at, updated_at: Timestamps
    
    # Relationships:
    - Asset (many-to-one)
    - Scan (many-to-one)
    - PQCClassification (one-to-many) → Certificates can have multiple PQC classifications
```

#### PQCClassification Model
```python
class PQCClassification(Base, SoftDeleteMixin):
    # Updated columns:
    - algorithm_name: Name of cryptographic algorithm
    - algorithm_type: symmetric/asymmetric/hash
    - quantum_safe_status: safe/unsafe/migration_advised
    - nist_category: NIST quantum resistance category
    - pqc_score: 0-100 score for post-quantum readiness
    - created_at, updated_at: Timestamps
    
    # NEW Relationships:
    - Certificate (many-to-one) → Back-reference to certificate model
    - Asset (many-to-one)
    - Scan (many-to-one)
```

### 2. **Complete MySQL Schema** (`schema-complete.sql`)

Comprehensive CREATE TABLE statements for:

| Table | Purpose | Key Columns |
|-------|---------|-----------|
| `users` | RBAC/Authentication | id, username, role, email, password_hash |
| `scans` | Scan metadata | scan_id, target, status, compliance_score, report_json |
| `assets` | Inventory (soft delete) | id, target (unique), asset_type, owner, risk_level, last_scan_id |
| `certificates` | TLS cert details | asset_id (FK), scan_id (FK), issuer, subject_cn, company_name, valid_until, expiry_days, key_length, tls_version, fingerprint_sha256, is_expired, is_self_signed |
| `pqc_classification` | Quantum-safe analysis | certificate_id (FK), asset_id (FK), algorithm_name, quantum_safe_status, pqc_score, nist_category |
| `compliance_scores` | Security ratings | asset_id (FK), scan_id (FK), type (pqc/tls/overall), score_value, tier |
| `discovery_items` | Discovered assets | scan_id (FK), asset_id (FK), type, status |
| `cbom_entries` | CBOM components | scan_id (FK), asset_id (FK), algorithm_name, nist_status, quantum_safe_flag |
| `cbom_summary` | CBOM high-level | scan_id (FK, unique), total_components, weak_crypto_count |
| `cyber_rating` | Enterprise rating | scan_id (FK), enterprise_score, rating_tier |
| `asset_dns_records` | DNS discovery | scan_id (FK), hostname, record_type, record_value |
| `audit_logs` | Immutable audit trail | actor_user_id (FK), event_category, entry_hash (UNIQUE), previous_hash |

**Key Features:**
- ✅ All tables use UTF8MB4 for international characters
- ✅ Proper indexes on frequently-queried columns (asset_id, scan_id, expiry_dates, quantum status)
- ✅ Foreign key constraints with CASCADE deletes
- ✅ Soft-delete support (is_deleted + deleted_at + deleted_by_user_id)
- ✅ Audit trail with immutable triggers (append-only audit_logs)
- ✅ Hash chain for cryptographic integrity verification
- ✅ Timestamp columns (created_at, updated_at) on all mutable tables

### 3. **PQC Dashboard Query Helpers** (`src/services/pqc_dashboard_queries.py`)

Reusable query functions with proper SQLAlchemy ORM usage:

#### Asset + Certificate Joins
```python
def get_assets_with_certificate_details(asset_id_filter, limit, include_expired):
    """Returns (Asset, Certificate, PQCClassification) tuples with proper LEFT JOINs"""
    
def get_per_asset_certificate_table(asset_id):
    """Returns certificate details formatted for dashboard table display"""
```

#### Expiry Analysis
```python
def get_certificate_expiry_timeline():
    """Returns: {'0-30': 5, '30-60': 12, '60-90': 23, '>90': 156}"""
    
def get_issuer_breakdown(limit=20):
    """Returns top CAs: [{'issuer': 'Let\'s Encrypt', 'count': 45}, ...]"""
    
def get_company_breakdown(limit=20):
    """Returns organizations: [{'company': 'ACME Corp', 'count': 23}, ...]"""
```

#### PQC Analysis
```python
def get_pqc_classification_by_asset(asset_id):
    """Returns PQC status per asset with algorithm names and scores"""
    
def get_pqc_status_summary():
    """Returns: {'safe': 127, 'unsafe': 45, 'migration_advised': 12, 'unknown': 8}"""
    
def get_quantum_safe_percentage():
    """Returns float 0.0-100.0 for overall quantum-safe coverage"""
```

#### TLS + Crypto Analysis
```python
def get_tls_version_distribution():
    """Returns usage by version"""
    
def get_key_length_distribution():
    """Returns usage by key length (2048, 4096, etc.)"""
    
def get_self_signed_count():
get_expired_count():
```

#### All-in-One Dashboard Helper
```python
def get_pqc_dashboard_aggregated_data():
    """Single efficient query batch for complete dashboard"""
    Returns:
    {
        'kpis': {total_assets, total_certificates, quantum_safe_percent, ...},
        'expiry_timeline': {...},
        'issuer_breakdown': [...],
        'company_breakdown': [...],
        'pqc_status': {...},
        'tls_versions': [...],
        'key_lengths': [...],
        'assets_with_certs': [...]
    }
```

### 4. **Flask Routes** (`web/routes/pqc_dashboard.py`)

Production-ready Blueprint with HTML and JSON endpoints:

#### HTML Routes
```
GET /pqc/posture          → Main PQC posture dashboard (HTML)
GET /pqc/asset/<id>       → Per-asset certificate details (HTML)
```

#### JSON API Routes (caching-friendly)
```
GET /pqc/api/dashboard           → Full dashboard data (JSON)
GET /pqc/api/asset/<id>/certificates  → Asset cert table (JSON)
GET /pqc/api/expiry-timeline     → Expiry data (JSON)
GET /pqc/api/issuer-breakdown    → Issuer data (JSON)
GET /pqc/api/pqc-status          → PQC status data (JSON)
```

**Features:**
- ✅ Proper error handling with graceful fallbacks
- ✅ Database query failures don't crash dashboard
- ✅ Live MySQL queries via `pqc_dashboard_queries`
- ✅ Timestamp tracking for cache invalidation
- ✅ Login decorator for auth (integrate with your system)

### 5. **Jinja2 Template Macros** (`web/templates/pqc_certificate_details.html`)

Reusable template components for rendering:

#### Macros Provided
```jinja2
{% macro certificate_details_table(certificates) %}
  {# Full certificate table with all columns, color-coded status #}
  
{% macro expiry_timeline_cards(timeline) %}
  {# 4 card layout: 0-30 (red), 30-60 (yellow), 60-90 (blue), >90 (green) #}
  
{% macro issuer_breakdown_chart(issuer_breakdown) %}
  {# Horizontal bar chart showing top CAs #}
  
{% macro company_breakdown_list(company_breakdown) %}
  {# List view of organizations #}
  
{% macro pqc_status_cards(pqc_summary, quantum_safe_pct) %}
  {# KPI cards: quantum-safe %, safe/unsafe/migration/unknown counts #}
  
{% macro tls_version_distribution(versions) %}
  {# TLS 1.3 / 1.2 / 1.0 / etc. distribution #}
  
{% macro key_length_distribution(key_lengths) %}
  {# Key length distribution with security labels #}
```

**Color Coding:**
- 🔴 **0-30 days** → Red (urgent renewal)
- 🟡 **30-60 days** → Yellow (monitor)
- 🔵 **60-90 days** → Blue (normal)
- 🟢 **>90 days** → Green (comfortable)

---

## Integration Steps

### Step 1: Update Database Schema
```bash
# Backup current database
mysqldump quantumshield > quantumshield_backup.sql

# Apply complete schema (creates missing tables, adds missing columns)
mysql quantumshield < schema-complete.sql

# Verify migration
mysql -e "USE quantumshield; SHOW TABLES;" | wc -l
# Should show all 14 tables
```

### Step 2: Update Models
```bash
# The src/models.py file has been updated with:
# - Enhanced Certificate model (added subject_cn, company_name, expiry_days, etc.)
# - Enhanced PQCClassification model (added back-reference to Certificate)
# - No breaking changes to existing models
```

### Step 3: Install Query Helper Module
```bash
# Copy src/services/pqc_dashboard_queries.py
# Already provided, no additional installation needed
```

### Step 4: Register Flask Routes
```python
# In web/app.py or your main app initialization:
from web.routes.pqc_dashboard import register_pqc_routes

# Inside your create_app() function:
register_pqc_routes(app)

# This registers:
# GET /pqc/posture
# GET /pqc/asset/<id>
# GET /pqc/api/*
```

### Step 5: Add Templates
```bash
# Copy web/templates/pqc_certificate_details.html
# Import and use macros in your dashboard templates:

{% import 'pqc_certificate_details.html' as pqc %}
{{ pqc.certificate_details_table(vm.certificates) }}
{{ pqc.expiry_timeline_cards(vm.expiry_timeline) }}
# ... etc
```

### Step 6: Test the Flow

```bash
# 1. Start your Flask app
python web/app.py

# 2. Create test asset
curl -X POST http://localhost:5000/api/assets \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "asset_type": "Web App", "owner": "test"}'

# 3. Create test scan with certificate
# (Your scan ingestion logic populates certificates table)

# 4. View dashboard
open http://localhost:5000/pqc/posture

# 5. View per-asset details
open http://localhost:5000/pqc/asset/1

# 6. Test JSON API
curl http://localhost:5000/pqc/api/dashboard | jq .

# 7. Verify certificate table populated
mysql -e "SELECT COUNT(*) FROM quantumshield.certificates;"
```

---

## Data Flow

```
┌─────────────────┐
│  Scan Process   │
│  (External)     │
└────────┬────────┘
         │
         ▼
┌──────────────────────┐
│ Save Asset           │◄─── Assets Table
│ (if new)             │
└────────┬─────────────┘
         │
         ▼
┌──────────────────────┐
│ Parse Certificates   │
│ From TLS Handshake   │
└────────┬─────────────┘
         │
         ▼
┌──────────────────────┐     ┌──────────────────┐
│ Save Certificates    │────►│ Certificates Table │
│ - CN, Issuer, Co.    │     │ - issuer          │
│ - Expiry, Key Length │     │ - subject_cn      │
│ - TLS Version        │     │ - company_name    │
│ - Fingerprint        │     │ - valid_until     │
│ - is_expired flag    │     │ - expiry_days     │
└────────┬─────────────┘     │ - key_length      │
         │                   │ - is_self_signed  │
         ▼                   └──────────────────┘
┌──────────────────────┐
│ Analyze PQC Safety   │
│ of Algorithms        │
└────────┬─────────────┘
         │
         ▼
┌───────────────────────┐    ┌──────────────────┐
│ Save PQC              │───►│ pqc_classification│
│ Classification        │    │ - algorithm_name  │
│ - Status: safe/unsafe │    │ - pqc_score       │
│ - NIST category       │    │ - nist_category   │
│ - Score (0-100)       │    │ - quantum_safe_   │
│                       │    │   status          │
└────────┬──────────────┘    └──────────────────┘
         │
         ▼
┌──────────────────────┐     ┌──────────────────┐
│ Calculate Compliance │────►│ compliance_scores│
│ - TPM, TLS, Overall  │     │ - type            │
│ - Score + tier       │     │ - score_value     │
│ - Color-coded status │     │ - tier            │
└──────────────────────┘     └──────────────────┘
         │
         ▼
┌────────────────────────────────────┐
│ Dashboard Queries (JOINs)          │
│ - assets → certificates → pqc      │
│ - Groupby issuer, company, TLS ver │
│ - Aggregate expiry dates           │
│ - Calculate percentages            │
└────────────────────────────────────┘
         │
         ▼
┌────────────────────────────────────┐
│ Dashboard Display                  │
│ - /pqc/posture (HTML)              │
│ - /pqc/asset/<id> (HTML)           │
│ - /pqc/api/* (JSON for SPA)        │
└────────────────────────────────────┘
```

---

## Sample Query Results

### Certificate Details Table
```
Common Name  │ Issuer          │ Company    │ Valid Until │ Days │ TLS   │ Key  │ PQC Status
─────────────┼─────────────────┼────────────┼─────────────┼──────┼───────┼──────┼──────────
example.com  │ Let's Encrypt   │ ACME Corp  │ 2025-12-31  │ 314  │ 1.3   │ 2048 │ SAFE  
api.example  │ DigiCert        │ ACME Corp  │ 2025-06-15  │ 176  │ 1.2   │ 4096 │ UNSAFE
*.example    │ Self-signed     │ ACME Corp  │ 2024-12-25  │ EXPIRED!       │ 1.2  │ 1024 │ UNSAFE
```

### Expiry Timeline
```
0-30 days:   5 certs (🔴 Urgent renewal)
30-60 days:  12 certs (🟡 Monitor)
60-90 days:  23 certs (🔵 Normal)
>90 days:    156 certs (🟢 Comfortable)
```

### PQC Status Summary
```
Quantum-Safe Coverage: 65.4%

Safe Algorithms:            127 ✓
Vulnerable Algorithms:       45 ✗
Migration Advised:           12 ⚠️
Unknown:                      8 ?
```

### Issuer Breakdown
```
Let's Encrypt        45 certs
DigiCert             18 certs
GoDaddy              12 certs
GlobalSign            8 certs
Self-signed           3 certs
```

---

## Performance Considerations

### Indexes Created
```sql
-- Certificate table
INDEX idx_asset_id (asset_id)
INDEX idx_scan_id (scan_id)
INDEX idx_subject_cn (subject_cn)
INDEX idx_issuer (issuer)
INDEX idx_company_name (company_name)
INDEX idx_ca_name (ca_name)
INDEX idx_valid_until (valid_until)
INDEX idx_is_expired (is_expired)
INDEX idx_is_deleted (is_deleted)
UNIQUE INDEX uq_fingerprint_sha256 (fingerprint_sha256)
UNIQUE INDEX uq_serial (serial)

-- PQC Classification
INDEX idx_certificate_id (certificate_id)
INDEX idx_asset_id (asset_id)
INDEX idx_quantum_safe_status (quantum_safe_status)
INDEX idx_pqc_score (pqc_score)
```

### Query Optimization Tips
1. **Batch queries** - Use `get_pqc_dashboard_aggregated_data()` instead of multiple queries
2. **Cache results** - Dashboard data changes infrequently; cache with TTL
3. **Pagination** - For asset lists with many certificates, paginate results
4. **Filtered joins** - Always filter `is_deleted=False` at join time (in WHERE clause)

### Caching Strategy
```python
from flask_caching import Cache

cache = Cache(app, config={'CACHE_TYPE': 'simple'})

@pqc_bp.route('/api/dashboard')
@cache.cached(timeout=3600)  # Cache for 1 hour
def api_pqc_dashboard():
    return get_pqc_dashboard_aggregated_data()

# Invalidate cache when data changes:
@app.after_request
def invalidate_dashboard_cache(response):
    if request.method in ['POST', 'PUT', 'DELETE']:
        cache.delete('api_pqc_dashboard')
    return response
```

---

## Troubleshooting

### Problem: "Certificate details not showing"
**Solution:** Check that:
1. Certificates table exists: `SHOW TABLES LIKE 'certificates'`
2. Certificates have data: `SELECT COUNT(*) FROM certificates WHERE is_deleted=False`
3. Foreign keys are valid: `SELECT asset_id FROM certificates LIMIT 1` (should exist in assets table)
4. Model relationships are correct: `from src.models import Asset, Certificate`

### Problem: "Expiry days showing NULL"
**Solution:** The `expiry_days` column needs to be calculated when saving cert:
```python
from datetime import datetime

cert.valid_until = datetime.fromisoformat('2025-12-31')
cert.expiry_days = (cert.valid_until - datetime.utcnow()).days
db.session.add(cert)
db.session.commit()
```

### Problem: "Slow dashboard loads"
**Solution:** 
1. Use `get_pqc_dashboard_aggregated_data()` (single query batch)
2. Add database indexes to expiry timeline queries
3. Implement caching (see above)
4. Reduce result limit for large datasets

### Problem: "PQC status always showing 'unknown'"
**Solution:** Ensure PQCClassification records are being created during scan ingestion:
```python
# When saving scan results:
pqc = PQCClassification(
    certificate_id=cert.id,
    asset_id=asset.id,
    algorithm_name='RSA',
    quantum_safe_status='unsafe',  # ← Must set this
    pqc_score=42.0,
    nist_category='??'
)
db.session.add(pqc)
```

---

## References

### Files Modified/Created
1. ✅ `src/models.py` - Enhanced Certificate & PQCClassification models
2. ✅ `schema-complete.sql` - Complete MySQL schema with all tables
3. ✅ `src/services/pqc_dashboard_queries.py` - Query helper module (400+ lines)
4. ✅ `web/routes/pqc_dashboard.py` - Flask routes (7 endpoints)
5. ✅ `web/templates/pqc_certificate_details.html` - Jinja2 macros

### SQL Tables Managed
- assets
- certificates (enhanced)
- pqc_classification (enhanced)
- compliance_scores
- discovery_items
- cbom_entries
- cbom_summary
- cyber_rating
- audit_logs (append-only)
- scans
- users

### Relationships Defined
```
Asset (1) ──────────┐
                    ├──► (M) Certificates ──────┐
                    │                           ├──► (M) PQCClassification
                    ├──► (M) PQCClassification──┘
                    │
                    ├──► (M) ComplianceScores
                    │
                    └──► (M) CBOMEntries

Scan (1) ──────┐
               ├──► (M) Certificates
               ├──► (M) PQCClassification
               ├──► (M) ComplianceScores
               └──► (M) CBOMEntries
```

---

## Next Steps

1. **Migrate Database** → Apply `schema-complete.sql`
2. **Update Flask App** → Register PQC routes in `web/app.py`
3. **Run Tests** → Verify certificate data is being saved
4. **Deploy Templates** → Add PQC dashboard to navigation
5. **Monitor Performance** → Use database queries monitoring
6. **Set Cache TTLs** → Configure based on your scan frequency

---

## Support

For questions or issues:
- Check SQL table definitions in `schema-complete.sql`
- Review query helpers in `src/services/pqc_dashboard_queries.py`
- Inspect Flask route error logs in `web/routes/pqc_dashboard.py`
- Validate model relationships in `src/models.py`
