# KPI Calculation Guide – Dynamic Metrics for All Dashboards

## Overview

All dashboard KPIs are now calculated **dynamically from live database data** instead of hardcoded values. Each dashboard reads from completed scans, certificates, and asset records to compute real metrics.

---

## Dashboard KPI Calculations

### 1. **Asset Inventory Dashboard** (`/dashboard/assets`)

**View Model**: `_build_asset_inventory_view()` [lines 1381-1615 in web/app.py]

**Calculated KPIs**:
- **Total Assets** = Count of unique assets from scans + manually added assets
- **Public Web Apps** = Count of assets with `type == "Web App"`
- **APIs** = Count of assets with `type == "API"`
- **Servers** = Count of assets with `type == "Server"`
- **Expiring Certificates** = Count of assets with `cert_status == "Expiring"` (< 30 days)
- **High Risk Assets** = Count of assets with `risk` in {"Critical", "High"}

**Additional Metrics**:
- Asset Type Distribution (Web Apps, APIs, Servers, Load Balancers, Other)
- Risk Distribution (Critical, High, Medium, Low)
- Certificate Expiry Timeline (0-30, 30-60, 60-90, >90 days)
- IPv4/IPv6 Breakdown
- Risk Heatmap by Owner

**Data Source**: `scan_store` (in-memory) + `db.list_scans()` + manual assets

---

### 2. **CBOM Dashboard** (`/cbom-dashboard`)

**View Model**: `cbom_dashboard()` [lines 1886-1925 in web/app.py]

**Calculated KPIs**:
- **Total Applications** = Count of distinct scanned targets (unique full scans)
- **Sites Surveyed** = Count of distinct scanned targets
- **Active Certificates** = Count of all certificates in database
- **Weak Cryptography** = Count of:
  - Certificates with TLS < 1.2 (TLS 1.0, 1.1, SSLv3, SSLv2) + 
  - Certificates with key length < 2048 bits
- **Certificate Issues** = Same as weak cryptography

**Additional Metrics**:
- **Key Length Distribution** = Breakdown of certs by key size (4096+, 2048-4095, <2048)
- **Cipher Usage** = Top 5 cipher suites in use
- **Top Certificate Authorities** = Top 5 CAs by usage
- **Encryption Protocols** = TLS version distribution
- **Weakness Heatmap** = Breakdown of weak TLS vs weak key vulnerabilities

**Data Source**: `Certificate` model + `Scan` model

---

### 3. **PQC Posture Dashboard** (`/pqc-posture`)

**View Model**: `pqc_posture()` [lines 1930-2002 in web/app.py]

**Calculated KPIs**:
- **Elite** = Count of scans with PQC score ≥ 80%
- **Standard** = Count of scans with PQC score 60-79%
- **Legacy** = Count of scans with PQC score 40-59%
- **Critical** = Count of scans with PQC score < 40%

**Additional Metrics**:
- **Average PQC Score** = Mean of all `overall_pqc_score` values
- **Grade Distribution** = Above breakdown as heatmap
- **Recommendations**:
  - Total scanned targets
  - Average PQC readiness percentage
  - Critical applications requiring remediation

**Data Source**: `Scan` model records with status == "complete"

---

### 4. **Cyber Rating Dashboard** (`/cyber-rating`)

**View Model**: `cyber_rating()` [lines 2028-2096 in web/app.py]

**Calculated KPIs**:
- **Overall Score** = Average of all scan compliance scores (0-1000)
- **Label** = Tier based on overall score:
  - "Elite" = ≥ 850
  - "Standard" = 600-849
  - "Legacy" = 350-599
  - "Critical" = < 350

**Tier Counts**:
- **Elite-PQC** = Scans with score ≥ 850
- **Standard** = Scans with score 600-849
- **Legacy** = Scans with score 350-599
- **Critical** = Scans with score < 350

**Additional Metrics**:
- Tier Heatmap = Distribution across all tiers
- Uses `overall_pqc_score` field, falls back to `average_compliance_score`

**Data Source**: `Scan` model records with status == "complete"

---

### 5. **Reporting Dashboard** (`/reporting`)

**View Model**: `reporting()` [lines 2102-2147 in web/app.py]

**Calculated Summary Strings**:

| Metric | Calculation | Example |
|--------|-------------|---------|
| **Discovery** | `Targets: {unique_targets} \| Complete Scans: {total_scans} \| Assessed Endpoints: {num_scans}` | "Targets: 5 \| Complete Scans: 12 \| Assessed Endpoints: 12" |
| **PQC** | `Assessed endpoints: {num_scans} \| Average PQC Score: {avg_pqc}%` | "Assessed endpoints: 12 \| Average PQC Score: 67%" |
| **CBOM** | `Total certificates: {cert_count} \| Weak cryptography: {weak_count}` | "Total certificates: 45 \| Weak cryptography: 8" |
| **Cyber Rating** | `Average enterprise score: {avg_pqc}/100` | "Average enterprise score: 67/100" |
| **Inventory** | `Assets: {total} \| Expiring: {expiring} \| High Risk: {high_risk}` | "Assets: 12 \| Expiring: 2 \| High Risk: 3" |

**Data Source**: Aggregates from `_build_asset_inventory_view()`, `Certificate`, and `Scan` models

---

## Template Updates

### Asset Inventory Template (`web/templates/inventory.html`)

**Before** (hardcoded via undefined `summary` variable):
```html
<div class="stat-val">{{ summary.total_assets }}</div>
<div class="stat-val">{{ summary.api_count }}</div>
```

**After** (dynamic via calculated `vm.kpis`):
```html
<div class="stat-val">{{ vm.kpis.total_assets or 0 }}</div>
<div class="stat-val">{{ vm.kpis.apis or 0 }}</div>
```

All chart data also updated to use `vm.asset_type_distribution` and `vm.asset_risk_distribution` instead of undefined `summary.*` fields.

---

## Calculation Logic Patterns

All KPI functions follow this pattern:

```python
def dashboard_function():
    # 1. Execute database queries to get raw counts
    total = db_session.query(func.count(...)).scalar() or 0
    
    # 2. Apply filters/classifications
    weak = db_session.query(...).filter(weakness_condition).scalar() or 0
    
    # 3. Process data with Counter/aggregation
    status_dist = Counter()
    for item in items:
        if score >= threshold:
            status_dist["tier"] += 1
    
    # 4. Return dict with "empty" flag + "kpis" + breakdown dicts
    return {
        "empty": total == 0,
        "kpis": {...},
        "distribution": dict(status_dist),
    }
```

---

## Error Handling

All dashboard functions include `try/except` blocks:

- **Success**: Returns calculated KPIs from database
- **Exception**: Returns safe default KPIs with all zeros
- **No Data**: `"empty": True` flag prevents UI errors on empty dashboards

Example:
```python
except Exception as e:
    vm = {"empty": True, "kpis": {"total": 0, ...}}
    page_data = {"items": [], "total_count": 0}
```

---

## Testing

All 6 dashboard pages pass integration tests:
- ✅ `test_asset_inventory_page` - KPI calculations validated
- ✅ `test_cbom_dashboard_page` - Certificate metrics validated
- ✅ `test_pqc_posture_page` - PQC scoring validated
- ✅ `test_cyber_rating_page` - Rating calculations validated
- ✅ `test_reporting_page` - Summary metrics validated
- ✅ `test_asset_discovery_page` - Related metrics validated

**41/41 tests passing** (2.91s)

---

## Performance Notes

- **Asset Inventory**: Scans `scan_store` + `db.list_scans()` (blended feed)
- **CBOM Dashboard**: Scans all `Certificate` rows (typically < 1000)
- **PQC Posture**: Scans all completed `Scan` rows (typically < 100)
- **Cyber Rating**: Scans all completed `Scan` rows (typically < 100)
- **Reporting**: Executes ~5 COUNT queries + 1 aggregation

**Optimization**: Add caching at dashboard level if scan/cert counts exceed 10,000 rows.

---

## Troubleshooting

**Issue**: Dashboard shows "empty" or all zeros
- **Cause**: No scans with `status == "complete"` in database
- **Fix**: Run `/scan-center` with a target, wait for completion

**Issue**: Certificate counts are 0 but scans exist
- **Cause**: Scans in database but Certificate rows not populated
- **Fix**: Verify scan ingest pipeline created Certificate records (check `scan_store` + database insert logic)

**Issue**: PQC scores showing as 0%
- **Cause**: `overall_pqc_score` field not populated in Scan
- **Fix**: Check scan report generation creates this field; fallback uses `average_compliance_score`

---

## Future Enhancements

1. **Caching**: Add Redis/in-memory cache for KPI calculations
2. **Time-series**: Track KPI changes over time (trending)
3. **Alerting**: Trigger notifications when KPIs cross thresholds
4. **Export**: Download KPI reports as CSV/JSON
5. **Drill-down**: Click KPI card to filter underlying data

