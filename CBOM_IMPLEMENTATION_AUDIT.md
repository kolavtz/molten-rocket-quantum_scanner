# CBOM (Cryptographic Bill of Materials) Implementation Audit
**Date:** 2026-03-29 | **Scope:** Current state analysis of CBOM dashboard, APIs, services, and frontend

---

## Executive Summary

The CBOM implementation is **API-first and largely complete**, with all major components in place:
- **7 API endpoints** for metrics, entries, charts, minimum elements, and export
- **Service layer** providing data retrieval and transformation logic
- **Database models** (CBOMEntry, CBOMSummary) with CERT-IN Table 9 compliance support
- **JavaScript-driven UI** with client-side pagination, search, and chart rendering
- **Chart/visualization infrastructure** for key length, protocol, and cipher suite distributions

However, several **consistency, completeness, and UX gaps** exist that should be addressed.

---

## 1. CBOM Template (`cbom_dashboard.html`)

### Current State

**File:** [web/templates/cbom_dashboard.html](web/templates/cbom_dashboard.html)

#### 1.1 Data Rendering Strategy
- **Hybrid approach:** Server-rendered KPI placeholders + API-driven hydration
- Initial page load shows server-generated KPI values via Jinja2 templating (lines 57-71)
- On DOM ready, JavaScript calls `syncCbom()` to fetch live data from `/api/cbom/metrics`, `/api/cbom/charts`, `/api/cbom/entries`
- **Fallback behavior:** If API fails, displays "latest available data" message (line 363)

#### 1.2 UI Components

**KPI Section (lines 57-71):**
- 5 KPI cards in a 5-column grid (responsive to 3 columns on <1200px)
- Cards: Applications, Sites, Active Certs, Weak Crypto, Issues
- Color-coded values: Safe (green), Critical (red), High (orange)
- Clean glass-card styling with sans-serif typography

**Chart Section (lines 74-109):**
- **3-column layout** for charts (Key Length | Protocol Donut | Top Ciphers)
- Responsive: collapses to 1 column on mobile
- Rendering via client-side JavaScript functions (`renderKeyLengths`, `renderProtocolDonut`, `renderCiphers`)

**Data Table (lines 111-154):**
- **8 columns:** Asset Name, Cert Status, Key Len, Protocol, Cipher Suite, CA, Expires On, Certificate Details
- Collapsible X.509 details panel using HTML `<details>` element (lines 138-153)
- X.509 fields shown: Version, Serial, Signature Algorithm, Issuer, Validity, Subject, Extensions, etc.
- **Paginated:** Prev/Next buttons with metadata display (e.g., "Showing 1-25 of 127 entries")

#### 1.3 Search/Filter/Pagination Controls
- **Search input** with custom "q" parameter (line 117)
- **Pagination controls:** Previous/Next buttons (disabled state management in JS)
- **Export button:** Triggers `/api/cbom/export` download (line 119)
- Search/pagination trigger `syncCbom()` to reload table data

### Issues Found

#### Issue 1.1: Hardcoded 60% bar width in initial template render
**Location:** [cbom_dashboard.html](cbom_dashboard.html#L103)
```jinja2
<div class="bar-fill" style="width: 60%;"></div>  <!-- hardcoded in template -->
```
**Impact:** Initial page load shows incorrect visual; corrected by JS (`renderKeyLengths`), but causes layout shift.
**Fix:** Remove inline style or use `0%` as placeholder.

#### Issue 1.2: Conic gradient hardcoded in protocol donut initial state
**Location:** [cbom_dashboard.html](cbom_dashboard.html#L106)
```jinja2
<div id="protocolDonut" ... style="background: conic-gradient(var(--pqc-safe) 0% 45%, ...);">
```
**Impact:** Initial render shows 45% TLS 1.3, then JS updates to actual value. Visual flicker.
**Fix:** Use data attributes or hidden data element for initial values.

#### Issue 1.3: No loading skeleton or placeholder states
**Current:** Shows "Syncing CBOM telemetry…" text only.
**Recommended:** Add skeleton loaders for chart cards and table rows during API fetch.

#### Issue 1.4: Certificate details fallback is incomplete
**Location:** [cbom_dashboard.html](cbom_dashboard.html#L138-L153)
The template tries to render `{{ cert.get('...') }}` but `cert` comes from Jinja2 context (`row.certificate_details`), not the API response.
**Impact:** X.509 details render from stale Jinja2 data, overwritten by JS (lines 312-317 in renderEntries).
**Current workaround:** renderEntries() doesn't yet build the full X.509 detail HTML, just shows serial in last column.

#### Issue 1.5: No "No Data" or empty state rendering in initial template
**Current:** Table body is empty until API responds.
**Recommended:** Add server-side fallback row showing "No CBOM entries. Run scans to populate CBOM."

---

## 2. CBOM API Routes (`dashboard_api.py`)

### Current State

**File:** [web/routes/dashboard_api.py](web/routes/dashboard_api.py)

#### 2.1 Endpoints Overview

| Endpoint | Method | Purpose | Query Params |
|----------|--------|---------|--------------|
| `/api/cbom/metrics` | GET | KPI summary (applications, sites, certs, issues) | `page`, `page_size`, `search`, `sort`, `order` |
| `/api/cbom/entries` | GET | Paginated CBOM entry list | `page`, `page_size`, `search`, `sort`, `order` |
| `/api/cbom/summary` | GET | Single scan CBOM summary | `scan_id` (required) |
| `/api/cbom/charts` | GET | Chart datasets + explanations | `page`, `page_size` |
| `/api/cbom/minimum-elements` | GET | CERT-IN Table 9 minimum elements with coverage | `page`, `page_size` |
| `/api/cbom` | GET | Alias for `/api/cbom/entries` | (same as entries) |
| `/api/cbom/export` | GET | Full CBOM JSON export (KPIs + entries + charts + minimum elements) | `page`, `page_size` (uses max 250) |

**Lines 980-1200**

#### 2.2 Request/Response Contracts

**`GET /api/cbom/metrics`** (lines 980-991)
- **Response:** `{ success: true, data: { items: [], total: 0, page: 1, page_size: 25, kpis: { total_applications, sites_surveyed, ... } } }`
- **Filters payload:** `{ sort, order, search }`
- Data envelope built by `build_data_envelope([], 0, params, kpis)`

**`GET /api/cbom/entries`** (lines 997-1012)
- **Response:** `{ success: true, data: { items: [{ asset_id, asset_name, key_length, cipher_suite, ca, tls_version, ... }], total: N, page, page_size, kpis: {...} } }`
- **Supports:** pagination (page, page_size), search, sort (asset_name, key_length, etc.), order (asc/desc)

**`GET /api/cbom/charts`** (lines 1058-1103)
- **Response:** Single item with chart datasets + explanatory metadata
  ```json
  {
    "key_length_distribution": { "2048": 42, "4096": 15, ... },
    "protocol_versions": { "TLS 1.3": 30, "TLS 1.2": 20, ... },
    "cipher_suite_usage": { "TLS_AES_256_GCM_SHA384": 28, ... },
    "top_cas": { "Let's Encrypt": 50, "DigiCert": 20, ... },
    "minimum_elements": { ... },
    "chart_explanations": {
      "key_length_distribution": { "chart_type": "bar", "x_axis": "...", "what_it_represents": "..." },
      ...
    }
  }
  ```
- **Supported filtering:** None (charts are global summary, not per-asset)

**`GET /api/cbom/minimum-elements`** (lines 1108-1137)
- **Response:** Includes paginated minimum-element entries + field coverage summary
  ```json
  {
    "items": [{ id, asset_id, asset_name, asset_type, element_name, ... }],
    "total": N,
    "minimum_elements": {
      "asset_type_distribution": { "algorithm": 150, "certificate": 200, ... },
      "field_coverage": { "asset_type": { "count": 350, "coverage_pct": 100 }, ... },
      "field_definitions": { "asset_type": { "description": "...", "required": true }, ... },
      "coverage_summary": { "required_fields": 24, "covered_fields": 18, "coverage_pct": 75 }
    }
  }
  ```

**`GET /api/cbom/export`** (lines 1146-1165)
- **Response:** JSON file attachment (Content-Disposition: attachment)
- **Payload structure:**
  ```json
  {
    "generated_at": "ISO timestamp",
    "kpis": { ... },
    "entries": [ ... ],
    "charts": { "key_length_distribution": {...}, "cipher_usage": {...}, ... },
    "minimum_elements": { ... }
  }
  ```
- Uses 250 entries per page (configurable via page_size, max 250) for export volume

#### 2.3 Supported Filtering & Pagination

- **Pagination:** `page` (default 1), `page_size` (default 25, max 250 for export)
- **Search:** `search` parameter (fuzzy match on asset name, CA, cipher suite, TLS version)
- **Sorting:** `sort` param + `order` (asc/desc)
  - Available sort fields: `asset_name`, `asset_id`, `key_length`, `cipher_suite`, `ca`, `tls_version`, `valid_until`, `last_scan`

### Issues Found

#### Issue 2.1: `/api/cbom/metrics` returns empty items array
**Location:** [dashboard_api.py](dashboard_api.py#L980-L991)
```python
data = build_data_envelope([], 0, params, kpis)  # items=[], total=0
```
**Impact:** Frontend expects `data.items` for rendering; receives empty array. OK for KPI-only use, but inconsistent with other endpoints.
**Recommendation:** Return a single summary item instead of empty array, e.g.:
```python
items = [{"type": "cbom_summary", **cbom_data.get("kpis", {})}]
data = build_data_envelope(items, 1, params, kpis)
```

#### Issue 2.2: `/api/cbom/summary` endpoint underutilized
**Location:** [dashboard_api.py](dashboard_api.py#L1016-L1057)
- Requires `scan_id` query param but template doesn't link to per-scan CBOM views
- Only returns single item (CBOMSummary record), not full entry list
- Could be extended to support drill-down from Scan Center → CBOM detail

#### Issue 2.3: No filtering support on `/api/cbom/charts`
**Current:** Charts are global aggregates only.
**Gap:** No way to filter charts by asset_id, date range, or search term.
**Recommendation:** Accept optional `asset_id`, `start_date`, `end_date` params and pass to `CbomService.get_cbom_dashboard_data()`.

#### Issue 2.4: `/api/cbom/export` doesn't respect all page size limits correctly
**Location:** [dashboard_api.py](dashboard_api.py#L1146-L1165)
```python
page_size=max(params["page_size"], 250),  # Should be min(), not max()
```
**Impact:** User can request `page_size=1000`, export will use 1000 entries instead of capping at 250.
**Fix:**
```python
page_size=min(max(params["page_size"], 25), 250),
```

#### Issue 2.5: No rate-limiting or caching on export endpoint
**Current:** `/api/cbom/export` regenerates full payload on every request.
**Performance risk:** Large CBOM datasets (1000s of entries) will be slow.
**Recommendation:** Cache export payload with 5-minute TTL, invalidate on scan completion.

#### Issue 2.6: API doesn't expose "Last Scan" timestamp or asset link metadata in entries
**Current:** `applications` array includes `asset_id` and `asset_name`, but no link to asset detail endpoint.
**Recommendation:** Add `asset_detail_url` or expose asset object with full metadata.

---

## 3. CBOM Service (`cbom_service.py`)

### Current State

**File:** [src/services/cbom_service.py](src/services/cbom_service.py)

#### 3.1 Service Methods

**`CbomService.get_cbom_dashboard_data()`** (lines 487-765)
- **Signature:**
  ```python
  @classmethod
  def get_cbom_dashboard_data(
      cls,
      asset_id: Optional[int] = None,
      start_date: Optional[str] = None,
      end_date: Optional[str] = None,
      limit: int = 200,
      page: int = 1,
      page_size: int = 100,
      sort_field: str = "asset_name",
      sort_order: str = "asc",
      search_term: str = "",
  ) -> Dict[str, Any]:
  ```
- **Returns:** Comprehensive dashboard data dict with:
  - `kpis`: 5 KPIs (total_applications, sites_surveyed, active_certificates, weak_cryptography, certificate_issues)
  - `key_length_distribution`, `cipher_usage`, `ca_distribution`, `protocol_distribution`: Chart data
  - `applications`: Paginated certificate list with full X.509 details
  - `page_data`: Pagination metadata (total_count, page, page_size, has_next, has_prev)
  - `minimum_elements`: CERT-IN Table 9 minimum element payload
  - `weakness_heatmap`: 2D matrix of weakness categories (Transport, Lifecycle, Identity, CBOM)

#### 3.2 Data Retrieval Logic

**Query Construction:**
- **Scan filters** (soft-delete aware): `Scan.is_deleted == False`, `Scan.status == "complete"`, `Scan.add_to_inventory == True`
- **Cert filters:** Explicit joins to Asset + Scan, soft-delete checks on both
- **Date filtering:** Optional `start_date` / `end_date` applied to scan timestamp (`Scan.scanned_at` or `Scan.completed_at` or `Scan.started_at`)

**Certificate Detail Enrichment (lines 699-712):**
- Primary source: `_certificate_details_from_cert_row()` — builds dict from Certificate columns (serial, issuer, validity, etc.)
- Secondary source: `_find_report_certificate_details()` — looks up full X.509 details from `Scan.report_json` using serial/CN/endpoint matching
- Merged dict: report details override cert row fallback

**MINIMUM_ELEMENT_FIELDS (lines 439-462):**
```python
[
  "asset_type", "element_name", "primitive", "mode", "crypto_functions",
  "classical_security_level", "oid", "key_id", "key_state", "key_size",
  "key_creation_date", "key_activation_date", "protocol_name", "protocol_version_name",
  "cipher_suites", "subject_name", "issuer_name", "not_valid_before", "not_valid_after",
  "signature_algorithm_reference", "subject_public_key_reference", "certificate_format",
  "certificate_extension",
]
```

#### 3.3 Minimum Elements Payload Builder
**`_build_minimum_elements_payload()`** (lines 282-448)
- Queries CBOMEntry table for inventory-promoted scans
- Build items (top 200 by ID desc)
- Calculates field coverage: for each MINIMUM_ELEMENT_FIELD, counts non-NULL entries and coverage %
- Returns:
  - `total_entries`: count of CBOM entries
  - `asset_type_distribution`: histogram of asset types (algorithm, key, protocol, certificate)
  - `field_coverage`: per-field count + coverage % for each required field
  - `field_definitions`: semantic descriptions of each field
  - `coverage_summary`: aggregate stats (required=24 fields, covered=N, coverage_pct=X%)
  - `items`: actual entry rows (paginated)

#### 3.4 Key Computed Metrics

**Weakness Categories (lines 742-749):**
```
- Transport: Weak TLS + Weak Keys
- Lifecycle: Expired certs
- Identity: Self-signed certs
- CBOM: Entry issues + Summary issues
```

**Certificate Issues Calculation (lines 655-690):**
- Sums weak TLS versions, weak key lengths (<2048), expired, self-signed counts
- Plus CBOMEntry quantum_safe_flag=False count
- Plus CBOMSummary cert_issues_count aggregate
- Returns max(weak_crypto_total, cbom_issue_total)

### Issues Found

#### Issue 3.1: Certificate detail fallback doesn't always populate X.509 fields
**Location:** [cbom_service.py](cbom_service.py#L90-L118)
`_certificate_details_from_cert_row()` is sparse — returns empty strings for many X.509 fields (extensions, key_usage, etc.).
**Impact:** X.509 details panel in UI shows dashes for most fields unless report_json contains full certificate_details dict.
**Recommendation:**
- Populate more Certificate model columns during scan ingestion (e.g., certificate_extensions, key_usage, san_list)
- Or enhance report_json certificate_details parsing to be more complete

#### Issue 3.2: Search can be slow on large inventories
**Location:** [cbom_service.py](cbom_service.py#L262-L275)
```python
if search_term:
    like = f"%{search_term}%"
    q = q.filter(
        Asset.target.ilike(like)
        | Certificate.ca.ilike(like)
        | Certificate.cipher_suite.ilike(like)
        | Certificate.tls_version.ilike(like)
    )
```
**Impact:** Full-table scans on large certificate tables; no indexed prefix matching.
**Recommendation:** Use indexed columns only (target, ca have indexes) or add search hint; reject empty search terms; cache recent searches.

#### Issue 3.3: `_build_applications_query()` doesn't include reporting metadata
**Current:** Returns only Certificate + Asset columns.
**Gap:** No risk_level, pqc_score, compliance_tier from AssetMetric or PQCClassification.
**Recommendation:** Left-join AssetMetric to enrich rows with risk/PQC data for inline risk coloring in UI.

#### Issue 3.4: Field coverage calculation is inefficient
**Location:** [cbom_service.py](cbom_service.py#L361-L390)
- Executes one query per MINIMUM_ELEMENT_FIELD (24+ queries for field coverage)
- Could be optimized with a single parameterized UNION or GROUP BY with CASE statements

#### Issue 3.5: No explicit ordering of key_length_distribution
**Location:** [cbom_service.py](cbom_service.py#L705-L710)
```python
key_length_dist = {
    str(int(k)) if k is not None else "Unknown": v
    for k, v in db_session.query(Certificate.key_length, func.count(Certificate.id))...
    .group_by(Certificate.key_length)
    .all()
}
```
**Impact:** Keys appear in arbitrary order (DB sort order). UI should sort numerically (512, 1024, 2048, 4096) but doesn't.
**Fix:** Add `.order_by(Certificate.key_length.asc())` before `.all()`.

---

## 4. CBOM Builder & CycloneDX Generator

### Current State

**Files:** 
- [src/cbom/builder.py](src/cbom/builder.py) — CBOM data model + builder
- [src/cbom/cyclonedx_generator.py](src/cbom/cyclonedx_generator.py) — CycloneDX 1.6 export

#### 4.1 CBOM Builder (`builder.py`)

**Class Hierarchy:**
```
CryptoAsset       # Single crypto asset record (legacy compat)
  ├─ asset_id, host, port, service
  ├─ protocol_version, cipher_suite, cipher_bits, key_exchange
  ├─ cert_subject, cert_issuer, cert_serial, cert_not_before, cert_not_after
  ├─ cert_signature_algorithm, cert_public_key_type, cert_public_key_bits
  └─ is_quantum_safe, pqc_status, risk_level

CBOM              # Container and data model
  ├─ serial_number, version, timestamp, tool metadata
  ├─ assets: List[CryptoAsset]
  └─ CERT-IN typed inventories:
      ├─ algorithms: List[Dict]
      ├─ keys: List[Dict]
      ├─ protocols: List[Dict]
      └─ certificates: List[Dict]

CBOMBuilder       # Assembles CBOM from TLS + PQC results
  └─ build(tls_results, pqc_assessments) → CBOM
```

**Build Process:**
1. Iterates over TLS results paired with PQC assessments by index
2. Per TLS result:
   - Builds CryptoAsset (legacy compat) from TLS + PQC data
   - Extracts Algorithm records (cipher, key exchange, signature)
   - Extracts Key record (public key from cert)
   - Extracts Protocol record (TLS version + cipher suite)
   - Extracts Certificate record (X.509 subject/issuer/validity)
3. Returns populated CBOM with both legacy assets list + typed inventories

**Output to CycloneDX:**
- `cbom.to_dict()` returns nested structure with `assets` + `cert_in_inventory`
- CycloneDXGenerator.generate() formats as CycloneDX 1.6 JSON

#### 4.2 CycloneDX Generator

**Strategy:**
- **Preferred:** Uses `cyclonedx-python-lib` if installed
- **Fallback:** Hand-crafted JSON if library unavailable

**Library-based generation** (lines 66-103):
- Creates `cyclonedx.model.Bom` and Component objects per asset
- Maps CBOM properties to CycloneDX properties (namespace `quantum-safe:`)
- Sets ComponentType.CRYPTOGRAPHIC_ASSET
- Exports via JsonV1Dot6

**Manual fallback** (not shown in excerpt):
- Builds CycloneDX 1.6 dict manually if library unavailable
- Risk: drift from actual spec if not maintained

### Issues Found

#### Issue 4.1: CBOM builder depends on pairing TLS + PQC by list index
**Location:** [builder.py](builder.py#L174-L179)
```python
for i, tls_data in enumerate(tls_results):
    pqc_data = pqc_assessments[i] if i < len(pqc_assessments) else {}
```
**Risk:** If TLS and PQC result lists are not aligned or have different ordering, mismatched PQC status assigned to wrong endpoints.
**Recommendation:** Join by endpoint identity (host:port) instead of index; validate alignment.

#### Issue 4.2: CycloneDX property namespace hardcoded
**Location:** [cyclonedx_generator.py](cyclonedx_generator.py#L87-L97)
```python
Property(name="quantum-safe:protocol", value=...)
```
**Concern:** No namespace prefix validation; if metadata evolves, properties become unmaintainable.
**Recommendation:** Define constant namespace prefix; document property schema.

#### Issue 4.3: Export doesn't include CERT-IN minimum element fields
**Current:** CycloneDX export focuses on legacy CryptoAsset structure.
**Gap:** No export of CBOMEntry.asset_type, element_name, primitive, mode, etc.
**Recommendation:** If CERT-IN compliance required, enrich CycloneDX properties with minimum element fields or create separate CERT-IN JSON export format.

#### Issue 4.4: No validation of required fields in CBOM before export
**Current:** Builder accepts partial/empty data and exports as-is.
**Recommendation:** Validate required CERT-IN fields before finalizing CBOM; warn if coverage <80%.

---

## 5. Frontend JavaScript

### Current State

**File:** [web/templates/cbom_dashboard.html](web/templates/cbom_dashboard.html#L215) (script block)

#### 5.1 State Management

**Page-scoped variables:**
```javascript
let cbomPage = 1;           // Current page number
let cbomHasNext = false;    // Pagination metadata
let cbomHasPrev = false;
```
- Simple in-memory state; no persistence across page reloads
- Pagination resets to page 1 on search

#### 5.2 Core Functions

**`syncCbom()`** (lines 333-363)
- Fetches from 3 endpoints in parallel: `/api/cbom/metrics`, `/api/cbom/charts`, `/api/cbom/entries`
- Includes `search` param from input value (named "q")
- On success: updates KPIs, chart visuals, table rows
- On failure: sets error message, shows last known data

**`updateKpis(kpis)`** (lines 290-295)
- Updates 5 KPI card text values with `.toLocaleString()` formatting

**`renderKeyLengths(dist, totalApps)`** (lines 297-310)
- Maps key_length_distribution dict to HTML bar-row elements
- Calculates bar width as `(count / totalApps) * 100%`
- Handles empty state ("No key-length data available")

**`renderProtocolDonut(protocols)`** (lines 312-320)
- Calculates TLS 1.3 / TLS 1.2 / Legacy percentages
- Generates conic-gradient CSS dynamically
- Updates center text with TLS 1.3 %

**`renderCiphers(cipherUsage)`** (lines 322-335)
- Renders top 5 cipher suites as ranked list with count badges
- Handles empty state

**`renderEntries(items)`** (lines 337-357)
- Iterates over entries and builds table rows with escaping (`esc()` function)
- Shows asset name, cert status (hardcoded "Valid"), key length, protocol, cipher, CA, expiry
- **Gap:** Doesn't render X.509 certificate_details panel (should show full details)

**`updatePager(total, page, pageSize)`** (lines 359-368)
- Calculates prev/next button enabled state
- Updates pagination metadata text (e.g., "Showing 1-25 of 100 entries")

**Event Handlers:**
- **Export button:** Triggers download of `/api/cbom/export?q=...`
- **Search button:** Resets page to 1, calls `syncCbom()`
- **Prev/Next buttons:** Decrement/increment cbomPage, call `syncCbom()`
- **DOMContentLoaded:** Calls `syncCbom()` to load initial data

#### 5.3 Escaping and Security

**`esc()` function** (lines 226-231)
- HTML entity escaping for XSS protection: &, <, >, ", '
- Applied to all user-controlled fields in renderEntries

### Issues Found

#### Issue 5.1: Search parameter mismatch
**Location:** [cbom_dashboard.html](cbom_dashboard.html#L344-L347)
```javascript
const q = document.getElementById('cbomSearchInput')?.value || '';
fetch('/api/cbom/entries?page=' + ... + '&q=' + encodeURIComponent(q), ...)
```
**Problem:** API expects `search` param, not `q`.
**Impact:** Search doesn't work; API ignores `q` parameter.
**Fix:** Change line 347 to use `search` instead of `q`:
```javascript
fetch('/api/cbom/entries?page=...' + '&search=' + encodeURIComponent(q), ...)
```

#### Issue 5.2: renderEntries doesn't build X.509 details panel
**Current:** Table row renders only basic fields (asset, status, key_length, protocol, cipher, CA, expiry).
**Gap:** X.509 details in `row.certificate_details` are fetched but not displayed; template's `<details>` element remains empty.
**Fix:** Enhance renderEntries to build collapsible details HTML from certificate_details object.

#### Issue 5.3: No incremental/infinite scroll support
**Current:** Only supports page-based navigation (Prev/Next).
**Recommendation:** Add load-more button or infinite scroll for better UX on slow connections.

#### Issue 5.4: Export button doesn't disable properly
**Location:** [cbom_dashboard.html](cbom_dashboard.html#L369-L381)
```javascript
document.getElementById('exportCbomBtn').addEventListener('click', async () => {
    const btn = document.getElementById('exportCbomBtn');
    btn.disabled = true;
    btn.textContent = 'Preparing...';
    try {
        window.location.href = '/api/cbom/export?q=' + encodeURIComponent(q);
    } catch (e) {
        alert('Export failed. Check connection.');
    } finally {
        setTimeout(() => {
            btn.disabled = false;  // Re-enables after 2 seconds
            btn.textContent = 'Export CBOM JSON';
        }, 2000);
    }
});
```
**Problem:** `window.location.href` doesn't throw on network error; download happens async. Button re-enables immediately even if export failed.
**Fix:** Use fetch + blob download with proper error handling:
```javascript
try {
    const resp = await fetch('/api/cbom/export?search=...');
    if (!resp.ok) throw new Error(await resp.text());
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'cbom_export.json';
    a.click();
    URL.revokeObjectURL(url);
} catch (e) {
    alert('Export failed: ' + e.message);
} finally {
    btn.disabled = false;
    btn.textContent = 'Export CBOM JSON';
}
```

#### Issue 5.5: No visual feedback during API fetch
**Current:** State message updates but no loading spinner or progress indicator.
**Recommendation:** Add spinner animation or skeleton loaders for better perceived performance.

#### Issue 5.6: Pagination doesn't persist search term on page navigation
**Current:** `cbomPage` is in-memory; search state resets if user navigates away.
**Recommendation:** Use URL query params to persist state (e.g., `?search=...&page=2`).

---

## 6. Database Models

### Current State

**File:** [src/models.py](src/models.py#L312-L375)

#### 6.1 CBOMSummary Table

```python
class CBOMSummary(Base, SoftDeleteMixin):
    __tablename__ = 'cbom_summary'
    id = Column(BigInteger, primary_key=True)
    asset_id = Column(BigInteger, ForeignKey('assets.id'), nullable=True, index=True)
    scan_id = Column(BigInteger, ForeignKey('scans.id'), unique=True)
    total_components = Column(Integer, default=0)
    weak_crypto_count = Column(Integer, default=0)
    cert_issues_count = Column(Integer, default=0)
    json_path = Column(String(500))
```

**Use:** Scan-level aggregates (weak crypto components, cert issues).
**Unique constraint:** One CBOMSummary per Scan.

#### 6.2 CBOMEntry Table

```python
class CBOMEntry(Base, SoftDeleteMixin):
    __tablename__ = 'cbom_entries'
    id = Column(BigInteger, primary_key=True)
    scan_id = Column(BigInteger, ForeignKey('scans.id'))
    asset_id = Column(BigInteger, ForeignKey('assets.id'), nullable=True)
    
    # Asset/Element classification (CERT-IN Table 9)
    asset_type = Column(String(50))           # algorithm, key, protocol, certificate
    element_name = Column(String(255))         # e.g., "AES-128-GCM", "TLS 1.3"
    primitive = Column(String(100))            # signature, cipher, hash, kdf
    mode = Column(String(100))                 # GCM, CBC, ECB
    crypto_functions = Column(Text)            # JSON or CSV of functions
    classical_security_level = Column(Integer) # bits
    oid = Column(String(255), index=True)      # Object Identifier
    
    # Key metadata
    key_id = Column(String(255))
    key_state = Column(String(50))
    key_size = Column(Integer)
    key_creation_date = Column(DateTime, nullable=True)
    key_activation_date = Column(DateTime, nullable=True)
    
    # Protocol metadata
    protocol_name = Column(String(100))
    protocol_version_name = Column(String(50)) # TLS 1.2, TLS 1.3
    cipher_suites = Column(Text)               # CSV or JSON
    
    # Certificate metadata
    subject_name = Column(String(500))
    issuer_name = Column(String(500))
    not_valid_before = Column(DateTime, nullable=True)
    not_valid_after = Column(DateTime, nullable=True)
    signature_algorithm_reference = Column(String(255))
    subject_public_key_reference = Column(String(255))
    certificate_format = Column(String(100))   # X.509
    certificate_extension = Column(String(32)) # .crt, .der, etc.
    
    # Legacy fields
    key_length = Column(Integer)
    protocol_version = Column(String(50))
    nist_status = Column(String(50))
    quantum_safe_flag = Column(Boolean, default=False)
    hndl_level = Column(String(50))
```

**Use:** Per-asset cryptographic asset inventory with CERT-IN minimum element support.
**Indexes:** scan_id, asset_id, asset_type, oid

### Issues Found

#### Issue 6.1: `crypto_functions` and `cipher_suites` stored as Text without documented format
**Columns:** `crypto_functions` and `cipher_suites` are `Text` type.
**Problem:** Unclear if JSON, CSV, or pipe-delimited; no constraints.
**Recommendation:** Define format (JSON preferred) and validate on insert.

#### Issue 6.2: `nist_status` and `hndl_level` fields are unused
**Location:** [models.py](src/models.py#L360-L366)
**Recommendation:** Either populate them during scan ingestion or remove them.

#### Issue 6.3: No NOT NULL constraint on required CERT-IN fields
**Current:** All MINIMUM_ELEMENT_FIELDS are nullable.
**Concern:** CERT-IN compliance may require some fields to be NOT NULL.
**Recommendation:** Document which fields are truly optional; add NOT NULL where appropriate.

#### Issue 6.4: `certificate_extension` column seems designed for file extension, not X.509 extension
**Current column:** `String(32)` — actually seems sized for file extension (.crt, .der, .pem)
**Use case:** Tracking X.509 certificate extensions (Key Usage, SAN, etc.) — would need Text or JSON.
**Recommendation:** Rename or clarify purpose; consider separate `certificate_extensions_json` column for X.509 extensions.

---

## 7. Data Flow Analysis: Scan → CBOM → API → UI

```
Scan Execution (web/app.py)
    ↓
TLS Analysis → report_json with tls_results[]
    ↓
CBOM Generation (CBOMBuilder)
    ├─ Input: tls_results[], pqc_assessments[]
    ├─ Output: CBOM with assets + cert_in_inventory
    │
CBOMSummary + CBOMEntry Persistence
    ├─ CBOMBuilder.build() populates CBOM.certificates (CERT-IN typed)
    ├─ scan_certificate_and_generate_entries() maps CycloneDX → CBOMEntry rows
    └─ Database insert/update on Asset/Scan completion
    
API Requests (dashboard_api.py)
    ├─ /api/cbom/entries → CbomService.get_cbom_dashboard_data()
    │  └─ Queries Certificate + Asset + CBOMEntry tables
    │  └─ Returns paginated list + KPIs
    │
    ├─ /api/cbom/charts → CbomService.get_cbom_dashboard_data()
    │  └─ Aggregates key_length, cipher_suite, tls_version, ca distributions
    │
    └─ /api/cbom/export → JSON blob with all above
    
Frontend Rendering (cbom_dashboard.html)
    ├─ Server-render: KPI placeholders + template fallbacks
    ├─ JS DOMContentLoaded: fetch /api/cbom/metrics + /api/cbom/charts + /api/cbom/entries
    ├─ Client-side rendering: updateKpis, renderKeyLengths, renderProtocolDonut, renderEntries
    └─ User interactions: search → syncCbom(), pagination → syncCbom()
```

---

## 8. Current Gaps & Recommendations

### 8.1 **Critical Issues**

| Issue | Location | Severity | Impact |
|-------|----------|----------|--------|
| Search param mismatch (`q` vs `search`) | Frontend JS (line 347) | HIGH | Search doesn't work |
| Missing X.509 details rendering | Frontend JS (renderEntries) | HIGH | UI shows truncated details |
| `/api/cbom/export` page_size logic inverted | dashboard_api.py (line 1152) | MEDIUM | Export doesn't respect limits |

### 8.2 **Completeness Gaps**

| Gap | Recommendation |
|-----|-----------------|
| No per-asset CBOM drill-down | Extend `/api/cbom/summary?asset_id=X` endpoint |
| No export scheduling | Add scheduled CBOM export task (daily/weekly) |
| No CBOM versioning/change tracking | Add CBOM version column to CBOMSummary, track deltas |
| Minimum elements coverage is text-only | Add visual gauge/sparkline for coverage % in UI |
| No CERT-IN full compliance validation | Add validator to check all 24 fields populated before export |
| Certificate details incomplete in DB | Populate more X.509 columns during scan ingestion |

### 8.3 **UX/Performance Issues**

| Issue | Impact | Fix |
|-------|--------|-----|
| No skeleton loaders during API fetch | Perceived slowness | Add spinner/skeleton to chart cards + table |
| Page state doesn't persist in URL | Search/sort lost on reload | Use query params (e.g., `?search=term&sort=key_length&order=desc&page=2`) |
| Field coverage calculation runs 24+ queries | Slow API response (1000s of entries) | Optimize with single GROUP BY + CASE |
| Search uses ILIKE without index hints | Full-table scan on large inventory | Use indexed columns only or add FULLTEXT index |
| Export doesn't paginate on large datasets | Memory/timeout on 10k+ entries | Implement streaming export or limit to 1000 entries |
| No caching on API responses | Redundant DB queries per request | Cache `/api/cbom/charts`, `/api/cbom/metrics` with 5-minute TTL |

### 8.4 **Consistency with Other Dashboards**

**Recommendation:** CBOM dashboard should align with **PQC Posture** and **Asset Inventory** dashboards:

- **Search params:** All should use `search` (not `q`)
- **Sort params:** Standardize sort column names across all dashboards
- **Export format:** JSON response bodies should match envelope structure
- **Chart rendering:** Use shared chart library or D3 wrappers for consistency
- **Table styling:** Use shared table macro and pagination controls
- **Empty states:** Standardized messaging and skeleton loading

---

## 9. Files to Rewrite/Refactor

### 9.1 **High Priority**

1. **[web/templates/cbom_dashboard.html](web/templates/cbom_dashboard.html)**
   - Fix search param from `q` to `search` (line 347)
   - Fix hardcoded bar width and conic-gradient (lines 103-106)
   - Add skeleton loaders during API fetch
   - Enhance renderEntries to build X.509 details panel from certificate_details
   - Use URL query params to persist search/sort/page state
   - Fix export function to use fetch + blob download with proper error handling

2. **[web/routes/dashboard_api.py](web/routes/dashboard_api.py)**
   - Fix `/api/cbom/export` page_size logic (line 1152): `max()` → `min()`
   - Extend `/api/cbom/charts` to accept optional `asset_id`, `start_date`, `end_date` filters
   - Return non-empty items array from `/api/cbom/metrics` (line 985)
   - Add rate-limiting or caching to `/api/cbom/export`

3. **[src/services/cbom_service.py](src/services/cbom_service.py)**
   - Add `.order_by(Certificate.key_length.asc())` to key_length_distribution query (line 705)
   - Optimize field coverage calculation: use single query instead of 24+
   - Enrich `_build_applications_query` to include AssetMetric + PQCClassification joins
   - Add `asset_detail_url` to applications response payload

### 9.2 **Medium Priority**

4. **[src/cbom/builder.py](src/cbom/builder.py)**
   - Change TLS↔PQC pairing from index-based to endpoint-identity based (host:port matching)
   - Add validation of required CERT-IN fields before finalizing CBOM
   - Document property namespace; define constant prefix

5. **[src/cbom/cyclonedx_generator.py](src/cbom/cyclonedx_generator.py)**
   - Enrich CycloneDX properties with CERT-IN minimum element fields if compliance required
   - Add validation of export format before output

6. **[src/models.py](src/models.py)**
   - Document `crypto_functions` and `cipher_suites` format (JSON preferred)
   - Add NOT NULL constraints to required CERT-IN fields
   - Clarify/rename `certificate_extension` if it's not file extension
   - Populate `nist_status` and `hndl_level` during ingestion, or remove

---

## 10. Summary Table: Component Health

| Component | Completeness | Correctness | Performance | UX | Maintainability |
|-----------|--------------|-------------|-------------|-----|-----------------|
| Template | 85% | 70% | 70% | 75% | 75% |
| API Routes | 90% | 75% | 70% | N/A | 80% |
| Service Layer | 85% | 80% | 60% | N/A | 80% |
| CBOM Builder | 80% | 75% | N/A | N/A | 70% |
| CycloneDX Gen | 80% | 85% | N/A | N/A | 70% |
| Database Models | 85% | 80% | N/A | N/A | 75% |
| Frontend JS | 75% | 70% | 70% | 70% | 70% |

**Overall Grade: B+ (82%)**

---

## Appendix A: Quick Reference — API Endpoint Examples

### Fetch CBOM KPIs
```bash
curl -X GET "http://localhost:5000/api/cbom/metrics?page=1&page_size=25"
```

### Search CBOM Entries
```bash
curl -X GET "http://localhost:5000/api/cbom/entries?search=letsencrypt&page=1&page_size=50&sort=key_length&order=desc"
```

### Export Full CBOM JSON
```bash
curl -X GET "http://localhost:5000/api/cbom/export" -o cbom_export.json
```

### Get Minimum Elements Coverage
```bash
curl -X GET "http://localhost:5000/api/cbom/minimum-elements?page=1&page_size=100"
```

---

## Appendix B: CERT-IN Table 9 Minimum Element Fields

All 24 required fields for PNB compliance:

1. **asset_type** — Algorithm, key, protocol, or certificate
2. **element_name** — e.g., "AES-128-GCM"
3. **primitive** — Signature, cipher, hash, KDF
4. **mode** — GCM, CBC, ECB, etc.
5. **crypto_functions** — Supported operations
6. **classical_security_level** — Bits
7. **oid** — Object Identifier
8. **key_id** — Key reference
9. **key_state** — Active, revoked, expired
10. **key_size** — Bits
11. **key_creation_date** — ISO timestamp
12. **key_activation_date** — ISO timestamp
13. **protocol_name** — TLS, SSH, IPsec
14. **protocol_version_name** — TLS 1.2, TLS 1.3
15. **cipher_suites** — Supported suites
16. **subject_name** — Certificate subject DN
17. **issuer_name** — CA issuer DN
18. **not_valid_before** — Validity start
19. **not_valid_after** — Validity end
20. **signature_algorithm_reference** — RSA-SHA256, etc.
21. **subject_public_key_reference** — Key algorithm + size
22. **certificate_format** — X.509, PEM, DER
23. **certificate_extension** — File extension or X.509 extensions
24. **certificate_subject_key_id** — X.509 extension (computed)

**Current Coverage:** ~18 fields persisted; 6 missing or incomplete.

