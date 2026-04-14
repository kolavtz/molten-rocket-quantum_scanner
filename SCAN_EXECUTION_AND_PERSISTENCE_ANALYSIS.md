# Scan Execution & Persistence Code Analysis

**Date:** 2026-04-13  
**Purpose:** Map SSL/TLS certificate and discovery result fetching, parsing, and database persistence.

---

## 1. MAIN SCAN ORCHESTRATION

### Primary Entry Point: `run_scan_pipeline()`

| Location | Function | Purpose |
|----------|----------|---------|
| [web/app.py](web/app.py#L1560) Line 1560 | `run_scan_pipeline(target, ports=None, asset_class_hint=None, scan_kind="manual", scanned_by=None, add_to_inventory=False)` | Main scan orchestrator. Enforced workflow: Discovery → TLS Analysis → PQC Detection → Risk Scoring → CBOM Generation → SQL persistence → Response |
| [src/services/inventory_scan_service.py](src/services/inventory_scan_service.py#L55) Line 55 | `run_scan_pipeline(target, ports, options, scan_runner)` | Service-level wrapper that validates targets, defaults to `web.app.run_scan_pipeline` as runner, persists raw JSON artifact in `scan_results/` |
| [src/services/inventory_scan_service.py](src/services/inventory_scan_service.py#L89) Line 89 | `submit_scan_pipeline(...)` | Queues execution on shared `ThreadPoolExecutor` (async background runner) |

### Service Discovery Phase

| Location | Code | Purpose |
|----------|------|---------|
| [web/app.py](web/app.py#L1568) Line 1568-1580 | `scanner.discover_services(target, ports)` | Broad port sweep using `NetworkScanner` → returns `Endpoint[]` with `host`, `port`, `service`, `is_tls`, `banner` |
| [web/app.py](web/app.py#L1586) Line 1586-1603 | Fallback: `scanner.discover_targets(target, ports)` | If no TLS from discover_services, try deeper discovery |
| [web/app.py](web/app.py#L1610) Line 1610-1617 | Last resort: Direct `analyze_endpoint(target, 443)` | If all discovery fails, try port 443 directly |

---

## 2. SSL/TLS CERTIFICATE FETCHING & PARSING

### TLS Analysis Phase

| Location | Code | When It Runs | Input | Output |
|----------|------|--------------|-------|--------|
| [web/app.py](web/app.py#L1619) Line 1619-1626 | `analyzer.analyze_endpoint(ep.host, ep.port)` for each endpoint | For each TLS-capable endpoint discovered | `host`, `port` | `TLSEndpointResult` object |
| [web/app.py](web/app.py#L1627) Line 1627 | `_normalize_tls_result(result.to_dict())` | After successful analysis | `TLSEndpointResult` | Normalized dict with TLS fields |

### TLS Analyzer Implementation

| File | Line | Function | Purpose |
|------|------|----------|---------|
| [src/scanner/tls_analyzer.py](src/scanner/tls_analyzer.py#L270) | L270-620 | `TLSAnalyzer.analyze_endpoint(host, port)` | Orchestrates TLS analysis using stdlib + SSLyze |
| [src/scanner/tls_analyzer.py](src/scanner/tls_analyzer.py#L344) | L344-360 | `_analyze_with_stdlib(result, host, port)` | Uses Python `ssl` module to fetch certificate via TLS handshake |
| [src/scanner/tls_analyzer.py](src/scanner/tls_analyzer.py#L377) | L377-420 | `_parse_stdlib_cert(cert_dict, cert_der)` | Parses certificate fields: CN, O, OU, serial, validity dates, key length, fingerprints |

### Certificate Parsing Details

**Extracted from TLS handshake:**
- **Subject:** `CN`, `O`, `OU` (organization unit)
- **Issuer:** `CN`, `O`, `OU`
- **Validity:** `valid_from_dt`, `valid_until_dt`
- **Key Info:** `key_type`, `key_length` (bits)
- **Fingerprints:** `fingerprint_sha256`, `fingerprint_sha1`, `fingerprint_md5`
- **Certificate Details:** Full JSON dump in `certificate_details`
- **TLS Info:** `protocol_version`, `cipher_suite`, `supported_protocols`
- **Extensions:** `san_domains` (Subject Alternative Names)

---

## 3. DATABASE PERSISTENCE — CORE FLOW

### Step 1: Scan Record Creation

| Location | Line | Code | Table | Operation |
|----------|------|------|-------|-----------|
| [web/app.py](web/app.py#L1731) | L1731-1747 | `db_scan = Scan(...)` | `scans` | **ORM object creation** (not yet in DB) |
| [web/app.py](web/app.py#L1748) | L1748 | `db_session.add(db_scan)` | `scans` | Add to session |
| [web/app.py](web/app.py#L1749) | L1749 | `db_session.flush()` | `scans` | **INSERT into DB**, assign auto-increment `id` |

**Fields persisted:**
- `scan_id` (UUID short, 8 chars)
- `target` (canonical hostname)
- `status` = "complete" / "failed"
- `asset_class` (deduced from discovery)
- `started_at`, `completed_at`, `scanned_at`
- `total_assets` (count of discovered services)
- `compliance_score`, `overall_pqc_score`
- `cbom_path` (file path to JSON)
- `report_json` (full scan report as JSON blob)

### Step 2: Asset Resolution/Creation

| Location | Line | Code | Purpose |
|----------|------|------|---------|
| [web/app.py](web/app.py#L1780) | L1780-1830 | `Asset.query.filter(...).first()` or `Asset(...)` | Idempotent asset fetch/create by canonical target |
| | L1830 | `db_session.add(asset_obj)` | Add new asset if not found |
| | L1835 | `db_session.flush()` | **INSERT/UPDATE asset** |

**Asset fields:**
- `name` / `target` (canonical hostname)
- `asset_class` (inferred)
- `owner` (from scan metadata)
- `risk_level`
- `notes`

### Step 3: Certificate Persistence (ORM + SQL)

#### **ORM Path (Primary)** — [web/app.py](web/app.py#L1840) L1840-1930

```python
# For each TLS result:
cert_obj = Certificate(
    asset_id=asset_id,          # Foreign key to assets.id
    scan_id=scan_pk,            # Foreign key to scans.id
    endpoint="host:port",
    issuer="CN=..., O=...",
    subject="CN=..., O=...",
    serial=tls.get("serial_number"),
    valid_from=tls.get("valid_from_dt"),
    valid_until=tls.get("valid_until_dt"),
    fingerprint_sha256=normalized_fp,
    tls_version=tls.get("protocol_version"),
    key_length=int(tls.get("key_length", 0)),
    cipher_suite=tls.get("cipher_suite"),
    certificate_details=details_json_text,
    # ... other fields
)
db_session.add(cert_obj)  # L1929
db_session.flush()        # L1932 — **INSERT into certificates table**
```

| Table | Fields Persisted | Line | Operation |
|-------|------------------|------|-----------|
| `certificates` | asset_id, scan_id, endpoint, issuer, subject, serial, valid_from, valid_until, fingerprint_sha256/sha1/md5, tls_version, cipher_suite, key_length, is_expired, is_self_signed, certificate_details, san_domains | 1908-1930 | **ORM INSERT via db_session.add()** |

#### **Raw SQL Path (Alternative)** — [src/scanner/ssl_worker.py](src/scanner/ssl_worker.py#L127) L127-269

Used by standalone SSL worker for certificate persistence:

```sql
INSERT INTO certificates (
    asset_id, scan_id, issuer, subject, subject_cn, serial, valid_from, valid_until,
    fingerprint_sha256, fingerprint_sha1, fingerprint_md5, tls_version, key_length,
    cipher_suite, signature_algorithm, ca, san_domains, certificate_details,
    dedup_algorithm, dedup_value, dedup_hash, is_current, first_seen_at, last_seen_at
) VALUES (...)
```

| File | Line | Operation | Purpose |
|------|------|-----------|---------|
| [src/scanner/ssl_worker.py](src/scanner/ssl_worker.py#L162) | L162-185 | Raw SQL `INSERT ...` | Bulk certificate insert with dedup tracking |
| [src/scanner/ssl_worker.py](src/scanner/ssl_worker.py#L158) | L158-161 | `UPDATE certificates SET is_current=0 WHERE asset_id=...` | Mark previous certificates as outdated |

---

## 4. DISCOVERY TABLE PERSISTENCE

### Discovery Tables Summary

| Table | Purpose | Fields | Persisted By |
|-------|---------|--------|--------------|
| `discovery_ssl` | TLS/certificate discovery results | endpoint, tls_version, cipher_suite, key_length, subject_cn, issuer, valid_until, pqc_score, **pqc_assessment**, status, promoted_to_inventory, promoted_at | [web/app.py](web/app.py#L1204) L1204-1243 |
| `discovery_domains` | Domain names (primary + SAN) | domain, status, promoted_to_inventory, promoted_at | [web/app.py](web/app.py#L1029) L1029-1048 |
| `discovery_ips` | IP addresses resolved | ip_address, subnet, location, status, promoted_to_inventory | [web/app.py](web/app.py#L1080) L1080-1110 |
| `discovery_software` | Services/software detected | product, version, port, category, status | (implied in `_persist_split_discovery_rows`) |

### Discovery Persistence Function

| Location | Function | Purpose |
|----------|----------|---------|
| [web/app.py](web/app.py#L1018) | `_persist_split_discovery_rows(scan_pk, asset_id, target, discovered_services, tls_results, pqc_assessments, location_points, promoted_to_inventory=False)` | **Master discovery INSERT function** |

**Called from:**
- [web/app.py](web/app.py#L2295) L2295 — Main `run_scan_pipeline()`

**Entry Point:**
```python
_persist_split_discovery_rows(
    scan_pk=scan_pk,
    asset_id=asset_id,
    target=target,
    tls_results=tls_results,
    pqc_assessments=pqc_dicts,
    discovered_services=discovered_services,
    location_points=location_points,
    promoted_to_inventory=add_to_inventory,
)
```

### Discovery SSL Insert — [web/app.py](web/app.py#L1204) L1204-1243

```sql
INSERT INTO discovery_ssl (
    scan_id, asset_id, endpoint, tls_version, cipher_suite, key_exchange,
    key_length, subject_cn, issuer, valid_until, pqc_score, pqc_assessment, status,
    promoted_to_inventory, promoted_at, created_at, updated_at, is_deleted
) VALUES (...)
```

**Key Points:**
- One row per TLS endpoint discovered
- Includes `pqc_score` and `pqc_assessment` from PQC detector
- `promoted_to_inventory` flag when asset is added to inventory

### Discovery Domains Insert — [web/app.py](web/app.py#L1029) L1029-1048

```sql
INSERT INTO discovery_domains (
    scan_id, asset_id, domain, status, promoted_to_inventory,
    promoted_at, created_at, updated_at, is_deleted
) VALUES (...)
```

**Domains included:**
- Primary target hostname
- All SANs from discovered certificates

### Discovery IPs Insert — [web/app.py](web/app.py#L1080) L1080-1110

```sql
INSERT INTO discovery_ips (
    scan_id, asset_id, ip_address, subnet, location, status,
    promoted_to_inventory, promoted_at, created_at, updated_at, is_deleted
) VALUES (...)
```

---

## 5. PQC & FINDINGS PERSISTENCE

### PQC Classification

| Location | Line | Table | Operation |
|----------|------|-------|-----------|
| [web/app.py](web/app.py#L1940) | L1940-1953 | `pqc_classifications` | ORM `PQCClassification` object creation and INSERT |

```python
for pq in pqc_dicts:
    pqc_obj = PQCClassification(
        scan_id=scan_pk,
        asset_id=asset_id,
        algorithm_name=pq.get("algorithm"),
        algorithm_type=pq.get("category"),
        quantum_safe_status=pq.get("status"),
        nist_category=pq.get("nist_status"),
        pqc_score=float(pq.get("score", 0))
    )
    db_session.add(pqc_obj)
```

### Findings Detection & Persistence

| Location | File | Purpose | When Called |
|----------|------|---------|-------------|
| [src/services/finding_detection_service.py](src/services/finding_detection_service.py#L30) | Line 30-80 | `FindingDetectionService.detect_and_store_findings(asset_id, scan_id)` | After certificate persistence |
| | | **Detects:** expired certs, weak TLS versions, weak key lengths, self-signed certs | Post-scan |
| | | **Creates:** `Finding` ORM objects and INSERTs to `findings` table | Batch create |

```python
finding_obj = Finding(
    asset_id=asset_id,
    scan_id=scan_id,
    certificate_id=cert.id,
    issue_type=finding["issue_type"],  # e.g., "expired_certificate"
    severity=finding["severity"],      # HIGH, MEDIUM, LOW
)
db_session.add(finding_obj)
```

---

## 6. DB COMMIT & TRANSACTION

### Final Commit

| Location | Line | Code | Effect |
|----------|------|------|--------|
| [web/app.py](web/app.py#L2322) | L2322 | `db_session.commit()` | **COMMIT all INSERTs to MySQL** |
| | | | All `db_session.add()` calls are now persisted |
| | | | Discovery, certificates, PQC, findings all in DB |

### Exception Handling

| Location | Line | Behavior |
|----------|------|----------|
| [web/app.py](web/app.py#L2232-2330) | L2232-L2330 | **Try/except block** — if any persistence fails, sets `orm_persisted=False` in report and logs error |
| | | **Note:** Exceptions DO NOT rollback scan creation (scan still marked "complete" in DB) |

---

## 7. IN-MEMORY STORAGE & RESPONSE FLOW

### In-Memory Store Update

| Location | Line | Code | Purpose |
|----------|------|------|---------|
| [web/app.py](web/app.py#L2328) | L2328 | `scan_store[scan_id] = report` | Cache scan report dict in memory |
| | | | Used for immediate `/results` page load without re-query |

### Response to Frontend

| Location | Route | Response | Contains |
|----------|-------|----------|----------|
| [web/routes/scans.py](web/routes/scans.py#L1001) | `POST /api/scans` | Full `report` dict | `scan_id`, `status`, `tls_results`, `pqc_assessments`, `discovered_services`, **discovered_ssl** (from DB) |
| [web/app.py](web/app.py#L4514) | `GET /results/<scan_id>` | Rendered `results.html` | Template displays report + live DB queries for certificates/discovery |

---

## 8. POTENTIAL DISCONNECTS & ISSUES

### ✅ **Correct Flow: ORM Path**
1. **Fetch** → `TLSAnalyzer.analyze_endpoint()` gets real certificates from network
2. **Parse** → `_parse_stdlib_cert()` extracts fields
3. **Persist (DB)** → `Certificate(...)` + `db_session.add()` + `db_session.flush()`
4. **Persist (Discovery)** → `_persist_split_discovery_rows()` INSERTs into `discovery_ssl`
5. **Response** → Report dict contains scan info; UI queries DB for latest status
6. **Commit** → `db_session.commit()` finalizes all writes

### ⚠️ **Potential Issue #1: Scan Marked Complete Before Persistence**

| Location | Line | Issue |
|----------|------|-------|
| [web/app.py](web/app.py#L1739) | L1739 | `status="complete"` set when Scan ORM object created, **NOT** verified after persistence |
| | L1749 | Flush happens, but if later INSERT fails, scan is still "complete" in DB |

**Consequence:** 
- Scan shows "complete" even if certificates/discovery INSERTs failed
- Frontend sees scan complete but no discovery data

### ⚠️ **Potential Issue #2: Exception Handling Doesn't Rollback**

| Location | Line | Issue |
|----------|------|-------|
| [web/app.py](web/app.py#L2232) | L2232 | Wrapped in try/except, but **no rollback on exception** |
| | | If Certificate INSERT fails, Scan is still in DB |

**Consequence:**
- Orphaned scan records with missing certificates
- `orm_persisted` field set to False but scan status still "complete"

### ⚠️ **Potential Issue #3: Raw SQL Worker vs. ORM Mismatch**

| Location | Purpose | Risk |
|----------|---------|------|
| [src/scanner/ssl_worker.py](src/scanner/ssl_worker.py#L127) | Standalone certificate persistence using raw SQL | Different INSERT logic than ORM path — may have schema drift |
| | | Dedup algorithm (`compute_dedup_values()`) shared, but field mappings could diverge |

### ⚠️ **Potential Issue #4: Discovery Tables Not Always Persisted**

| Location | Line | Condition |
|----------|------|-----------|
| [web/app.py](web/app.py#L1008) | L1008 | `_persist_split_discovery_rows()` only called if `_db_table_exists("discovery_ssl")` |
| | | If table doesn't exist, **discovery table INSERTs are skipped silently** |

**Consequence:**
- Some environments may lack discovery tables
- Tests may fail due to missing data

### ✅ **Correct Behavior: Async Background Scan**

| File | Location | Behavior |
|------|----------|----------|
| [web/routes/scans.py](web/routes/scans.py#L694) | L694-760 | `_process_job()` runs scan pipeline and calls `db.save_scan(report)` if `not report.get("orm_persisted")` |
| | | Ensures double-persistence: ORM path in pipeline + DB wrapper for safety |

---

## 9. SUMMARY TABLE: ALL PERSIST POINTS

| Component | Table | Persist Method | Location | Line | Committed By |
|-----------|-------|-----------------|----------|------|--------------|
| Scan Record | `scans` | ORM add/flush | web/app.py | 1748-1749 | db_session.commit() L2322 |
| Asset | `assets` | ORM add/flush | web/app.py | 1830 | db_session.commit() L2322 |
| Certificate | `certificates` | ORM add/flush | web/app.py | 1929-1932 | db_session.commit() L2322 |
| PQC Classification | `pqc_classifications` | ORM add/flush | web/app.py | 1950-1952 | db_session.commit() L2322 |
| CBOM Summary | `cbom_summaries` | ORM add/flush | web/app.py | 1958-1962 | db_session.commit() L2322 |
| Discovery SSL | `discovery_ssl` | Raw SQL INSERT | web/app.py | 1204-1243 | db_session.execute() L1243 |
| Discovery Domains | `discovery_domains` | Raw SQL INSERT | web/app.py | 1029-1048 | db_session.execute() L1048 |
| Discovery IPs | `discovery_ips` | Raw SQL INSERT | web/app.py | 1080-1110 | db_session.execute() L1110 |
| Findings | `findings` | ORM add | src/services/finding_detection_service.py | 30-80 | Service caller commits |

---

## 10. VALIDATION CHECKLIST

- [ ] **Network Discovery** — `NetworkScanner.discover_services()` returns real endpoints
- [ ] **TLS Analysis** — `TLSAnalyzer.analyze_endpoint()` fetches real certificates via socket
- [ ] **Certificate Fields** — All subject, issuer, validity, fingerprints, extensions parsed correctly
- [ ] **Scan Record** — INSERT happens with `db_session.flush()` at L1749
- [ ] **Asset Record** — Created/found idempotently at L1780-1835
- [ ] **Certificate Rows** — Inserted at L1908-1932 with full certificate details as JSON
- [ ] **Discovery SSL** — Inserted at L1204-1243 with PQC scores
- [ ] **Discovery Domains** — Inserted at L1029-1048 with primary + SANs
- [ ] **Discovery IPs** — Inserted at L1080-1110 with geolocation if available
- [ ] **PQC Classifications** — Inserted at L1940-1953
- [ ] **Findings** — Created and persisted via `FindingDetectionService`
- [ ] **DB Commit** — All changes committed at L2322
- [ ] **Response** — Scan report dict returned with `orm_persisted=True` if successful

---

## 11. KEY FILE REFERENCES

**Core Scan Orchestration:**
- [web/app.py](web/app.py#L1560-L2330) — `run_scan_pipeline()` function (Full pipeline)
- [src/services/inventory_scan_service.py](src/services/inventory_scan_service.py#L55-L100) — Service-level wrapper

**TLS Analysis:**
- [src/scanner/tls_analyzer.py](src/scanner/tls_analyzer.py#L270-L620) — TLS endpoint analysis
- [src/scanner/network_discovery.py](src/scanner/network_discovery.py) — Service discovery

**Persistence:**
- [web/app.py](web/app.py#L1018-L1240) — `_persist_split_discovery_rows()` (Discovery table INSERTs)
- [src/models.py](src/models.py#L210-L330) — ORM models (Certificate, Asset, Scan, Discovery tables)
- [src/database.py](src/database.py#L1136) — Database initialization

**Findings & PQC:**
- [src/services/finding_detection_service.py](src/services/finding_detection_service.py#L1-L100) — Finding creation
- [src/services/pqc_calculation_service.py](src/services/pqc_calculation_service.py) — PQC metrics

**API Routes:**
- [web/routes/scans.py](web/routes/scans.py#L1-L50) — Scan API endpoints
- [web/blueprints/api_assets.py](web/blueprints/api_assets.py#L245) — Discovery API returns

---

**End of Analysis**
