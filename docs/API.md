# QuantumShield API Reference

## V2 Refactor Reference (Inventory-Centric, API-First)

For the strict GLOBAL_APP_REFACTOR_V2 contract (inventory-only KPI scope, no hardcoded metrics, universal envelope, per-page endpoint matrix, and SQL/data-flow guardrails), see:

- `docs/GLOBAL_APP_REFACTOR_V2.md`
- `schema_v2_inventory_api_first.sql`

## Base URL

```
http://127.0.0.1:5000
```

---

## Endpoints

### `GET /api/dashboard` *(Primary Dashboard API)*

Single endpoint for unified dashboard state (inventory, dashboard metrics, recent scans, scan status).

Query params:
- `include_discovery=true|false`

Example:
```bash
curl -X GET http://127.0.0.1:5000/api/dashboard
```

---

### `POST /api/dashboard` *(Primary Action API)*

Single action endpoint for scan + dashboard operations.

Request body must include `action`.

Supported actions:
- `dashboard.refresh`
- `scan.run`
- `scan.inventory.all`
- `scan.inventory.status`
- `scan.inventory.asset`
- `scan.inventory.history`
- `scan.inventory.schedule.get`
- `scan.inventory.schedule.set`

Example (refresh):
```bash
curl -X POST http://127.0.0.1:5000/api/dashboard \
  -H "Content-Type: application/json" \
  -d '{"action":"dashboard.refresh","include_discovery":true}'
```

Example (run one scan):
```bash
curl -X POST http://127.0.0.1:5000/api/dashboard \
  -H "Content-Type: application/json" \
  -d '{"action":"scan.run","target":"example.com"}'
```

---

### Deprecated compatibility endpoints

The following still work, but are deprecated and return deprecation metadata/headers:
- `POST /api/inventory/scan` → use `POST /api/dashboard` with `action=scan.inventory.all`
- `GET /api/inventory/scan-status` → use `POST /api/dashboard` with `action=scan.inventory.status`
- `POST /api/inventory/asset/<id>/scan` → use `POST /api/dashboard` with `action=scan.inventory.asset`
- `GET /api/inventory/asset/<id>/history` → use `POST /api/dashboard` with `action=scan.inventory.history`
- `GET|POST /api/inventory/schedule` → use `POST /api/dashboard` with `action=scan.inventory.schedule.get|set`
- `GET /api/discovery-graph` → use `POST /api/dashboard` with `action=dashboard.refresh` and `include_discovery=true`

---

### Scan Center (API-first)

**Canonical UI route:** `GET /scans`  
**Legacy compatibility route:** `GET /scan-center` (same scan center view)

Role access:
- Single scan: `Admin`, `Manager`, `SingleScan`, `Viewer`
- Bulk scan and scheduling: `Admin`, `Manager`

#### `GET /api/scans`

Returns scan history (paginated mode) and supports filtering/sorting.

Query params:
- `page` (default `1`)
- `page_size` (default `25`, max `250`)
- `q` (search in scan_id, target, status)
- `status` (`running|completed|failed`)
- `sort` (`scan_id|target|status|assets_found|pqc_score|date`)
- `order` (`asc|desc`)

#### `POST /api/scans`

Queue a single scan.

Body fields:
- `target` (required)
- `ports` (optional list or comma-string)
- `autodiscovery` (optional bool)
- `add_to_inventory` (optional bool)
- `owner`, `risk_level`, `notes` (optional inventory metadata)
- `asset_class_mode` (`auto|manual`)
- `asset_class_value` (required when manual mode)

#### `POST /api/scans/bulk`

Queue sequential bulk scans (Admin/Manager only).

Body fields:
- `targets` (required array)
- `target_entries` (optional array of `{target, ports}`; supports per-target ports, preferred for CSV uploads)
- `ports` (optional list/comma-string)
- `autodiscovery` (optional bool)
- `add_to_inventory` (optional bool)
- `owner`, `risk_level`, `notes` (optional inventory metadata)
- `asset_class_mode` (`auto|manual`)
- `asset_class_value` (manual override)

#### `GET /api/scans/<scan_id>/status`

Live status for queued/running/completed/failed scan jobs.

#### `GET /api/scans/metrics`

Operational scan center KPIs (total/completed/running/failed, recent activity, success rate, PQC average).

#### `GET /api/scans/<scan_id>/certificates`

Detailed SSL/TLS certificate inventory for a scan result.

Query params:
- `page` (default `1`)
- `page_size` (default `25`, max `200`)
- `q` or `search` (issuer/subject/endpoint/fingerprint match)
- `sort` (`valid_until|issuer|subject_cn|tls_version|key_length|endpoint|status`)
- `order` (`asc|desc`)

#### Scan schedules

- `GET /api/scan-schedules` (Admin/Manager)
- `POST /api/scan-schedules` (Admin/Manager)
- `DELETE /api/scan-schedules/<schedule_id>` (Admin/Manager)

---

### Recycle Bin & Asset Deletion

**All inventory deletions use soft deletes** — deleted assets, scans, and related records are marked as deleted without physical removal. This allows recovery via the Recycle Bin.

#### `GET /recycle-bin`

View soft-deleted assets and scans.

**Authentication:** Required (all users can view)

**Permissions:**
- View: All authenticated users
- Restore: Admin, Manager
- Permanently Delete: Admin only

**Response:** HTML page showing deleted assets and scans with restore/delete buttons.

---

#### `POST /recycle-bin`

Restore or permanently delete soft-deleted items.

**Query/Form Parameters:**

| Parameter | Type | Required | Values | Description |
|-----------|------|----------|--------|-------------|
| `action` | string | ✅ | `restore_assets`, `restore_scans`, `delete_assets`, `delete_scans` | Operation to perform |
| `asset_ids` or `scan_ids` | array | ✅ | IDs | Which items to act on |

**Actions:**

- `restore_assets`: Restore deleted assets (Admin/Manager only)
  - Clears `is_deleted`, `deleted_at`, `deleted_by_user_id` flags
  - Cascades restoration to child records (discovery_items, certificates, etc.)
  
- `restore_scans`: Restore deleted scans (Admin/Manager only)
  - Clears soft-delete markers
  
- `delete_assets`: Permanently purge soft-deleted assets (Admin only)
  - Hard DELETE from database with cascade to child records
  - Irreversible action — requires admin confirmation
  
- `delete_scans`: Permanently purge soft-deleted scans (Admin only)
  - Hard DELETE with full cascade

**Example:**
```bash
# Restore asset ID 42
curl -X POST http://127.0.0.1:5000/recycle-bin \
  -d "action=restore_assets&asset_ids=42"

# Permanently delete asset ID 42 (Admin only)
curl -X POST http://127.0.0.1:5000/recycle-bin \
  -d "action=delete_assets&asset_ids=42"
```

---

#### Dashboard Asset Deletion: `POST /dashboard/assets/<asset_id>/delete`

Soft-delete an asset immediately (moves to recycle bin).

**Authentication:** Required

**Permissions:** Admin, Manager

**Behavior:**
- Sets `is_deleted=True`, `deleted_at=NOW()`, `deleted_by_user_id=<current_user>`
- Cascades soft delete to:
  - `discovery_items` (network discoveries tied to asset)
  - `certificates` (TLS certs associated with asset)
  - `pqc_classifications` (PQC posture records)
  - `cbom_entries` (CBOM component entries)
  - `compliance_scores` (compliance metrics)
- Asset remains recoverable from `/recycle-bin`

**Response:** Redirect to previous page or `/asset-inventory` on success

---

### Soft Delete Behavior (All Endpoints)

**Query Filtering:**
- All inventory queries (asset lists, dashboards, charts) automatically exclude soft-deleted rows (`WHERE is_deleted = 0`)
- Deleted rows do NOT appear in counts, charts, or inventory listings

**CBOM import/scans included:**
- Certificates from deleted assets are not included in TLS metrics
- PQC scores exclude deleted records
- Compliance charts exclude deleted asset data

**Affected Entities:**
- `assets` — host/domain/IP records
- `scans` — scan run records
- `certificates` — TLS certificate metadata
- `discovery_items` — network discovery findings
- `pqc_classifications` — quantum-safe classification records
- `cbom_entries` — component BOM entries
- `compliance_scores` — compliance/KPI records

---



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

**REST API (CI/CD) — run a scan and get JSON results.**

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

**List stored scan results (scan center / automation).**

```bash
curl "http://127.0.0.1:5000/api/scans?page=1&page_size=25&sort=date&order=desc"
```

**Response (200, paginated mode):**
```json
{
  "items": [
    {
      "scan_id": "abc12345",
      "target": "google.com",
      "status": "completed",
      "assets_found": 1,
      "pqc_score": 83.5,
      "started_at": "2026-03-02T04:49:48+00:00",
      "completed_at": "2026-03-02T04:50:02+00:00",
      "date": "2026-03-02T04:49:48+00:00",
      "actions": "/results/abc12345"
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 25,
  "total_pages": 1,
  "kpis": {
    "total_scans": 1,
    "completed": 1,
    "running": 0
  }
}
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
