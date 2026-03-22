# QuantumShield API Inventory-First SQL Contract (GLOBAL_APP_REFACTOR_V2)

Date: 2026-03-22

This document defines the strict implementation contract for all pages:

- Home
- Asset Inventory
- Asset Discovery
- CBOM
- PQC Posture
- Cyber Rating
- Reporting
- Admin
- Docs

## 1) Hard enforcement rules

1. No hardcoded KPI/chart/table values.
2. `assets` (non-deleted only) is the single in-scope estate.
3. Any telemetry row contributes only when it links to active inventory:
	 - `JOIN assets a ON a.id = t.asset_id AND a.is_deleted = FALSE`
4. API-first flow is mandatory:
	 - Frontend → API endpoint → SQL query → JSON envelope → frontend render.
5. Universal list response envelope:

```json
{
	"success": true,
	"data": {
		"items": [],
		"total": 0,
		"page": 1,
		"page_size": 25,
		"total_pages": 1,
		"kpis": {}
	},
	"filters": {
		"sort": "id",
		"order": "asc",
		"search": ""
	}
}
```

## 2) Table classes

### Inventory-sourced (in-scope for enterprise dashboards)

- `assets`
- `certificates`
- `pqc_classification`
- `cbom_summary`
- `cbom_entries`
- `compliance_scores`
- `cyber_rating`
- `discovery_*` rows only when `asset_id` points to active `assets`

### Transient scan/discovery (out-of-scope until promoted)

- `discovery_domains`
- `discovery_ssl`
- `discovery_ips`
- `discovery_software`

Rows with `asset_id IS NULL` and/or `promoted_to_inventory = FALSE` are visible in Discovery page but excluded from Home/CBOM/PQC/Cyber/Reporting KPIs.

## 3) Common request parameters

All list endpoints accept:

- `page` (default `1`)
- `page_size` (default `25`, max `250`)
- `sort` (whitelisted only)
- `order` (`asc|desc`)
- `q` (search)

SQL pagination pattern:

```sql
... ORDER BY <whitelisted_column> <ASC|DESC>
LIMIT :page_size OFFSET :offset
```

## 4) Endpoint matrix with SQL query shapes

The SQL below is canonical query shape (parameterized), not hardcoded literal SQL.

### Home

#### `GET /api/home/metrics`

KPIs:

- `total_assets`
- `total_scans`
- `quantum_safe_percent`
- `vulnerable_assets_count`
- `average_pqc_score`

Query shapes:

```sql
SELECT COUNT(*) AS total_assets
FROM assets a
WHERE a.is_deleted = FALSE;

SELECT COUNT(*) AS total_scans
FROM scans s
WHERE s.is_deleted = FALSE;

SELECT
	COALESCE(AVG(CASE
		WHEN LOWER(p.quantum_safe_status) IN ('safe','quantum_safe','quantum-safe') THEN 100
		ELSE 0
	END), 0) AS quantum_safe_percent
FROM pqc_classification p
JOIN assets a ON a.id = p.asset_id
WHERE p.is_deleted = FALSE
	AND a.is_deleted = FALSE;

SELECT COUNT(DISTINCT a.id) AS vulnerable_assets_count
FROM assets a
LEFT JOIN pqc_classification p
	ON p.asset_id = a.id AND p.is_deleted = FALSE
WHERE a.is_deleted = FALSE
	AND (
		LOWER(a.risk_level) IN ('critical','high')
		OR LOWER(COALESCE(p.quantum_safe_status, 'unknown')) IN ('unsafe','migration_advised')
	);

SELECT COALESCE(AVG(cs.score_value), 0) AS average_pqc_score
FROM compliance_scores cs
JOIN assets a ON a.id = cs.asset_id
WHERE cs.is_deleted = FALSE
	AND a.is_deleted = FALSE
	AND LOWER(cs.score_type) = 'pqc';
```

---

### Asset Inventory

#### `GET /api/assets`

Inventory table rows, fully paginated/sortable/searchable.

Read query shape:

```sql
SELECT
	a.id,
	a.target AS asset_name,
	a.url,
	a.asset_type,
	a.owner,
	a.risk_level,
	a.last_scan_id,
	c.valid_until,
	c.key_length,
	c.tls_version
FROM assets a
LEFT JOIN certificates c
	ON c.asset_id = a.id AND c.is_deleted = FALSE
WHERE a.is_deleted = FALSE
	AND (
		:q = ''
		OR a.target LIKE :q_like
		OR a.url LIKE :q_like
		OR a.asset_type LIKE :q_like
		OR a.owner LIKE :q_like
		OR a.risk_level LIKE :q_like
	)
ORDER BY <sort_whitelist> <asc_desc>
LIMIT :page_size OFFSET :offset;

SELECT COUNT(*)
FROM assets a
WHERE a.is_deleted = FALSE
	AND (
		:q = ''
		OR a.target LIKE :q_like
		OR a.url LIKE :q_like
		OR a.asset_type LIKE :q_like
		OR a.owner LIKE :q_like
		OR a.risk_level LIKE :q_like
	);
```

KPI shape:

```sql
SELECT asset_type, COUNT(*)
FROM assets
WHERE is_deleted = FALSE
GROUP BY asset_type;

SELECT risk_level, COUNT(*)
FROM assets
WHERE is_deleted = FALSE
GROUP BY risk_level;

SELECT
	SUM(CASE WHEN c.valid_until < NOW() THEN 1 ELSE 0 END) AS expired,
	SUM(CASE WHEN c.valid_until >= NOW() AND c.valid_until < DATE_ADD(NOW(), INTERVAL 30 DAY) THEN 1 ELSE 0 END) AS expiring_30,
	SUM(CASE WHEN c.valid_until >= DATE_ADD(NOW(), INTERVAL 30 DAY) AND c.valid_until < DATE_ADD(NOW(), INTERVAL 90 DAY) THEN 1 ELSE 0 END) AS expiring_90,
	SUM(CASE WHEN c.valid_until >= DATE_ADD(NOW(), INTERVAL 90 DAY) THEN 1 ELSE 0 END) AS valid_long
FROM certificates c
JOIN assets a ON a.id = c.asset_id
WHERE c.is_deleted = FALSE
	AND a.is_deleted = FALSE;
```

#### `POST /api/assets`

Create asset manually.

```sql
INSERT INTO assets (asset_key, target, name, url, ipv4, ipv6, asset_type, owner, risk_level, source, is_deleted)
VALUES (:asset_key, :target, :name, :url, :ipv4, :ipv6, :asset_type, :owner, :risk_level, 'manual', FALSE);
```

#### `POST /api/assets/{asset_id}/edit`

```sql
UPDATE assets
SET name = :name,
		url = :url,
		owner = :owner,
		asset_type = :asset_type,
		risk_level = :risk_level,
		updated_at = NOW()
WHERE id = :asset_id
	AND is_deleted = FALSE;
```

#### `POST /api/assets/{asset_id}/delete` (soft delete)

```sql
UPDATE assets
SET is_deleted = TRUE,
		deleted_at = NOW(),
		deleted_by = :user_id,
		updated_at = NOW()
WHERE id = :asset_id
	AND is_deleted = FALSE;
```

---

### Asset Discovery

#### `GET /api/discovery?tab=domains|ssl|ips|software`

Each tab reads its own discovery table with inventory linkage flags.

Domain tab shape:

```sql
SELECT
	d.id,
	d.domain,
	d.status,
	d.registration_date,
	d.registrar,
	d.promoted_to_inventory,
	d.asset_id,
	CASE WHEN a.id IS NULL THEN FALSE ELSE TRUE END AS in_inventory,
	d.created_at
FROM discovery_domains d
LEFT JOIN assets a
	ON a.id = d.asset_id AND a.is_deleted = FALSE
WHERE d.is_deleted = FALSE
	AND (
		:q = ''
		OR d.domain LIKE :q_like
		OR d.registrar LIKE :q_like
		OR d.status LIKE :q_like
	)
ORDER BY <sort_whitelist> <asc_desc>
LIMIT :page_size OFFSET :offset;
```

SSL tab shape (same pattern for `discovery_ssl`), IP tab (`discovery_ips`), software tab (`discovery_software`).

#### `POST /api/discovery/promote`

Promote discovered row to inventory.

Transaction shape:

```sql
-- 1) Load discovery row by tab+id where not deleted.

-- 2) Upsert inventory asset by canonical key.
INSERT INTO assets (asset_key, target, name, url, asset_type, owner, risk_level, source, is_deleted)
VALUES (:asset_key, :target, :name, :url, :asset_type, :owner, :risk_level, 'scan_promoted', FALSE)
ON DUPLICATE KEY UPDATE
	is_deleted = FALSE,
	updated_at = NOW();

-- 3) Mark discovery row promoted and linked.
UPDATE discovery_<tab>
SET asset_id = :asset_id,
		promoted_to_inventory = TRUE,
		promoted_at = NOW(),
		promoted_by = :user_id,
		updated_at = NOW()
WHERE id = :discovery_id
	AND is_deleted = FALSE;
```

---

### CBOM

#### `GET /api/cbom/metrics`

```sql
SELECT
	COUNT(DISTINCT cs.asset_id) AS applications,
	COUNT(DISTINCT ce.asset_id) AS sites,
	COUNT(DISTINCT c.id) AS active_certs,
	SUM(CASE WHEN ce.quantum_safe_flag = FALSE THEN 1 ELSE 0 END) AS weak_crypto,
	SUM(CASE WHEN c.valid_until < NOW() OR c.is_self_signed = TRUE THEN 1 ELSE 0 END) AS cert_issues
FROM cbom_summary cs
LEFT JOIN cbom_entries ce
	ON ce.cbom_summary_id = cs.id AND ce.is_deleted = FALSE
LEFT JOIN certificates c
	ON c.asset_id = cs.asset_id AND c.is_deleted = FALSE
JOIN assets a
	ON a.id = cs.asset_id
WHERE cs.is_deleted = FALSE
	AND a.is_deleted = FALSE;
```

#### `GET /api/cbom/entries`

```sql
SELECT
	ce.id,
	a.target AS asset_name,
	ce.algorithm_name,
	ce.category,
	ce.key_length,
	ce.protocol_version,
	ce.nist_status,
	ce.quantum_safe_flag,
	ce.hndl_level,
	ce.created_at
FROM cbom_entries ce
JOIN assets a ON a.id = ce.asset_id
WHERE ce.is_deleted = FALSE
	AND a.is_deleted = FALSE
	AND (
		:q = ''
		OR a.target LIKE :q_like
		OR ce.algorithm_name LIKE :q_like
		OR ce.category LIKE :q_like
		OR ce.protocol_version LIKE :q_like
		OR ce.nist_status LIKE :q_like
	)
ORDER BY <sort_whitelist> <asc_desc>
LIMIT :page_size OFFSET :offset;
```

#### `GET /api/cbom/charts`

Distribution shapes:

```sql
SELECT ce.key_length, COUNT(*)
FROM cbom_entries ce
JOIN assets a ON a.id = ce.asset_id
WHERE ce.is_deleted = FALSE AND a.is_deleted = FALSE
GROUP BY ce.key_length;

SELECT ce.algorithm_name AS cipher, COUNT(*)
FROM cbom_entries ce
JOIN assets a ON a.id = ce.asset_id
WHERE ce.is_deleted = FALSE AND a.is_deleted = FALSE
GROUP BY ce.algorithm_name;

SELECT c.ca, COUNT(*)
FROM certificates c
JOIN assets a ON a.id = c.asset_id
WHERE c.is_deleted = FALSE AND a.is_deleted = FALSE
GROUP BY c.ca
ORDER BY COUNT(*) DESC
LIMIT 10;

SELECT ce.protocol_version, COUNT(*)
FROM cbom_entries ce
JOIN assets a ON a.id = ce.asset_id
WHERE ce.is_deleted = FALSE AND a.is_deleted = FALSE
GROUP BY ce.protocol_version;
```

---

### PQC Posture

#### `GET /api/pqc-posture/metrics`

```sql
SELECT
	AVG(cs.score_value) AS avg_score,
	SUM(CASE WHEN LOWER(cs.tier) = 'elite' THEN 1 ELSE 0 END) AS elite_count,
	SUM(CASE WHEN LOWER(cs.tier) = 'standard' THEN 1 ELSE 0 END) AS standard_count,
	SUM(CASE WHEN LOWER(cs.tier) = 'legacy' THEN 1 ELSE 0 END) AS legacy_count,
	SUM(CASE WHEN LOWER(cs.tier) = 'critical' THEN 1 ELSE 0 END) AS critical_count
FROM compliance_scores cs
JOIN assets a ON a.id = cs.asset_id
WHERE cs.is_deleted = FALSE
	AND a.is_deleted = FALSE
	AND LOWER(cs.score_type) = 'pqc';
```

#### `GET /api/pqc-posture/assets`

```sql
SELECT
	a.id,
	a.target AS asset_name,
	a.ipv4,
	a.ipv6,
	COALESCE(cs.score_value, 0) AS score,
	COALESCE(cs.tier, 'unknown') AS tier,
	COALESCE(p.quantum_safe_status, 'unknown') AS pqc_support,
	s.scanned_at AS last_scan
FROM assets a
LEFT JOIN compliance_scores cs
	ON cs.asset_id = a.id
 AND cs.is_deleted = FALSE
 AND LOWER(cs.score_type) = 'pqc'
LEFT JOIN pqc_classification p
	ON p.asset_id = a.id
 AND p.is_deleted = FALSE
LEFT JOIN scans s
	ON s.id = a.last_scan_id
 AND s.is_deleted = FALSE
WHERE a.is_deleted = FALSE
	AND (
		:q = ''
		OR a.target LIKE :q_like
		OR a.owner LIKE :q_like
		OR cs.tier LIKE :q_like
		OR p.quantum_safe_status LIKE :q_like
	)
ORDER BY <sort_whitelist> <asc_desc>
LIMIT :page_size OFFSET :offset;
```

---

### Cyber Rating

#### `GET /api/cyber-rating`

```sql
SELECT
	cr.id,
	a.target AS url,
	cr.enterprise_score,
	cr.rating_tier,
	cr.generated_at,
	cr.scan_id
FROM cyber_rating cr
JOIN assets a ON a.id = cr.asset_id
WHERE cr.is_deleted = FALSE
	AND a.is_deleted = FALSE
	AND (
		:q = ''
		OR a.target LIKE :q_like
		OR cr.rating_tier LIKE :q_like
	)
ORDER BY <sort_whitelist> <asc_desc>
LIMIT :page_size OFFSET :offset;

SELECT COALESCE(AVG(cr.enterprise_score), 0) AS enterprise_score
FROM cyber_rating cr
JOIN assets a ON a.id = cr.asset_id
WHERE cr.is_deleted = FALSE
	AND a.is_deleted = FALSE;
```

Tier derives algorithmically from real aggregate score only (no hardcoded sample values).

---

### Reporting

#### `GET /api/reports/scheduled`

```sql
SELECT
	rs.id,
	rs.schedule_uid,
	rs.report_type,
	rs.frequency,
	rs.schedule_date,
	rs.schedule_time,
	rs.timezone_name,
	rs.enabled,
	rs.status,
	rs.created_at
FROM report_schedule rs
WHERE rs.is_deleted = FALSE
	AND (
		:q = ''
		OR rs.report_type LIKE :q_like
		OR rs.frequency LIKE :q_like
		OR rs.status LIKE :q_like
	)
ORDER BY <sort_whitelist> <asc_desc>
LIMIT :page_size OFFSET :offset;
```

#### `GET /api/reports/ondemand`

```sql
SELECT
	rr.id,
	rr.request_uid,
	rr.report_type,
	rr.status,
	rr.output_format,
	rr.created_at,
	rr.started_at,
	rr.completed_at
FROM report_requests rr
WHERE rr.is_deleted = FALSE
	AND (
		:q = ''
		OR rr.report_type LIKE :q_like
		OR rr.status LIKE :q_like
		OR rr.request_uid LIKE :q_like
	)
ORDER BY <sort_whitelist> <asc_desc>
LIMIT :page_size OFFSET :offset;
```

#### `POST /api/reports/scheduled`

Validation rule: every selected asset must exist and be active.

```sql
SELECT COUNT(*) AS valid_count
FROM assets
WHERE id IN (:asset_ids)
	AND is_deleted = FALSE;

INSERT INTO report_schedule (...)
VALUES (...);

INSERT INTO report_schedule_assets (report_schedule_id, asset_id)
VALUES (:schedule_id, :asset_id);
```

#### `POST /api/reports/request`

```sql
SELECT COUNT(*) AS valid_count
FROM assets
WHERE id IN (:asset_ids)
	AND is_deleted = FALSE;

INSERT INTO report_requests (...)
VALUES (...);

INSERT INTO report_request_assets (report_request_id, asset_id)
VALUES (:request_id, :asset_id);
```

---

### Admin

#### `GET /api/admin/metrics`

```sql
SELECT COUNT(*) FROM users WHERE is_active = TRUE;
SELECT COUNT(*) FROM scans WHERE is_deleted = FALSE;
SELECT COUNT(*) FROM report_requests WHERE status IN ('queued','running') AND is_deleted = FALSE;
```

#### `POST /api/admin/api-keys`

```sql
UPDATE users
SET api_key_hash = :hash,
		updated_at = NOW()
WHERE id = :user_id
	AND is_active = TRUE;
```

#### `POST /api/admin/flush-cache`

No DB mutation required (cache invalidation op).

---

### Docs

#### `GET /api/docs`

Returns API catalog from route registry or maintained endpoint map.

## 5) Inventory enforcement for every aggregate

Any KPI/chart query must either:

1. Query from `assets WHERE is_deleted = FALSE`, or
2. Join telemetry to active `assets`.

Forbidden pattern:

```sql
SELECT COUNT(*) FROM pqc_classification WHERE is_deleted = FALSE;
```

Required pattern:

```sql
SELECT COUNT(*)
FROM pqc_classification p
JOIN assets a ON a.id = p.asset_id
WHERE p.is_deleted = FALSE
	AND a.is_deleted = FALSE;
```

## 6) Empty-state and error contract

### Empty DB / no rows

Always return `success=true` with zero envelope:

```json
{
	"success": true,
	"data": {
		"items": [],
		"total": 0,
		"page": 1,
		"page_size": 25,
		"total_pages": 1,
		"kpis": {
			"total_assets": 0
		}
	},
	"filters": {
		"sort": "id",
		"order": "asc",
		"search": ""
	}
}
```

### Invalid query params

```json
{
	"success": false,
	"error": {
		"message": "Invalid sort field.",
		"status": 400,
		"hint": "Use one of: id,target,owner,..."
	}
}
```

## 7) Scan → Discovery → Inventory propagation

1. Scan runs and writes `scans` + `discovery_*` rows (transient).
2. Discovery page shows rows with `in_inventory=false`.
3. Operator triggers `POST /api/discovery/promote`.
4. Asset row is created/linked in `assets`.
5. All inventory-guarded dashboards now include that asset.
6. If soft-deleted later, all dashboards auto-exclude it via `assets.is_deleted = FALSE` filter.

