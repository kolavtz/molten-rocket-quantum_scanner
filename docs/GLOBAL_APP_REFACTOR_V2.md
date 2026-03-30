# GLOBAL_APP_REFACTOR_V2 — Inventory-Centric API-First Refactor Spec

Date: 2026-03-22  
Applies to: QuantumShield (ParaCipher, PSB Cybersecurity Hackathon 2026)

## 1) Non-negotiable operating rules

1. **No hardcoded dashboard data**  
   Every KPI/card/chart/table value must be produced from MySQL queries over persisted tables.

2. **Asset Inventory is the only in-scope estate**  
   Any telemetry row affects KPIs only when it joins to `assets` where `assets.is_deleted = FALSE`.

3. **Strict data flow**  
   Frontend → Flask API → SQL/MySQL query → JSON response → frontend render.

4. **Soft delete semantics**  
   Removing an asset means setting `is_deleted = TRUE`; all KPI queries exclude deleted assets, automatically removing that asset from all dashboards.

5. **No direct template DB binding**  
   Templates only render API payloads.

6. **Global table UX contract**  
   Sort + search + page size + prev/next + go-to-page, backed by SQL `ORDER BY`, `LIKE`, `LIMIT`, `OFFSET`.

## 2) Target menu and UI contract

Top navigation (header):
- Home
- Asset Inventory
- Asset Discovery
- CBOM
- PQC Posture
- Cyber Rating
- Reporting
- Admin
- Docs
- Night/Day toggle
- User menu

## 3) Data domains: in-scope vs transient

### Inventory-sourced (in-scope for all KPI dashboards)
- `assets`
- `certificates`
- `pqc_classification`
- `cbom_summary`, `cbom_entries`
- `compliance_scores`
- `cyber_rating`
- inventory-linked discovery rows (`discovery_*` where `asset_id` set to active asset)

### Transient scan discovery (out-of-scope until promoted)
- `discovery_domains`, `discovery_ssl`, `discovery_ips`, `discovery_software` rows with `asset_id IS NULL` and/or `promoted_to_inventory = FALSE`

These are visible in Discovery UI as "discovered not inventoried", but must not be counted in Home/CBOM/PQC/Cyber/Reporting KPIs.

## 4) Canonical schema (MySQL 8)

Primary DDL file: `schema_v2_inventory_api_first.sql`.

Required tables included:
- `users`
- `audit_logs`
- `assets`
- `scans`
- `discovery_domains`
- `discovery_ssl`
- `discovery_ips`
- `discovery_software`
- `certificates`
- `pqc_classification`
- `cbom_summary`
- `cbom_entries`
- `compliance_scores`
- `cyber_rating`
- `report_schedule`
- `report_requests`
- `report_schedule_assets`
- `report_request_assets`

### Soft-delete columns
Applied where operationally appropriate:
- `is_deleted BOOLEAN NOT NULL DEFAULT FALSE`
- `deleted_at DATETIME`
- `deleted_by VARCHAR(36)` (FK to `users.id` where relevant)

### Performance/indexing strategy
- Composite active filters (`asset_id, is_deleted, date/metric`) on telemetry tables.
- Endpoint filter indexes (`status`, `scanned_at`, `target`, etc.).
- Join indexes on all foreign keys.
- View `v_inventory_assets` + supporting views (`v_inventory_*`) to prevent accidental KPI leakage from non-inventory assets.

## 5) Environment contract

The app must load DB connection from `.env` as canonical keys:
- `DB_HOST`
- `DB_PORT`
- `DB_USER`
- `DB_PASSWORD`
- `DB_NAME`

Backward-compatible aliases are allowed (`MYSQL_*`) but must map to canonical `DB_*` values.

## 6) Universal API response envelope

All list-like API reads return:
- `success`
- `data.items`
- `data.total`
- `data.page`
- `data.page_size`
- `data.total_pages`
- `data.kpis`
- `filters.sort`
- `filters.order`
- `filters.search`

Error responses return:
- `success = false`
- `error.message`
- `error.status`
- optional `error.hint`

## 7) Common query parameter contract

All list endpoints accept (unless endpoint-specific override):
- `page` (default 1)
- `page_size` (default 25, bounded)
- `sort`
- `order` (`asc|desc`)
- `q` (text search)

Query pattern:
1. Build base query.
2. Apply inventory guard via join to active `assets` (or query directly from `assets`).
3. Apply search filter.
4. Apply sort map whitelist.
5. Compute `total`.
6. Apply `LIMIT/OFFSET`.

## 8) Endpoint map by section (API-first)

## Home

### `GET /api/home/metrics`
KPIs:
- Total Assets
- Total Scans
- Quantum Safe %
- Vulnerable Assets Count
- Average PQC Score

Inventory guard:
- All asset-based aggregates join `v_inventory_assets`.

Representative SQL shape:
- `COUNT(*) FROM v_inventory_assets`
- `COUNT(*) FROM scans WHERE is_deleted = FALSE`
- `AVG(pqc_score) FROM v_inventory_pqc`
- vulnerable count via unsafe/high-risk statuses joined to active assets.

---

## Asset Inventory

### `GET /api/assets`
Inventory table + inventory KPIs.

Includes only:
- `assets.is_deleted = FALSE`

KPI examples:
- totals by `asset_type`
- risk distribution from `assets.risk_level`
- certificate expiry buckets from `v_inventory_certificates`
- IPv4/IPv6 breakdown from `assets.ipv4/ipv6`

### `POST /api/assets`
Create asset manually (operator/admin).

### `POST /api/assets/{asset_id}/edit`
Update asset metadata.

### `POST /api/assets/{asset_id}/delete`
Soft delete asset.

---

## Asset Discovery

### `GET /api/discovery?tab=domains|ssl|ips|software`
Returns discovery rows with inventory linkage flags:
- `in_inventory` boolean
- `asset_id` nullable
- `promoted_to_inventory` boolean

KPI rule:
- Global Discovery KPIs shown on discovery page may include “discovered total”, but cross-page/global enterprise KPIs must use in-inventory only.

### `POST /api/discovery/promote`
Promote discovered entity to inventory.
Input examples:
- discovery table type + row id
- optional override `asset_type`, `owner`, `risk_level`

Behavior:
1. Upsert/create asset row in `assets`.
2. Backfill `asset_id`, `promoted_to_inventory = TRUE`, `promoted_at`, `promoted_by` on discovery row.
3. Future telemetry ingest for that endpoint links to this `asset_id`.

---

## CBOM

### `GET /api/cbom/metrics`
CBOM KPI cards from `cbom_summary`/`cbom_entries` joined to active assets.

### `GET /api/cbom/entries`
Paginated CBOM entries table (`v_inventory_cbom_entries`).

### `GET /api/cbom/summary?scan_id=...`
Summary row scoped by scan (still only valid where summary belongs to active asset).

### `GET /api/cbom/charts`
Distributions:
- key length
- cipher usage
- top CAs
- protocol versions

### `GET /api/cbom`
Alias to entries for UI compatibility.

---

## PQC Posture

### `GET /api/pqc-posture/metrics`
Tier percentages and average score from `v_inventory_pqc` and `v_inventory_compliance`.

### `GET /api/pqc-posture/assets`
Inventory asset table with PQC status and score.

### `GET /api/pqc-posture`
Alias to assets endpoint.

---

## Cyber Rating

### `GET /api/cyber-rating`
Per-asset cyber score table from `v_inventory_cyber_rating`.

KPI examples:
- enterprise aggregate score (0–1000)
- tier counts
- total URLs/assets in scope

No static values allowed; all are computed from current DB rows.

---

## Reporting

### `GET /api/reports/scheduled`
Schedule table from `report_schedule` (+ selected inventory assets via junction table).

### `GET /api/reports/ondemand`
History table from `report_requests`.

### `POST /api/reports/scheduled`
Create/update schedule; selected assets must exist in `assets` and be active.

### `POST /api/reports/request`
Create report request; all requested `asset_id` values validated against active inventory.

### `GET /api/reports`
Alias for scheduled list.

---

## Admin

### `GET /api/admin/metrics`
Operational metrics (users, scans, queue depth, etc.) from MySQL.

### `POST /api/admin/api-keys`
Generate/revoke API keys.

### `POST /api/admin/flush-cache`
Invalidate API caches.

### `GET /api/config/theme`
Read theme config.

### `POST /api/config/theme`
Update theme config.

---

## Docs

### `GET /api/docs`
Machine-readable endpoint catalog for the UI docs page.

## 9) Per-page KPI guardrails (inventory enforcement)

For Home, Discovery global cards, CBOM, PQC, Cyber, Reporting:
- Every aggregate query must include `JOIN v_inventory_assets a ON ...` or query directly from `v_inventory_*`.
- Any row with no active inventory asset must be excluded.

## 10) Empty-state contract

When DB is clean:
- `success = true`
- `data.items = []`
- all totals and KPI numeric fields = `0`
- descriptive UI empty-state text (no sample rows)

When filters match nothing:
- same shape, `items = []`, `total = 0`

When invalid query param:
- `success = false`, `error.status = 400`

## 11) Scan → Discovery → Inventory propagation workflow

1. Operator scans target (`scans` + `discovery_*` rows created).
2. Discovery shows rows as “not inventoried”.
3. Operator clicks “Add to Inventory” (`POST /api/discovery/promote`).
4. Asset created/linked in `assets`.
5. All dashboards now include that asset automatically through inventory-guarded SQL.
6. If asset is soft-deleted later, all dashboards exclude it without extra special-case logic.

## 12) SQL query patterns (canonical snippets)

1. Active inventory base:
- `FROM assets a WHERE a.is_deleted = FALSE`

2. Inventory + telemetry:
- `JOIN <telemetry_table> t ON t.asset_id = a.id AND t.is_deleted = FALSE`

3. Paginated table pattern:
- `SELECT ... ORDER BY <whitelisted_column> <asc|desc> LIMIT :page_size OFFSET :offset`

4. Search pattern:
- `AND (a.target LIKE :q OR a.owner LIKE :q OR ...)`

5. Count pattern:
- `SELECT COUNT(*)` with same filter set as list query.

## 13) Frontend page contract

Each page owns only:
- endpoint URLs
- filter state (search/sort/page/page_size)
- rendering logic for envelope payload

Each page must not:
- calculate authoritative KPI values locally
- fetch DB or read server globals directly

## 14) Verification checklist for judges

1. Start app with empty DB → all pages show zero-state (no fake numbers).  
2. Run a scan → discovery rows appear only in Discovery.  
3. Before promotion → Home/CBOM/PQC/Cyber totals unchanged.  
4. Promote discovered endpoint to inventory → totals update across dashboards.  
5. Soft-delete asset → totals drop across all dashboards immediately.  
6. Re-open any table page and verify SQL-backed sort/search/pagination behavior.

## 15) Migration execution recommendation (phased)

Phase A: Schema migration + compatibility layer  
Phase B: API endpoints stabilized with universal envelope  
Phase C: Frontend all pages switched to API-only data fetching  
Phase D: Remove legacy mixed route logic and dead code  
Phase E: Add integration tests for inventory guardrail + end-to-end scan/promotion flow
