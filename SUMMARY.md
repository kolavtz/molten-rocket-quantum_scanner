# Milestone 1 Summary — Scan API + Background Runner + Persisted Sample Artifact

Date: 2026-04-10
Repo: `molten-rocket-quantum_scanner`

## What was implemented

### 1) Service-level scan orchestrator (new)
File: `src/services/inventory_scan_service.py`

Implemented top-level orchestration helpers:
- `run_scan_pipeline(target, ports=None, options=None, scan_runner=None)`
  - Validates and canonicalizes targets via `sanitize_target`.
  - Delegates to existing pipeline runner (defaults to `web.app.run_scan_pipeline` if none provided).
  - Persists a raw JSON artifact in `scan_results/` with required naming:
    - `scan_<timestamp>_<uuid>.json`
  - Stores artifact path in response (`raw_result_path`).
- `submit_scan_pipeline(...)`
  - Queues execution on a shared `ThreadPoolExecutor` for local async/background execution.
  - Worker size is configurable with `QSS_SCAN_MAX_WORKERS`.

### 2) Scans API contract alignment (incremental, backward-compatible)
File: `web/routes/scans.py`

Updated scans endpoints to emit universal envelope while preserving legacy keys:
- Added success envelope shape:
  - `{ "success": true, "data": {...}, "error": null }`
- Added error envelope shape:
  - `{ "success": false, "data": {}, "error": {"code": "...", "message": "..."} }`
- `GET /api/scans`
  - Returns envelope + legacy top-level pagination fields for current clients.
- `POST /api/scans`
  - Returns requested contract payload:
    - `data.job_id`
    - `data.status_url`
  - Keeps legacy `status`, `scan_id`, `job_id` top-level fields for compatibility.
- `GET /api/scans/<scan_id>/status`
  - Returns envelope for both in-flight and persisted scan states.
- `GET /api/scans/<scan_id>/result`
  - Returns envelope for report/snapshot retrieval.

Background execution now routes through the new service orchestrator helper for consistent validation + raw artifact persistence behavior.

### 3) Prompt persistence deliverable
File: `COPILOT_PROMPT.md`

Added the full implementation prompt content at repo root as requested.

### 4) Environment hygiene fix
File: `.env`

Sanitized local `.env` to placeholder values only (removed hardcoded credentials/secrets) and retained required variable keys including AI + scan worker configuration.

---

## Tests added/updated

### Updated
- `tests/integration/test_integration_scans_api_driven.py`
  - Added envelope assertions for scans list and scan start/status flow.

### New
- `tests/unit/test_scan_pipeline_orchestrator.py`
  - Verifies `run_scan_pipeline` persists `scan_<timestamp>_<uuid>.json` artifact.
  - Verifies `submit_scan_pipeline` returns a `Future` and completes successfully.
  - Verifies invalid target sanitization is rejected.

---

## Validation run

Executed:
- `pytest tests/integration/test_integration_scans_api_driven.py tests/unit/test_scan_pipeline_orchestrator.py -q`

Result:
- `16 passed`

---

## How to run a sample scan

1. Start the app.
2. Send a scan request:
   - `POST /api/scans` with JSON body, e.g. target + ports.
3. Poll `status_url` from response.
4. On completion, check:
   - `GET /api/scans/<scan_id>/result`
   - Raw artifact in `scan_results/scan_<timestamp>_<uuid>.json`

---

## Notes / next milestones

This milestone intentionally focuses only on scan API contract + background orchestration + persisted raw artifact path.
Remaining major workstreams (CBOM export contract expansion, 2FA, AI/RAG hardening, vulnerability API, CI matrix, etc.) should proceed in separate small PRs.

---

# Milestone 2 Summary — Query Contract Harmonization (`search` canonical, `q` compatibility)

Date: 2026-04-10

## What was implemented

### 1) Scan list + certificate APIs now prefer `search`
File: `web/routes/scans.py`

- `GET /api/scans`
  - Normalizes query input using `search` first, then falls back to `q`.
  - Returns both legacy-compatible aliases at top level:
    - `search`: normalized value
    - `q`: normalized value
- `GET /api/scans/<scan_id>/certificates`
  - Uses `search` first, then `q` fallback.
  - Filters payload now includes both `search` and `q` for compatibility.

### 2) Asset inventory page context now accepts `search`
File: `web/routes/assets.py`

- Asset inventory context builder now reads:
  - `search` first
  - `q` as fallback

This keeps server-rendered inventory filtering aligned with API-first query semantics.

## Tests added/updated

- `tests/integration/test_integration_scans_api_driven.py`
  - Added `test_scans_list_accepts_search_and_q_params` to verify canonical `search` behavior and `q` backward compatibility.
- `tests/smoke/test_smoke_dashboard_apis.py`
  - Extended `test_api_assets_accepts_query_params` to assert `search` is accepted by `/api/assets`.

## Validation run

- Targeted newly-added compatibility tests:
  - `2 passed`

Note: running the entire smoke file currently surfaces a pre-existing schema drift issue in discovery SQL (`d.updated_at` missing in SQLite test schema), unrelated to this milestone's query-parameter changes.
