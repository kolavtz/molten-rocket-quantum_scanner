# Memory – Sessions

Use 2–5 lines per session.

- [2026-03-19] Implemented Recycle Bin for all core entities in QuantumShield. Ensured soft deletes, admin-only restore/hard-delete, and exclusion from metrics and normal queries.
- [YYYY-MM-DD] …
- [2026-03-20] Fixed production runtime crashes from schema/model drift (`Scan.certificates`, `Asset.notes`, and `target` key assumptions in dashboard builders).
- [2026-03-20] Hardened MySQL init to repair legacy `scans` tables (`scan_id`, `report_json`, unique index) and align `report_schedules.created_by_id` type with `users.id`.
- [2026-03-20] Removed destructive ORM `drop_all/create_all` init path in `src/db.py`; delegated init to canonical `src/database.py`.
- [2026-03-20] Added regressions in `tests/test_database.py` and `tests/test_asset_service.py`; full targeted suite now passes.
- [2026-03-20] Unified table UX to client-side interactions: removed server-sort/pagination controls from table templates and switched table headers to JS-driven sorting.
- [2026-03-20] Updated table-backed routes to return full record sets for UI sorting/search across all rows (not only server-paginated slices).
- [2026-03-20] Fixed inventory scheduler overlap handling: automated sweep now treats in-progress scans as a skip, not a failure.
- [2026-03-20] Removed non-ASCII status glyphs from scheduler logs to prevent Windows cp1252 UnicodeEncodeError crashes.
- [2026-03-20] Cleared all current workspace Problems by fixing Jinja inline-style parser issues and ORM field typing/boolean checks in app routes.
- [2026-03-20] Verified startup command launches without reported traceback and confirmed Problems panel returns zero errors across files.
- [2026-03-20] Startup hardening: moved scheduler startup to runtime-only path, disabled auto scheduler by default, and switched startup console banners to ASCII-safe output.
- [2026-03-20] Reduced perceived startup hangs by adding DB init progress logs and lowering MySQL connect retries/timeouts with env overrides.
- [2026-03-20] Fixed end-to-end inventory scan flow by replacing fragile `from web.app import run_scan_pipeline` service import with injected app-configured runner from blueprint routes.
- [2026-03-20] Added live inventory bulk-scan progress state in service status API (percent, current/total, current target, success/fail counters) and surfaced it in Inventory UI polling.
- [2026-03-20] Updated inventory control panel to trigger background scan asynchronously and include CSRF token for schedule-save POST requests.
- [2026-03-20] Added first-class API-equivalent inventory routes under `/api/inventory/*` (scan-all, status, scan-asset, history, schedule) and switched Inventory UI fetch calls to use these API paths.
- [2026-03-20] Converted per-row inventory scan action to async API call with data-attribute dispatch to avoid inline Jinja/JS parser issues and full-page redirects.
