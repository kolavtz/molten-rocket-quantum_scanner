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
