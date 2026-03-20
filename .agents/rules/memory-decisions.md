# Memory – Decisions

Format: [DATE] Area – Decision – Rationale

- [2026-03-19] QuantumShield – All deletions are soft deletes with a Recycle Bin, never load deleted rows into normal queries – preserves auditability and safety.
- [YYYY-MM-DD] …
- [2026-03-20] Database bootstrap – Canonical schema init lives in `src/database.py`; `src/db.py` must not drop/recreate metadata – prevents destructive drift that removed `scans.report_json`/`scan_id` and broke FKs.
- [2026-03-20] Dashboard resilience – Asset and scan view builders must tolerate mixed legacy row shapes (`target` vs `name`) and mixed scan feeds (DB + in-memory) – keeps routes stable during migrations and DB outages.
- [2026-03-20] Table UX – For interactive dashboard tables, prefer client-side sort/search/pagination and return full row sets from route handlers – prevents full-page reloads and avoids sorting only a server page slice.
