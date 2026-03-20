# Memory – Decisions

Format: [DATE] Area – Decision – Rationale

- [2026-03-19] QuantumShield – All deletions are soft deletes with a Recycle Bin, never load deleted rows into normal queries – preserves auditability and safety.
- [YYYY-MM-DD] …
- [2026-03-20] Database bootstrap – Canonical schema init lives in `src/database.py`; `src/db.py` must not drop/recreate metadata – prevents destructive drift that removed `scans.report_json`/`scan_id` and broke FKs.
- [2026-03-20] Dashboard resilience – Asset and scan view builders must tolerate mixed legacy row shapes (`target` vs `name`) and mixed scan feeds (DB + in-memory) – keeps routes stable during migrations and DB outages.
- [2026-03-20] Table UX – For interactive dashboard tables, prefer client-side sort/search/pagination and return full row sets from route handlers – prevents full-page reloads and avoids sorting only a server page slice.
- [2026-03-20] Scheduler overlap policy – If an automated inventory sweep starts while another scan is running, log and skip that cycle (status=in_progress) instead of treating as an error.
- [2026-03-20] Logging portability – Use ASCII-only status text in scheduler logs to avoid Windows cp1252 encoding failures in console handlers.
- [2026-03-20] Scheduler lifecycle – Do not start scheduler during module import; start only in runtime entrypoint to avoid duplicate threads/reloader side-effects and perceived startup stalls.
- [2026-03-20] DB startup resilience – Keep MySQL probe fast-fail by default (short timeout/retries) and make values env-configurable so app can fall back to JSON mode quickly when DB is unreachable.
- [2026-03-20] Inventory scan orchestration – Inventory routes must inject the scan pipeline callable via app config instead of importing `web.app` from service code – avoids duplicate module initialization and scan flow breakage under different run modes.
- [2026-03-20] Inventory UX telemetry – Bulk inventory scans must expose per-asset progress (`current/total/target/success/fail`) through status polling for real-time operator feedback.
