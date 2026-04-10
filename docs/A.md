Title: QuantumShield (Molten Rocket Quantum Scanner) — Full Upgrade & Implementation Prompt for VS Code Copilot

Purpose
You are acting as an expert pair-programming assistant inside VS Code Copilot. Your job is to upgrade and complete the repository at https://github.com/kolavtz/molten-rocket-quantum_scanner.git to implement a production-ready, API-first, data-driven cybersecurity dashboard named QuantumShield. Follow the repo's existing patterns, prioritize correctness and security, and produce incremental, test-covered changes. Where required, update or override any .agent / .instructions / .AGENTS.md files to accomplish the task, but do not commit secrets.

Target outcomes (high-level)
1. Full-featured API-first Flask app with endpoints and pages: Home, Scans Center, Asset Inventory, Asset Discovery, CBOM, PQC Posture, Cyber Rating, Reporting, Admin, Users, Audit, API Keys, Recycle Bin, Theme, Docs.
2. Robust scanner pipeline (network discovery, TLS analysis using SSLyze by default) that persists raw scan artifacts + normalized DB rows (assets, scans, certificates, cbom_entries, findings).
3. CBOM: CycloneDX-compatible exports, Table 9 minimum element preservation, and clean UI presentation with export ability.
4. PQC & risk services: deterministic scoring, summary tables, and consistent APIs.
5. Security-first: sanitized inputs, parameterized SQLAlchemy queries, CSRF-safe AJAX, role-based access control, and resilience against SQL injection and other common web attacks.
6. AI assistant integration: local LM Studio (OpenAI-compatible) for chat + RAG over repo/scan data. Use http://localhost:1234 OpenAI-compatible endpoints. Harden RAG against injection and data leakage.
7. 2FA via pyotp with QR and backup codes; DB fields to persist 2FA secrets securely (encrypted), and account recovery flows.
8. Fixed UI behavior: tokenized theme, accessible design, fixed AI assistant UI widget pinned to the bottom corner.
9. CI/CD: GitHub Actions pipeline to run tests, lint, migrations, and optional deployments.
10. Testing & regression: unit, integration, and regression tests (including a test that uses a public/free third-party CVE API like https://cve.circl.lu/api/ to display vulnerabilities for a target domain).

Assumptions for the AI agent (strict)
- Work in repo root. Use Python + Flask + SQLAlchemy patterns present in repo.
- Do not create or commit real secrets; create `.env.example` placeholders and, if required, create `.env` locally with placeholders only (do not commit real values).
- Use SSLyze as the TLS augmentation library and ensure requirements updated (`sslyze>=5.2.0`) if not present.
- Use Alembic or the repo's migration mechanism for schema changes. Add migrations or SQL change scripts.
- Persist raw scan JSON in `scan_results/` and normalized rows into DB.
- Use `pytest` for tests; keep tests deterministic (use fixtures or recorded sample JSON).

Style/constraints for Copilot outputs
- Small, incremental commits — one logical change per commit.
- Add/modify tests for each behavior changed.
- Keep controllers thin; implement business logic in `src/services/`.
- Preserve soft-delete discipline (fields: `is_deleted`, `deleted_at`, `deleted_by_user_id`).
- Follow existing token-based theming and design-system conventions in `web/static/css/` and `web/theme.json`.
- Avoid drive-by refactors. If refactor needed, do it in a separate commit with tests.

Top-level instructions (step-by-step)
1. Repo scan & orientation
   - Read `README.md`, `web/app.py`, `web/routes/`, `web/blueprints/`, `src/`, `web/templates/`, `tests/`.
   - Report any file/route name mismatches (template expects `q` vs actual `search` etc.) as TODOs with references.

2. Create or update API contracts (blueprints)
   - For each major area implement clearly documented JSON endpoints (list, detail, create/update, delete/restore, exports).
   - Ensure envelope: { "success": boolean, "data": {...}, "error": null or {code,message} }.
   - For list endpoints ensure: items, total, page, page_size, total_pages, filters.

3. Database & migrations
   - Update or add columns for:
     - `users` table: `two_factor_enabled` (bool), `two_factor_secret_enc` (encrypted text), `two_factor_backup_codes` (encrypted json), `last_login_at`
     - `certificates`: fields for X.509 normalized fields: `fingerprint_sha256`, `public_key_fingerprint_sha256`, `certificate_format`, `subject_cn`, `issuer_name`, `not_valid_before`, `not_valid_after`, `signature_algorithm`
     - `cbom_entries`: ensure Table 9 fields exist: `asset_type`, `element_name`, `oid`, `primitive`, `mode`, `crypto_functions`, `classical_security_level`, `key_id`, `key_state`, `key_size`, `protocol_version_name`, etc.
     - `asset_metrics` summary table fields for `pqc_score`, `risk_penalty`, `asset_cyber_score` etc.
   - Add migrations for these changes and include sample SQL or Alembic revision.

4. Scanner pipeline & orchestration
   - Use `src/scanner/network_discovery.py`, `src/scanner/tls_analyzer.py`, and `src/scanner/pqc_detector.py` as basis.
   - Add or ensure a top-level `run_scan_pipeline(target, ports, options)` in `src/services/inventory_scan_service.py` that:
     - Validates targets (no command injection, canonicalize).
     - Queues scan to a background worker (use `concurrent.futures.ThreadPoolExecutor` for local dev; design so it can be replaced by Celery/RQ later).
     - Persists raw JSON in `scan_results/` with a naming scheme: `scan_<timestamp>_<uuid>.json`.
     - Normalizes and persists rows: assets, scans, certificates, cbom_entries, findings, asset_metrics updates.
   - Use SSLyze to enrich TLS data and fall back gracefully when unreachable.
   - Implement idempotent creation of Asset rows when scanning inventory items (based on canonical target/hostname).
   - Provide API endpoints:
     - POST `/api/scans` — start a scan; body: { target, type, ports, scan_options } → returns { job_id, status_url }.
     - GET `/api/scans` — list scans (paginated).
     - GET `/api/scans/<scan_id>/status` — job status.
     - GET `/api/scans/<scan_id>/result` — final stored scan result or raw file link.

5. CBOM & CycloneDX exports
   - Implement `src/cbom/builder.py` to convert scan results into CBOM rows preserving Table 9 minimum elements.
   - Implement `src/cbom/cyclonedx_generator.py` with a function `generate_cyclonedx(scan_id, include_full_x509=False)` that outputs valid CycloneDX JSON (1.6) to `scan_results/cbom_*.json`.
   - Add API endpoint `GET /api/cbom/export?scan_id=&selected_keys=` for generation and download.

6. PQC & Risk scoring services
   - Implement `src/services/pqc_calculation_service.py` and `src/services/risk_calculation_service.py`.
   - PQC service inputs: certificate public key algorithm, signature algorithm, key length, presence of PQC markers from TLS analyzer. Outputs: `pqc_score` (0..100), `pqc_tier` (`elite`,`standard`,`legacy`,`critical`,`unknown`).
   - Risk service inputs: findings (severity counts), certificate expiry proximity, TLS weaknesses. Outputs: `risk_penalty`, `asset_cyber_score` (0..1000 or normalized scale).
   - Update `asset_metrics` after scan completion.

7. UI pages & templates
   - Ensure `web/templates/*` pages use API endpoints instead of inline DB queries.
   - Implement or fix:
     - Home dashboard: request `/api/home/metrics` to render KPI cards, charts, and top risk list.
     - Scans Center: new API-first view (`web/templates/scans.html`) driven by `/api/scans`.
     - Asset Inventory: server-side pagination and `/api/assets` list endpoint.
     - Asset Discovery: list transient discoveries and promotion endpoint `/api/assets/promote`.
     - CBOM: `/api/cbom` endpoints for metrics and lists.
     - PQC Posture: `/api/pqc-posture/metrics` and `/api/pqc-posture/assets`.
     - Cyber Rating: `/api/cyber-rating`.
     - Reporting: `/api/reports`.
     - Recycle Bin: lists soft-deleted rows and restore/purge actions.
     - Admin Theme editor: loads/saves `web/theme.json`.
   - Accessibility & UX: apply tokenized CSS variables (tokens listed in repo), ensure keyboard nav, focus states, color contrast, and responsive layout. Use ui-ux-pro-max guidelines for cards, spacing, and chart color tokens.

8. Subdomain discovery & discovery features
   - Implement a discovery service `src/services/discovery_service.py` that:
     - For an inventory domain, performs:
       - DNS enumeration via `dnspython` to query A, AAAA, NS, TXT, CNAME, and attempt common subdomains list (configurable).
       - crt.sh scraping (certificate transparency) and `https://crt.sh/?q=%25example.com&output=json` fallback to discover subdomains (HTTP client with rate limiting).
       - Reverse lookups and PTR where useful.
     - Persist discovered subdomains as discovery rows; display them in Asset Discovery with promotion to inventory.
     - Ensure DNS queries respect network boundaries and do not run open-zone transfers by default.

9. Vulnerability regression test integration (third-party CVE API)
   - Implement `src/services/vuln_fetcher.py` that can query a free CVE API, e.g. CIRCL CVE API: https://cve.circl.lu/api/ (e.g., `/search/<product>` or `/domain/<domain>` where supported), or call National Vulnerability Database (NVD) if API key available.
   - Provide a page `/vulnerabilities` and API endpoint `/api/vulnerabilities?target=` that returns a table of open vulnerabilities relevant to discovered software or common fingerprints and suggested mitigation steps (mapping to CWE/CVE descriptions).
   - Add a regression test that asserts the vulnerability API returns a JSON list and the UI renders table rows (mocked or recorded fixture to avoid flakiness).

10. LM Studio AI assistant + RAG (localhost:1234)
    - Implement an AI assistant UI component pinned to bottom-right of every page (persistent, fixed).
    - Create a backend `src/services/ai_assistant_service.py` that:
      - Calls LM Studio endpoints at `http://localhost:1234/v1/chat/completions` or `/v1/responses` as available. Use a configurable base URL env var `AI_SERVER_URL` (default `http://localhost:1234`).
      - For RAG: create an ingestion pipeline that extracts sanitized, non-sensitive content from scan results and CBOMs, vectorizes it via `POST http://localhost:1234/v1/embeddings` and stores embeddings in a vector DB (FAISS or SQLite+annoy). Use an in-repo small vectorstore helper `src/utils/vectorstore.py`. Always remove secrets (passwords, API keys, private keys) before embedding.
      - Query-time: given user chat, fetch embeddings, build context (top-k), and send as `system` or context to the LM. Limit token context; truncate safely.
      - Protect against prompt-injection: sanitize user inputs, limit which DB fields are included, enforce strict allow-list of fields (no raw private keys).
      - Implement a minimal server-side rate limit and request logging for assistant calls.
    - UI: small chat window, option to summarize selected scan JSON, create remediation suggestions, and ask clarifying questions. Include "Export summary" and "Open related asset" actions in results.
    - Ensure the assistant respects role checks: only permitted roles can query sensitive evidence.

11. 2-Factor Authentication (pyotp)
    - Add endpoints and UI for enabling/disabling 2FA:
      - POST `/api/users/<id>/2fa/enable` — returns QR code (SVG or PNG) and secret (show secret once).
      - POST `/api/users/<id>/2fa/verify` — verify token and persist encrypted secret + generate backup codes.
      - Backup codes generation: create 8 one-time backup codes and store encrypted; allow user to view/print once.
    - Use `pyotp` for TOTP and `qrcode` to generate QR. Save secrets encrypted using app `SECRET_KEY` and a secure encryption helper (e.g., Fernet or AES with key from env).
    - Add DB columns described earlier and migration. Add tests for enabling/verification and login flows.

12. X.509 normalization and rendering
    - When TLS analyzer extracts certificate, persist normalized fields in `certificates` table.
    - Provide an API `/api/certificates/<id>` that returns normalized fields and a minimal UI viewer that renders details (subject, issuer, validity, raw public-key fingerprint).
    - Provide "Export X.509" action to download PEM / DER and add "Export JSON" for structured fields (but UI should show data neatly, not raw JSON blob as default).

13. Resilience & large-scale attacks
    - Add rate-limiting for public endpoints (use `flask-limiter` or a middleware).
    - Ensure background scan worker pools have job queue limits and error retries.
    - Design DB queries to use proper indexes and summary tables to avoid heavy ad-hoc queries.
    - Add monitoring hooks and logs for scan throughput and error rates (structured logging).
    - Add input validation on endpoints (max length, allowed characters for targets, IP whitelist/blacklist config).
    - Use per-endpoint CSRF protection and JSON 403 for AJAX as the repo expects.

14. CI/CD
    - Add `.github/workflows/ci.yml`:
      - Steps: checkout, set up Python, install requirements, run linters (flake8/ruff), run pytest, run migrations check, build wheel, optional docker build.
      - Add a job to run `pytest -k "not integration"` and a separate optional integration job requiring DB service.
    - Add pipeline step to run migration checks and require manual approval to apply migrations to production.

15. Tests & validation
    - Add unit tests for each new service:
      - scanner pipeline unit tests (use saved sample JSON scan fixtures in `tests/fixtures/scan_*`).
      - CBOM builder tests asserting Table 9 fields map correctly.
      - PQC & risk service tests verifying deterministic outputs on sample inputs.
      - AI assistant RAG helper unit tests mocking LM Studio responses.
      - 2FA tests using `pyotp` to generate valid/invalid codes.
    - Add integration tests for major API flows (asset creation, scanning, promoting discovery, CBOM export).
    - Add a nightly or regression test to run vulnerability fetcher against a recorded fixture from CIRCL API.

16. Documentation & deliverable
    - Add or update docs in `docs/` describing:
      - How to run locally (venv, .env example).
      - How to start LM Studio and configure `AI_SERVER_URL`.
      - How to run scans, view CBOM, and export.
      - The API contract for major endpoints (example request & response).
      - The theme tokens and how to edit theme via Admin page.
    - Create `COPILOT_PROMPT.md` in repo root that contains this full prompt for future use.

Detailed API contract examples (copy these exact shapes into the new blueprints)
- POST /api/scans
  Request:
  {
    "target": "example.com",
    "ports": [443],
    "scan_kind": "immediate",
    "promote_to_asset": true
  }
  Response:
  {
    "success": true,
    "data": {
      "job_id": "uuid-1234",
      "status_url": "/api/scans/uuid-1234/status"
    }
  }

- GET /api/scans
  Query params: page, page_size, q, sort, order
  Response:
  { "success": true, "data": { "items": [ {...scan row...} ], "total": 123, "page":1, "page_size":25, "total_pages":5 } }

- GET /api/cbom
  Query params: page, page_size, filters, row_key
  Response:
  { "success": true, "data": { "items":[ {...cbom_row...} ], "summary": { "key_length_distribution": {...}, "protocol_usage": {...}}}}

- POST /api/users/<id>/2fa/enable
  Response:
  { "success": true, "data": { "qr_svg": "<svg>...</svg>", "secret_base32": "ABCD..." }}

- POST /api/ai/query
  Request:
  { "prompt": "Summarize latest scan for example.com", "use_rag": true, "asset_id": 123 }
  Response:
  { "success": true, "data": { "assistant_id": "uuid", "reply": "..." }}

Database & schema guidance (sample)
- Use SQLAlchemy models in `src/models.py`. Example for certificate fields:
  - fingerprint_sha256 = db.Column(db.String(64), index=True)
  - public_key_fingerprint_sha256 = db.Column(db.String(64))
  - certificate_format = db.Column(db.String(32))
  - subject_cn = db.Column(db.String(512))
  - issuer_name = db.Column(db.String(512))
  - not_valid_before = db.Column(db.DateTime)
  - not_valid_after = db.Column(db.DateTime)
- Ensure created_at, updated_at, is_deleted, deleted_at are present for all major models.
- Add indexes on frequently filtered columns: asset_id, scan_id, fingerprint_sha256, is_deleted.

Security checklist to enforce programmatically
- Use SQLAlchemy parameterized queries — never build SQL via string concatenation with user input.
- Validate and canonicalize `target` and `hostname` input: hostnames only include A-Z a-z 0-9 - .; IP address validated separately.
- Escape or strip CRLF and other control characters.
- On any data used in prompts/embeddings, sanitize to remove secrets and PII. Truncate long fields; use field allow-list.
- Add Content Security Policy (CSP) headers for templates.
- Add rate limiting and request size limits.
- Ensure CSRF token required for form POSTs; AJAX returns JSON 403 for CSRF failures.

LM Studio & RAG safety specifics
- Use `AI_SERVER_URL` env var default `http://localhost:1234`.
- Embeddings: call `POST ${AI_SERVER_URL}/v1/embeddings` with only allowed sanitized text pieces, and store vectors with a reference id.
- At query time compute embedding for user query, find top-k relevant passages, and include only those passages in LM prompt.
- Before embedding, remove: `PRIVATE KEY`, `-----BEGIN`, credentials, emails if customers want privacy; provide a sensitive-fields list and a toggle for admins to allow more context.
- Limit token-size > 30k guardrails: if selected context > model token limit, truncate least-relevant fragments.

How to present changes to maintainers
- For each commit include:
  - One-line summary + 2–3 line description
  - Files changed
  - New tests added and how to run them
- Create PR template for major features that require manual validation.

Acceptance criteria (automated/verifiable)
- All unit tests run and pass locally with `pytest`.
- New endpoints return the specified envelope and pass schema checks with sample calls (tests provided).
- A sample scan (use included sample JSON) results in:
  - persisted `scan_results/scan_*.json`,
  - certificate rows created with fingerprint fields,
  - CBOM rows created and available at `/api/cbom`.
- 2FA flow has tests for enable/verify and login fallback using backup codes.
- AI assistant can call LM Studio mock during tests (use VCR or requests-mock) and RAG uses stored embeddings correctly to include context.
- Vulnerability fetcher test uses a recorded fixture and asserts table shape and mitigation text mapping.

A4 formatting and deliverable specifics
- Export or save this prompt as `COPILOT_PROMPT.md` at repo root.
- Provide a printable A4 CSS snippet `docs/a4.css` with:
  - @page { size: A4; margin: 1in; }
  - body { font-family: "DejaVu Sans", "Arial", sans-serif; font-size: 11pt; line-height: 1.4; }
- When producing the final handoff document, include header/footer with repo name and date.

Operations & how to run locally (short)
- Create venv, install requirements: `pip install -r requirements.txt`
- Create `.env` from `.env.example` and set `DATABASE_URL`, `SECRET_KEY`, `AI_SERVER_URL` (for LM Studio).
- Run migrations: `python apply_models_schema.py` (or `alembic upgrade head` if Alembic used).
- Start Flask dev server: `flask run` or `python web/app.py`.
- Start LM Studio separately (if using local): follow LM Studio docs; ensure it listens at `http://localhost:1234`.
- Run tests: `pytest -q`

Developer deliverables and structure
- New/modified files should be grouped logically; include short-purpose comments in new modules.
- Add tests to `tests/` and fixtures under `tests/fixtures/`.
- Add `docs/` updates for setup and API docs.
- Add a `docs/CHANGELOG_UPGRADE.md` explaining major changes for maintainers.

Override instruction (explicit)
- When implementing these changes, you may update or override `.agent`, `.instructions`, or `.AGENTS.md` files in the repo only to clarify agent-run behavior for automated tooling. Do NOT remove existing instructions unless you add a clear rationale comment at top and leave original content in git history.

Developer behavior & constraints
- If a change requires secrets or real external services (e.g., NVD API key), add placeholders and a documented local test mode with sample data.
- If a requested feature would require substantial infra (e.g., managed vector DB), implement a lightweight local alternative (FAISS/SQLite) and document how to replace with managed service.
- If a change touches sensitive or destructive actions (DB purge), require admin confirmation via UI and tests.
- When in doubt, prefer small, tested, reversible commits.

End of prompt
- After implementing the first small milestone (scan API + background runner + one full sample scan persisted), produce a single `SUMMARY.md` that lists what was implemented, how to run sample scan, and what tests to run. Post that summary as a PR description.
