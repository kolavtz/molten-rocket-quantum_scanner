QuantumShield (Molten Rocket Quantum Scanner) — Expanded Copilot Prompt

Purpose and Overview

This expanded instruction file is intended to be an authoritative, exhaustive specification document that an advanced code generation assistant (e.g. VS Code Copilot) or an engineering team can follow to upgrade, finish, test, and document the QuantumShield project (a.k.a. Molten Rocket Quantum Scanner). The goal is to provide a single source of truth with step-by-step tasks, example code patterns, API contracts, DB migrations, security rules, testing scenarios, operational instructions, and acceptance criteria.

Use the entire document as the master instruction. When generating code, tests, or docs, keep changes small and test-covered. If an operation requires secret keys or external paid services, provide a local-mode alternate and document explicit steps for plugging the real service in later.

This expanded prompt includes:
- Purpose & outcomes (concise summary)
- Detailed developer tasks (atomic, ordered)
- Deep API contract definitions with sample payloads and examples
- Data model and migration examples (SQLAlchemy and migration snippets)
- Scanner pipeline: architecture, sample code, error handling, idempotence
- CBOM and CycloneDX export: mapping and generator details
- PQC & risk scoring: algorithms, test fixtures, and deterministic examples
- UI/UX requirements and accessibility checklist
- AI Assistant & RAG: ingestion, vector store, prompt-sanitization, and usage
- 2FA: flows, DB schema, and verification tests
- Vulnerability fetcher: external API integration and regression testing
- Security matrix and hardened rules (SQL injection, XSS, CSRF, prompt injection)
- CI/CD pipeline and release checklist
- Acceptance criteria and how to verify them
- A4 printable formatting snippet and how to produce a human-readable handoff

NOTE: This document is intentionally verbose and prescriptive. Treat it as a living runbook that the developer uses to implement reliable, auditable changes.

SECTION 1 — PRODUCT GOALS (DETAILED)

QuantumShield is a defense-oriented security product that:
- Scans endpoints (hosts, domains, services) and collects TLS and certificate telemetry.
- Normalizes telemetry into a cryptographic bill of materials (CBOM) and stores both raw evidence and normalized rows.
- Computes PQC readiness and risk metrics for each asset and the organization as a whole.
- Presents API-driven dashboards (Home, Scan Center, Inventory, Discovery, CBOM, PQC, Cyber Rating, Reporting).
- Provides an AI assistant integrated locally (LM Studio style) that can summarize, recommend remediation, and be used in a restricted RAG configuration.

Primary constraints:
- "Real data only" principle: dashboard metrics must be derived from persisted DB rows (no seeded demo values surviving in production).
- Soft-delete: deletes should not physically remove evidence by default.
- Security-first: parameterized queries, sanitized inputs, content policies, and CSRF protections.
- API-first: pages should be driven by JSON endpoints with consistent envelopes and pagination.

SECTION 2 — HIGH-LEVEL ARCHITECTURE

The system is split into layers:
- Web UI layer (`web/`): Flask app (`web/app.py`), templates, static assets, theme tokens, and blueprint registration.
- API blueprints (`web/blueprints/`): JSON endpoints that return stable envelopes for the UI.
- Domain services (`src/services/`): orchestrate business logic like scanning, CBOM construction, PQC scoring, reporting, and vulnerability fetching.
- Scanner (`src/scanner/`): network discovery, TLS negotiation, and PQC detection.
- CBOM (`src/cbom/`): parsing/building cryptographic inventory rows and CycloneDX exports.
- Persistence (`src/models.py`, `src/db.py`): SQLAlchemy models and DB session management, plus migrations.
- Tests (`tests/`): unit and integration tests with deterministic fixtures.

SECTION 3 — DEVELOPER TASKS (ATOMIC AND ORDERED)

This section breaks the work into small, verifiable tasks. Each task should be a single commit with tests and documentation.

Task 0: Repo orientation (one-time)
- Read `README.md`, `docs/`, `web/app.py`, `web/templates/base.html`, `web/blueprints/*`, and `src/services/*`.
- Create a file `docs/WORKING_NOTES.md` that lists files you read and any initial TODOs discovered.

Task 1: Add/ensure an environment example
- Create or update `.env.example` with keys: `DATABASE_URL`, `SECRET_KEY`, `AI_SERVER_URL`, `QSS_AI_USE_RAG`, `QSS_AGENT_ENABLED`.
- Add a short `docs/ENV.md` describing values and local development defaults (e.g., sqlite, `sqlite:///data/dev.db` for local mode).

Task 2: Database migrations and model updates (atomic)
- Purpose: Add fields and tables required by the expanded feature set.

2.1: Add fields to `users` model:
- two_factor_enabled = Boolean, default False
- two_factor_secret_enc = Text (encrypted)
- two_factor_backup_codes_enc = Text (encrypted JSON list)
- last_login_at = DateTime

2.2: Add X.509 normalized fields to `certificates` model and migration:
- fingerprint_sha256 (String(64), index)
- public_key_fingerprint_sha256 (String(64))
- certificate_format (String(32))
- subject_cn (String(512))
- issuer_name (String(512))
- not_valid_before (DateTime)
- not_valid_after (DateTime)
- signature_algorithm (String(128))

2.3: Ensure `cbom_entries` contains Table 9 fields:
- asset_type, element_name, oid, primitive, mode, crypto_functions, classical_security_level,
- key_id, key_state, key_size, key_creation_date, key_activation_date, protocol_version_name

2.4: Ensure `asset_metrics` exists (materialized summary) and add fields for pqc_score, risk_penalty, asset_cyber_score.

2.5: Add necessary indexes on frequently queried fields: `asset_id`, `scan_id`, `is_deleted`, `fingerprint_sha256`.

Migrations: use Alembic or the repo's migration method. Create example migration SQL statements for MySQL style (as repo might use MySQL):

-- Example migration snippet (MySQL-like):
-- ALTER TABLE users ADD COLUMN two_factor_enabled TINYINT(1) DEFAULT 0, ADD COLUMN two_factor_secret_enc TEXT;
-- ALTER TABLE certificates ADD COLUMN fingerprint_sha256 VARCHAR(64), ADD COLUMN public_key_fingerprint_sha256 VARCHAR(64), ...;

Task 3: Scanner pipeline — run_scan_pipeline skeleton
- Create `src/services/inventory_scan_service.py` with a function `run_scan_pipeline(target, ports=None, options=None)`.
- Responsibilities:
  - Sanitize and canonicalize `target` (strip whitespace, verify domain or IP pattern, return 400 if invalid).
  - Create or find Asset row for canonical target (idempotent).
  - Insert a `scans` row with status `queued` and generated `job_id` (uuid).
  - Submit work to background thread executor, store the future mapping in an in-memory store (dict) keyed by job_id for simplistic polling.
  - Background worker must:
    - Execute `network_discovery` to capture open ports and services.
    - For ports that speak TLS (e.g., 443), call `tls_analyzer` to run SSLyze and extract TLS fields.
    - Run `pqc_detector` to classify algorithms and mark PQC indicators.
    - Build a scan report dict and write it to `scan_results/scan_<timestamp>_<uuid>.json`.
    - Persist certificates, cbom_entries, findings and update `asset_metrics`.
    - Set scan status to `completed` or `failed` with error payload.

Sample code sketch (skeleton):

from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

executor = ThreadPoolExecutor(max_workers=4)
job_store = {}

def start_scan(target, ports=None, options=None):
    job_id = str(uuid4())
    scan = ScanModel.create(...)  # ORM model create helper
    future = executor.submit(_scan_worker, job_id, target, ports or [443], options)
    job_store[job_id] = future
    return job_id

def _scan_worker(job_id, target, ports, options):
    try:
        # discovery -> tls -> pqc -> cbom -> persist
        report = build_report_for_target(target, ports, options)
        save_report_file(report, job_id)
        persist_report(report, job_id)
        update_scan_status(job_id, 'completed')
    except Exception as e:
        update_scan_status(job_id, 'failed', str(e))

Key details:
- Persist raw JSON and also insert structured rows.
- Use parameterized DB operations and SQLAlchemy sessions with commit/rollback patterns.

Task 4: API endpoints (blueprints)
- Create or update blueprints in `web/blueprints/` with consistent envelope responses, for example by using a helper `api_response(success, data=None, error=None)`.

4.1: Scans blueprint (web/blueprints/api_scans.py)
- POST /api/scans -> create scan job
- GET /api/scans -> paginated list
- GET /api/scans/<scan_id>/status -> returns job state (queued/running/completed/failed)
- GET /api/scans/<scan_id>/result -> returns stored scan JSON or a link to the artifact

4.2: Assets blueprint (web/blueprints/api_assets.py)
- GET /api/assets -> list with page, page_size, q, sort, order
- POST /api/assets -> create asset manually
- PATCH /api/assets/<id> -> update
- DELETE /api/assets/<id> -> soft-delete
- POST /api/assets/<id>/restore -> restore soft-delete

4.3: CBOM blueprint
- GET /api/cbom -> list entries + summary
- GET /api/cbom/export -> generate CycloneDX JSON and send file attachment

4.4: PQC blueprint
- GET /api/pqc-posture/metrics
- GET /api/pqc-posture/assets

4.5: Cyber Rating & Reporting
- GET /api/cyber-rating
- GET /api/reports (list), POST /api/reports (create on-demand), GET /api/reports/<id>/artifact

Implementation details for blueprints:
- Use `@bp.route('/api/scans', methods=['POST'])` and JSON input.
- Validate input with a shared validator `src/validators/request_validators.py`.
- Return `api_response(True, {'job_id': job_id, 'status_url': f'/api/scans/{job_id}/status'})`.

Task 5: CBOM builder & CycloneDX export
- Implement `src/cbom/builder.py` with methods:
  - `extract_cbom_entries_from_scan(report)` — returns list of dicts ready to persist.
  - `persist_cbom_entries(entries)` — writes rows, returns row_keys or IDs.
- Implement `src/cbom/cyclonedx_generator.py`:
  - Build a CycloneDX JSON structure following 1.6 specification with components list representing cryptographic assets.
  - Include Table 9 fields as `properties` or `components` extended fields per CycloneDX extension guidelines.
  - Save to `scan_results/cbom_{scan_id}.json` and provide download endpoint.

Mapping rules guidance:
- Each certificate or key identified should map to a CycloneDX component with fields for algorithm, key_size, use, validity ranges, fingerprint.
- When fields are missing, the generator must include `null` or `unknown` markers rather than fabricating data.

Task 6: PQC and risk calculators
- Create `src/services/pqc_calculation_service.py` which exposes `calculate_asset_pqc(asset_row, certificates, cbom_entries)` and returns a stable dict with: `pqc_score`, `pqc_tier`, `pqc_evidence` (list of reasons)

Example deterministic rules (start simple and document so tests can assert on them):
- If any certificate uses an algorithm in `legacy_algorithms = ['rsa-1024', 'dsakey-512']` or key_size <= 1024 -> `pqc_tier` = 'legacy', pqc_score decreases significantly.
- If public key uses ECDSA with curve `secp256r1` or RSA >= 2048 -> `pqc_tier` = 'standard'.
- If the asset has hybrid PQC+classical markers or all keys classified as quantum-resistant -> `pqc_tier` = 'elite', pqc_score high.

Risk calculation service (`src/services/risk_calculation_service.py`)
- Input: `findings` list with severities (low/medium/high/critical), certificate expiry days, weak_tls_count.
- Weighted formula example: `risk_penalty = sum(severity_weight[s] for each finding) + (100 / max(1, days_to_expiry)) + weak_tls_count * 10`.
- `asset_cyber_score` = `max(0, 1000 - risk_penalty*10)` (example normalization) — document exactly.

Task 7: UI updates & template wiring
- Ensure `web/templates/*` call API endpoints via `api_client.js`.
- Replace server-rendered table logic that executed raw DB queries with client-side fetch to `/api/assets` and render via reusable table macro.
- Use `web/static/js/api-table.js` patterns to unify pagination and filtering.
- Ensure all pages use the tokenized CSS variables from `web/theme.json`.
- Add the pinned AI assistant widget in `web/templates/base.html` with markup like:
  <div id="ai-assistant" class="ai-assistant fixed bottom-right">...</div>
  and ensure CSS `position: fixed; bottom: 24px; right: 24px; z-index: 1000;` and accessible controls.

Accessibility & UX rules to enforce:
- All interactive elements have keyboard focus and aria attributes.
- Colors meet WCAG contrast ratio 4.5:1 for text.
- Provide tooltips and long-form explanations for PQC and CBOM terms.

Task 8: Discovery & subdomain harvesting
- Implement `src/services/discovery_service.py` with methods:
  - `enumerate_subdomains(domain, use_crtsh=True, additional_list=None)`
  - Use `dnspython` to query DNS A/AAAA/CNAME for candidate names.
  - Use rate-limited HTTP client for crt.sh, obey robots and throttling rules.
  - Persist discoveries in `discovery` table with fields: `id, discovered_host, discovered_ip, discovered_by, discovered_at, promoted_to_asset_id`.
- Promotion endpoint `POST /api/assets/promote` to convert a discovery record to a curated asset.

Task 9: Vulnerability fetcher & regression testing
- Implement `src/services/vuln_fetcher.py` that accepts `product_name` or `target_hostname` and calls a free CVE API (CIRCL's api) or uses recorded fixtures.
- Map returned CVE entries to mitigation suggestions using simple rules (link to vendor advisory, recommended patch, suggested config change like disabling TLS 1.0, rotating keys, etc.).
- Add tests that use `responses` or `requests-mock` to return recorded CVE fixtures and assert the API returns sanitized, structured data.

Task 10: AI assistant and RAG implementation

10.1: Basic assistant integration
- Backend service `src/services/ai_assistant_service.py` with functions:
  - `send_chat(messages, model, max_tokens, use_rag=False, rag_context=[])` — builds and sends requests to LM Studio.
  - `load_models()` — optional to pre-warm or load model via `POST /api/v1/models/load`.
- Use `requests` with timeouts and retries. Wrap calls and ensure they return a normalized JSON envelope.

10.2: RAG pipeline
- Indexing pipeline steps:
  1. Load scan and cbom content that is allowed to be indexed (use allow-list of fields).
  2. Sanitize content: redact private keys, credentials, email addresses, PII.
  3. Split into passages (e.g., 200-500 token chunks) with metadata {source, scan_id, asset_id, filename}.
  4. Call embedding endpoint `POST ${AI_SERVER_URL}/v1/embeddings` to get vector.
  5. Insert into lightweight vector index (FAISS with on-disk persistence or an SQLite-backed vector store). Implement `src/utils/vectorstore.py` interface.

- Query time steps:
  1. Compute embedding for user query using LM Studio embeddings endpoint.
  2. Query vectorstore (top-k) and retrieve passages.
  3. Construct prompt that includes a short system instruction, the sanitized retrieved passages, and the user query.
  4. Call Chat completions endpoint and return reply.

RAG security rules:
- Always enforce a maximum allowed field list for indexing. Do not index `private_key`, `raw_pem`, `passwords`.
- Keep a maximum context token length and if exceeded, prefer higher similarity passages and drop older or lower scoring ones.
- Sanitize passages and mask any discovered secrets.
- Add logging of interactions for auditing and a per-user request quota.

Task 11: 2FA flows and backup codes
- Use `pyotp` to generate TOTP secret.
- Encryption helper: implement `src/utils/crypto.py` with Fernet symmetric encryption using `SECRET_KEY` (note: for higher security, use a separate KMS, but document replacement steps).
- When enabling 2FA:
  1. Generate secret: `secret = pyotp.random_base32()`.
  2. Generate provisioning URI: `pyotp.totp.TOTP(secret).provisioning_uri(name=user_email, issuer_name='QuantumShield')` and produce QR via `qrcode` library.
  3. Store encrypted secret in `two_factor_secret_enc` and set `two_factor_enabled=True` only after user verifies code within `/api/users/<id>/2fa/verify`.
  4. Generate backup codes: random 8 codes, hashed or encrypted, store them and show them once to the user.
- Add tests:
  - Verify that a valid `pyotp` token is accepted.
  - Verify that invalid tokens fail.
  - Verify that backup codes can be used once and then invalidated.

Task 12: Certificates normalization and viewer
- When TLS analyzer extracts certificate data, populate normalized fields into `certificates` table.
- Add endpoint `/api/certificates/<id>` that returns normalized fields and an optional `pem` if user requests to download (authorized).
- UI: `certificates.html` modal or drawer that shows subject, issuer, validity, key size, signature algorithm, PQC notes and a link to export PEM or JSON.

Task 13: Hardening for scale and attacks
- Rate-limiting: Add `flask-limiter` config with default 100 req/min for authenticated users and 10 req/min for unauthenticated; adjust per endpoint (e.g., scans creation stricter).
- Input validation: Use `marshmallow` or `pydantic` validators for request schemas; reject long or malformed `target` fields.
- CSRF: Use `Flask-WTF` or `flask-seasurf` for form CSRF protection; ensure AJAX JSON endpoints detect missing CSRF token and return JSON 403.
- Logging: Structured JSON logging with `python-json-logger` and a log level mapping for production.
- Background executor safety: limit `ThreadPoolExecutor` queue size and implement bounded semaphore to avoid OOM during massive scan bursts.

Task 14: CI/CD pipeline
- Provide `.github/workflows/ci.yml` with jobs:
  - test: checkout, setup python, cache pip, install, lint (`ruff`), test (`pytest -q`), build docs.
  - integration (optional): matrix job that uses MySQL or sqlite service and runs integration suite.
  - deploy (manual trigger): build docker image, push to registry, and optionally run migrations behind a manual approval.

Include scripts for local simulation:
- `scripts/run_tests.sh` and `scripts/run_integration.sh` to simplify maintainers' work.

Task 15: Tests (detailed list)

Add tests under `tests/` with consistent naming:
- `tests/unit/test_pqc_service.py` — deterministic pqc inputs -> outputs.
- `tests/unit/test_cbom_builder.py` — sample scan fixture -> expected CBOM rows.
- `tests/unit/test_scan_pipeline.py` — run `run_scan_pipeline` against small recorded network result and assert persisted rows.
- `tests/integration/test_api_scans.py` — POST /api/scans -> poll status -> GET result -> assert artifact exists.
- `tests/integration/test_vuln_fetcher.py` — call `/api/vulnerabilities?target=` using recorded CIRCL response.
- `tests/unit/test_2fa.py` — enable flow and backup codes.
- `tests/unit/test_ai_rag.py` — mock LM Studio endpoints and ensure top-k retrieval influences assistant reply.

Fixtures:
- Place sample scan reports in `tests/fixtures/scan_sample_1.json` and `tests/fixtures/cbom_sample_1.json`.
- Use `pytest` fixtures to create an isolated DB session and rollback after tests.

SECTION 4 — SAMPLE SCHEMA & CODE SNIPPETS

4.1 Sample SQLAlchemy certificate model snippet (to include in `src/models.py`):

from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey
from sqlalchemy.orm import relationship

class Certificate(Base):
    __tablename__ = 'certificates'
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey('assets.id'), index=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), index=True)
    subject_cn = Column(String(512))
    issuer_name = Column(String(512))
    not_valid_before = Column(DateTime)
    not_valid_after = Column(DateTime)
    fingerprint_sha256 = Column(String(64), index=True)
    public_key_fingerprint_sha256 = Column(String(64))
    certificate_format = Column(String(32))
    signature_algorithm = Column(String(128))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    is_deleted = Column(Boolean, default=False)

4.2 Example migration fragment (Alembic revision in Python):

# alembic revision script example
from alembic import op
import sqlalchemy as sa

def upgrade():
    op.add_column('certificates', sa.Column('fingerprint_sha256', sa.String(length=64), nullable=True))
    op.create_index(op.f('ix_certificates_fingerprint_sha256'), 'certificates', ['fingerprint_sha256'])

def downgrade():
    op.drop_index(op.f('ix_certificates_fingerprint_sha256'), table_name='certificates')
    op.drop_column('certificates', 'fingerprint_sha256')

4.3 Sample scan job status endpoint (Flask blueprint):

@bp.route('/api/scans/<job_id>/status', methods=['GET'])
def get_scan_status(job_id):
    scan = ScanModel.get_by_job_id(job_id)  # service helper
    if not scan:
        return api_response(False, error={'code': 'not_found', 'message': 'Scan not found'}), 404
    return api_response(True, data={'job_id': job_id, 'status': scan.status, 'progress': scan.progress})

4.4 Example CycloneDX generator pseudocode (detailed mapping)

- components: for each cbom entry -> build a component with:
  - type: "library" or "file" depending on asset_type mapping
  - name: element_name
  - properties: include Table 9 fields as key/value pairs
  - hashes: include fingerprint_sha256

4.5 Example PQC scoring test fixture and expected outcome (toy example)

# tests/fixtures/pqc_input_1.json
{
  "asset_id": 1,
  "certificates": [
    {"algorithm": "rsa", "key_size": 2048, "signature_algorithm": "sha256WithRSAEncryption"}
  ],
  "cbom": []
}

expected_pqc_score = 60  # derived from deterministic formula

SECTION 5 — SECURITY DETAILS AND MITIGATIONS

This section lists the security rules to apply in code and testing. Each rule must have at least one automated test that asserts it is enforced.

5.1 SQL injection
- Use SQLAlchemy ORM or `text()` with bound parameters; never format user input into SQL strings.
- Add tests that attempt to inject payload `"; DROP TABLE users; --` into search param and verify data intact and HTTP 400/422 returned.

5.2 CSRF and AJAX
- For HTML forms use the usual CSRF token approach.
- For AJAX, accept `X-CSRF-Token` header and if missing return JSON 403. Add test for AJAX 403.

5.3 XSS
- Use Jinja2 `{{ }}` escaping by default; mark safe only when content sanitized.
- For any HTML returned in fields, sanitize via `bleach` with strict allow-list.

5.4 Prompt injection and LM calls
- Sanitize user-supplied prompts and queries.
- Do not allow raw scan JSON to be appended into prompts; only include pre-selected sanitized passages.
- Add tests that feed malicious prompt fragments into the RAG helper and assert returned prompt sent to LM does not include blacklisted tokens like `PRIVATE KEY` or `-----BEGIN`.

5.5 Rate-limiting & brute force
- Apply `flask-limiter` or middleware for login endpoints and scan creation.
- Add unit test to validate 429 is returned after threshold.

5.6 Secrets management
- Never write private keys, credentials, or API keys to logs or to publicly accessible files.
- Use encryption helpers for 2FA secrets and backup codes.

SECTION 6 — AI ASSISTANT SPECIFICS (IMPLEMENTATION & SAFETY)

Detailed steps for RAG ingestion and retrieval:
- Fields allowed for indexing by default: public textual fields from scans such as `summary`, `endpoint_description`, `certificate_subject`, `issuer_name`, `cipher_suite`, `pqc_assessment`.
- Fields NOT allowed: `private_key`, `p12_password`, `raw_pem`, `credentials`, `headers.Authorization`.

Ingestion pseudocode:

for report in new_reports:
    passages = split_report_into_chunks(report)
    for p in passages:
        if contains_disallowed_tokens(p):
            p = mask_sensitive_items(p)
        vec = call_embeddings_api(p)
        vector_store.insert(document_id=report_id, passage_id=..., vector=vec, metadata={...})

At query time:
- Use top-k retrieval (k=3..5 by default), include source attributions in the assistant response, and show a link to the original scan artifact for authorized users.
- Add `explain` flag in the assistant response that includes which passages were used so an auditor can validate where the answer came from.

SECTION 7 — TESTING STRATEGY

7.1 Unit tests
- Keep unit tests small and fast.
- Use mocked external dependencies: LM Studio endpoints, CIRCL CVE API, dns queries, and SSLyze results.

7.2 Integration tests
- Use a MySQL or sqlite instance for integration tests; keep a separate test DB and teardown after use.
- Ensure tests are idempotent by using transactional rollbacks or recreating schema for each test.

7.3 Regression tests
- Add recorded fixtures for external APIs (CIRCL, crt.sh, LM Studio) using `vcrpy` or `responses`.
- Add nightly job in CI to run a set of regression tests with these fixtures.

7.4 Security test examples
- SQL injection attempt in `q` param returns 400/422 and no schema changes.
- Ensure CSRF missing header for AJAX returns JSON 403.

SECTION 8 — CI/CD AND RELEASE WORKFLOW

8.1 CI configuration
- `.github/workflows/ci.yml` with jobs: linting (ruff), tests (pytest), docs build, and optional container build.
- Gate merges to main branch on `ci` pass.

8.2 Release & migration
- Use migration scripts checked into `migrations/` and require a manual approval step in releases when migrations are present.
- Provide `scripts/apply_migrations_to_prod.sh` with safety checks (backup DB, run migrations in transaction where supported).

8.3 Deploy notes
- Provide a sample `docker-compose.yml` for local dev with services: app, db (mysql), redis optional, vectorstore optional.
- Document environment variables and secret handling in `docs/DEPLOYMENT.md`.

SECTION 9 — DOCUMENTATION AND HANDOFF

- Save `docs/A.md` (this file's replica of the short prompt) and `docs/expanded_copilot_prompt.md` (this file) in the `docs/` directory.
- Add `docs/README_FOR_MAINTAINERS.md` explaining how to start development, run tests and where to look for core logic.
- After finishing the first milestone produce `docs/SUMMARY.md` with a short list of tasks completed.

SECTION 10 — ACCEPTANCE CRITERIA (CHECKLIST)

- [ ] API endpoints implemented and returning correct envelopes with pagination metadata.
- [ ] Sample scan persisted to `scan_results/` and normalized rows present.
- [ ] CBOM export is valid CycloneDX JSON for a sample scan.
- [ ] PQC & risk services produce deterministic outputs with test coverage.
- [ ] Vulnerability fetcher returns curated CVE list in tests using recorded fixtures.
- [ ] AI assistant can produce safe replies using local LM Studio mock in tests.
- [ ] 2FA flows implemented with tests for enabling, verifying, backup codes usage.
- [ ] Security tests for injection and CSRF pass.
- [ ] CI passes for lint and tests.

OPERATIONAL NOTES

- If any new dependency is added (e.g., `sslyze`, `dnspython`, `pyotp`, `faiss-cpu`), add it to `requirements.txt` and update `docs/ENV.md`.
- For vectorstore: prefer small `faiss-cpu` for local testing and add a shim `src/utils/vectorstore.py` to swap implementations.
- For scale: recommend swapping thread executor with a dedicated queue such as Celery and using Redis and a worker pool.

PRINTING & A4 FORMATTING

- Provide `docs/a4.css` as a small stylesheet suitable for printing `expanded_copilot_prompt.md` to A4.
- Example rules:
@page { size: A4; margin: 1in; }
body { font-family: "DejaVu Sans", "Arial", sans-serif; font-size: 11pt; line-height: 1.4; color: #111; }
pre { font-family: "Courier New", monospace; font-size: 9pt; }

FINAL NOTES

This expanded prompt is intentionally comprehensive so an engineer or Copilot instance can proceed from an initial milestone to a finished product while maintaining security, auditability, and testability. If you want the document further expanded into a step-by-step implementation timeline with example commits and PR titles, say so and I will produce a `docs/implementation_timeline.md` with a commit-level breakdown and runnable patch suggestions.

End of expanded prompt
