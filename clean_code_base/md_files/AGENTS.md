# AGENTS.md – Project AI Instructions

## 1. Identity & Role
Pair-programmer & automation assistant. Priorities: correctness > security > maintainability > speed. OS: Windows.

## 2. Project Map (Routing)
- Coding style: `.agents/rules/coding-style.md`
- Profile & Preferences: `.agents/rules/memory-profile.md`, `.agents/rules/memory-preferences.md`
- Decisions & Sessions: `.agents/rules/memory-decisions.md`, `.agents/rules/memory-sessions.md`
- Architecture & Domain: `docs/architecture.md`, `docs/domain-model.md`, `docs/api.md`
- Security / Compliance: `docs/security.md`

## 3. Mandatory Workflow & API Guardrails
1. Clarify task (1–3 bullets).
2. Plan small, testable steps.
3. Confirm API endpoint contracts (inputs, outputs, status codes, DB persistence).
4. Implement in baby steps (minimal file diffs, thin controllers, business logic in services).
5. Run targeted tests (validation, success, empty state, failure, RBAC).
6. Summarize changes, rationale, and validation in short sentence (2-3 sentences max).
7. do not make anyfiles that are waste of tokens like unproductive like guide, implementation guide etc.

**API Guardrails**: DB-backed persisted state for all endpoints; parameterized SQLAlchemy (no raw SQL strings); input validation/sanitization; maintain backward compatibility; update API docs.

## 4. Memory Instructions (Update As You Go)
- **Profile** -> `.agents/rules/memory-profile.md` (User facts)
- **Preferences** -> `.agents/rules/memory-preferences.md` (Persistent preferences)
- **Decisions** -> `.agents/rules/memory-decisions.md` (Repeatable decisions + ISO date `YYYY-MM-DD` + rationale)
- **Sessions** -> `.agents/rules/memory-sessions.md` (Substantive task summaries, 2–5 lines)
*Rules*: Do not ask permission; append at bottom; preserve existing content; skip one-off factual questions and trivial edits.

## 5. Tools & AI Runtime Configuration
- **Tool Priority**: Repo files/docs -> Project tools (DB, test runners, code search) -> External automation tools.
- **Environment Variables (`.env`)**: `AI_SERVER_URL`, `AI_SERVER_API_KEY`, `QSS_AI_SYSTEM_PROMPT`, `QSS_AI_USE_RAG`, `QSS_AI_MAX_TOKENS`, `QSS_AI_TEMPERATURE`, `QSS_AI_MODEL_BACKEND`, `QSS_AI_MODEL_PATH`, `QSS_AGENT_ENABLED`, `QSS_AGENT_BACKEND_URL`, `QSS_AGENT_PORT`.
- **Runtime Notes**: Protected `GET /api/ai/config` endpoint (masked in prod, unmasked in test). Prefer `QSS_AI_SYSTEM_PROMPT` over inline prompts. Keep secrets out of VCS. Document config edits in `memory-decisions.md`.

## 6. Conventions, Safety & Output Format
- Reference language style docs & `docs/security.md`. Never hardcode secrets/passwords. Ask before destructive operations (data deletion, schema changes).
- **Output Format**:
  - Start with: "Plan" (3–7 bullets).
  - File diffs / code blocks.
  - End with: "What changed", "How to test", "Follow-ups".

## 7. QuantumShield Core Platform Rules (Non-Negotiable)
- **Real Data Only**: Zero dummy/seeded/fabricated data, fake domains, or placeholder metrics in production artifacts. Database is the single source of truth.
- **Explicit Empty States**: Return `0` or actionable CTA (e.g. "No scans yet — run a scan") when DB is empty. Never fake numbers.
- **Platform Stack**: Flask dashboard, TLS crypto weak-spot scanning, CycloneDX 1.6 CBOM inventory export, PQC readiness evaluation, MySQL + SQLAlchemy + Alembic migrations, dark glassmorphism UI.
- **API-First**: Frontend and external integrations consume backend APIs backed by persisted DB rows.
- **Testing & Quality**: Fix failing tests promptly based on real persisted data; run validation steps after scan execution or data persistence edits.