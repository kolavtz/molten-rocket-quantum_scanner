# AGENTS.md – Project AI Instructions

## 1. Identity & role

You are a pair-programmer and automation assistant working in this repo.
Priorities: correctness > security > maintainability > speed.

## 2. Project map (ROUTING)

When you need details, do NOT guess. Prefer these files:

- Coding style: `.agents/rules/coding-style.md`
- My profile & preferences: `.agents/rules/memory-profile.md`, `.agents/rules/memory-preferences.md`
- Past decisions & tradeoffs: `.agents/rules/memory-decisions.md`
- Recent work context: `.agents/rules/memory-sessions.md`
- Architecture & domain:
  - `docs/architecture.md`
  - `docs/domain-model.md`
  - `docs/api.md`
- Security / compliance: `docs/security.md`

If information is not present, ask a concise question instead of inventing it.

## 3. Workflow (MANDATORY)

Follow this workflow unless the user explicitly overrides it:

1. Clarify the task in 1–3 bullet points.
2. Plan changes as small, testable steps.
3. For API work, define or confirm endpoint contract first (inputs, outputs, status codes, persistence impact).
4. Implement in baby steps, editing the minimum number of files.
5. Run targeted tests for changed behavior (validation, success, empty state, failure paths, RBAC if applicable).
6. Summarize what changed, why, and what was validated.

Always:
- Prefer small, composable functions over large ones.
- Keep diffs focused and avoid drive-by refactors.
- Keep controllers thin and move business logic into services.
- Enforce "real data only" behavior (no seeded/fabricated API responses).

API implementation guardrails:
- All new/changed endpoints must be backed by persisted DB state.
- Validate and sanitize all external/user inputs.
- Use parameterized SQLAlchemy patterns (avoid string-built SQL).
- Maintain backward compatibility unless user explicitly requests a breaking change.
- Update relevant API docs when endpoint contracts change.

## 4. Memory (MANDATORY – UPDATE AS YOU GO)

Update memory files AS YOU GO, not at the end of a session.

| Trigger                              | Action                                      |
|--------------------------------------|---------------------------------------------|
| Learn a fact about the user          | Update `.agents/rules/memory-profile.md`    |
| Learn a persistent preference        | Update `.agents/rules/memory-preferences.md`|
| Make or observe a repeatable decision| Append to `.agents/rules/memory-decisions.md` with date and rationale |
| Finish substantive task or session   | Append 2–5 line summary to `.agents/rules/memory-sessions.md` |

Skip:
- One-off factual questions
- Trivial edits with no reusable learning

DO NOT ASK for permission to update these memory files. Just update when appropriate.

When editing memory:
- Preserve existing content.
- Add new entries at the bottom with ISO date (YYYY-MM-DD).
- Keep entries concise and factual.

## 5. Tools / MCP / external systems

When tools are available (MCP, browser, Google Workspace, etc.), follow this order of operations:

1. Use repo files and docs first.
2. Use project-scoped tools (DB, test runners, code search etc.).
3. Use external automation tools only when the task explicitly requires them.

Prefer tools over guessing. If you are uncertain and a tool can resolve it, call the tool.

## AI / Agent configuration (runtime)

When working with the AI assistant or building agentic features, configuration is read from environment variables (the app loads `.env`). Keep secrets out of source control and prefer masked values when returning runtime config.

Key environment variables (set in `.env` or provided by the orchestration environment):

- `AI_SERVER_URL` — External LM server base URL (example: `http://127.0.0.1:1234`). The app will POST to `{AI_SERVER_URL}/v1/chat/completions`.
- `AI_SERVER_API_KEY` — Optional API key for external LM servers (included as `Authorization: Bearer <key>` and `X-API-Key` when present).
- `QSS_AI_SYSTEM_PROMPT` — Server-side default instruction for the assistant (can be overridden per-request). Keep this concise and authoritative.
- `QSS_AI_USE_RAG` — `true|false` flag to enable RAG augmentation in CBOM queries and related endpoints.
- `QSS_AI_MAX_TOKENS` — Default max tokens for server-side LLM calls.
- `QSS_AI_TEMPERATURE` — Default temperature for server-side LLM calls.
- `QSS_AI_MODEL_BACKEND` / `QSS_AI_MODEL_PATH` — When running a local backend via `LLMClient`, configure backend and model path.
- `QSS_AGENT_ENABLED` — Toggle for a separate agent orchestrator (if used).
- `QSS_AGENT_BACKEND_URL` / `QSS_AGENT_PORT` — Where an external agent orchestrator listens.

Runtime notes:
- The app exposes a protected endpoint (admin-only) `GET /api/ai/config` which returns a masked view of these settings for debugging. In TESTING mode the full values may be returned for test assertions.
- Prefer changing the assistant's behavior via `QSS_AI_SYSTEM_PROMPT` in production rather than embedding long system prompts in code. For temporary overrides the UI may include `system_prompt` in the chat request JSON.
- Never commit real API keys or model files to source control. Use a secrets manager or CI/CD pipeline variables for production deployments.

If you update any of these variables, document the change in `.agents/rules/memory-decisions.md` with date and rationale.

## 6. Coding conventions (POINTERS ONLY)

Do NOT restate detailed style here. Instead, follow and reference:

- Global language style: `.agents/rules/coding-style.md`
- Framework patterns: `docs/architecture.md`, `docs/api.md`

If you see code that conflicts with these rules, follow the docs over legacy code unless the user says otherwise.

## 7. Safety & boundaries

- Never introduce real secrets, keys, or passwords into the repo.
- For anything security-sensitive, check `docs/security.md` and ask if unclear.
- If you’re more than mildly uncertain about a destructive operation (data deletion, schema change), ask before proceeding.

## 8. Output format

For implementation tasks:

- Start with: “Plan” and 3–7 bullets.
- Then show diffs or code blocks per file.
- End with:
  - “What changed”
  - “How to test”
  - “Follow-ups” (if any).

Stay concise. Avoid long explanations unless the user asks.

## 9. Local overrides

You can create small per-folder AGENTS.md files to override or extend the root router. Those should be <100 lines and point back to shared docs.


QuantumShield Project Instructions

Purpose
-------
Provide clear, enforceable implementation rules for building and evolving QuantumShield as a data-first, API-driven, security-led cybersecurity platform.
Guiding Principles
------------------
- Real data only: no seeded rows, placeholder metrics, or fake domains may survive in production artifacts. Empty states are clearer than fabricated numbers.
- Security and correctness outweigh speed: prefer auditability, parameterized SQLAlchemy queries, and resilient network handling for scans and reports.
- Keep the UI focused on the mission: a top navigation header, glassmorphic styling, and metrics derived directly from persisted results.
- the database is the source of truth: all charts, reports, and exports query actual tables; no in-memory fakes or hardcoded values.
- Iteratively build with feedback loops: start with a minimal viable product and expand features guided by real data and user needs, not assumptions. 
- Every decision and implementation must align with these principles to ensure we build a trustworthy, useful product that can evolve with real customer feedback and data.
- make sure to do a validation run after every significant implementation step to confirm that the changes have the intended effect and do not introduce regressions. This is especially important for scan execution and data persistence features, where the risk of silent failures or fabricated results is highest.
- make ui consistent with the dark glassmorphism theme and ensure that all data points are backed by actual database queries, never hardcoded or fabricated values. Always include explicit empty states when data is absent.
- when implementing scan execution, ensure that the service layer handles retries and error states gracefully, and that all results are persisted in the database with a clear contract for how scan status is determined from the underlying job state and artifacts. Avoid any shortcuts that would lead to non-persistent or fabricated scan results.
- for authentication and RBAC, implement a secure baseline that can be extended with real user management in the future, but do not hardcode any credentials or roles in source(except that explecitly added by coder ( like admin and manager users)). Use environment variables and configuration to control access and behavior, and ensure that the system can operate securely even in a development environment without seeded users.
- when generating the CBOM export, ensure that it is derived directly from the database rows and that it includes all relevant fields according to the CycloneDX 1.6 specification, without fabricating any data. The export should be a true reflection of the persisted state of the system, and should not include any placeholder values or assumptions about the data.
- for metrics and reports, ensure that all calculations are based on persisted scan data and that any scheduled reports are stored in the database with clear metadata about their schedule and delivery. Avoid any in-memory calculations that are not backed by actual data, and ensure that the system can generate accurate reports based on the real state of the database.
- it is also good practice to document any assumptions, decisions, or clarifications in the `.instructions.md` file as the project evolves, so that future contributors have a clear understanding of the rationale behind certain implementations and can maintain consistency with the original vision and principles of the project.
- use the `agency-agents` toolkit for any complex tasks that may benefit from specialized agents, but ensure that all outputs from these agents are validated against the project rules and principles before being integrated into the codebase or prompts. Always review and test generated code to confirm it adheres to the no-seeded-data rule and other guiding principles.
- QuantumShield is a Flask-powered cybersecurity dashboard that scans public assets for cryptographic weaknesses, generates CBOM inventories, evaluates PQC readiness, and delivers actionable risk metrics via API-driven UI. It implements a durable, soft-delete-aware data model to turn raw TLS telemetry into enterprise-grade security posture insights. Its importance lies in helping organizations identify and prioritize quantum-vulnerable cryptography before attacks exploit it, bridging compliance gaps like PNB/CERT-IN standards and NIST PQC guidelines with a user-friendly, data-first interface.
- if any test fails for the application or page or code you are working on, prioritize fixing the test and ensuring that it reflects the real behavior of the system based on persisted data. Do not bypass or ignore failing tests, as they are crucial for maintaining the integrity of the project and ensuring that all features work as intended with real data. If a test is failing due to a legitimate issue in the code, address that issue directly rather than modifying the test to fit an expected outcome that may not be accurate. Always aim for tests that validate the real behavior of the system and reflect the guiding principles of the project, especially the commitment to real data and no seeded values.
- use api based interactions for all features, ensuring that the frontend and any external integrations rely on the same data and logic as the backend. This promotes consistency and reduces the risk of discrepancies between different parts of the system. When implementing new features or pages, always create corresponding API endpoints that provide the necessary data directly from the database, and ensure that all frontend components consume these APIs rather than relying on any hardcoded values or assumptions about the data. This approach ensures that the entire system is cohesive and that all data points are traceable back to the database, reinforcing the principle of real data only.
- do not hallucinate any data or metrics in the UI or reports. If a particular metric cannot be calculated due to lack of data, the system should gracefully handle this by showing an empty state or a message indicating that the data is not available, rather than fabricating a number. This is crucial for maintaining trust with users and ensuring that all information presented is accurate and based on real data from the database.
- do not hallucinate on code implementations, especially for critical features like scan execution, data persistence, authentication, and report generation. Always ensure that any code generated or implemented is based on a clear understanding of the requirements and is validated through testing to confirm that it behaves as expected with real data. Avoid any assumptions about how certain features should work without first confirming those assumptions through implementation and testing.
- when implementing features that involve external interactions, such as network scans or API calls, ensure that the system is designed to handle failures gracefully and that all results are logged and persisted appropriately. Do not assume that external interactions will always succeed, and ensure that the system can recover from errors without losing data or leaving the system in an inconsistent state.
- always validate and sanitize any inputs, especially for features that involve user input or external data,to prevent security vulnerabilities such as injection attacks. Ensure that all inputs are handled securely and that the system does not trust any data that has not been explicitly validated and sanitized.
- when implementing authentication and role-based access control, ensure that the system is designed with security best
- we are using windows operating system, so make sure to use appropriate file paths and commands that are compatible with Windows when implementing features or running scripts. Always test your implementations in the target environment to confirm that they work as expected and do not introduce any platform-specific issues.

Platform Rules
--------------
1. **No dummy data anywhere.** If a metric cannot be calculated because the database is empty, render `0` or a clear call-to-action such as “No scans yet — run a scan”. Charts, reports, and services must query actual tables.
2. **MySQL + environment configuration.** Use SQLAlchemy models/migrations (Alembic preferred). All connection strings and secrets live in `.env`; check `.env.sample` into source control with only names (no values):
   - `DATABASE_URL` or `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASS`, `DB_NAME`
   - `SECRET_KEY`
   - `DEBUG_LOGIN_BYPASS` (defaults to `False`)
   - Additional feature flags as needed.

Non-Negotiable Principles
-------------------------
- Real data only. No seeded/demo/fabricated rows, metrics, domains, or scan outcomes in production artifacts.
- Database is the source of truth. UI, charts, exports, and reports must be backed by persisted rows.
- Security and correctness over speed. Use validation, sanitization, and parameterized SQLAlchemy queries.
- API-first architecture. Frontend and integrations must consume backend APIs, not hardcoded values.
- Explicit empty states. If data is missing, return zeros or actionable messages (never fake numbers).