# Workflow – Preferred Development Flow

Follow this unless the user explicitly overrides it.

1. Clarify the task in 1–3 bullets.
2. For API-related tasks, define/confirm endpoint contract first (route, request schema, response keys, status codes, persistence behavior).
3. Create a short plan (3–7 steps) and update the repo TODO list.
4. Implement minimal changes (baby steps) with one focused commit per step.
5. Add or update tests that exercise:
	- input validation
	- success path
	- empty-state behavior (no fabricated data)
	- failure path
	- RBAC path (when auth/roles apply)
6. Run targeted tests locally; describe broader test runs when necessary.
7. Push, open a PR with a short description, API contract notes, and test instructions.

Guidelines:
- Prefer TDD when the change touches core logic; otherwise write a focused test.
- Use feature branches and descriptive branch names (feature/..., fix/...).
- Keep each commit focused: change one concept per commit.
- Keep controllers thin; place heavy logic in service classes.
- Treat DB rows as source of truth for all metrics/charts/exports.

Tool ordering:
- Search repo/docs → define/confirm API contract → run baseline tests → edit code → run targeted tests → update docs/memory files → PR.
