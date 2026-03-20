# Workflow – Preferred Development Flow

Follow this unless the user explicitly overrides it.

1. Clarify the task in 1–3 bullets.
2. Create a short plan (3–7 steps) and update the repo TODO list.
3. Implement minimal changes (baby steps) with one focused commit per step.
4. Add or update tests that exercise the behavioral change.
5. Run targeted tests locally; describe broader test runs when necessary.
6. Push, open a PR with a short description and test instructions.

Guidelines:
- Prefer TDD when the change touches core logic; otherwise write a focused test.
- Use feature branches and descriptive branch names (feature/..., fix/...).
- Keep each commit focused: change one concept per commit.

Tool ordering:
- Search repo/docs → run tests → edit code → run tests → update memory files → PR.
