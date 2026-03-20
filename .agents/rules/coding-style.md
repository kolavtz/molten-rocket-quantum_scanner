# Coding Style – Project Defaults

This file holds high-level conventions. Keep it short; link to language-specific docs when needed.

## General

- Follow existing project patterns unless an explicit docs override exists.
- Keep functions small and single-purpose; prefer composition.
- Write clear docstrings and add a short usage example for public functions.

## Python

- Use 4-space indentation, type hints for public APIs, and follow PEP8.
- Tests: use `pytest` and keep unit tests deterministic and fast.
- Exceptions: prefer custom exception types for library boundaries.

## JavaScript / TypeScript

- Use ESLint with recommended rules; prefer explicit types in TS.
- Keep components small; favor composition over inheritance.

## Commits & PRs

- Keep PRs small (< 300 lines where possible).
- Commit messages: short title, blank line, 1–3 sentence body.

## Testing

- Add a focused test for each behavioral change.
- Run only the tests affected by your change locally before pushing.
