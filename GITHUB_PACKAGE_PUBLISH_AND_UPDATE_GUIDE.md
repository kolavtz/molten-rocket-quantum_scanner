# GitHub Package Publish + Auto-Update Management Guide

This guide gives a complete, production-safe flow for:

1. Publishing updates through GitHub
2. Auto-updating your deployed app when a new update is available
3. Managing release/update workflow with GitHub Actions
4. Knowing exactly what to set in `.env`

---

## 1) First, choose your "publish" model

### Model A — **Publish the app code** (recommended for this repo)
Use GitHub branch + release tags + CI/CD deploy. This is already supported by this project.

### Model B — **Publish a Python package** (PyPI / GitHub Packages)
Use this only if you need a reusable installable library/CLI. This repo currently does **not** have packaging metadata (`pyproject.toml` / `setup.py`), so that is a separate setup project.

For your current architecture, Model A is the right fit.

---

## 2) GitHub update-management flow (Model A)

### Step 1 — Protect and version your `main` branch

- Protect `main` (require PR + passing checks)
- Use semantic tags: `v2.4.0`, `v2.4.1`, etc.
- Add release notes so deployment changes are auditable

### Step 2 — Run CI and deploy via GitHub Actions

This repository already has:

- `.github/workflows/ci.yml`
- `.github/workflows/ci-cd-deploy.yml`

`ci-cd-deploy.yml` already does:

1. test job (`pytest`)
2. deploy job over SSH
3. server-side `git fetch` + `git reset --hard origin/<branch>`
4. dependency install
5. service restart

Set these **GitHub repository secrets** (not `.env`):

- `PRODUCTION_HOST`
- `PRODUCTION_SSH_USER`
- `PRODUCTION_SSH_KEY`
- `PRODUCTION_SSH_PORT`
- `PRODUCTION_DEPLOY_PATH`
- `PRODUCTION_BRANCH`

### Step 3 — Enable runtime startup auto-update (optional)

On the deployed server, enable runtime updater in `.env`:

- `QSS_GITHUB_REPO_OWNER=your-github-org-or-user`
- `QSS_GITHUB_REPO_NAME=your-repository-name`
- `QSS_GITHUB_UPDATE_ON_START=true`
- `QSS_ALLOW_AUTO_UPDATE=true`

Optional knobs:

- `QSS_GITHUB_UPDATE_SCHEDULED=true` — keep polling for new releases in the background
- `QSS_GITHUB_UPDATE_INTERVAL_MINUTES=60` — how often to check when scheduled mode is enabled
- `QSS_GITHUB_RELEASE_ASSET_NAME=` — pin a specific release asset if you want to choose a wheel explicitly
- `QSS_GITHUB_TOKEN=` — optional token for private repos or higher API rate limits

Behavior in current code (`web/app.py` + `src/services/github_update_manager.py`):

- On startup, it calls GitHub Releases API for the configured repo
- Compares the latest release tag against the installed package version
- If a newer release exists and updates are allowed, it installs the newest wheel/asset with `pip`
- The process then re-execs itself so the new version is live immediately
- If scheduled mode is enabled, a daemon thread polls GitHub at the configured interval and performs the same update flow

---

## 3) `.env` variables required for update management

### Required for GitHub release updater

- `QSS_GITHUB_REPO_OWNER` — GitHub user or org name
- `QSS_GITHUB_REPO_NAME` — repository name
- `QSS_GITHUB_UPDATE_ON_START` — `true|false`
- `QSS_ALLOW_AUTO_UPDATE` — `true|false`

### Optional runtime controls

- `QSS_GITHUB_UPDATE_SCHEDULED` — background polling on/off
- `QSS_GITHUB_UPDATE_INTERVAL_MINUTES` — polling interval
- `QSS_GITHUB_RELEASE_ASSET_NAME` — explicitly choose a wheel/archive asset
- `QSS_GITHUB_TOKEN` — private repo or rate-limit helper

### Backward-compatible aliases retained in code

- `QSS_AUTO_UPDATE_ON_START` — legacy startup flag, still supported
- `QSS_ALLOW_AUTO_PULL` — legacy allow flag, still supported
- `QSS_GIT_BRANCH` — legacy branch updater flag, retained for older deployments

### Recommended operational safety variables

- `QSS_ENV=production`
- `QSS_DEBUG=false`
- `QSS_FORCE_HTTPS=true`

### Not `.env` (GitHub-side secrets only)

Do **not** place these in app `.env`; keep in GitHub Secrets:

- `PRODUCTION_HOST`
- `PRODUCTION_SSH_USER`
- `PRODUCTION_SSH_KEY`
- `PRODUCTION_SSH_PORT`
- `PRODUCTION_DEPLOY_PATH`
- `PRODUCTION_BRANCH`

---

## 4) Suggested release process (clean and repeatable)

1. Create feature branch
2. Open PR and pass CI
3. Merge to `main`
4. Tag release (`vX.Y.Z`)
5. GitHub Actions attaches release assets (and optionally publishes to PyPI)
6. Server restarts with latest version
7. Runtime updater remains as a safety net for startup/scheduled checks

---

## 5) Security and reliability guardrails

- Never commit real credentials to `.env.sample` or docs
- Keep production checkout clean; startup updater refuses hard reset on dirty tree
- Prefer CI/CD deploy as primary; runtime auto-update as secondary fallback
- Use least-privilege deploy SSH key
- Keep rollback path: previous release tag + service restart

---

## 6) If you later want actual Python package publishing (Model B)

You will need to add:

- `pyproject.toml` with package metadata
- Build pipeline (`python -m build`)
- Publish pipeline (`twine upload` for PyPI or GitHub Packages)
- Version source of truth (`pyproject.toml` or SCM tags)

This is intentionally separate from app deployment and should be introduced only if you need pip-installable distribution.

### Current scaffold in this repo

This repo now includes a basic package scaffold:

- `pyproject.toml` — setuptools build metadata
- `web/__init__.py` — makes the Flask web directory importable
- `web.app:main` — package entry point for running the installed app
- `.github/workflows/package-release.yml` — builds wheel/sdist on tags and can publish a PyPI release when `PYPI_API_TOKEN` is configured

Recommended release flow:

1. Merge changes to `main`
2. Create a semantic tag like `v0.1.0`
3. GitHub Actions builds `dist/*.whl` and `dist/*.tar.gz`
4. Release assets are attached to the GitHub release
5. Optional: PyPI publish runs if `PYPI_API_TOKEN` is available
