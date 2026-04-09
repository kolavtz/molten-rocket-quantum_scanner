# Files Manifest — Registered Blueprints & API Manifests

This manifest lists the blueprints and route modules present in the codebase and the blueprints the Flask app registers at runtime (or can register via the centralized initializer). It is intended to be an accurate, up-to-date reference for integration and deployment.

Notes
-----
- Core page-level blueprints are registered directly in `web/app.py`.
- API blueprints are mounted centrally via `web.blueprints.api_blueprint_init.register_api_blueprints(app)` and are version-aware via `QSS_API_VERSION` (default `v1`). Set `QSS_API_VERSION=""` to mount directly under `/api`.
- Legacy overlapping dashboard API blueprints (api_home, api_assets, api_cbom, etc.) are only mounted when the environment flag `QSS_ENABLE_LEGACY_DASHBOARD_API_BLUEPRINTS` is truthy.

Core (directly registered) blueprints
-----------------------------------

- `web.blueprints.dashboard.dashboard_bp`
  - blueprint name: `quantumshield_dashboard`
  - url_prefix: `/dashboard`
  - Purpose: Main executive dashboard pages, geojson feed, asset add/CRUD endpoints used by the UI.

- `web.routes.assets.assets_bp`
  - blueprint name: `assets`
  - url_prefix: (none — registered at app root)
  - Purpose: Inventory UI routes, asset forms, discovery promotion, and per-asset pages.

- `web.routes.dashboard_api.api_dashboards_bp`
  - blueprint name: `api_dashboards`
  - url_prefix: (none)
  - Purpose: Dashboard-focused JSON helpers consumed by server-rendered templates.

- `web.routes.scans.scans_bp`
  - blueprint name: `scans`
  - url_prefix: (none)
  - Purpose: Scan center UI, scan queueing, status polling and related pages.

API blueprints (defined under `web/blueprints/`) — mounted by `register_api_blueprints(app)`
----------------------------------------------------------------------------------

These modules provide the API-first surface. `register_api_blueprints(app)` mounts a minimal set by default (api_root, api_incidents, api_docs, api_ai) under `/api/<version>` (or `/api` when `QSS_API_VERSION` is empty). Optional legacy blueprints are mounted when `QSS_ENABLE_LEGACY_DASHBOARD_API_BLUEPRINTS` is enabled.

- `web.blueprints.api_root` — var: `api_root` — declared prefix: `/api`
  - Endpoints: `/` (API metadata), `/health`, `/openapi.json`

- `web.blueprints.api_incidents` — var: `api_incidents` — declared prefix: `/api/incidents`
  - Endpoints: list/create/detail/update incidents, incident events

- `web.blueprints.api_docs` — var: `api_docs` — declared prefix: `/api`
  - Endpoints: docs UI, small OpenAPI-like spec used by `/api/openapi.json`

- `web.blueprints.api_ai` — var: `api_ai` — declared prefix: `/api/ai`
  - Endpoints: `/cbom-context`, `/cbom-query`, `/cbom-query/stream`, `/cbom-reindex`, and related AI assistant endpoints

- `web.blueprints.api_home` — var: `api_home` — declared prefix: `/api/home` (legacy)
  - Endpoints: `/metrics` (home KPIs)

- `web.blueprints.api_assets` — var: `api_assets` — declared prefix: `/api` (legacy)
  - Endpoints: `/assets`, `/assets/<id>/scans`, `/discovery`

- `web.blueprints.api_cbom` — var: `api_cbom` — declared prefix: `/api/cbom` (legacy)
  - Endpoints: `/metrics`, `/entries`, `/charts`, `/summary`, `/export`, `/minimum-elements`

- `web.blueprints.api_pqc` — var: `api_pqc` — declared prefix: `/api/pqc-posture` (legacy)
  - Endpoints: `/metrics`, `/assets`

- `web.blueprints.api_cyber` — var: `api_cyber` — declared prefix: `/api/cyber-rating` (legacy)
  - Endpoints: `/`, `/history`

- `web.blueprints.api_reports` — var: `api_reports` — declared prefix: `/api/reports` (legacy)
  - Endpoints: `/scheduled`, `/ondemand`, `/<id>`

- `web.blueprints.api_admin` — var: `api_admin` — declared prefix: `/api/admin`
  - Endpoints: admin-only API key management, admin metrics, flush-cache

Route modules (page-level)
--------------------------

- `web.routes.pqc_dashboard` — var: `pqc_bp` — url_prefix: `/pqc` (register via `register_pqc_routes(app)`)
  - Purpose: PQC posture pages and per-asset PQC views (posture charts, expiry timelines)

- `web.routes.dashboard_api` — var: `api_dashboards_bp` — url_prefix: (none)
  - Purpose: Additional JSON helpers / internal APIs for templates

- `web.routes.assets` — var: `assets_bp` — url_prefix: (none)
  - Purpose: Inventory UI and forms

- `web.routes.scans` — var: `scans_bp` — url_prefix: (none)
  - Purpose: Scan center UI, status endpoints

Helpers & important files
-------------------------

- `web/blueprints/api_blueprint_init.py` — Centralized API mounting (`register_api_blueprints(app)`) and versioning logic.
- `middleware/api_auth.py` — API key auth decorators and `APIKey` model utilities.
- `utils/api_helper.py` — Response envelope helpers, pagination, and common formatters.
- `web/blueprints/api_docs.py` — `API_ENDPOINTS_SPEC` is used to publish a lightweight endpoint spec; update when endpoints change.

Runtime verification (quick)
---------------------------
Start the Flask app and inspect `app.url_map` to see exactly what endpoints are active in your environment (this accounts for `QSS_API_VERSION` and the legacy toggle):

```py
from web.app import app
for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
    print(rule.rule, '->', rule.endpoint)
```

Want an export? I can generate a machine-readable dump (JSON/CSV) of `app.url_map` and save it under `tmp/registered_endpoints.json` — tell me which format you prefer.

---

Last updated: 2026-04-09
