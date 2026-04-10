# QuantumShield project guide

QuantumShield is a Flask-based cybersecurity dashboard and scanner for the PNB Cybersecurity Hackathon 2026. The project is built around a simple but demanding idea: scan public-facing assets, discover the cryptographic reality behind them, normalize that discovery into structured records, and then turn the results into decisions that humans can read quickly. It is not just a scanner. It is an inventory engine, a CBOM generator, a PQC-readiness evaluator, a reporting console, a soft-delete aware asset manager, and a themed web application whose visuals are controlled by reusable tokens instead of one-off page styling.

This guide is intentionally long and practical. It explains what the project does, why it does it, how data moves through it, what each folder is for, how the major pages behave, which APIs power which screens, how the theme system works, why the app insists on soft deletes and role checks, and which details matter when you are extending or debugging the codebase. The goal is to make the repo understandable as a product, not just as a pile of files.

## What the project is for

At a product level, QuantumShield exists to answer a specific security question: “Which assets in our estate still rely on cryptography that is weak, legacy, or not ready for the post-quantum era?” The project scans targets, extracts TLS and certificate telemetry, converts that telemetry into a cryptographic bill of materials, calculates PQC and risk scores, assigns labels, and renders the results in dashboards that are designed for operators, managers, and administrators.

The project also has a second goal: it wants the data model to be durable. That is why the repository contains migrations, soft-delete support, a consistent API envelope, and summary tables for metrics. The app is not merely trying to show current numbers; it is trying to store enough canonical history that those numbers can be re-used, audited, and visualized later without recalculating everything from scratch.

There is also a third goal, which is easy to miss if you only look at the UI: the repo is designed to be an API-first system. The pages are server-rendered, but the important numbers, tables, filters, and detail views are powered by JSON APIs. This gives the application a better structure for future automation, testing, and dashboard refactoring. In practice, it means the browser asks Flask for structured data, Flask asks MySQL for structured data, and the frontend renders the payload with predictable behavior.

## High-level behavior

When the app is working as intended, it behaves like this:

1. A user signs in and lands in the dashboard shell.
2. The top navigation exposes the main business areas: Home, Scan Center, Asset Inventory, Asset Discovery, CBOM, PQC Posture, Cyber Rating, Reporting, Admin, and Docs.
3. The user can start a scan from the scan center, or use inventory/discovery flows to manage assets first.
4. The scanner inspects a target and produces structured telemetry: TLS versions, cipher suites, certificates, endpoint classification, CBOM component data, recommendations, and labels.
5. The backend persists the scan, the CBOM rows, the certificates, the findings, and the summary metrics.
6. The UI shows the scan in tables, detail drawers, charts, and result pages.
7. The dashboard pages remain stable under soft deletes, role restrictions, and theme changes because the data is filtered and rendered through shared conventions.

That last point matters. The app is not trying to be flashy for the sake of it. It is trying to be reliable under change. That is why the codebase has a shared table helper, a shared theme system, reusable macros, and a bias toward explicit route contracts.

## Top-level directory structure

The repository is organized into a few distinct layers: application code, support services, front-end assets, tests, docs, and migration/schema artifacts. The exact file list is large, but the important shape is easy to understand.

### Root-level map

| Path | Purpose |
|---|---|
| `web/` | Flask app, templates, routes, static assets, theme data |
| `src/` | Domain logic, scanner pipeline, DB access, services, validators |
| `tests/` | Unit, integration, smoke, and security-oriented tests |
| `docs/` | Architecture notes, API docs, guides, math spec, user guide |
| `migrations/` | SQL migration scripts for schema evolution |
| `utils/` | Shared helpers used by APIs and formatting layers |
| `design-system/` | Design references and UI system artifacts |
| `.agents/` | Local agent instructions, memory, and skill metadata |
| `scan_results/` | Generated scan output artifacts such as CBOM and report JSON |
| `certs/` | Certificate-related fixtures and generated assets |
| `tmp/` | Temporary working artifacts |

The repo also includes operational files like `requirements.txt`, `Dockerfile`, `Procfile`, `pytest.ini`, and several scripts used for debugging or data repair. These are not the core product, but they matter because they show how the project is run, tested, and maintained.

### `web/`

This is the presentation and application shell layer. It contains the Flask application object, route blueprints, HTML templates, static CSS/JS, and the persisted theme configuration in `theme.json`.

Important items under `web/` include:

- `app.py`: the central Flask app, theme management, route registration, scan orchestration hooks, and several main page handlers.
- `routes/`: server-side route modules for assets, scans, dashboard APIs, PQC pages, and admin views.
- `blueprints/`: API endpoint modules that expose the JSON contract used by the UI.
- `templates/`: Jinja2 templates for pages like Home, Scan Center, Asset Inventory, CBOM, PQC Posture, Cyber Rating, Reporting, Recycle Bin, Admin, and Docs.
- `static/css/`: the design system and shared responsive styling.
- `static/js/`: the runtime behavior for theme handling, scan orchestration, table interactions, and API communication.
- `theme.json`: persisted light/dark/system theme state and color tokens.

The `web/` folder is where most users’ experience lives. It is also where many of the design-system decisions show up, because the repo uses CSS custom properties as the contract between theme settings and page components.

### `src/`

This is the backend logic layer. It contains the scanner internals, data services, validators, risk calculators, and support code that transforms raw telemetry into durable records and metrics.

Important subpackages include:

- `scanner/`: network discovery, TLS analysis, and PQC detection.
- `cbom/`: CBOM assembly and CycloneDX export generation.
- `validator/`: quantum-safe validation and certificate issuance logic.
- `reporting/`: result summaries and migration recommendations.
- `services/`: higher-level orchestration, persistence helpers, risk/PQC calculations, and dashboard query services.
- `db.py` and `database.py`: DB session and persistence wiring.
- `models.py`: ORM models for assets, scans, certificates, findings, metrics, and related entities.
- `table_helper.py`: helpers for table rendering and pagination behavior.

The `src/` folder is where the app becomes more than a static dashboard. It is the layer that decides what a scan means, what a finding means, which data is persisted, and how summary scores are computed.

### `tests/`

The test suite is broad and intentionally layered. There are smoke tests, integration tests, unit tests, security-related checks, DB tests, and API envelope tests. This reflects the product’s emphasis on stable backend behavior. The UI can be polished, but if the data flow is wrong then the app is lying to the operator.

### `docs/`

The docs folder is not incidental. It contains several implementation guides, architecture notes, math definitions, SRS-derived explanations, and operational instructions. A few especially important files are:

- `GLOBAL_APP_REFACTOR_V2.md`
- `API.md`
- `ARCHITECTURE_AND_QUANTUM_SAFE_GUIDE.md`
- `KPI_CALCULATION_GUIDE.md`
- `srs.md` and `srs_final.md`
- `Table 9_ Minimum Elements for Cryptographic Assets.md`
- `math-defination-for-quantumshield-app.md`
- `USER_GUIDE.md`
- `DEPLOYMENT.md`

The docs folder is part of the product because the project is clearly meant to be maintained, refactored, and extended rather than used once and forgotten.

### `.agents/`

This folder is for agent instructions, memories, and skills. It is not runtime code, but it matters because it shapes how automated coding helpers should interpret the repo. In a project like this, where there are many cross-cutting concerns, having repo-specific guidance is surprisingly important. It helps keep design, testing, and implementation aligned.

## Why the project is structured this way

The repository is split into layers because the product has several different kinds of logic that should not be mixed together.

### Separation of concerns

The scanner pipeline, the dashboard presentation, and the metrics/calculation code each have different failure modes:

- The scanner can fail because a target is unreachable, a certificate is malformed, or a network connection times out.
- The dashboard can fail because JSON payloads are malformed, templates reference missing fields, or the page state gets out of sync.
- The metrics layer can fail because a query is incorrect, a soft-deleted row leaks into aggregates, or a calculation is inconsistent across pages.

By separating these concerns, the app can be tested more precisely and extended more safely. For example, if the PQC score formula changes, the service layer can be updated without reworking every template.

### Why APIs sit between data and UI

The project leans heavily on APIs because the UI needs predictable data structures. Tables need pagination metadata. Charts need series labels and counts. Detail panels need payloads that can be re-rendered without reloading a page. If templates directly contained database queries, the app would become brittle and difficult to test. Instead, the UI asks for JSON, and the backend decides how to compute or load that JSON.

### Why soft deletes are used

The app treats inventory and scans as security evidence. Deleting evidence outright is a bad default. Soft delete lets the application remove records from normal user flows while retaining the ability to restore them from the recycle bin and keeping historical consistency in reports. This is especially useful for security dashboards where the current state and the audit trail both matter.

### Why theme tokens are used

The theme system is token-based because page-local colors do not scale well. A dashboard application has too many cards, tables, badges, alerts, buttons, charts, and modal surfaces to manage manually. CSS custom properties give the app a shared visual language. That makes dark mode, light mode, system mode, and future palette changes easier to handle.

## Runtime flow at a glance

The application flow can be understood in five stages:

1. **User interaction** — the user opens a page, enters a target, clicks an action, or navigates to a detail view.
2. **Route handling** — Flask receives the request, checks login and role requirements, and dispatches to a route or API endpoint.
3. **Query and computation** — services and database helpers pull the needed rows, filter out soft-deleted data, and compute the relevant metrics.
4. **Persistence** — scans, certificates, CBOM entries, findings, and summary rows are written or updated in the database.
5. **Rendering** — the frontend receives JSON or server-rendered HTML and presents tables, cards, charts, or detail panels.

This flow is deliberate. It keeps the scan logic close to the data, the API contract close to the frontend, and the UI logic close to the page. It also makes the system easier to debug because you can inspect each stage separately.

## Data flow in more detail

The core data flow starts when a target is scanned. The scan path is roughly:

1. A user submits a target in the Scan Center or via API.
2. The backend validates the input target and optional ports.
3. A job is queued or executed via the scan orchestration layer.
4. The scanner discovers network services, negotiates TLS, extracts certificate material, and classifies cryptographic components.
5. The pipeline builds a structured scan report.
6. The report is stored to disk and/or a persisted scan store, and selected pieces are saved to relational tables.
7. CBOM rows are derived from the report and persisted.
8. Findings are detected and saved.
9. PQC and risk metrics are computed and stored in summary tables.
10. The UI polls status, fetches the result, and renders the latest state.

The important thing to notice is that the same underlying scan creates multiple layers of output. There is the raw report, the machine-readable CBOM output, the finding records, the asset metrics, and the user-facing summary. Each layer has a different purpose.

### Why the app stores both raw and derived data

The raw scan report matters because it is the canonical artifact of what the scanner saw at the time. The derived metrics matter because dashboards should not have to recompute complex aggregations on every page load. The app can therefore show current values quickly while still retaining the original scan evidence for review and detail pages.

### Why inventory-linked scope matters

Many dashboards in the project only count active inventory assets. This is a deliberate decision in the V2 refactor. Discovery data that has not yet been promoted to inventory may be visible in discovery pages, but it should not inflate enterprise KPIs. That distinction prevents the system from overstating security posture based on transient or uncurated data.

### Why roles matter in the data flow

The app uses role gating because some actions are safe for read-only users and some are not. For example, a viewer can inspect a scan center and potentially run single-target scans, but only an admin or manager should be able to execute bulk scans or manage schedules. Role checks are not just security; they are also a product-design decision that keeps risky controls away from users who do not need them.

## Backend architecture

The backend is Flask-based, but it is not a minimal single-file app. It has been shaped into a modular structure:

- `web/app.py` acts as the central application bootstrap and includes theme handling, route registration, and several top-level page handlers.
- `web/routes/` contains domain route modules for assets, scans, dashboards, and PQC pages.
- `web/blueprints/` provides API blueprints for the JSON contract.
- `src/services/` contains business logic that can be reused by routes, APIs, tests, and background operations.
- `src/scanner/` contains the actual discovery and TLS/PQC analysis layers.
- `src/cbom/`, `src/validator/`, and `src/reporting/` turn scan output into product output.

The backend design has a very clear pattern: raw input goes into scanner components, scan results become structured Python dictionaries, service layers persist and normalize those dictionaries, and route layers present the outcome as HTML or JSON.

### Why `web/app.py` still matters so much

Even though the app is modular, `web/app.py` remains important because it is the place where the app starts. It wires theme state, default colors, role access, some compatibility routes, and the main Flask app context. In a larger framework, some of these concerns might move into separate factories or configuration objects. Here they live together because the application is still fairly compact and because the theme/admin behavior is tightly coupled to the app shell.

### Why service classes exist

The `src/services/` layer is the “thinking” layer. It encapsulates operations like computing PQC scores, calculating risk penalties, refreshing cert expiry buckets, detecting findings, formatting dashboard payloads, and turning rows into digestible summary data. This is useful because logic that belongs to the product should not be duplicated between a route, a scheduled job, and a test fixture.

### Why blueprints exist alongside route modules

The `web/routes/` and `web/blueprints/` split gives the app two different styles of endpoint organization. Route modules often handle HTML pages or mixed HTML/API behavior that sits close to user flows. Blueprints cleanly isolate public JSON endpoints for dashboards and external consumption. This division makes the API contract easier to reason about when you are building front-end components or tests.

## Frontend architecture

The frontend uses server-rendered templates plus client-side JavaScript. It does not rely on a heavy SPA framework, which keeps the stack simpler and easier to reason about in a security product.

### Template-first rendering

The base shell is rendered with Jinja2 templates. Individual pages extend `base.html`, inherit the global nav and theme variables, and then inject page-specific content. This is ideal for a dashboard where different pages have different data sets but still share the same visual shell.

### Shared JavaScript runtime

There are a few important JavaScript files:

- `app.js` handles theme resolution, nav behavior, and mobile dropdown interactions.
- `scans.js` drives the scan center interactions: posting scan requests, polling status, rendering detail panels, and managing schedules.
- `api-table.js` abstracts the reusable table component pattern used by dashboard pages.
- `api_client.js` provides a reusable fetch wrapper.

The app intentionally avoids an overcomplicated frontend stack. That choice fits the product: the logic is mostly around forms, tables, drawers, and charts rather than complicated client-side routing.

### Why the UI uses shared components

The project has enough pages that duplicated table code would become a maintenance hazard. Shared macros and helpers let the app keep consistent search, sort, and pagination behavior. The same goes for buttons, cards, badges, and detail rows. The visual system is a product feature, not just an aesthetic layer.

## Design philosophy and token preference

One of the most important parts of the project is its token system. The repo uses semantic CSS variables instead of random hardcoded colors because the product needs predictable contrast and consistent theming.

### Core token families

The key tokens are:

- `--bg-primary`
- `--bg-secondary`
- `--bg-card`
- `--bg-input`
- `--border-subtle`
- `--border-hover`
- `--text-primary`
- `--text-secondary`
- `--text-muted`
- `--accent`
- `--accent-hover`
- `--accent-muted`
- `--text-on-accent`
- `--safe`
- `--safe-bg`
- `--warn`
- `--warn-bg`
- `--danger`
- `--danger-bg`
- `--info`
- `--info-bg`

These tokens form the visual grammar of the app. Background tokens define the shell. Text tokens define hierarchy. Accent tokens define interactive controls and emphasis. Semantic tokens define success, warning, and danger states.

### Why `text_on_accent` exists

The theme system includes a separate `text_on_accent` token because accent surfaces are not guaranteed to be dark enough for a universal text color. In dark mode, a light-on-accent label is usually correct. In light mode, a darker accent label may be better if the accent button or badge is very bright. The token exists to preserve contrast and avoid forcing one text color into every accent context.

### Why color diversity is semantic, not random

The app does not use colors just to make the screen busy. Blue is used for primary actions and generic emphasis. Green is used for success and safe states. Amber is used for warnings. Red is used for risks and destructive action. Cyan and slate can appear in charts, borders, or secondary surfaces. This gives the UI enough variety to feel alive while still telling the user what each color means.

### Why the app avoids monochrome defaults

Security dashboards can look sterile very quickly if the palette is only black, white, and gray. The repo originally experimented with harsher palettes, but the current direction is a deeper blue/turquoise/amber/red system that still maintains strong contrast. The purpose is not style for its own sake; it is to make dense information visually scannable.

## Directory guide in practical terms

This section gives you the “what lives where” explanation that is usually missing from simple tree diagrams.

### `web/app.py`

This file is the central application bootstrap. It configures the Flask app, sets up theme loading and normalization, registers routes, and exposes a few top-level HTML pages. It also contains compatibility behavior for legacy routes and support logic for scan handling. In a small-to-medium Flask app, `app.py` tends to accumulate the glue code that doesn’t belong anywhere else.

Why it exists:

- It gives the app a single entry point.
- It centralizes theme defaults and persisted theme state.
- It keeps compatibility routes alive while the UI evolves.
- It provides the canonical app object for deployment and tests.

### `web/routes/`

These modules define the page-facing route logic for major functional areas. For example, `assets.py` handles inventory CRUD and inventory-specific actions, `scans.py` handles scan orchestration and scan history, `dashboard_api.py` exposes dashboard data, and `pqc_dashboard.py` covers PQC posture screens.

Why it exists:

- Keeps HTML routes and API endpoints organized by domain.
- Prevents `app.py` from becoming a monolith.
- Lets tests target a specific domain’s logic.

### `web/blueprints/`

These are the JSON API modules. They follow the same domain boundaries as the routes layer but are more explicitly tied to data payloads than to rendered pages.

Why it exists:

- It formalizes the JSON contract.
- It lets front-end components rely on stable response shapes.
- It makes API docs and tests easier to maintain.

### `web/templates/`

This folder contains all the Jinja2 page templates. It is where the app’s functional surfaces are visually assembled.

Key templates include:

- `base.html`: global shell, nav, theme variables, and layout.
- `home.html` / `index.html`: executive summary and KPI landing view.
- `scans.html`: modern scan center.
- `scan_center.html`: legacy/compatibility scan center.
- `asset_inventory.html`: inventory table, filters, and action flows.
- `asset_discovery.html`: discovery tabs, promotion flows, and network graph.
- `cbom_dashboard.html`: CBOM summary and minimum element inventory.
- `pqc_posture.html`: posture charts and PQC classification tables.
- `cyber_rating.html`: aggregate score and rating views.
- `reporting.html`: report schedules and generated report listings.
- `recycle_bin.html`: soft-deleted record management.
- `admin_theme.html`: theme token editor and mode selector.
- `admin_users.html`: user administration and role management.
- `docs.html`: built-in API and product documentation.

### `web/static/css/`

This is the design system layer. It is split into a main stylesheet and several page-specific or shared enhancement files.

- `style.css` is the primary global stylesheet.
- `table.css` handles table/search/pagination surfaces.
- `api_dashboards.css` styles API-driven dashboard cards and KPI layouts.
- `quantum_ui_refresh.css` adds cross-page depth, glass effects, and responsive improvements.

### `web/static/js/`

This folder contains the runtime behaviors that make the UI interactive.

- `app.js` manages theme preference and nav behavior.
- `api_client.js` wraps API fetches.
- `api-table.js` renders reusable tables from API payloads.
- `scans.js` powers the scan center and detail drawer.

### `src/scanner/`

This package is the technical heart of the scanner.

- `network_discovery.py` finds open services and interesting ports.
- `tls_analyzer.py` negotiates TLS and extracts certificate/cipher data.
- `pqc_detector.py` classifies algorithms and checks for PQC readiness.

### `src/cbom/`

These modules turn scan output into cryptographic inventory artifacts.

- `builder.py` assembles CBOM rows from scanner data.
- `cyclonedx_generator.py` creates CycloneDX-compatible JSON exports.

### `src/validator/`

Validation modules check whether the current cryptographic state meets policy expectations.

- `quantum_safe_checker.py` determines whether a target or row is considered quantum-safe.
- `certificate_issuer.py` handles digital labeling and certificate-like outputs for the UI.

### `src/reporting/`

Reporting modules take structured data and turn it into human-readable recommendation output.

- `report_generator.py` builds summary reports.
- `recommendation_engine.py` produces migration guidance and server-specific suggestions.

### `src/services/`

This is where business logic lives. The services folder is especially important in the current architecture because the app is becoming more data-driven and less template-driven.

Important service files include:

- `asset_service.py`: asset-centric business logic.
- `dashboard_data_service.py`: aggregates for dashboard pages.
- `distribution_service.py`: counts and distributions for charts.
- `finding_detection_service.py`: finding extraction and persistence.
- `pqc_calculation_service.py`: PQC scoring and classification.
- `risk_calculation_service.py`: risk penalties and cyber score.
- `inventory_scan_service.py`: asset scan orchestration.
- `certificate_telemetry_service.py`: certificate-centric telemetry retrieval.
- `cyber_reporting_service.py`: reporting metrics and output handling.

### `tests/`

Tests are deliberately split by concern:

- `unit/` for isolated behavior,
- `integration/` for end-to-end route/service behavior,
- `smoke/` for app-level “does this still basically work?” checks,
- `security/` for more sensitive checks,
- and standalone files for targeted regressions.

### `migrations/`

Migration SQL scripts encode schema changes outside the runtime app. The repo’s migration files show an important design point: the database is treated as a first-class part of the product, not just an implementation detail.

### `utils/`

Utility helpers like `api_helper.py` format ORM objects into JSON-friendly shapes. These helpers are useful because they prevent route modules from becoming serialization spaghetti.

## Major pages and what each one does

This is the part most people want first when they ask for “all the details.” The project has several user-facing screens, each of which plays a distinct role in the product.

### 1. Home / Executive dashboard

Files:

- `web/templates/home.html`
- `web/templates/index.html`
- `web/blueprints/api_home.py`
- `src/services/dashboard_data_service.py`

What it does:

The Home page is the executive landing zone. It summarizes the asset estate, the risk posture, the PQC posture, and the current scan state in a way that management and operators can understand quickly. It typically contains KPI cards, charts, top-risk summaries, and drilldown entries.

Why it exists:

- It gives a quick read of the whole system.
- It lets users spot drift, risk spikes, and scan coverage gaps.
- It provides a top-level story before the user goes deeper into inventory or CBOM.

Behavior:

- Reads current metrics from the dashboard API.
- Uses theme tokens for chart colors and badge states.
- Shows active assets only, never soft-deleted rows.
- Provides navigation into deeper pages such as inventory, scans, and PQC.

### 2. Scan Center

Files:

- `web/templates/scans.html`
- `web/templates/scan_center.html`
- `web/routes/scans.py`
- `web/static/js/scans.js`
- `web/static/js/api-table.js`

What it does:

The Scan Center is where users start scans, queue bulk scans, inspect scan history, open detail views, and manage scan schedules. This is the operational center of the product and one of the most interactive pages in the repo.

Why it exists:

- Operators need a fast, focused place to launch scans.
- Scan history and live status need to be visible in one place.
- The detail drawer lets a user inspect both the live status and the stored result without leaving the page.

Behavior:

- Single-target scans are available to all allowed roles.
- Bulk scans and schedules are restricted to admin/manager roles.
- The page can show live polling, scan summaries, raw JSON snapshots, and result links.
- Row clicks in the history table can open detail content.
- Schedule creation and deletion are handled from the same page.

Why the page is split between `scans.html` and `scan_center.html`:

- `scans.html` is the newer API-first scan UI.
- `scan_center.html` preserves compatibility for legacy routes and behaviors.
- This lets the application evolve without breaking old links or tests.

### 3. Asset Inventory

Files:

- `web/templates/asset_inventory.html`
- `web/routes/assets.py`
- `web/blueprints/api_assets.py`
- `src/services/asset_service.py`

What it does:

The inventory page is the canonical list of active assets. It supports search, sort, pagination, row actions, bulk actions, detail access, and scan initiation. It is one of the most important pages in the product because all global KPIs depend on inventory-scoped data.

Why it exists:

- This is the curated estate the dashboards care about.
- Soft deletes keep the audit trail while removing clutter from active views.
- Inventory actions are how users promote discovery into managed assets.

Behavior:

- Displays only active assets.
- Supports bulk delete, bulk edit, and bulk scan actions.
- Uses table helpers and reusable API table behavior.
- Opens detail modals and a dedicated asset detail page.
- Displays a recycle-bin-aware workflow rather than physically deleting evidence.

### 4. Asset Discovery

Files:

- `web/templates/asset_discovery.html`
- `web/routes/assets.py`
- `web/blueprints/api_assets.py`

What it does:

The discovery page is where the app presents transient discoveries such as domains, SSL endpoints, IPs, and software findings that may or may not already be in inventory. It helps operators discover things before deciding whether to promote them.

Why it exists:

- Discovery is the bridge between raw scanning and managed inventory.
- It prevents the inventory from being polluted by unverified rows.
- It gives operators a place to review, filter, and promote findings.

Behavior:

- Has tabbed views for different discovery categories.
- Can render graph visualizations and tabular lists.
- Provides promotion actions that move data into managed asset records.
- Tracks which discoveries are already inventoried and which are still transient.

### 5. CBOM Dashboard

Files:

- `web/templates/cbom_dashboard.html`
- `web/blueprints/api_cbom.py`
- `src/services/cbom_service.py`
- `src/cbom/builder.py`

What it does:

The CBOM dashboard is the cryptographic inventory screen. It summarizes key lengths, cipher usage, certificate authorities, protocol versions, and the minimum CBOM elements that are required for the project’s Table 9 mapping.

It also acts as the project’s PNB / CERT-IN CBOM evidence view, so the page needs to be explicit about which cryptographic fields are being captured and why they matter.

Why it exists:

- CBOM is the product’s way of turning cryptographic telemetry into a structured inventory.
- It is a bridge between scan results and compliance analysis.
- It helps the user answer what cryptographic materials are present, where, and in what state.

Behavior:

- Shows KPI cards for total apps, sites surveyed, active certs, weak crypto, and certificate issues.
- Shows a **Key Length Distribution** bar chart, where each bar represents the number of assets using that key length bucket.
- Shows a **Protocol Usage** donut chart, where the slices represent the share of TLS 1.3, TLS 1.2, and legacy protocol usage across the dataset.
- Shows a **Top Cipher Suites** list, where each row represents a cipher suite and the label indicates whether its usage is currently healthy or worth watching.
- Shows the **Minimum CBOM Elements (Table 9)** section with asset-type distribution and field coverage bars.
- Shows a detailed entries table with search and pagination.
- Can export or present structured cryptographic records.
- Links CBOM rows back to assets and scan records.

Minimum CBOM element fields that the dashboard should explain and preserve:

- **Asset / algorithm identity**: `asset_type`, `element_name`, `oid`, `primitive`, `mode`, `crypto_functions`, `classical_security_level`.
- **Key lifecycle**: `key_id`, `key_state`, `key_size`, `key_creation_date`, `key_activation_date`.
- **Protocol and transport**: `protocol_name`, `protocol_version_name`, `cipher_suites`.
- **Certificate identity and validity**: `subject_name`, `issuer_name`, `not_valid_before`, `not_valid_after`, `signature_algorithm_reference`, `subject_public_key_reference`, `certificate_format`, `certificate_extension`.

For the PNB / CERT-IN CBOM interpretation, these fields answer the practical questions operators care about:

- What algorithm or cryptographic asset is in use?
- Is it a primitive, a key, a protocol, or a certificate?
- What mode, key size, and lifecycle state does it have?
- Which protocol version and cipher suites depend on it?
- Which certificate subject, issuer, validity window, and signature/public-key references prove it?

### 6. PQC Posture

Files:

- `web/templates/pqc_posture.html`
- `web/routes/pqc_dashboard.py`
- `web/blueprints/api_pqc.py`
- `src/services/pqc_calculation_service.py`

What it does:

This page shows how ready assets are for post-quantum cryptography. It turns classification and score logic into readable posture charts, tables, and trend views.

Why it exists:

- PQC readiness is one of the core business questions.
- The page makes it easy to separate safe, standard, legacy, and critical assets.
- It helps prioritize migration work.

Behavior:

- Displays overview cards for the percentage of **Elite**, **Standard**, and **Legacy** assets plus the count of **Critical Apps**.
- Shows the **Asset Classifications** list, where each value is the count of assets in that classification bucket.
- Shows the **Application Status Distribution** bar chart, where each bar represents the percentage of assets in a PQC status bucket for the current filtered dataset.
- The status bars should be explained in plain language, for example:
	- **safe**: algorithms or certificates are currently considered quantum-safe.
	- **unsafe**: the cryptography is not yet considered quantum-safe.
	- **migration_advised**: the asset is still operational but should be migrated soon.
	- **unknown**: the scanner could not confidently classify the algorithm.
- Shows the **Risk Heatmap**, where each tile is a count of assets at the intersection of the displayed dimensions.
- Shows the per-asset telemetry table with readiness score, PQC tier, quantum-safe algorithms, vulnerable algorithms, last scan time, and scan type.
- Uses the same scoring logic across the app.
- Should never show deleted or out-of-scope rows.

For the PQC charts, the user should be able to tell at a glance whether the estate is mostly safe, where the legacy concentration sits, and which assets need migration work first.

### 7. Cyber Rating

Files:

- `web/templates/cyber_rating.html`
- `web/blueprints/api_cyber.py`
- `src/services/risk_calculation_service.py`

What it does:

Cyber Rating combines PQC posture and risk penalties into a broader enterprise score. It is the “how bad is the current posture?” page.

Why it exists:

- PQC score alone is not enough if findings are severe.
- Enterprise leadership often wants one score, one tier, and a trend line.
- This page turns complex inputs into a business-facing rating.

Behavior:

- Renders aggregate rating data from summary tables or API payloads.
- Uses threshold-based tiers.
- Encourages remediation prioritization.

### 8. Reporting

Files:

- `web/templates/reporting.html`
- `web/blueprints/api_reports.py`
- `src/reporting/report_generator.py`
- `src/reporting/recommendation_engine.py`

What it does:

The reporting page manages scheduled and on-demand report workflows, plus generated artifacts.

Why it exists:

- Teams need a repeatable way to generate and consume security summaries.
- Scheduled reports support operational cadence.
- On-demand reports support ad hoc analysis and executive reviews.

Behavior:

- Shows report lists and schedule configuration.
- Pulls from reporting APIs rather than hardcoding content.
- Surfaces generated report artifacts and request statuses.

### 9. Recycle Bin

Files:

- `web/templates/recycle_bin.html`
- `web/routes/assets.py`

What it does:

The recycle bin is where soft-deleted assets and scan-related objects can be restored or purged.

Why it exists:

- It protects evidence while still allowing cleanup.
- It enforces the app’s soft-delete-first philosophy.
- It gives administrators a controlled place to manage deletions.

Behavior:

- Shows deleted rows only.
- Lets privileged users restore or permanently purge.
- Keeps destructive behavior explicit and controlled.

### 10. Admin Theme Settings

Files:

- `web/templates/admin_theme.html`
- `web/app.py`
- `web/theme.json`

What it does:

This is the theme control center. It allows the user to choose a startup mode and tune the active dark and light palettes.

Why it exists:

- The theme should be managed centrally, not from a header toggle.
- Design tokens are part of the app’s product identity.
- Admin users need a place to control the global appearance safely.

Behavior:

- Presents dark, light, and global mode settings.
- Uses tokenized input fields and color pickers.
- Updates persisted palette configuration.

### 11. Admin Users, Audit, and Profile pages

Files:

- `web/templates/admin_users.html`
- `web/templates/admin_audit.html`
- `web/templates/profile.html`
- `web/templates/login.html`
- `web/templates/forgot_password.html`
- `web/templates/setup_password.html`

What they do:

These pages handle user administration, account setup, profile editing, and security administration. They are not the main product features, but they are essential operational surfaces.

## The API surface in practical detail

The API layer is one of the most important parts of the project because the UI depends on it. The following is a practical catalog of the major endpoint families.

### Dashboard API

The dashboard APIs provide the global metrics used by the home screen and other top-level summaries.

Typical behavior:

- Load inventory-scoped metrics.
- Calculate KPI counts and chart series.
- Filter out soft-deleted data.
- Return a consistent JSON envelope.

### Assets API

The assets APIs power inventory and discovery flows.

Common behaviors:

- List assets with pagination and search.
- Create new asset rows.
- Edit asset metadata.
- Soft-delete and restore assets.
- Serve asset detail payloads and scan history.

### Scan API

The scan API is the operational API for the Scan Center.

Important endpoints include:

- `GET /api/scans`
- `POST /api/scans`
- `POST /api/scans/bulk`
- `GET /api/scans/<scan_id>/status`
- `GET /api/scans/<scan_id>/result`
- `GET/POST/DELETE /api/scan-schedules`

What it does:

- Accepts scan requests.
- Returns scan history.
- Exposes live status.
- Returns full stored scan results.
- Supports scheduling for periodic scans.

### CBOM API

The CBOM API exposes the cryptographic inventory in list and chart form.

Typical behaviors:

- Return entry lists with search and sorting.
- Provide summary metrics.
- Support the table-9 minimum element views.

### PQC API

The PQC API surfaces classification and scoring data.

Typical behaviors:

- Return posture summaries.
- Return asset-level classifications.
- Provide score distributions.

### Cyber Rating API

The cyber rating API returns enterprise score data and rating history.

Typical behaviors:

- Expose aggregate score metrics.
- Return breakdowns and trends.
- Keep the rating consistent with the same risk formulas used elsewhere.

### Reporting API

The reporting API manages report generation, scheduled jobs, and report retrieval.

### Docs API

The docs endpoint serves the human-readable API catalog. This is helpful because the app itself is the source of truth for supported operations.

## Data model and persistence philosophy

QuantumShield’s persistence layer follows a very clear philosophy: keep raw evidence, keep normalized relational data, and keep summary tables for speed.

### Raw evidence

Raw evidence includes scan reports, discovered services, TLS handshake details, certificate metadata, and the source JSON artifacts saved in `scan_results/`.

Why keep it:

- It supports auditing.
- It lets you re-run calculations if formulas change.
- It gives detail pages something real to show.

### Normalized relational data

Relational tables include assets, scans, certificates, discovery rows, CBOM entries, findings, and user/admin records.

Why keep it:

- It makes filtering and joins efficient.
- It supports inventory and dashboard queries.
- It keeps the data model consistent across the app.

### Summary tables

Summary tables include asset metrics, org metrics, cert expiry buckets, TLS compliance scores, digital labels, and cyber rating snapshots.

Why keep them:

- They make dashboard pages fast.
- They reduce duplicate calculations.
- They are easier to chart and paginate.

### SQL table formats and schema shape

The SQL layer is intentionally relational first, with a few denormalized summary tables for speed. Most tables follow the same format:

- **Primary key**: a numeric `id` or a semantic `asset_id` if the row is 1:1 with an asset.
- **Foreign keys**: point to `assets`, `scans`, `certificates`, `cbom_entries`, or `users`.
- **Soft delete fields**: `is_deleted`, `deleted_at`, `deleted_by_user_id`.
- **Audit fields**: `created_at`, `updated_at`, and sometimes `calculated_at`.
- **Filter columns**: `asset_type`, `severity`, `tier`, `status`, `tls_version`, `key_length`, `label`.
- **Index columns**: foreign keys, timestamps, and heavily filtered columns.

The most important tables are:

- `assets`
	- Core inventory record.
	- Typical columns: `id`, `target`, `asset_type`, `owner`, `risk_level`, `ipv4`, `ipv6`, `url`, `is_deleted`, timestamps.
	- Purpose: the anchor row for every dashboard scope decision.
- `scans`
	- Scan execution history and state.
	- Typical columns: `id`, `target`, `status`, `scan_kind`, `scanned_at`, `started_at`, `completed_at`, `result_scan_id`, `is_deleted`.
	- Purpose: live status, history, and result linkage.
- `certificates`
	- TLS/certificate evidence attached to assets and scans.
	- Typical columns: `id`, `asset_id`, `scan_id`, `subject_cn`, `issuer`, `valid_from`, `valid_until`, `tls_version`, `cipher_suite`, `key_length`, `is_expired`, `is_self_signed`, `endpoint`.
	- Purpose: certificate telemetry, expiry analysis, and PQC scoring inputs.
- `cbom_entries`
	- Cryptographic inventory rows.
	- Typical columns: `id`, `asset_id`, `scan_id`, `algorithm_name`, `asset_type`, `element_name`, `primitive`, `mode`, `oid`, `protocol_version_name`, `cipher_suite`, `subject_name`, `issuer_name`.
	- Purpose: Table 9 compliance view and CBOM list pages.
- `findings`
	- Security issues extracted from scans.
	- Typical columns: `id`, `finding_id`, `asset_id`, `scan_id`, `issue_type`, `severity`, `description`, `metadata_json`, `certificate_id`, `cbom_entry_id`, `is_deleted`.
	- Purpose: risk calculations, audit trail, and drilldowns.
- `asset_metrics`
	- Materialized per-asset calculations.
	- Typical columns: `asset_id`, `pqc_score`, `risk_penalty`, `total_findings_count`, `critical_findings_count`, `pqc_class_tier`, `asset_cyber_score`, timestamps.
	- Purpose: fast dashboard reads without recomputing every request.
- `org_pqc_metrics`
	- Daily enterprise snapshot table.
	- Typical columns: `metric_date`, `total_assets`, `elite_assets_count`, `legacy_assets_count`, `pct_elite`, `avg_pqc_score`, `quantum_safe_pct`, etc.
	- Purpose: trend lines and historical overview.
- `cert_expiry_buckets`
	- Daily certificate expiry summary.
	- Typical columns: `bucket_date`, `count_0_to_30_days`, `count_31_to_60_days`, `count_61_to_90_days`, `count_greater_90_days`, `count_expired`.
	- Purpose: expiry timeline charts.
- `tls_compliance_scores`
	- TLS hygiene summary by asset.
	- Typical columns: `asset_id`, `tls_score`, `weak_tls_version_count`, `weak_cipher_count`, `weak_key_length_count`.
	- Purpose: protocol and cipher compliance views.
- `digital_labels`
	- Derived asset labels for executive filtering.
	- Typical columns: `asset_id`, `label`, `confidence_score`, `based_on_pqc_score`, `based_on_critical_findings`, `label_generated_at`.
	- Purpose: inventory filtering and home dashboard summaries.

### SQL conventions and query patterns

The SQL usage in the app follows a few repeated conventions:

- **Always filter soft-deleted rows** in user-facing queries.
- **Prefer `COUNT(*)`, `COUNT(DISTINCT ...)`, and `GROUP BY`** for dashboard metrics.
- **Use `ORDER BY ... LIMIT ... OFFSET ...`** for paginated tables.
- **Whitelist sort columns** instead of accepting arbitrary SQL sort text.
- **Use joins only when needed**; keep page queries lean and avoid N+1 patterns.
- **Use summary tables** for expensive repeated reads, especially home/PQC/cyber pages.

Typical SQL shapes look like this in plain English:

- inventory list: select active assets, sort by requested column, page through results;
- CBOM dashboard: group entries by key length, cipher suite, protocol, and CA;
- PQC posture: group compliance scores by tier and calculate percentage of each tier;
- reporting: fetch scheduled jobs and generated report rows ordered by newest first;
- recycle bin: select only rows where `is_deleted = true`.

### Relationship map

The common foreign-key relationships are:

- `assets.id` → `scans.asset_id`, `certificates.asset_id`, `cbom_entries.asset_id`, `findings.asset_id`, `asset_metrics.asset_id`, `digital_labels.asset_id`
- `scans.id` → `certificates.scan_id`, `cbom_entries.scan_id`, `findings.scan_id`
- `certificates.id` → `findings.certificate_id`, `pqc_classification.certificate_id`
- `cbom_entries.id` → `findings.cbom_entry_id`

This is why an asset detail page can collect certificate, finding, CBOM, and PQC data together without guessing. The tables are designed to be joined, not improvised.

### Soft-delete discipline

The app treats soft delete as a first-class constraint. Read queries should filter deleted rows, and dashboard computations should honor that filter by default. This is crucial because stale or deleted records can distort security posture if they leak into charts and counts.

### Why there are summary services instead of raw template math

Templates should not compute business logic. If a page has to decide whether an asset is critical or how many certificates are expiring, the logic should live in a service or query layer. That makes the formula reusable, testable, and visible in one place.

## Theme system, token preference, and visual conventions

The token system deserves a dedicated explanation because it is one of the clearest examples of how the repo balances design and maintainability.

### Theme modes

The app supports three conceptual modes:

- **Dark mode** — the default-feeling security-console look, based on navy, slate, and bright semantic accent colors.
- **Light mode** — a high-readability dashboard palette with bright card surfaces and strong borders.
- **System mode** — the runtime mode that follows the user’s OS preference unless explicitly overridden.

The persisted theme file stores a current mode plus dark and light token maps. The runtime code normalizes those values so that malformed or incomplete color values do not break the entire interface.

### Preferred token behavior

The project’s preferred behavior is:

1. Use `bg_*` tokens for surfaces and layout shells.
2. Use `text_*` tokens for hierarchy and readability.
3. Use `accent` for primary action states and highlighted links.
4. Use `safe`, `warn`, and `danger` for semantic meaning.
5. Keep `text_on_accent` distinct so buttons and badges are legible in both light and dark themes.

### Practical palette direction

The project does not want a flat grayscale console. It prefers a layered, contrast-safe palette with enough color to separate meaning without becoming noisy. The recurring visual language is:

- blue for actions and selected state,
- green for success and safe posture,
- amber for caution and upcoming risk,
- red for destructive and critical states,
- slate/navy for shells and elevated panels.

This is why you see chart colors, badges, and button states pulled from the same token family.

### Why the theme lives in `web/theme.json`

The persisted theme file is not just a preference cache. It is a runtime source of truth that the backend loads and sanitizes. That means a user can change the theme in the admin screen and the app will keep that preference across refreshes or restarts. This is important because dashboards are often used repeatedly by the same team, and visual consistency is part of usability.

### Why the navbar toggle was removed

The user-facing theme toggle used to sit in the top navigation, but that turned out to be visually cluttered and inconsistent with the desired admin workflow. Moving the toggle into the theme settings page did two things:

- It reduced header clutter.
- It made theme control feel like an administrative configuration, not a casual display switch.

This is a good example of the repo’s UI philosophy: functionality should live where the user expects to manage it.

### Why 3D effects are subtle, not flashy

The app now uses shadow depth, slight hover lift, soft gradients, and glass borders. It does not use dramatic parallax or heavy animation by default because the product is still a security dashboard. The visuals should support comprehension, not distract from it. The goal is “modern product depth,” not “arcade interface.”

## Detailed backend behavior and why it does specific things

This section explains some of the app’s non-obvious implementation choices.

### Why scans are queued or threaded

Scanning can take time. Even small TLS checks may involve network timeouts, host resolution, certificate parsing, and file generation. The app therefore uses background job behavior or threaded processing for scan flows so the UI does not lock up while a request is running.

The behavior makes the app more responsive, and it makes the scan center feel operational instead of static.

### Why a scan result endpoint exists

The scan center needs to show both live status and the final result. A status endpoint alone is not enough because a job may be complete while the full result payload is larger than the status snapshot. A dedicated result endpoint solves this by returning the stored scan report or the current report snapshot if needed.

This is also better for the UI because the detail drawer can ask for two kinds of data:

 - the live job state,
 - the persisted final result.

## Recent implementation updates (2026-03 — 2026-04)

The project has had a concentrated set of changes and hardenings in March–April 2026. Below is a concise summary of the most important implementation and API-level changes; each bullet includes the primary places to review and the tests used for verification.

- Scans API & orchestration
	- API-first scan flows were added in `web/routes/scans.py`: `GET /api/scans`, `POST /api/scans`, `POST /api/scans/bulk`, `GET /api/scans/<id>/status`, `GET /api/scans/metrics` and `GET /api/scans/<scan_id>/certificates`. See `web/templates/scans.html` and `web/static/js/scans.js` for UI wiring. (See: /memories/repo/scans-api-driven-migration-2026-03-22.md)
	- Scan orchestration now uses background worker threads, in-memory tracking IDs for polling, and sequential multi-target processing.

- CBOM and certificate handling
	- `CbomService` now aggregates `DiscoverySSL` and `Certificate` telemetry (dedupe + meta counters) so CBOM views reflect both discovery and inventory sources. Inventory gating was relaxed so non-deleted scan telemetry is visible in CBOM. (See: /memories/repo/cbom-discovery-ssl-linking-2026-03-29.md)
	- Stable `row_key` identifiers added; `GET /api/cbom/export` supports filtering by `selected_keys` or single `row_key`. Per-row `Extract X.509` export actions and multi-select export are available in the UI. (See: /memories/repo/cbom-multiselect-row-export-2026-03-30.md)
	- X.509 minimum fields are surfaced in CBOM rows (Issued To / Issued By / Validity / SHA-256 fingerprints); public-key SHA-256 fallback derivation is implemented when DB fields are sparse. TLS analyzer writes `certificate_format`, `fingerprint_sha256`, and `public_key_fingerprint_sha256` into `certificate_details`. (See: /memories/repo/cbom-x509-minimum-fields-ui-refinement-2026-03-30.md)

- TLS analyzer & discovery sync
	- The TLS enrichment was switched to SSLyze-based augmentation (replacing the previous pyOpenSSL augmentation). Discovery SSL telemetry gained `pqc_score` and `pqc_assessment` fields; schema compatibility shims were added for legacy DBs. Requirements were updated to include `sslyze>=5.2.0`. (See: /memories/repo/sslyze-and-discovery-sync-2026-03-28.md)
	- `run_scan_pipeline()` now reliably resolves/creates `Asset` rows so certificates, PQC, CBOM and discovery rows remain relationally synced.

- Discovery timestamp & promotion semantics
	- Discovery detection time now falls back safely via `coalesce(promoted_at, scan.completed_at, scan.scanned_at, scan.started_at, scan.created_at)` to avoid missing timestamps in discovery models. Promotion to inventory is explicit; discovery rows are persisted even when not promoted. (See: /memories/repo/discovery-timestamp-fallback-fix-2026-03-29.md)

- PQC, dashboards & API harmonization
	- PQC metrics and assets endpoints were normalized so KPI math and table rows share a single asset-level evidence model. `/api/pqc-posture/metrics` and `/api/pqc-posture/assets` now provide consistent payloads and server-side status filtering. (See: /memories/repo/pqc-posture-tier-consistency-2026-03-29.md)
	- Cyber Rating was normalized to a 0–1000 enterprise score with tier bands (Elite/Standard/Legacy/Critical) exposed via `/api/cyber-rating`. Scan schedule endpoints expanded to full CRUD. (See: /memories/repo/memory-decisions.md)
	- Template parameter mismatches (e.g. `q` vs `search`) and a blueprint naming mismatch in `home.html` were identified as blocking issues; fixes are referenced in the memory notes and should be applied before restart. (See: /memories/repo/dashboard-critical-fixes-2026-03-29.md)

- Security and UX hardening
	- CSRF handling now returns JSON 403 for AJAX calls; shared fetch/response hardening was added (same-origin headers, CSRF forwarding) so AJAX clients get consistent JSON errors instead of HTML redirects. Modal behavior, login UX, and theme contrast received accessibility and stability fixes. (See: /memories/repo/memory-decisions.md)

- DB, services and testing
	- Runtime DB compatibility checks and schema shims were added for discovery PQC fields. Services now resolve `db_session` via `src.db.db_session` at use time to make testing easier and patch-friendly. Targeted regression tests for CBOM parsing, PQC metrics, and discovery persistence were added or updated; test counts and commands are recorded in memory notes. (See: /memories/repo/*)

- Deployment & developer notes
	- Remote MySQL deployment scripts were standardized (`scripts/remote_db_check.py`, `scripts/push_sql_to_remote.py`). `.env.example` remains a placeholder-only file; do not commit real credentials. Requirements updated for new TLS tooling (SSLyze). (See: /memories/repo/memory-decisions.md)

Where to look
- Primary files and folders: `web/routes/scans.py`, `web/static/js/scans.js`, `src/cbom/builder.py`, `src/scanner/tls_analyzer.py`, `src/services/cbom_service.py`, `web/templates/cbom_dashboard.html`, `web/templates/scans.html`, `web/blueprints/api_cbom.py`
- Memory and verification notes: `/memories/repo/scans-api-driven-migration-2026-03-22.md`, `/memories/repo/cbom-discovery-ssl-linking-2026-03-29.md`, `/memories/repo/sslyze-and-discovery-sync-2026-03-28.md`, `/memories/repo/dashboard-critical-fixes-2026-03-29.md`, `/memories/repo/memory-decisions.md`.

If you are applying these changes locally: run the targeted pytest modules listed in the memory files (examples shown near each memory entry) and restart the Flask app to pick up template/blueprint renames and new endpoints.

The `scan_results/` folder contains JSON output like CBOM and scan reports. This matters because the app is not only a dashboard; it is also an evidence system. By storing the artifact on disk, the project preserves the exact data that fed the UI at the time of a scan. That is valuable for debugging, auditing, and future schema migrations.

### Why finding detection is separate from scanning

Finding detection is not the same as raw scanning. Scanning extracts the facts; finding detection interprets them against policy. For example, a certificate being present is a fact. A certificate being expired or using a weak key length is a finding. Keeping that logic separate lets the app update policy rules without rewriting the scanner.

### Why PQC and risk calculations are separate services

PQC posture answers one question: “How ready is the cryptography?” Risk penalty answers another: “How severe are the issues we found?” The project then combines these into an asset cyber score and enterprise rating. That separation makes the formulas easier to test and easier to explain to stakeholders.

### Why the app uses summary tables

Dashboard pages are read much more often than scans are written. Summary tables make reads fast and cheap. Instead of recomputing every distribution from raw telemetry on every page load, the app can update metrics once and then read them many times. This is a classic tradeoff for dashboard-heavy applications.

## Page-by-page functional details

This section goes deeper into each page and what behavior it should show.

### Home page behavior details

The home dashboard should feel like a triage console. Its job is not to drown the user in raw rows. It should summarize the estate and point the user toward the next best action.

It typically includes:

- KPI cards for totals and risk levels,
- charts for distributions,
- recent results or quick scan statuses,
- quick links into inventory, scan center, and CBOM.

Why it behaves this way:

- The user may open the home page first thing in the morning to see if something changed overnight.
- A compact but informative dashboard makes that easy.
- Home should not require the user to know the app’s internal schema.

### Scan Center behavior details

The scan center is intentionally more operational than decorative. It includes form controls for single scans, bulk scans, autodiscovery, inventory-creation options, and schedule management.

It does a few important things:

- lets a user type a target and run an immediate scan,
- lets managers bulk scan a list of targets,
- shows status progression so the user sees queued/running/completed states,
- lets the user click on a row to inspect scan details,
- and keeps schedules in the same workflow area because scheduled execution is operationally close to live scans.

Why the detail drawer matters:

- It keeps the user on the same page.
- It avoids losing context when switching to another screen.
- It exposes both human-readable summary and raw JSON.

### Asset Inventory behavior details

Inventory is the place where the app becomes a management system rather than just a scanner. The page supports:

- filtering,
- sorting,
- pagination,
- bulk selection,
- edit actions,
- delete/restore flows,
- scan initiation,
- detail modals,
- and bulk scan actions.

Why the page uses a shared table abstraction:

- The inventory table is large and interactive.
- Sort and search must be consistent.
- The same table behavior is likely used elsewhere, so the code should be reusable.

### Asset Discovery behavior details

Discovery is a staging area. It should show newly found domains, SSL records, IPs, and software discoveries. It should make it easy to decide whether each row belongs in inventory.

Why this matters:

- Not every discovery is an inventory asset.
- Keeping discovery separate from inventory preserves data quality.
- The promotion step makes the app’s estate curation explicit.

### CBOM behavior details

The CBOM page is special because it is both a compliance summary and a cryptographic inventory browser.

It should:

- show counts by key length,
- show cipher suite usage,
- show protocol versions,
- show certificate authorities,
- expose minimum element mappings,
- and connect the user back to the owning asset when possible.

Why it includes the Table 9 minimum elements view:

- The project has a documented requirement to track a specific list of cryptographic elements.
- Mapping those elements into the UI makes the requirement visible and testable.
- It also helps with future data enrichment and migration work.

### PQC Posture behavior details

The PQC page should answer whether the estate is ready for post-quantum migration and where the weak areas are.

It should show:

- counts of elite/standard/legacy/critical assets,
- score distributions,
- trend lines if available,
- and filterable asset-level details.

Why this is a separate page from Cyber Rating:

- PQC posture is about cryptographic readiness.
- Cyber rating is about overall security impact.
- They are related, but not identical.

### Cyber Rating behavior details

Cyber rating compresses posture and risk into a more executive-friendly score. That score is useful because not everyone wants to reason about key lengths, TLS versions, and finding weights every time.

The page should:

- present the aggregate score prominently,
- show tier breakdowns,
- explain what drives the score,
- and support drilldowns into underlying asset metrics.

### Reporting behavior details

The reporting page exists because security work often needs to be delivered on a schedule. The app should support report generation workflows that are visible, repeatable, and auditable.

This page usually handles:

- scheduled reports,
- on-demand reports,
- report history,
- generated artifacts,
- and report-specific filters or delivery details.

### Admin Theme behavior details

The admin theme page is where the app’s visual contract is managed. It is also where the app’s startup mode can be controlled.

Why this is useful:

- The theme becomes part of system administration.
- Users can control appearance without touching code.
- A shared theme file means the rest of the app can remain token-driven.

### Admin Users and Audit behavior details

These pages exist to keep the application maintainable in a real team environment. They cover user roles, account management, and historical actions.

Why they matter:

- Role-based access is part of the app’s security model.
- Audit trails are useful when changes happen to assets, scans, or settings.
- Admin pages help enforce operational discipline.

## API behavior patterns and response conventions

The API shape is consistent across the app for a reason.

### Common envelope style

Most list APIs return a structure that includes:

- items,
- total counts,
- current page,
- page size,
- total pages,
- KPI fragments,
- and filters.

This is the right choice for table-driven pages because the frontend can render pagination, search, and sorting without having to infer metadata from arbitrary payloads.

### Search and pagination behavior

The app prefers server-side search and pagination. That means the query string usually contains things like `page`, `page_size`, `sort`, `order`, and `q`.

Why server-side search is preferred:

- It keeps the UI responsive for larger datasets.
- It prevents the browser from loading too much data.
- It ensures the counts and tables stay consistent with the database.

### Sort whitelisting

The backend generally uses sort maps or allowed field lists rather than accepting arbitrary SQL sort input. This is important because it avoids accidental injection-like behavior and makes the endpoint contract explicit.

### Soft-delete filtering

All major APIs should filter deleted rows. This is not only a security measure; it is a product integrity measure. If a row is deleted, it should stop showing up in active KPI views, tables, and charts unless the page explicitly says it is looking at deleted data.

### Read-only versus action endpoints

The project carefully separates read endpoints from action endpoints.

- Read endpoints are for tables, charts, details, and histories.
- Action endpoints are for starting scans, restoring assets, deleting items, promoting discoveries, or changing settings.

This separation helps the UI stay predictable and the tests stay focused.

### API-driven frontend and backend flow

The frontend is deliberately thin: it renders the shell, requests JSON, and paints the data. The backend owns the actual logic.

The flow usually looks like this:

1. **Template renders** a page shell with Jinja2.
2. **JavaScript initializes** the relevant module for the page.
3. **Browser calls JSON APIs** using `fetch` or the shared API client.
4. **Backend queries MySQL** using the relational tables and summary tables described above.
5. **Backend returns a consistent envelope** with `success`, `data`, and pagination/filter metadata when needed.
6. **Frontend renders charts, cards, and tables** from the JSON payload.

This pattern is used across the major dashboard surfaces:

- Home page loads KPIs and charts from dashboard APIs.
- Scan Center loads scan history, scan status, and scan results from scan APIs.
- Asset Inventory loads table rows and action responses from asset APIs.
- CBOM loads metrics, minimum elements, and entries from CBOM APIs.
- PQC loads posture summaries and asset-level classifications from PQC APIs.
- Cyber Rating loads enterprise score data from rating APIs.
- Reporting loads schedules and artifacts from report APIs.

### API response shapes used by tables

Most table endpoints return a shape like this:

- `success`: boolean
- `data.items`: list of row objects
- `data.total`: total row count
- `data.page`: current page number
- `data.page_size`: page size used
- `data.total_pages`: computed page count
- `data.filters`: echoed query state (`sort`, `order`, `search`)

That shape is important because the shared table helper can render the same controls everywhere without custom code for each page.

### Frontend data binding conventions

The UI usually binds data in four layers:

- **KPI cards** for summary counts and percentages,
- **Charts** for grouped distributions,
- **Tables** for row-level inspection,
- **Detail panels or drawers** for the selected asset, scan, or result.

The frontend keeps state in the URL when possible (`q`, `sort`, `order`, `page`, `page_size`) so the page can be shared and refreshed without losing context.

### Why the frontend stays API-first

The API-first model gives the app a few benefits:

- easier testing,
- stable contracts,
- reusable data for charts and tables,
- fewer template-side calculations,
- and simpler future automation.

It also makes the app easier to reason about when debugging. If a chart is wrong, you can check the API payload. If the payload is wrong, you can check the SQL query. That is a lot better than hunting through templated arithmetic in a corner of the page.

## Data flow by subsystem

### Scan flow

1. User submits target.
2. Route validates target and permissions.
3. Scan service spawns or handles the job.
4. Network discovery identifies open ports and services.
5. TLS analyzer extracts certificate and cipher details.
6. PQC detector classifies algorithm states.
7. CBOM builder assembles cryptographic inventory rows.
8. Report generator produces summary objects and recommendations.
9. Finder and risk services store findings and metrics.
10. Scan status and result APIs expose the final state.
11. Frontend renders the result and detail views.

### Inventory flow

1. Discovery or scan reveals a new host or service.
2. The user promotes or creates an asset.
3. Asset row is written with metadata.
4. Certificates, CBOM entries, and PQC rows join to that asset.
5. Dashboard queries include the asset in metrics.
6. If deleted, the asset is soft-deleted and excluded from active views.

### CBOM flow

1. Scan report contains cryptographic components.
2. Builder or service maps them into CBOM rows.
3. Table 9 minimum elements are preserved where available.
4. The CBOM dashboard groups and displays them.
5. The data can be exported or used for compliance analysis.

### PQC and risk flow

1. Scan results create PQC classifications and findings.
2. PQC service computes endpoint and asset scores.
3. Risk service computes penalties and cyber score.
4. Summary tables are updated.
5. Posture and rating pages read the stored values.

### Reporting flow

1. The report generator turns current metrics into a report object.
2. Scheduled jobs or on-demand actions save that output.
3. The reporting page exposes the status and the artifact.

## Testing, validation, and quality controls

The test suite is broad because the app has many moving parts.

### Why there are many tests

This project spans multiple layers: scanner, database, dashboard, APIs, deletion flows, and theme behavior. If the tests were shallow, regressions could easily slip in. The suite therefore includes:

- unit tests for isolated services,
- integration tests for API and DB flows,
- smoke tests for page availability,
- and regression tests for specific bug fixes.

### What the tests tend to verify

- Scans still produce results.
- API contracts still return expected envelopes.
- Soft-deleted records remain excluded.
- CBOM mappings include the expected table-9 fields.
- PQC and risk calculations remain consistent.
- UI behavior remains tied to the right routes and role checks.

### Why some tests are skipped or marked legacy

The repo includes evolving schemas and partially migrated areas. In those cases, some legacy tests are intentionally marked as skipped because they depend on older fields or older response shapes. That is not necessarily a bug; it is a sign that the repository is in active refactor mode and the test suite must keep up with the current contract.

## Operational details and how to run the project

### Typical local development flow

The usual workflow is:

1. Create or activate the Python environment.
2. Install requirements.
3. Ensure the DB environment variables are configured in `.env`.
4. Run the Flask app or use the provided launch scripts.
5. Open the browser and verify the dashboards.
6. Run tests after changes.

### Why environment variables matter

The project uses environment variables for DB connection and runtime configuration so the same code can run locally, in CI, or in a deployment container. The repo also includes `.env.example`, which is a common sign that local configuration is expected and should be explicit.

### Why there are scripts for debugging and repair

You will find scripts such as schema checkers, deletion debuggers, column sync tools, and restart helpers. This is normal for a project that has been actively refactored and that needs to reconcile schema and application code. Those scripts reduce manual database pain and help keep the repo healthy.

## Minor details that are easy to miss

This section captures the small things that matter when you work in the repo.

### `base.html` is the global contract

The base template sets the nav, shared CSS variables, active theme tokens, and top-level page shell. If a page looks wrong but the data is right, start here. A lot of downstream pages inherit from this file.

### `table_helper.py` is a quiet but important utility

Table helpers reduce duplication across pages that need sorting, pagination, and empty states. In a data-heavy app, this kind of utility is worth protecting because it keeps UX consistent.

### Page names and route names are intentionally close

The repo often uses names that are very close between the page route, API route, and template file. That makes navigation easier to reason about. It also means you should be careful when renaming things, because compatibility routes may still depend on old names.

### Some files are compatibility layers, not preferred surfaces

Examples include `scan_center.html` alongside `scans.html`. If you are trying to understand the future direction of the app, look at the newer API-first pages and helpers. If you are trying to preserve compatibility, keep both surfaces in mind.

### Design-system files are not decorative

`README_DESIGN_SYSTEM.md`, `DESIGN_SYSTEM_GUIDE.md`, `quantum_ui_refresh.css`, and related documents are part of the implementation story. They are not just style references; they define how the app should feel and how components should behave.

### The repo has a lot of generated artifacts

Files in `scan_results/`, logs, cache directories, and generated summaries may be present. These are useful for debugging and demonstrations, but they should not be confused with source-of-truth runtime logic.

## The scanner, CBOM, validator, and reporting pipeline in narrative form

To understand the product end to end, it helps to tell the story once.

The user enters a target into the Scan Center. The application validates that target and starts the scan. The network discovery layer checks which ports are reachable. The TLS analyzer negotiates secure connections where possible and extracts certificate details. The PQC detector inspects the cryptographic components and marks them as quantum-safe, quantum-vulnerable, or hybrid depending on the algorithm set and policy rules.

Once the raw scan data is assembled, the CBOM builder writes it into a structured bill of materials. The validator layer checks whether the current cryptography aligns with the project’s PQC expectations. The reporting layer then turns those findings into guidance, recommendations, and a clean summary page. The service layer computes PQC scores, risk penalties, and enterprise ratings so the dashboard can show stable metrics.

That story is what the app is really doing. The pages are just different ways of telling it.

## Why the app feels the way it does

The app’s current behavior is a mix of product requirements and implementation pragmatism.

- It feels dashboard-like because it is summarizing security data.
- It feels operational because scans are live and stateful.
- It feels admin-oriented because there are role-gated actions and theme controls.
- It feels safe because the color system is semantic, the deletes are soft, and the APIs are explicit.
- It feels maintainable because the data is centralized in services and summary tables.

The project is trying to be a real security console rather than a toy. That means it needs to balance clarity, data correctness, and speed.

## A compact “what to look at first” list

If you are new to the codebase, the fastest way to orient yourself is:

1. Read `README.md` for the overall product summary.
2. Read `docs/GLOBAL_APP_REFACTOR_V2.md` for the inventory-centric API contract.
3. Read `web/app.py` to see the app bootstrap and theme behavior.
4. Read `web/templates/base.html` to understand the global shell.
5. Read `web/templates/scans.html` and `web/static/js/scans.js` for the scan center.
6. Read `web/templates/asset_inventory.html` and `web/routes/assets.py` for inventory flows.
7. Read `web/templates/cbom_dashboard.html` and `src/services/cbom_service.py` for CBOM logic.
8. Read `src/services/pqc_calculation_service.py` and `src/services/risk_calculation_service.py` for scoring logic.
9. Read `web/theme.json` and `web/static/css/style.css` for the theme system.
10. Skim the tests to see what behaviors the repo already considers important.

## Final summary

QuantumShield is a security dashboard with a strong data backbone. It scans targets, stores evidence, builds CBOMs, calculates PQC posture, measures risk, and presents the outcome in a token-driven UI with role-aware behavior and soft-delete safe inventory management. The repository is deliberately layered so that scanning, persistence, metrics, and UI concerns do not collapse into one another. That is why the folder structure looks the way it does, why the APIs are shaped the way they are, and why the app has so many service modules and templates.

If you keep one mental model in mind while reading or editing the codebase, keep this one: **the scanner discovers facts, the services interpret facts, the APIs expose facts, and the templates present facts**. Everything else in the repo supports that pipeline.

## Appendix A: file-by-file reference notes

This appendix gives short but useful notes on the files that matter most when you are working in the repo. It is not a full source-code dump; it is a practical map.

### Core application files

- `web/app.py` — application bootstrap, theme loading, compatibility routes, top-level page handlers, and scan-related orchestration glue.
- `web/theme.json` — persisted theme settings and palette tokens. It is read by the app and updated from the admin theme page.
- `config.py` — runtime constants such as DB config, risk weights, PQC thresholds, and scanner defaults.
- `src/db.py` — DB session wiring and ORM access.
- `src/database.py` — persistence helpers for scan storage and retrieval.
- `src/models.py` — ORM classes used by the inventory, scan, CBOM, and metrics layers.

### Route and API files

- `web/routes/assets.py` — inventory CRUD, delete/restore, bulk actions, asset detail route, and discovery promotion flows.
- `web/routes/scans.py` — scan lifecycle management, scan history, live status, result retrieval, and scheduling endpoints.
- `web/routes/dashboard_api.py` — dashboard payload helpers and top-level metrics behavior.
- `web/routes/pqc_dashboard.py` — PQC posture page route logic.
- `web/blueprints/api_home.py` — home metrics API.
- `web/blueprints/api_assets.py` — asset inventory and asset detail APIs.
- `web/blueprints/api_cbom.py` — CBOM entries and metrics APIs.
- `web/blueprints/api_pqc.py` — PQC posture APIs.
- `web/blueprints/api_cyber.py` — cyber rating APIs.
- `web/blueprints/api_reports.py` — reporting APIs.
- `web/blueprints/api_docs.py` — API catalog and docs pages.

### Scanner and report files

- `src/scanner/network_discovery.py` — finds services and reachable ports.
- `src/scanner/tls_analyzer.py` — extracts TLS and certificate material.
- `src/scanner/pqc_detector.py` — classifies algorithms and PQC readiness.
- `src/cbom/builder.py` — assembles cryptographic inventory rows.
- `src/cbom/cyclonedx_generator.py` — writes CycloneDX export payloads.
- `src/validator/quantum_safe_checker.py` — policy checks for quantum-safe status.
- `src/validator/certificate_issuer.py` — label/certificate issuance helpers.
- `src/reporting/report_generator.py` — builds report objects and summaries.
- `src/reporting/recommendation_engine.py` — produces migration guidance and remediation suggestions.

### Service files

- `src/services/dashboard_data_service.py` — dashboard payload assembly and KPI grouping.
- `src/services/distribution_service.py` — counts, distributions, expiry buckets, and chart-friendly summaries.
- `src/services/finding_detection_service.py` — turns telemetry into findings.
- `src/services/pqc_calculation_service.py` — computes PQC score and classification.
- `src/services/risk_calculation_service.py` — computes penalties, cyber score, and vulnerability summaries.
- `src/services/cyber_reporting_service.py` — report-facing aggregations and rating logic.
- `src/services/certificate_telemetry_service.py` — certificate-oriented lookup and telemetry logic.
- `src/services/inventory_scan_service.py` — asset scanning helper logic.

### Template files

- `web/templates/base.html` — shared shell, nav, theme variables, and layout inheritance.
- `web/templates/home.html` — home dashboard.
- `web/templates/index.html` — landing/entry page variant.
- `web/templates/scans.html` — new scan center.
- `web/templates/scan_center.html` — compatibility scan center.
- `web/templates/asset_inventory.html` — inventory table and bulk action UI.
- `web/templates/asset_discovery.html` — discovery tabs and graph.
- `web/templates/cbom_dashboard.html` — CBOM metrics and tables.
- `web/templates/pqc_posture.html` — PQC readiness page.
- `web/templates/cyber_rating.html` — risk/enterprise score page.
- `web/templates/reporting.html` — scheduled and on-demand reporting.
- `web/templates/recycle_bin.html` — deletion recovery and purge UI.
- `web/templates/admin_theme.html` — theme management page.
- `web/templates/admin_users.html` — user/role management.
- `web/templates/docs.html` — built-in docs and endpoint guide.
- `web/templates/results.html` — detailed result page for a completed scan.
- `web/templates/asset_detail.html` — asset detail page with linked telemetry.

### Static assets

- `web/static/css/style.css` — main design system and layout styling.
- `web/static/css/table.css` — table/search/pagination surfaces.
- `web/static/css/api_dashboards.css` — dashboard card and KPI presentation.
- `web/static/css/quantum_ui_refresh.css` — shared depth and responsiveness enhancement layer.
- `web/static/js/app.js` — theme and nav runtime.
- `web/static/js/scans.js` — scan center runtime.
- `web/static/js/api-table.js` — reusable data table runtime.
- `web/static/js/api_client.js` — API client wrapper.

### Docs and guides

- `README.md` — product summary and quick start.
- `docs/GLOBAL_APP_REFACTOR_V2.md` — inventory-centric API-first contract.
- `docs/API.md` and `docs/api.md` — API reference and endpoint behavior.
- `docs/ARCHITECTURE_AND_QUANTUM_SAFE_GUIDE.md` — architecture and compliance context.
- `docs/math-defination-for-quantumshield-app.md` — metric formula basis.
- `docs/Table 9_ Minimum Elements for Cryptographic Assets.md` — CBOM element requirements.
- `docs/USER_GUIDE.md` — user-facing workflow guide.
- `docs/DEPLOYMENT.md` — deployment notes.
- `docs/SECURITY.md` if present in your branch or environment — security boundaries and operational cautions.

## Appendix B: configuration and environment notes

### `.env`

The project expects database and runtime configuration in `.env`. The canonical keys are the DB settings used by the app, and the repo keeps an `.env.example` so you can see the required shape without exposing secrets.

Commonly relevant environment settings include:

- `DB_HOST`
- `DB_PORT`
- `DB_USER`
- `DB_PASSWORD`
- `DB_NAME`

The repo may also support backward-compatible aliases such as older `MYSQL_*` names, but the V2 refactor docs treat the `DB_*` family as the canonical form.

### App configuration behavior

The application configuration influences:

- scan behavior,
- scheduler behavior,
- database connectivity,
- risk thresholds,
- PQC thresholds,
- and possibly the default theme mode.

This matters because a dashboard app often has a hidden assumption that “the page is static.” In QuantumShield, the page is only stable because the underlying config is stable. If config changes, the dashboard and scoring behavior change too.

### Why there are many helper scripts

There are scripts for schema checking, column synchronization, deletion inspection, boot/debug output, and other operational tasks. These scripts are the residue of a real application that has been evolved over time. Rather than ignoring them, it is better to treat them as maintenance tools that show where the project has had to deal with schema drift, migration gaps, or debug workflows.

## Appendix C: testing map by concern

### Scanner tests

The scanner tests usually verify:

- network discovery behavior,
- TLS analysis behavior,
- PQC detection behavior,
- and scan-result assembly.

These tests are important because the whole app depends on the scanner producing clean structured data. If the scanner output is wrong, every downstream chart and score is suspect.

### CBOM tests

CBOM-related tests verify:

- CBOM builder output,
- entry formatting,
- table-9 field mapping,
- and summary data integrity.

These tests matter because the CBOM dashboard is only useful if the cryptographic rows are correctly normalized.

### Dashboard and envelope tests

The dashboard/API envelope tests check:

- response shapes,
- pagination metadata,
- table behaviors,
- and whether the expected keys exist.

This is critical because the frontend expects stable payloads and should not have to guess at the shape of a response.

### Deletion and recycle-bin tests

Deletion tests verify that:

- assets are soft-deleted,
- dependent rows are handled correctly,
- deleted data stays out of active views,
- and restore or purge paths behave as expected.

This is one of the most important categories because the app uses deletion as part of its operational model, not as a trivial afterthought.

### Theme and UI tests

UI-related tests or checks should verify:

- navbar behavior,
- theme control placement,
- visibility of relevant buttons,
- and page rendering under the current token system.

### Why some tests use fixtures heavily

Security dashboards often need a lot of structured sample data. Fixtures let the tests create assets, scans, certificates, and findings without depending on a live production environment. This keeps the suite reproducible and makes regressions easier to isolate.

## Appendix D: maintenance advice for future changes

### If you add a new dashboard page

Do not start by styling the page directly. Start by defining:

1. the data source,
2. the API response shape,
3. the page’s KPI cards,
4. the table or chart behavior,
5. and the soft-delete / scope rules.

Once the data contract is clear, the template is much easier to build.

### If you change a metric formula

Update the formula in one service layer first, then make sure:

- the persisted summary table gets refreshed,
- the API exposes the same definition,
- the UI consumes the new value consistently,
- and any tests that encode the formula are updated.

If the formula changes but the frontend still interprets the old logic, the app becomes misleading.

### If you add a new color token

Add it to the token source, define its meaning, and use it consistently. Avoid using a color just because it looks nice in one place. The theme should remain semantic.

### If you add a new action endpoint

Make sure the endpoint has:

- a clear authorization rule,
- explicit request validation,
- a predictable response envelope,
- and a UI affordance that explains what the action does.

### If you add a new page that shows a table

Re-use the existing table helper pattern if possible. The project already values shared search/sort/pagination behavior, so a one-off table should be the exception, not the norm.

## Appendix E: the “why” behind a few subtle product choices

### Why the project keeps a human-readable docs surface inside the app

Security tools are easier to adopt when the operator does not have to leave the product to understand the product. The built-in docs page gives the app a self-describing quality that is useful for onboarding and validation.

### Why the app leans toward action-oriented labels

Buttons like “Run Scan,” “Open Result,” “Inspect,” and “Create Schedule” are deliberately direct. A security console should reduce ambiguity. Operators should not have to translate abstract terms into action.

### Why the interface tries to balance density and whitespace

Too much whitespace wastes screen space on the kinds of pages this app has. Too little whitespace makes the data unreadable. The current design direction aims for dense but calm panels, where cards and tables have enough separation to be scannable without feeling empty.

### Why the product keeps both raw JSON and rendered summaries

Raw JSON is for fidelity and debugging. Rendered summaries are for daily use. The project needs both because different stakeholders need different views of the same evidence.

### Why the repo values compatibility routes

Compatibility routes protect the project while the UI evolves. They are especially useful in a refactoring-heavy codebase, because they let you improve the new experience without breaking old bookmarks or hidden tests that still hit legacy paths.

## Appendix F: quick mental model for new contributors

If you only remember one page of this guide, remember this one:

- **`src/scanner/`** discovers data.
- **`src/services/`** interprets and stores data.
- **`web/blueprints/` and `web/routes/`** expose data.
- **`web/templates/` and `web/static/`** present data.
- **`docs/`** defines expected behavior and formulas.
- **`tests/`** prevent the product from drifting away from those expectations.

That is the real architecture of the project.




