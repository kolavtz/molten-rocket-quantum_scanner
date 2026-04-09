home page prompt:
# Home Dashboard Specification

## Overview
The Home Dashboard provides a unified security posture view, displaying asset inventory, risk metrics, and discovery activity. All data originates from backend APIs.

## Layout & Components

### Header Navigation
Top navigation bar with sections:
- Home
- Scans Center
- Asset Inventory
- Asset Discovery
- CBOM
- Posture of PQC
- Cyber Rating
- Reporting

### Primary Metrics Row
Four key-value cards displaying:
- Total Assets Count
- Public Web Apps Count
- APIs
- Servers

### Secondary Metrics Row
Four cards displaying:
- Expiring Certificates (< 30 days)
- High Risk Assets
- Total Scans Completed
- Weak Cipher Details

### Charts Section

#### Asset Type Distribution
Donut chart showing asset breakdown by type (fetched via `/api/home/metrics` or `/api/cbom/charts`).

#### Asset Risk Distribution
Horizontal bar chart displaying risk level counts (Critical, High, Medium, Low) via `/api/home/metrics` or `/api/cbom/metrics`.

#### High Risk Percentage
Single metric card showing percentage of assets with risk score ≥ threshold (via `/api/home/metrics`).

#### Certificate Expiry Timeline
Stacked bar chart with four buckets (0–30, 30–60, 60–90, 90+ days) via `/api/cbom/charts`.

### Geolocation Map
OpenStreetMap component displaying asset locations (via `/api/discovery/ip-locations`). Markers indicate risk level via color coding.

### Top 10 High Risk Assets Table
Sortable table with columns:
- Asset Name
- Asset Type
- Risk Score
- Last Scan Date

Data paginated from `/api/assets?risk_min=75&sort=risk_score&order=desc`.

### Recent Discoveries (Last 7 Days)
Table listing assets added to discovery within 7 days:
- Asset Name/Identifier
- Type (Domain, IP, SSL, Software)
- Discovery Date
- Status

Data from `/api/discovery?sort=detection_date&order=desc`.

### Top 5 Vulnerable Software
List displaying software with known vulnerabilities (via `/api/discovery?tab=software&sort=risk_score&order=desc`).

## Empty State UX
When no data exists:
- Show placeholder cards with "No data available" messaging.
- Provide action links to Asset Discovery or Scans Center.
- Maintain layout integrity.

## Design System
- **Theme**: Dark glassmorphism with translucent panels.
- **Color Coding**: Risk levels (Red=Critical, Orange=High, Yellow=Medium, Green=Low).
- **Typography**: High contrast for readability.
- **Accessibility**: WCAG 2.1 AA compliance (focus states, keyboard navigation, labels).

## API Integration Notes
- All endpoints return paginated, time-series, or aggregated JSON.
- Implement error boundaries for failed requests.
- Cache asset distribution and expiry data (5-minute TTL recommended).
- Real-time updates for recent discoveries via polling or WebSocket.

redo all the ui components for the main dashboard the first dashboard (home dashboard ), should have details like main dashboard should list total assets count, public web apps count, apis, servers, expiring certificate details(expiring in less than 30 days ), and high risk assets in the top row then, list donut or other type of chart of asset type by distribution, and asset risk distribution single line bar chart and percentage of asset under high risk, certificate expiry timelines where it list 0-30 days, 30-60 days, 60 - 90 days and more than 90 days, there should be openstreet map component which should show the location of assets on the map, and there should be a table which list the top 10 high risk assets with details like asset name, asset type, risk score, and last scan date. The UI should be modern dark glassmorphism style with strong readability and accessibility. The navigation should be a top header menu with sections for Home, Scans center, Asset Inventory, Asset Discovery, CBOM, Posture of PQC, Cyber Rating, and Reporting. For empty DB states, render clear UX messages, total scans completed, weak cipher details, and top 5 vulnerable software details.
recent discovery like if something is in inventory and its discovered in last 7 days it should be listed in the home dashboard with details like asset name, asset type, discovery date, and risk score. The home dashboard should also have a section for recent discoveries, listing assets that were added to the inventory in the last 7 days, along with their asset name, asset type, discovery date, and risk score. The overall design should prioritize readability and accessibility while maintaining a modern dark glassmorphism aesthetic.

#### Asset Type Distribution

asset inventory page should have a table listing all assets with columns for asset name, asset type, risk score, last scan date, and actions (view details, edit, delete). The page should also include filters for asset type and risk score, as well as a search bar for quick asset lookup. For empty states, display a message like "No assets found. Please add assets to the inventory." The design should be consistent with the modern dark glassmorphism style used throughout the application. anything in the table should be clickable to view more details about the asset, and there should be clear calls to action for editing or deleting assets. The page should also include pagination if there are a large number of assets in the inventory. the asset inventory 
page should support real-time data fetching via API endpoints:
- `GET /api/assets` (with query params: `search`, `page`, `page_size`, `sort`, `order`, `asset_type`, `risk_min`, `risk_max`)
- `GET /api/assets/{id}` (for detail view)
- `GET /api/assets/{id}/comprehensive` (for Intelligence modal)
- `POST /api/assets` (for create/scan)
- `DELETE /api/assets/{id}` (for soft-deletion)

All table rows, filter dropdowns, and search inputs must be wired to actual API calls with proper error handling, loading states, and validation. No seeded or mock data—only persisted database results. Implement skeleton loaders during fetch, empty state when API returns zero results, and error alerts if API calls fail. Use the standardized response envelope: `{success: true, data: {...}, meta: {...}}`.

asset inventory page should have a table listing all assets with columns for asset name, asset type, risk score, last scan date, and actions (view details, edit, delete). The page should also include filters for asset type and risk score, as well as a search bar for quick asset lookup. For empty states, display a message like "No assets found. Please add assets to the inventory." The design should be consistent with the modern dark glassmorphism style used throughout the application. anything in the table should be clickable to view more details about the asset, and there should be clear calls to action for editing or deleting assets. The page should also include pagination if there are a large number of assets in the inventory.


### Asset Discovery Page
asset discovery page should have a tabbed interface with tabs for domains, SSL certificates, IP addresses, and software (via `GET /api/discovery?tab={domains|ssl|ips|software}&search={query}`). Each tab should display a table with relevant information for that category. Use `/api/discovery/promote` (POST) to move items to the inventory.

For map visualization, use `GET /api/discovery/ip-locations` which returns geo-enriched coordinates. The network mapping and topology should visualize relations between assets (if implemented in the backend/graph-layer).
### CBOM Page
## ✅ Rewritten Prompt: API-based Asset CBOM Dashboard

Build an internal dashboard that shows asset CBOM data from our own API.

- Define a REST API contract for CBOM assets (list, detail, filter by asset type/status, pagination).
- Implement backend endpoints (e.g., `GET /api/assets`, `GET /api/cbom/entries`, `GET /api/cbom/metrics`, `GET /api/cbom/charts`, `GET /api/cbom/export`) with DB persistence.
- Create frontend dashboard UI with:
  - asset table (name, id, owner, environment, CBOM completeness)
  - status badges (up-to-date, stale, missing)
  - search/filter (asset tag, cert status, scanner date) - use `search` parameter.
  - detail view for CBOM dependency tree and risk data (via `/api/cbom/summary` or `/api/assets/{id}/comprehensive`)
- Add sorting and pagination to both API and UI.
- Ensure security: auth check via `api_guard`, input validation, parameterized DB queries.
- Include tests for API routes and dashboard behaviors.


### Frontend: CBOM Dashboard & Summary Pages

#### CBOM Inventory Page
- **Table layout**: columns for software name, version, associated assets, risk score, and actions (view details, edit, delete)
- **Filtering**: by software name and risk score range
- **Search bar**: quick lookup by software name or asset tag
- **Empty state**: "No CBOM entries found. Please run a scan to populate the CBOM."
- **Row interactions**: click any row to view full details; clear CTAs for edit/delete
- **Pagination**: support large inventories with configurable page size
- **Design**: dark glassmorphism aesthetic with strong contrast for accessibility

#### CBOM Detail View
- **Dependency tree**: visual hierarchy of software components and their relationships
- **Risk metadata**: individual risk scores, vulnerability links, remediation guidance
- **Associated assets**: linked systems/environments using this component
- **Actions**: edit software metadata, mark as reviewed, delete entry

#### CBOM Summary Page (Metrics Dashboard)
- **Key metrics**: total unique software components, scan coverage (sites/assets surveyed)
- **Visualizations**:
    - Bar chart: distribution of risk scores (low/medium/high/critical)
    - Pie chart: breakdown of associated assets by software component
    - Trend graph: CBOM completeness over time
- **Cryptographic inventory**: 
    - Table: certificate name, issuer, expiration date, key length, cipher suite, associated assets
    - Weak cipher detection: highlight non-compliant encryption protocols
    - Protocol pie chart: distribution of TLS/SSL versions in use
    - Vulnerability summary: vulnerable certificate details with remediation links

#### Design & UX
- Maintain dark glassmorphism throughout (glassmorphic cards, subtle gradients, blur effects)
- Ensure WCAG AA contrast ratios and keyboard navigation
- Responsive layout for desktop and tablet views.
### CBOM Content and Cryptographic Inventory
The CBOM module provides a comprehensive inventory of software components and cryptographic assets via:
- `GET /api/cbom/metrics`: Global KPIs for weak crypto, cert health, and coverage.
- `GET /api/cbom/entries`: Table data for software components and associated assets.
- `GET /api/cbom/charts`: Data for algorithm, protocol, and key length distribution charts.
- `GET /api/cbom/export`: CycloneDX 1.6 compliant JSON export.

### Posture of PQC Page
The PQC posture page provides insights into post-quantum cryptography readiness via:
- `GET /api/pqc-posture/metrics`: Global readiness distribution and risk matrix data.
- `GET /api/pqc-posture/assets`: Asset list with PQC score and classification (Ready, Not Ready, etc.).

Actionable recommendations are derived from the `remedy_instructions` field in the response.

# Cyber Rating Page – Requirements & Design

The Cyber Rating page provides a consolidated organizational posture view and per-asset ratings via:
- `GET /api/cyber-rating`: Latest score (0–1000), tier (Elite, Standard, Legacy, Critical), and factor breakdown.
- `GET /api/cyber-rating/history?days={7|30|90}`: Historical score trend data.

Tier Definitions:
- **Elite (700–1000)**: Modern best-practice crypto posture.
- **Standard (400–699)**: Acceptable enterprise configuration.
- **Legacy (1–399)**: Weak but operational; remediation required.
- **Critical (0 or exploitable)**: Insecure or exploitable; immediate action required.

# Cyber Reporting
Manage reports via:
- `GET /api/reports/scheduled`: List configured recurring reports.
- `GET /api/reports/ondemand`: List or initiate on-demand report generations.
- `POST /report/generate`: Generate and download a PDF report.
- `POST /report/schedule`: Schedule a new report.

# Scan Center
Manage and track scanning activities via:
- `GET /api/scans`: List all scan history with status, timings, and targets.
- `GET /api/scans/{id}/status`: Track real-time status of a specific scan job.
- `POST /api/assets` (or `/api/scans`): Initiate a new scan by providing a target.
- `POST /api/assets/bulk` (or `/api/scans/bulk`): Initiate multiple scans.
ty and accessibility. 