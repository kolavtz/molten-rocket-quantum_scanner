## ✅ Rewritten Prompt: API-based Asset CBOM Dashboard

Build an internal dashboard that shows asset CBOM data from our own API.

- Define a REST API contract for CBOM assets (list, detail, filter by asset type/status, pagination).
- Implement backend endpoints (e.g., `GET /api/assets`, `GET /api/assets/{id}/cbom`) with DB persistence.
- Create frontend dashboard UI with:
  - asset table (name, id, owner, environment, CBOM completeness)
  - status badges (up-to-date, stale, missing)
  - search/filter (asset tag, cert status, scanner date)
  - detail view for CBOM dependency tree and risk data
- Add sorting and pagination to both API and UI.
- Ensure security: auth check, input validation, parameterized DB queries.
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
- Responsive layout for desktop and tablet views