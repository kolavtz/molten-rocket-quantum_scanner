You are implementing a production-grade upgrade of the QuantumShield web app (PSB Hackathon 2026) with two non-negotiable priorities:

1) Best-in-class UI/UX (modern, fast, accessible, responsive, consistent).
2) Fully functional API-first behavior using the latest active endpoints in this repo.

Build for correctness, maintainability, and real data integrity. Do not use dummy data in final features.

---

## 1) Product & Stack Constraints

- Backend: Flask 3 + Python 3.10+, SQLAlchemy, MySQL 8
- Frontend: Jinja2 templates + vanilla JS + Chart.js
- UI style: modern dark glassmorphism with strong readability and accessibility
- Navigation: top header menu (not sidebar)
- Core menu sections:
  - Home
  - Scans center
  - Asset Inventory
  - Asset Discovery
  - CBOM
  - Posture of PQC
  - Cyber Rating
  - Reporting

No fake placeholders for production screens. For empty DB states, render clear UX messages (e.g., “No data yet. Run a scan.”).

---

## 2) Latest Endpoint Contract (Use These)

Treat the following as the active API contract for dashboards and page data:

### Home
- `GET /api/home/metrics`

### Assets & Discovery
- `GET /api/assets`
- `POST /api/assets`
- `GET /api/assets/<id>`
- `GET /api/assets/<id>/scans`
- `GET /api/discovery?tab=domains|ssl|ips|software`
- `POST /api/discovery/promote`

### CBOM
- `GET /api/cbom/metrics`
- `GET /api/cbom/entries`
- `GET /api/cbom/summary?scan_id=<id>`

### PQC Posture
- `GET /api/pqc-posture/metrics`
- `GET /api/pqc-posture/assets`

### Cyber Rating
- `GET /api/cyber-rating`
- `GET /api/cyber-rating/history`

### Reporting
- `GET /api/reports/scheduled`
- `GET /api/reports/ondemand`
- `GET /api/reports/<id>`

### API docs
- `GET /api/docs`
- `GET /docs`

If you encounter old or alternate API docs, prefer endpoints that are actually implemented in code.

---

## 3) Universal Data UX Requirements (All Tables)

For every major table (Inventory, Discovery tabs, CBOM entries, PQC assets, Cyber history, Reporting):

- Sortable headers (asc/desc toggle)
- URL-synced sort/query state (`sort`, `order`, `q`, `page`, `page_size`)
- Server-side search
- Pagination with:
  - page size selector (10/25/50)
  - next/previous
  - direct “go to page N”
- Stable empty, loading, and error states

Use a reusable table abstraction (template macro + JS helper) to avoid duplicated logic.

---

## 4) Functional Quality Requirements

### Data integrity
- Use normalized relational modeling with proper foreign keys.
- Ensure soft-delete semantics are respected (`is_deleted` filtered in reads).
- Never show soft-deleted entities in dashboard metrics, charts, or table rows.

### Consistency
- Use a consistent response envelope (`success`, `data`, optional `filters`/meta).
- Keep naming and formatting consistent across pages and APIs.

### Performance
- Efficient pagination and query planning.
- Avoid N+1 query patterns for table views.
- Keep UI responsive under moderate dataset sizes.

### Security & roles
- Respect `@login_required` and role restrictions where applicable.
- Keep destructive actions protected with confirmation UX.

---

## 5) UI/UX Excellence Requirements

Design and implement professional UI behavior:

- Accessibility:
  - visible focus states
  - keyboard-navigable controls
  - semantic labels for icon buttons
  - sufficient contrast in dark theme
- Responsive:
  - mobile-first behavior
  - no horizontal overflow
  - stable layout at common breakpoints
- Interaction quality:
  - clear hover/active/disabled states
  - async loading feedback (skeleton/spinner)
  - non-blocking toasts and inline validation
- Visual consistency:
  - one icon style set
  - consistent spacing scale
  - typography hierarchy and semantic color tokens

---

## 6) Required Implementation Outputs

Produce and/or refactor code so the app includes:

1. API-driven data fetching layer for each page section.
2. Shared table/search/sort/pagination component pattern.
3. Refined page layouts for:
   - Home Dashboard
   - Asset Inventory
   - Asset Discovery
   - CBOM Dashboard
   - PQC Posture
   - Cyber Rating
   - Reporting
4. Reusable empty/loading/error state components.
5. Proper handling of soft-deleted records and stale references.

---

## 7) Definition of Done

The implementation is done only when:

- All key pages are API-driven and functional with real backend data.
- All major tables support sort/search/pagination with URL state.
- UI is visually consistent, responsive, and accessible.
- Empty states and failures are user-friendly and non-breaking.
- Endpoint usage matches the latest implemented routes listed above.
- No dummy seeded content is required for normal operation.

Focus on shipping a polished, scalable product experience—not just rendering data.