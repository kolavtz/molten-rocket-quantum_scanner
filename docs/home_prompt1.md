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
Donut chart showing asset breakdown by type (fetched via `/api/assets/distribution/by-type`).

#### Asset Risk Distribution
Horizontal bar chart displaying risk level counts (Critical, High, Medium, Low) via `/api/assets/distribution/by-risk`.

#### High Risk Percentage
Single metric card showing percentage of assets with risk score ≥ threshold (via `/api/assets/risk-percentage`).

#### Certificate Expiry Timeline
Stacked bar chart with four buckets:
- 0–30 days
- 30–60 days
- 60–90 days
- 90+ days

Data from `/api/certificates/expiry-timeline`.

### Geolocation Map
OpenStreetMap component displaying asset locations (via `/api/assets/geo-locations`). Markers indicate risk level via color coding.

### Top 10 High Risk Assets Table
Sortable table with columns:
- Asset Name
- Asset Type
- Risk Score
- Last Scan Date

Data paginated from `/api/assets/high-risk?limit=10`.

### Recent Discoveries (Last 7 Days)
Table listing assets added to inventory within 7 days:
- Asset Name
- Asset Type
- Discovery Date
- Risk Score

Data from `/api/assets/recent-discoveries?days=7`.

### Top 5 Vulnerable Software
List displaying software with known vulnerabilities (via `/api/vulnerabilities/top-software`).

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