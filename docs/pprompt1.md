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

redo all the ui components for the main dashboard the first dashboard (home dashboard ), should have details like main dashboard should list total assets count, public web apps count, apis, servers, expiring certificate details(expiring in less than 30 days ), and high risk assets in the top row then, list donut or other type of chart of asset type by distribution, and asset risk distribution single line bar chart and percentage of asset under high risk, certificate expiry timelines where it list 0-30 days, 30-60 days, 60 - 90 days and more than 90 days, there should be openstreet map component which should show the location of assets on the map, and there should be a table which list the top 10 high risk assets with details like asset name, asset type, risk score, and last scan date. The UI should be modern dark glassmorphism style with strong readability and accessibility. The navigation should be a top header menu with sections for Home, Scans center, Asset Inventory, Asset Discovery, CBOM, Posture of PQC, Cyber Rating, and Reporting. For empty DB states, render clear UX messages, total scans completed, weak cipher details, and top 5 vulnerable software details.
recent discovery like if something is in inventory and its discovered in last 7 days it should be listed in the home dashboard with details like asset name, asset type, discovery date, and risk score. The home dashboard should also have a section for recent discoveries, listing assets that were added to the inventory in the last 7 days, along with their asset name, asset type, discovery date, and risk score. The overall design should prioritize readability and accessibility while maintaining a modern dark glassmorphism aesthetic.

#### Asset Type Distribution

asset inventory page should have a table listing all assets with columns for asset name, asset type, risk score, last scan date, and actions (view details, edit, delete). The page should also include filters for asset type and risk score, as well as a search bar for quick asset lookup. For empty states, display a message like "No assets found. Please add assets to the inventory." The design should be consistent with the modern dark glassmorphism style used throughout the application. anything in the table should be clickable to view more details about the asset, and there should be clear calls to action for editing or deleting assets. The page should also include pagination if there are a large number of assets in the inventory. the asset inventory 
page should support real-time data fetching via API endpoints:
- `GET /api/assets` (with query params for filters, search, pagination)
- `GET /api/assets/{id}` (for detail view)
- `DELETE /api/assets/{id}` (for deletion)
- `PUT /api/assets/{id}` (for edits)

All table rows, filter dropdowns, and search inputs must be wired to actual API calls with proper error handling, loading states, and validation. No seeded or mock data—only persisted database results. Include skeleton loaders during fetch, empty state when API returns zero results, and error alerts if API calls fail.

asset inventory page should have a table listing all assets with columns for asset name, asset type, risk score, last scan date, and actions (view details, edit, delete). The page should also include filters for asset type and risk score, as well as a search bar for quick asset lookup. For empty states, display a message like "No assets found. Please add assets to the inventory." The design should be consistent with the modern dark glassmorphism style used throughout the application. anything in the table should be clickable to view more details about the asset, and there should be clear calls to action for editing or deleting assets. The page should also include pagination if there are a large number of assets in the inventory.


### Asset Discovery Page
asset discovery page should have a tabbed interface with tabs for domains, SSL certificates, IP addresses, and software. Each tab should display a table with relevant information for that category, such as domain name, certificate details, IP address, or software name and version. The page should also include filters and search functionality for each category, as well as clear calls to action for promoting discovered items to the asset inventory. For empty states, display messages like "No domains discovered yet. Run a scan to find new assets." The design should maintain the modern dark glassmorphism aesthetic while ensuring strong readability and accessibility.
 The design should be consistent with the modern dark glassmorphism style used throughout the application. anything in the table should be clickable to view more details about the asset. asset discovery page should have ip to location mapping with openstreet map component which should show the location of discovered ip addresses on the map. The page should also include a section for recent discoveries, listing items that were discovered in the last 7 days, along with their name, type, discovery date, and risk score. The overall design should prioritize readability and accessibility while maintaining a modern dark glassmorphism aesthetic. also sould have a network mapping, asset discovery should also track details like detection date product name, version, associated assets, and risk score for software discoveries. The design should maintain the modern dark glassmorphism aesthetic while ensuring strong readability and accessibility. The network mapping should visually represent the relationships between discovered assets, showing how they are connected within the network. This could be implemented using a graph visualization library, allowing users to easily understand the structure of their asset network and identify potential vulnerabilities or points of interest. The design should prioritize clarity and usability while maintaining the overall aesthetic of the application. network mapping and topology shoud visualize relation between assets and how they are connected in the network, showing details like asset name, and ip related to that mapping and topology. 
### CBOM Page
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
 the cbom page should have a table listing all CBOM entries with columns for software name, version, associated assets, risk score, and actions (view details, edit, delete). The page should also include filters for software name and risk score, as well as a search bar for quick lookup. For empty states, display a message like "No CBOM entries found. Please run a scan to populate the CBOM." The design should be consistent with the modern dark glassmorphism style used throughout the application. anything in the table should be clickable to view more details about the CBOM entry, and there should be clear calls to action for editing or deleting entries. The page should also include pagination if there are a large number of CBOM entries in the inventory. The CBOM summary page should provide an overview of the CBOM metrics, including the total number of unique software components, the distribution of risk scores across all entries, and a breakdown of associated assets by software component. This page should also include visualizations such as bar charts or pie charts to represent the distribution of risk scores and associated assets.  
 The CBOM page should have at minimum cryptographic bills of materials including total software, sites surveyed, weak ciphers, vulnerable certificate details, encryptioh protocols pie chart, certificate details like certificate name, issuer, expiration date, key length, cipher, certificate issuer and any other relevant information from the ssl certificate, and associated assets. The design should maintain the modern dark glassmorphism aesthetic while ensuring strong readability and accessibility.


### Posture of PQC Page

 posture of pqc page should have a asset classification chart, pqc status for all the services like pqc ready, pqc not ready, needs improvement, and risk matrix for all the assets(consolidated), and a table listing all assets with their PQC status, risk score, and last scan date. The page should also include filters for PQC status and risk score, as well as a search bar for quick asset lookup. For empty states, display a message like "No assets found. Please run a scan to populate the asset inventory." The design should be consistent with the modern dark glassmorphism style used throughout the application. anything in the table should be clickable to view more details about the asset, and there should be clear calls to action for improving PQC posture. The page should also include visualizations such as bar charts or pie charts to represent the distribution of PQC status and risk scores across all assets. The PQC posture page should provide insights into the current state of post-quantum cryptography readiness across the asset inventory, highlighting areas that require attention. this page should also include important remedy instuctions and recommendations for improving the PQC posture of assets, such as upgrading to quantum-resistant algorithms or implementing additional security controls. The design should maintain the modern dark glassmorphism aesthetic while ensuring strong readability and accessibility. 

# Cyber Rating Page – Requirements & Design

## Overview

The Cyber Rating page provides a comprehensive overview of the organization's cybersecurity posture, highlighting strengths, weaknesses, and actionable improvement guidance. The design maintains a modern dark glassmorphism aesthetic with strong readability and accessibility.

## Core Metrics

**Cyber Rating Scale:** 0–1000 (normalized)
- **Elite (700–1000):** Modern best-practice crypto posture
- **Standard (400–699):** Acceptable enterprise configuration
- **Legacy (0–399):** Weak but operational; remediation required
- **Critical:** Insecure or exploitable; immediate action required

## Page Sections

### 1. Current Rating & Status
- Display current cyber rating score with visual indicator (gauge or color-coded badge)
- Show tier classification and brief assessment
- Include last update timestamp

### 2. Historical Trends
- Line chart showing cyber rating over time
- Trend indicators (improving, declining, stable)
- Comparison period selector (7 days, 30 days, 90 days, YTD)

### 3. Contributing Factors Breakdown
- Bar chart showing distribution of contributing factors (e.g., TLS version, ciphers, certificate strength, vulnerability count)
- Summary statistics for each factor

### 4. Compliance Tiers Table

| Tier | Security Level | Key Criteria | Requirements | Recommended Action |
|------|---|---|---|---|
| Tier-1 | Elite | Modern best-practice crypto | TLS 1.2/1.3 only; strong ciphers (AES-GCM, ChaCha20); ECDHE; certificates ≥2048-bit; HSTS enabled; no weak protocols or known vulnerabilities | Maintain configuration; periodic monitoring |
| Tier-2 | Standard | Acceptable enterprise | TLS 1.2 primary; legacy protocols phased; strong ciphers; key ≥2048-bit; forward secrecy optional | Improve gradually; disable legacy protocols; standardize cipher suites |
| Tier-3 | Legacy | Weak but operational | TLS 1.0/1.1 enabled; weak ciphers (CBC, 3DES); missing forward secrecy; key possibly 1024-bit | Remediation required; upgrade TLS stack; rotate certificates; remove weak ciphers |
| Critical | Insecure/Exploitable | Insecure baseline | SSL v2/v3 enabled; key <1024-bit; weak ciphers (<112-bit security); known vulnerabilities | Immediate action: block or isolate service; replace certificate and TLS configuration; patch vulnerabilities |

### 5. Recent Changes
- Timeline or list of significant rating changes (improvements/declines)
- Explanation of driver for each change

### 6. Recommendations
- Prioritized action items based on contributing factors
- Guidance for addressing high-risk assets
- PQC (post-quantum cryptography) posture improvements

## Scope

- **Consolidated view:** Aggregate cyber rating across all inventory items (holistic organizational posture)
- **Per-item view:** Individual cyber rating for each website/asset in inventory

## Empty State

"Cyber rating data not available. Please run scans to generate data."

## Design Notes

- Maintain dark glassmorphism aesthetic throughout
- Ensure WCAG 2.1 AA accessibility compliance
- Use clear, high-contrast indicators for rating tiers
- Responsive layout for desktop and mobile viewing


    the cyber rating page should display the current cyber rating score, historical trends of the cyber rating over time, and a breakdown of factors contributing to the current rating. The page should include visualizations such as line charts to show historical trends and bar charts to represent the distribution of contributing factors. For empty states, display a message like "Cyber rating data not available. Please run scans to generate data." The design should maintain the modern dark glassmorphism aesthetic while ensuring strong readability and accessibility. the cyber rating should be in a range of 0 to 1000 and should have clear indicators of what constitutes a good, average, or poor rating. The page should also include recommendations for improving the cyber rating based on the contributing factors, such as addressing high-risk assets or improving PQC posture. The design should maintain the modern dark glassmorphism aesthetic while ensuring strong readability and accessibility. like Tier Security Level Compliance Criteria Priority/Action cyber rating should have table with columns for tier, security level, compliance criteria, and priority/action. The table should clearly outline the requirements for each tier and provide actionable recommendations for improving the cyber rating based on the current state of the asset inventory. The design should maintain the modern dark glassmorphism aesthetic while ensuring strong readability and accessibility. like of some pqc rating is less than 400 then it should be legacy and critical and if its between 400 to 700 then it should be standard and if its above 700 then it should be elite. The cyber rating page should provide a comprehensive overview of the organization's cybersecurity posture, highlighting areas of strength and weakness, and offering clear guidance for improvement. The design should maintain the modern dark glassmorphism aesthetic while ensuring strong readability and accessibility. and highest maximum score after normaization should be 1000 and lowest should be 0. The page should also include a section for recent changes in the cyber rating, listing any significant improvements or declines in the rating along with the reasons for those changes. The design should maintain the modern dark glassmorphism aesthetic while ensuring strong readability and accessibility. this cyber rating should be for all the items in inventory section should be calculated for in consolidation data ( all data in total ) and single website also. 

    Tier-1 Elite Modern best- TLS 1.2/ TLS 1.3 only; Strong Ciphers (AES- Maintain Configuration;
    practise crypto GCM/ChaCha20); Forward Secrecy periodic monitoring;
    posture (ECDHE); certificate >2048-bit (prefer recommended baseline
    3072/4096): no weak protocols; no known for public-facing apps
    vulnerabilities: HSTS enabled
    Tier-2 Standard Acceptable TLS 1.2 supported but legacy protocols Improve gradually; disable
    enterprise allowed; Key>2048-bit; Mostly strong legacy protocols;
    configuration ciphers but backward compatibility allowed; standardise cipher suites.
    Forward secrecy optional

    Tier-3 Legacy Weak but still TLS 1.0/TLS 1.1 enabled; weak ciphers Remediation required;
    operational (CBC, 3DES); Forward secrecy missing; Key upgrade TLS stack; rotate
    possibly 1024-bit certificated; remove weak
    cipher suites

    Critical Insecure/ SSL V2 /SSL V3 enabled; Key <1024-bit; weak Immediate action block or
    exploitable cipher suites (<112-bit security) Known isolate service; replace
    vulnerabilities certificate and TLS
    configuration patch
    vulnerabiilties


// 

# Cyber Reporting

## Scheduled Reports

A dedicated section listing all reports configured to run on a regular basis. Each entry displays:
- Report name and type
- Schedule (frequency, next run time)
- Current status (active, paused, failed)
- Last execution timestamp

**Empty state:** "No scheduled reports found. Please set up scheduled reports."

## On-Demand Reports

User-initiated reporting interface allowing custom report generation based on:
- Specific criteria (threat types, assets, severity levels)
- Custom timeframes and date ranges
- Report format preferences

## Report Details View

Each report includes:
- **Findings:** Summarized security discoveries with severity indicators
- **Visualizations:** Charts and graphs tracking trends over time
- **Recommendations:** Prioritized remediation actions with estimated impact
- **Export options:** PDF, CSV, and scheduled delivery formats

## Design & UX

- Modern dark glassmorphism aesthetic with strong contrast for accessibility
- Clear hierarchy and readable typography
- Actionable insights to support:
    - Cybersecurity posture tracking
    - Trend identification
    - Progress monitoring
    - Remediation prioritization


cyber reporting should have a section for scheduled reports, listing all reports that are set to run on a regular basis along with their schedule and status. There should also be a section for on-demand reports, allowing users to generate reports based on specific criteria or timeframes. Each report should have a detailed view that includes the report's findings, visualizations, and recommendations for remediation. For empty states, display messages like "No scheduled reports found. Please set up scheduled reports." The design should maintain the modern dark glassmorphism aesthetic while ensuring strong readability and accessibility. The reporting page should provide users with actionable insights into their cybersecurity posture, helping them to identify trends, track improvements, and prioritize remediation efforts effectively. The design should maintain the modern dark glassmorphism aesthetic while ensuring strong readability and accessibility.
in the reporting section 

scan center should have a list of all scans that have been run, along with their status (completed, in progress, failed), start and end times, and the assets that were scanned. Users should be able to click on a scan to view detailed results, including any vulnerabilities found, risk scores, and recommendations for remediation. The page should also include filters for scan type, status, and date range, as well as a search bar for quick lookup. For empty states, display a message like "No scans found. Please run a scan to populate the scan center." The design should maintain the modern dark glassmorphism aesthetic while ensuring strong readability and accessibility. The scan center should provide users with comprehensive insights into their scanning activities, helping them to track progress, identify trends, and prioritize remediation efforts effectively. The design should maintain the modern dark glassmorphism aesthetic while ensuring strong readability and accessibility., the scan center should also have the option to add the scan should have option to add the scan details to the inventory section and cbom section if the user wants to. The scan center should also have a section for scheduled scans, allowing users to set up scans to run on a regular basis based on specific criteria or timeframes. Each scheduled scan should have a detailed view that includes the scan's parameters, schedule, and status. For empty states, display messages like "No scheduled scans found. Please set up scheduled scans." The design should maintain the modern dark glassmorphism aesthetic while ensuring strong readability and accessibility. The scan center should provide users with actionable insights into their scanning activities, helping them to track progress, identify trends, and prioritize remediation efforts effectively. The design should maintain the modern dark glassmorphism aesthetic while ensuring strong readability and accessibility. also keep in mind the asset inventory and scan centre are two different sections and they should be designed in a way that they are different but also consistent with each other in terms of design and user experience. The scan center should focus on providing insights into scanning activities, while the asset inventory should focus on providing a comprehensive view of the assets in the inventory. Both sections should maintain the modern dark glassmorphism aesthetic while ensuring strong readability and accessibility. 