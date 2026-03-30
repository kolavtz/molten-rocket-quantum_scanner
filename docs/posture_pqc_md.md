# PQC Posture Dashboard

## Overview
The PQC Posture page provides comprehensive visibility into post-quantum cryptography readiness across your asset inventory. It combines metrics, visualizations, and actionable insights to guide remediation efforts.

## Key Components

### 1. Summary Cards
- **PQC Ready**: Count and percentage of compliant assets
- **PQC Not Ready**: Count and percentage of non-compliant assets
- **Needs Improvement**: Count and percentage requiring updates
- **Risk Score**: Consolidated risk assessment across all assets

### 2. Visualizations
- **Asset Classification Chart**: Breakdown by asset type and PQC status
- **PQC Status Distribution**: Pie/bar chart showing ready vs. not ready vs. needs improvement
- **Risk Matrix**: Consolidated risk scores mapped across all assets
- **Trend Chart**: Historical PQC readiness over time (if scan history exists)

### 3. Asset Inventory Table
Sortable, filterable table with columns:
- Asset Name (clickable → details view)
- Asset Type
- PQC Status (badge: Ready / Not Ready / Needs Improvement)
- Risk Score (numeric)
- Last Scan Date
- Actions (view details, initiate scan)

### 4. Filters & Search
- **PQC Status Filter**: Multi-select (Ready, Not Ready, Needs Improvement)
- **Risk Score Range**: Slider (Low, Medium, High, Critical)
- **Asset Type Filter**: By classification
- **Search Bar**: Quick lookup by asset name or identifier

### 5. Remediation Guidance
- Recommended algorithm upgrades (e.g., CRYSTALS-Kyber, CRYSTALS-Dilithium)
- Implementation best practices and timeline priorities
- Links to relevant security controls and compliance standards

## Empty State
Display when no assets exist or no scans have run:
> "No assets found. Please run a scan to populate the asset inventory."

## Design Principles
- Modern dark glassmorphism aesthetic with frosted glass panels and gradient accents
- High contrast text for accessibility (WCAG AA minimum)
- Interactive elements are clearly labeled with call-to-action buttons
- All table rows and chart segments are clickable for drill-down detail views
