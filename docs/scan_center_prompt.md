
# Scan Center Requirements

## Overview
The Scan Center provides a comprehensive dashboard for managing and analyzing security scans. It displays scan history, enables detailed result review, and supports scheduling recurring scans.

## Core Features

### Scan History
- List view of all completed and in-progress scans
- Columns: scan name, status (completed/in-progress/failed), start time, end time, scanned assets
- Click scan to view detailed results: vulnerabilities, risk scores, remediation recommendations
- Filters: scan type, status, date range
- Search bar for quick lookup
- Empty state: "No scans found. Please run a scan to populate the scan center."

### Scan Integration
- Option to add scan results to Inventory section
- Option to add scan results to CBOM section
- User-initiated, per-scan basis

### Scheduled Scans
- Section for recurring scan configuration
- Create, edit, view, and delete scheduled scans
- Display: scan parameters, schedule, next run time, status
- Empty state: "No scheduled scans found. Please set up scheduled scans."

## Design & UX

### Visual
- Modern dark glassmorphism aesthetic
- Consistent with Asset Inventory in design language, distinct in layout and focus
- Strong readability and accessibility

### Interaction
- Scan Center: emphasizes scanning activities, trends, and remediation prioritization
- Asset Inventory: emphasizes asset catalog and composition
- Both sections maintain coherent navigation and information hierarchy

scan center should have a list of all scans that have been run, along with their status (completed, in progress, failed), start and end times, and the assets that were scanned. Users should be able to click on a scan to view detailed results, including any vulnerabilities found, risk scores, and recommendations for remediation. The page should also include filters for scan type, status, and date range, as well as a search bar for quick lookup. For empty states, display a message like "No scans found. Please run a scan to populate the scan center." The design should maintain the modern dark glassmorphism aesthetic while ensuring strong readability and accessibility. The scan center should provide users with comprehensive insights into their scanning activities, helping them to track progress, identify trends, and prioritize remediation efforts effectively. The design should maintain the modern dark glassmorphism aesthetic while ensuring strong readability and accessibility., the scan center should also have the option to add the scan should have option to add the scan details to the inventory section and cbom section if the user wants to. The scan center should also have a section for scheduled scans, allowing users to set up scans to run on a regular basis based on specific criteria or timeframes. Each scheduled scan should have a detailed view that includes the scan's parameters, schedule, and status. For empty states, display messages like "No scheduled scans found. Please set up scheduled scans." The design should maintain the modern dark glassmorphism aesthetic while ensuring strong readability and accessibility. The scan center should provide users with actionable insights into their scanning activities, helping them to track progress, identify trends, and prioritize remediation efforts effectively. The design should maintain the modern dark glassmorphism aesthetic while ensuring strong readability and accessibility. also keep in mind the asset inventory and scan centre are two different sections and they should be designed in a way that they are different but also consistent with each other in terms of design and user experience. The scan center should focus on providing insights into scanning activities, while the asset inventory should focus on providing a comprehensive view of the assets in the inventory. Both sections should maintain the modern dark glassmorphism aesthetic while ensuring strong readability and accessibility. also only scan but not added inventory should be not shown in the cbom and any other dashboard except scan center, only scan added inventory should be shown in the cbom and any other dashboard except scan center.