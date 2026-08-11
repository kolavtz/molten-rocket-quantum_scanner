# QuantumShield Component Breakdown by Page

## 📋 Overview

This document maps **components to build** for each page of QuantumShield, using the design system colors, typography, and spacing.

---

## 1. Scanner Page (`pages/scanner.md`)

**Purpose:** Minimal form for users to input scan targets  
**Pattern:** Lead Magnet + Form (3 fields max for best conversion)  
**Style:** Swiss Modernism (grid-based, rational)

### Components to Build

#### **Hero Section**
- Heading: "Scan for Quantum-Safe Crypto" (Inter 32px, #1E293B)
- Subheading: "Discover cryptographic assets and validate NIST PQC compliance" (Inter 18px, #475569)
- Background: #F8FAFC

#### **Form Container**
- Grid: 12-column layout, centered max-width 600px
- Padding: `var(--space-3xl)` (64px)
- Shadow: `var(--shadow-lg)`
- Border radius: 12px

#### **Input Field — Domain/IP**
- Label: "What would you like to scan?" (Inter 16px, #1E293B, font-weight: 600)
- Input: type="url" | type="text" (hostname or IP)
- Placeholder: "example.com or 192.168.1.1"
- Border: 2px solid #E2E8F0 on focus → #2563EB
- Padding: `var(--space-md)` (16px)
- Border radius: 8px
- Font: Inter 16px, #1E293B
- **Validation:** On blur, show error if invalid format

#### **Optional: Port Range Input**
- Label: "Ports to scan (optional)" (Inter 14px, #64748B)
- Input: type="text" (e.g., "443,8443" or "1-65535")
- Help text: "Leave blank for common crypto ports (443, 8443, 465, 993)" (Inter 12px, #94A3B8)
- Hidden by default, show on "Advanced Options" toggle

#### **Advanced Options Toggle**
- Component: Checkbox or Disclosure (accessible)
- Label: "Advanced options"
- On toggle: slide down additional inputs (port range, timeout)

#### **Submit Button — Scan Now**
- Button style: Primary (background: #F97316, text: white)
- Padding: `var(--space-md)` 24px horizontal, 12px vertical
- Font: Inter 16px, weight: 600
- Border radius: 8px
- Hover: opacity 0.9, translateY(-1px)
- Loading state: Show spinner inside button, disable click
- **Success feedback:** Navigate to Results page with scan ID

#### **Quick Links / Example Targets**
- Heading: "Try these examples:" (Inter 14px, #64748B)
- Pill buttons: `example.com`, `certbot.eff.org`, `google.com`
- On click: populate domain field + auto-focus

#### **Footer Note**
- Text: "Scans run concurrently. Results appear in dashboard." (Inter 12px, #94A3B8)
- Icon: Info icon (SVG, #94A3B8)

### Accessibility Checklist (Scanner)
- [ ] Form labels with `<label for="...">` matching input id
- [ ] Tab order: Domain → Ports (if visible) → Advanced → Submit
- [ ] Error messages in aria-live region
- [ ] Submit button with `aria-busy="true"` during load
- [ ] Keyboard: Enter submits form
- [ ] Touch: 44×44dp minimum on buttons

---

## 2. Results Page (`pages/results.md`)

**Purpose:** Full cryptographic asset inventory with compliance status  
**Pattern:** Before-After Transformation (legacy assets → quantum-safe status)  
**Style:** Trust & Authority (show badges, security credentials)

### Components to Build

#### **Header Section**
- Title: "Crypto Asset Inventory — [Domain]" (Inter 32px, #1E293B)
- Subtitle: "Generated [Date]" (Inter 14px, #64748B)
- Back button: `← Back to Scanner` (link style, #2563EB)
- Actions: Download CBOM (button, secondary), Rescan (button, primary)

#### **Summary Cards Row**
Horizontal scrollable row of 4 cards, each:
- Card background: #F8FAFC
- Card shadow: `var(--shadow-md)`
- Card padding: `var(--space-lg)` (24px)
- Border radius: 12px

**Card 1: Total Assets**
- Number: `{count}` (Inter 32px, #2563EB, weight: 700)
- Label: "Cryptographic Assets" (Inter 14px, #64748B)
- Icon: Stack/inventory (SVG, #2563EB, 24px)

**Card 2: Quantum-Safe Ready**
- Number: `{count}` (Inter 32px, #10B981, weight: 700) *[success green]*
- Label: "PQC Ready (ML-KEM/ML-DSA)" (Inter 14px, #64748B)
- Icon: Shield-check (SVG, #10B981, 24px)
- Tooltip: "Compliant with FIPS 203/204/205"

**Card 3: At Risk (Legacy Crypto)**
- Number: `{count}` (Inter 32px, #EF4444, weight: 700) *[warning red]*
- Label: "Requires Migration" (Inter 14px, #64748B)
- Icon: Alert-triangle (SVG, #EF4444, 24px)
- Tooltip: "HNDL (Harvest Now, Decrypt Later) vulnerable"

**Card 4: Compliance Score**
- Progress circle: 65% (example)
- Center: `65%` (Inter 24px, #2563EB, weight: 700)
- Label: "NIST PQC Compliance" (Inter 12px, #64748B)
- Animated: On mount, count up from 0 to 65%

#### **Risk Assessment Gauge**
- Style: Gauge chart (semi-circle)
- Color zones: Green (0-33), Amber (33-66), Red (66-100)
- Center value: "Medium Risk" (Inter 18px, #EF4444)
- Below: "HNDL Score: 6.2/10" (Inter 12px, #64748B)

#### **Crypto Assets Table**
Responsive table with sortable columns:

**Columns:**
1. **Asset Name** (sortable, default ascending)
   - Data: Certificate CN, cipher name, key exchange method
   - Example: "CN=example.com", "TLS_AES_256_GCM_SHA384", "X25519"
2. **Type** (sortable)
   - Data: "TLS Certificate" | "Cipher Suite" | "Key Exchange"
3. **Algorithm**
   - Data: RSA-2048, ECDSA P-256, ChaCha20-Poly1305, etc.
4. **Status** (sortable)
   - Data: Quantum-safe badge (green) OR Legacy warning (red)
5. **Compliance** (sortable)
   - Data: "NIST FIPS 203" | "FIPS 204" | "Not PQC"
6. **Actions**
   - Buttons: View Details, Migration Guide (dropdown)

**Table Features:**
- Pagination: 25 rows per page
- Filter: By type, status, compliance
- Search: Full-text on asset name/algorithm
- Sort: Click column header to toggle ascending/descending
- Responsive: On mobile, show 2 main columns + actions

#### **Asset Detail Modal** (on "View Details" click)
- Header: Asset name (Inter 24px, #1E293B)
- Fields:
  - Full Name / CN
  - Discovered: [Date/Time]
  - Port: [443, 8443, etc.]
  - Algorithm details (Key size, strength, NIST status)
  - Certificate chain (if applicable)
  - Recommendation (action text in orange)
- Action button: "View Migration Guide" → opens external doc or overlay

#### **Migration Guide Section** (below table)
- Heading: "Migration Roadmap" (Inter 24px, #1E293B)
- Accordion/collapsible list:
  - **Legacy Assets (RSA-2048, ECDSA P-256)**
    - Action: Migrate to ML-KEM (NIST FIPS 203)
    - Config example: For Nginx, Apache, AWS ALB
    - Snippet: Copyable code block
  - **Hybrid Approach (Recommended)**
    - Action: Deploy ML-KEM alongside existing cipher
    - Config: Example TLS config
  - **Timeline Suggestion**
    - Q2 2026: Audit complete
    - Q3 2026: Hybrid ciphers deployed
    - Q4 2026: Legacy ciphers deprecated

#### **Export CBOM Button**
- Primary button: "Download CBOM (CycloneDX)"
- On click: Trigger JSON file download
- File name: `{domain}_{date}_cbom.json`
- Format: CycloneDX 1.6 with crypto component metadata

### Accessibility Checklist (Results)
- [ ] Table headers: `<th scope="col">`
- [ ] Sortable columns: aria-sort="ascending|descending|none"
- [ ] Modal: role="dialog", focus trap, close with Escape
- [ ] All badges and icons have text label or aria-label
- [ ] Charts/gauges: Accessible text alternative (table)
- [ ] Expandable sections: aria-expanded="true|false"
- [ ] Links have descriptive text (not just "Click here")

---

## 3. Dashboard Page (`pages/dashboard.md`)

**Purpose:** Aggregate metrics, scan history, compliance trends  
**Pattern:** Before-After Transformation (scanning in progress → results visible)  
**Style:** Data visualization with pulse animations

### Components to Build

#### **Header Section**
- Title: "Dashboard" (Inter 32px, #1E293B)
- Filter: Date range selector (last 7 days, 30 days, custom)
- Actions: New Scan (button, primary), Export Report (button, secondary)

#### **Metric Cards Grid** (4 columns, responsive)
Same as Results Summary Cards, but with **animation on mount** (slide up from below, fade in).

- Total Scans
- Avg Assets Per Scan
- Compliance Trend (↑ improving, ↓ declining)
- At-Risk Assets (flagged count)

#### **Scan History Table**
Columns:
1. **Target** (domain/IP)
2. **Date** (formatted: "Mar 22, 2026 3:45 PM")
3. **Assets Found**
4. **Status** (badge: Completed, In Progress, Failed)
5. **Compliance** (% PQC ready)
6. **Actions** (View, Rescan, Export)

Features:
- Pagination: 10 rows per page
- Sort: By date (newest first), assets count, compliance %
- Filter: By status
- Row click: Navigate to Results page for that scan

#### **Compliance Trend Chart**
- Chart type: Line chart
- X-axis: Last 30 days (date labels)
- Y-axis: Compliance % (0–100)
- Data series: "PQC Ready %"
- Interactive: Hover tooltip shows exact % + asset count
- Animation: Line draws on mount (2s duration, ease-out)

#### **Risk Distribution Chart**
- Chart type: Donut/Pie
- Segments:
  - Green: Quantum-Safe Ready
  - Amber: At-Risk (legacy)
  - Red: Critical (no migration plan)
- Legend: Below chart, clickable to toggle visibility
- Animation: Segments fill on mount (staggered ~100ms each)

#### **Recent Activity Feed** (bottom section)
- Heading: "Recent Scans" (Inter 18px, #1E293B)
- List items:
  - "Scanned example.com (45 assets, 78% PQC ready)" — 2 hours ago
  - "Generated CBOM for api.target.com" — 1 day ago
  - "Migration guide created for legacy RSA-2048" — 3 days ago
- Each item: Hover shows timestamp, click navigates to scan result

#### **Alert Banner** (if applicable)
- Background: #EFF6FF (light blue) or #FEF3C7 (light amber)
- Border-left: 4px solid #2563EB or #F59E0B
- Text: "3 cryptographic assets require migration within 90 days" (Inter 14px, #1E293B)
- Icon: Info or warning (SVG, left-aligned)
- Close button: X (top-right)

### Animations for Dashboard
- Card entrance: Scale from 0.95 → 1, fade in (150ms, ease-out)
- Chart draws: Line/segments animate on mount (1.5–2s, ease-out)
- Metric pulse: Subtle pulse on high-risk metrics (infinite, 2s loop)
- Stagger: Cards stagger by 50ms each (offset from left to right)

### Accessibility Checklist (Dashboard)
- [ ] Charts have `<img alt="...">` or `<table>` fallback
- [ ] All metric numbers have context (label, unit)
- [ ] Alert banner: role="alert" or aria-live="polite"
- [ ] Charts: Tab navigable, arrow keys to switch data series
- [ ] Tooltips: Keyboard accessible (focus-triggered)
- [ ] Animations: Skip if prefers-reduced-motion set

---

## 🔧 Component Library (Reusable)

Build these **once**, use across all 3 pages:

### 1. **Button Component**
Variants: primary, secondary, outline, danger, disabled, loading
Props: size (sm|md|lg), onClick, disabled, loading, icon

### 2. **Card Component**
Props: children, shadow (sm|md|lg), padding, onClick, hoverable

### 3. **Input Component**
Props: type, label, placeholder, error, helpText, onChange, required, disabled

### 4. **Badge Component**
Variants: success (green), warning (amber), error (red), info (blue)
Props: children, variant

### 5. **Modal Component**
Props: open, title, children, onClose, actions (footer buttons)
Features: Focus trap, Escape to close, Backdrop click to close

### 6. **Table Component**
Props: data, columns (with sortable flags), loading, empty state
Features: Pagination, sort, accessible headers (aria-sort)

### 7. **Chart Components**
- LineChart (trends, time series)
- DonutChart (risk distribution)
- GaugeChart (compliance score)
- BarChart (optional, for comparisons)

### 8. **Spinner/Loader**
Props: size (sm|md|lg), text (optional)
Color: #2563EB (uses primary color)

### 9. **Toast/Notification**
Props: message, type (success|error|info), duration (auto-dismiss in 3s)
Position: Bottom-right or top-right

### 10. **Tooltip**
Props: text, position (top|bottom|left|right)
Trigger: Hover (web), long-press (mobile)
Delay: 200ms before show

---

## 📝 Page Implementation Order

**Recommended sequence** (simplest to most complex):

1. **Scanner** — Form only, minimal state management
2. **Results** — Table + cards + modal, reuse Button/Badge/Card
3. **Dashboard** — Charts, complex state, reuse all components

---

## 🎨 Design Token Usage

When building components, always use these tokens:

```jsx
// Colors
const PRIMARY = '#2563EB';
const SECONDARY = '#3B82F6';
const CTA = '#F97316';
const BACKGROUND = '#F8FAFC';
const TEXT = '#1E293B';

// Spacing
const SPACE = { xs: 4, sm: 8, md: 16, lg: 24, xl: 32, '2xl': 48, '3xl': 64 };

// Shadows
const SHADOW = {
  sm: '0 1px 2px rgba(0,0,0,0.05)',
  md: '0 4px 6px rgba(0,0,0,0.1)',
  lg: '0 10px 15px rgba(0,0,0,0.1)',
  xl: '0 20px 25px rgba(0,0,0,0.15)',
};

// Font
const FONT = {
  family: "'Inter', sans-serif",
  sizes: { xs: 12, sm: 14, base: 16, lg: 18, xl: 24, '2xl': 32 },
  weights: { light: 300, normal: 400, medium: 500, semiBold: 600, bold: 700 },
};
```

---

**Ready to build! Start with Scanner page, reference MASTER.md for detailed specs.**
