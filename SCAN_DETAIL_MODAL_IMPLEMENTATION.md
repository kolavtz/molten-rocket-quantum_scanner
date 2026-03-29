# Scan Detail Modal Implementation

**Status:** ✅ COMPLETE  
**Date:** 2026-03-28  
**Test Results:** 8/8 tests passing, 327/338 total tests pass (no regressions)

## Overview

A full-page modal experience replacing the `/results/<scan_id>` page navigation. Users now view scan results in an overlay without leaving the Scan Centre page.

## Architecture

### Design Pattern
- **Framework:** Vanilla JavaScript (no dependencies)
- **Styling:** Glassmorphism with backdrop blur (CSS3)
- **Z-Index:** 99000 (above all content)
- **Template Engine:** Jinja2

### Files Changed

#### 1. `web/templates/common/scan_detail_modal.html` (NEW)
840 lines: HTML structure + inline CSS + JavaScript controller

**Key Sections:**
- Modal shell: Fixed position overlay with glassmorphic backdrop
- Header: Title, subtitle, close button
- Content (scrollable): Loading state, metadata card, results grid, tables, recommendations
- JavaScript controller: `window.ScanDetailModal` object with `open()`, `close()`, `populateModal()` methods

**CSS Classes Used:**
- `.qs-modal-overlay` - Backdrop with blur effect
- `.qs-modal-shell` - Modal container
- `.qs-modal-header`, `.qs-modal-content` - Layout sections
- `.qs-detail-card` - Metadata card styling
- `.qs-modal-pill` - Status badges

**JavaScript API:**
```javascript
window.ScanDetailModal = {
  open(scanId),       // Fetch & display scan result
  close(),            // Hide modal
  populateModal(report), // Populate modal with report data
  _colorToRgb(color)  // Utility: convert hex to RGB
}
```

#### 2. `web/templates/base.html` (MODIFIED)
Added line ~334:
```html
{% include 'common/scan_detail_modal.html' %}
```
Placed after existing asset modal include.

#### 3. `web/templates/scans.html` (MODIFIED)
Changed `_scanActionButtons()` function:

**Before:**
```javascript
<a href="/results/${scanId}">View</a>
```

**After:**
```javascript
<button onclick="window.ScanDetailModal.open('${scanId}')">View</button>
```

#### 4. `tests/test_scan_detail_modal.py` (NEW)
8 integration tests covering:
- Template existence and Jinja2 compilation
- Modal inclusion in base.html
- Button trigger verification
- API endpoint contract
- HTML structure validation
- Accessibility attributes
- Keyboard handlers

## How It Works

### User Flow
1. User clicks "View" button in Scan Centre history table
2. Button calls `window.ScanDetailModal.open(scanId)`
3. Modal fetches `/api/scans/<scanId>/result`
4. Data populates modal sections (metadata, tables, recommendations)
5. User can close via:
   - Close button (top-right X)
   - Backdrop click
   - Escape key

### Modal States

#### Loading State
- Shows spinner and "Loading scan details..." message
- Hides all content until data arrives

#### Success State
- Displays all sections: metadata, results summary, tables, recommendations
- Tables scroll independently (max-height with overflow-y: auto)
- Status pills color-coded (green: ✓ pass, yellow: ⚠ warning, red: ✗ fail)

#### Error State
- Shows error message in place of content
- "Close" button available to dismiss modal
- Original page remains accessible

## API Contract

### Request
```
GET /api/scans/<scan_id>/result
Headers:
  Accept: application/json
  X-CSRFToken: <csrf_token>
```

### Response (Success)
```json
{
  "status": "success",
  "data": {
    "scan_id": "uuid",
    "requested_target": "example.com",
    "state": "completed",
    "initiated_at": "2026-03-28T10:00:00Z",
    "completed_at": "2026-03-28T10:05:30Z",
    "scan_type": "FULL_STACK",
    "duration_seconds": 330,
    "targets": [...],
    "certificates": [...],
    "total_targets": 15,
    "total_hosts": 45,
    "total_certificates": 8,
    "total_issues": 3
  }
}
```

### Response (Error)
```json
{
  "status": "error",
  "message": "Scan not found"
}
```

## Testing

### Manual Testing Checklist
- [ ] Click "View" button in Scan Centre → Modal opens with data
- [ ] Modal displays metadata (target, status, timestamps)
- [ ] Results summary grid displays counts
- [ ] Targets table scrolls vertically without overflow
- [ ] Certificates table displays SSL/TLS certs with status
- [ ] Close button (X) closes modal
- [ ] Backdrop click closes modal
- [ ] Escape key closes modal
- [ ] Error state shows on API failure
- [ ] Modal reopens for different scans

### Automated Tests
```bash
pytest tests/test_scan_detail_modal.py -v
# Expected: 8 PASSED
```

### Regression Testing
```bash
pytest tests/ -q
# Expected: 327+ passed (no failures from modal changes)
```

## Accessibility

- **ARIA:** `aria-hidden="true"` on backdrop, `aria-label` on buttons
- **Keyboard:** Escape and Tab navigation supported
- **Viewport:** Supports 375px minimum width (mobile)
- **Touch Targets:** Buttons ≥ 44×44px

## Performance

- Modal initializes on page load (HTML in base.html)
- API calls only when user clicks "View" (lazy load)
- Reuses modal container across multiple scans
- No external JavaScript libraries

## Security

- CSRF token validation via X-CSRFToken header
- URL encoding for scanId parameter
- HTML entity encoding in template
- No eval() or innerHTML assignment for user data

## Known Limitations

#### Phase 1 (Current)
- ❌ "Add to Inventory" button: Stubbed only
- ❌ "Download Report" button: Stubbed only
- ❌ Recommendations: Hardcoded in template (not backend-driven)
- ❌ Mobile responsive: Not yet tested on actual devices

#### Phase 2 (Future)
- Implement "Add to Inventory" → creates inventory entry with scan data
- Implement "Download Report" → generates PDF/JSON export
- Backend-driven recommendations from API response
- Mobile viewport testing and adjustments

## CSS Framework

Modal uses existing Quantum Shield design system:
```css
/* Colors */
--bg-darker: rgb(15, 23, 42)
--text-light: rgb(229, 231, 235)
--accent: rgb(139, 92, 246)

/* Effects */
backdrop-filter: blur(8px) saturate(150%)
z-index: 99000
```

## Deployment

1. Code changes ready in production branch
2. No database migrations required
3. No new environment variables needed
4. Backward compatible (no breaking changes)

## Quick Links

- Template: [web/templates/common/scan_detail_modal.html](web/templates/common/scan_detail_modal.html)
- Tests: [tests/test_scan_detail_modal.py](tests/test_scan_detail_modal.py)
- Modified: [web/templates/base.html](web/templates/base.html), [web/templates/scans.html](web/templates/scans.html)
- AGENTS.md Workflow: Follow 4-phase implementation pattern (plan → implement → test → document)
