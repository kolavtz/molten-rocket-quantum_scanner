# QuantumShield UI/UX Design System — HTML Implementation Guide

## Overview

Your QuantumShield app has been revamped with a professional, minimalist design system optimized for dark mode (OLED-friendly) with accessibility and clarity as core principles. This guide shows how to use the new CSS classes and structure throughout your HTML templates.

**Design Philosophy:**
- **Dark Mode OLED**: Deep slate backgrounds (#0f1219) to reduce eye strain
- **Minimalist**: Clear information hierarchy, no unnecessary visual clutter
- **Accessible**: WCAG AAA contrast ratios, keyboard navigation, proper labels
- **Responsive**: Mobile-first approach, smooth responsive breakpoints
- **Technical Excellence**: Designed for security professionals and developers

---

## Color System

All colors are defined as CSS variables in `web/static/css/style.css`. Use these throughout your templates:

### Semantic Colors
```css
--accent:           #4a9ead    /* Primary action, links */
--accent-hover:     #5cb8c9    /* Hover state */
--accent-muted:     rgba(...)  /* Subtle background */
--safe:             #34d399    /* Success, compliant */
--warn:             #fbbf24    /* Warning, attention */
--danger:           #f87171    /* Error, critical */
```

### Background Colors
```css
--bg-primary:       #0f1219    /* Main background */
--bg-secondary:     #161b26    /* Alternate section background */
--bg-card:          #1a2030    /* Card/panel background */
--bg-input:         #141924    /* Input field background */
```

### Text Colors
```css
--text-primary:     #e8ecf1    /* Body text */
--text-secondary:   #94a3b8    /* Secondary text */
--text-muted:       #64748b    /* Inactive, helper text */
```

---

## Typography System

All typography variables are available:

| Variable | Size | Use Case |
|----------|------|----------|
| `--text-xs` | 0.75rem (12px) | Labels, badges |
| `--text-sm` | 0.875rem (14px) | Helper text, secondary | 
| `--text-base` | 1rem (16px) | Body text |
| `--text-lg` | 1.125rem (18px) | Subsections |
| `--text-xl` | 1.25rem (20px) | Section titles |
| `--text-2xl` | 1.5rem (24px) | Large titles |
| `--text-3xl` | 1.875rem (30px) | Page section |
| `--text-4xl` | 2.25rem (36px) | Hero titles |

### Font Families
```css
--font-display:  'Inter', -apple-system, ...     /* Headings */
--font-body:     'Inter', -apple-system, ...     /* Body text */
--font-mono:     'JetBrains Mono', 'Fira Code'   /* Code, monospace */
```

### Font Weights
- `--weight-normal: 400`: Regular text
- `--weight-medium: 500`: Slightly emphasized
- `--weight-semibold: 600`: Column headers, badges
- `--weight-bold: 700`: Headings
- `--weight-extrabold: 800`: Hero titles

---

## Spacing Scale

Consistent 4px baseline (Material Design):

```css
--space-xs:   0.25rem (4px)
--space-sm:   0.5rem (8px)
--space-md:   1rem (16px)
--space-lg:   1.5rem (24px)
--space-xl:   2rem (32px)
--space-2xl:  3rem (48px)
--space-3xl:  4rem (64px)
```

**Usage**: `margin: var(--space-lg); padding: var(--space-md);`

---

## Component Classes

### 1. Forms & Inputs

#### Form Group
```html
<div class="form-group">
  <label for="email">Email Address <span style="color:var(--danger);">*</span></label>
  <input type="email" id="email" name="email" class="form-input" placeholder="you@example.com">
  <div class="help-text">We'll never share your email</div>
</div>
```

#### Text Inputs with States
```html
<!-- Normal -->
<input type="text" placeholder="Normal state" class="form-input">

<!-- Focused (auto) -->
<input type="text" class="form-input" autofocus>

<!-- Error -->
<input type="text" class="form-input error">
<div class="error-text">This field is required</div>

<!-- Success -->
<input type="text" class="form-input success">

<!-- Disabled -->
<input type="text" class="form-input" disabled>
```

#### Checkboxes & Radios
```html
<!-- Checkbox -->
<label class="checkbox">
  <input type="checkbox" name="agree">
  I agree to the terms and conditions
</label>

<!-- Radio Group -->
<label class="radio">
  <input type="radio" name="notification" value="email" checked>
  Email notifications
</label>
<label class="radio">
  <input type="radio" name="notification" value="sms">
  SMS notifications
</label>
```

#### Select Dropdowns
```html
<label for="asset-type">Asset Type</label>
<select id="asset-type" class="form-input">
  <option value="">-- Select --</option>
  <option value="server">🏦 Banking Server</option>
  <option value="api">🔌 Core Banking API</option>
  <option value="payment">💳 Payment Gateway</option>
</select>
```

#### Textarea
```html
<label for="notes">Additional Notes</label>
<textarea id="notes" class="form-input" placeholder="Enter your notes here..." rows="4"></textarea>
```

### 2. Buttons

#### Button Variants
```html
<!-- Primary (Default) -->
<button class="button">Save Changes</button>

<!-- Secondary -->
<button class="button secondary">Cancel</button>

<!-- Outline -->
<button class="button outline">Learn More</button>

<!-- Danger (Destructive) -->
<button class="button danger">Delete</button>

<!-- Ghost (Subtle) -->
<button class="button ghost">Skip</button>
```

#### Button Sizes
```html
<button class="button sm">Small</button>
<button class="button">Normal</button>
<button class="button lg">Large</button>
```

#### Full Width & Icons
```html
<!-- Full Width -->
<button class="button fullwidth">Submit Form</button>

<!-- With Icons -->
<button class="button">
  <i class="fas fa-save"></i> Save
</button>

<!-- Loading State -->
<button class="button loading" disabled>
  Processing...
</button>
```

### 3. Cards

```html
<div class="card">
  <div class="card-header">
    <h3>Scan Results</h3>
    <span class="badge success">Completed</span>
  </div>
  
  <div class="card-body">
    <p>Your scan has completed successfully. 127 assets found.</p>
  </div>
  
  <div class="card-footer">
    <button class="button secondary">Export</button>
    <button class="button">View Details</button>
  </div>
</div>
```

### 4. Badges

```html
<!-- Default (Info) -->
<span class="badge">Information</span>

<!-- Success -->
<span class="badge success">Compliant ✓</span>

<!-- Warning -->
<span class="badge warning">Needs Review !</span>

<!-- Danger -->
<span class="badge danger">Critical ✕</span>

<!-- With Icon -->
<span class="badge success">
  <i class="fas fa-check-circle"></i> PQC Ready
</span>
```

### 5. Alerts & Notices

```html
<!-- Success Alert -->
<div class="alert alert.success">
  <div class="alert-title">Scan Complete</div>
  <div class="alert-message">Your scan has been successfully processed.</div>
</div>

<!-- Warning Alert -->
<div class="alert alert.warning">
  <div class="alert-title">Review Required</div>
  <div class="alert-message">Some certificates may need attention.</div>
</div>

<!-- Error Alert -->
<div class="alert alert.error">
  <div class="alert-title">Scan Failed</div>
  <div class="alert-message">Connection timeout. Please try again.</div>
</div>

<!-- Info Alert -->
<div class="alert alert.info">
  <div class="alert-title">Pro Tip</div>
  <div class="alert-message">Using autodiscovery will scan additional ports.</div>
</div>
```

### 6. Enhanced Glass Card

```html
<div class="glass-card" style="padding: var(--space-lg);">
  <h3>Card Title</h3>
  <p>Card content goes here with smooth hover effects and shadows.</p>
</div>
```

---

## Layout & Grids

### Flexbox Utilities
```html
<!-- Horizontal Layout -->
<div style="display: flex; gap: var(--space-md);">
  <div>Item 1</div>
  <div>Item 2</div>
</div>

<!-- Vertical Stack -->
<div style="display: flex; flex-direction: column; gap: var(--space-sm);">
  <div>Item 1</div>
  <div>Item 2</div>
</div>

<!-- Centered Content -->
<div style="display: flex; align-items: center; justify-content: center; min-height: 200px;">
  Content
</div>
```

### Grid Utilities
```html
<!-- 2-Column Grid -->
<div class="grid cols-2">
  <div>Column 1</div>
  <div>Column 2</div>
</div>

<!-- 3-Column Grid -->
<div class="grid cols-3">
  <div>Col 1</div>
  <div>Col 2</div>
  <div>Col 3</div>
</div>

<!-- Auto-fit Grid (Responsive) -->
<div class="grid cols-auto">
  <div class="card">Card 1</div>
  <div class="card">Card 2</div>
  <div class="card">Card 3</div>
</div>
```

---

## Hero Section

```html
<section class="hero">
  <h1 class="hero-title">Your Main Title</h1>
  <p class="hero-subtitle">Supporting subtitle with additional context</p>
</section>
```

---

## Hero Badge

```html
<span class="hero-badge">
  <span class="badge-dot"></span> New Feature
</span>
```

---

## Accessibility Features

### Focus States (Automatic)
All interactive elements have built-in focus states. No additional CSS needed:
```html
<button class="button">Accessible Button</button>
<!-- Tabbing shows 2px outline -->
```

### Required Fields
```html
<label>
  Email Address
  <span style="color: var(--danger);">*</span>
</label>
```

### ARIA Labels (When Needed)
```html
<button aria-label="Close dialog">
  <i class="fas fa-times"></i>
</button>
```

---

## Mobile Responsive Breakpoints

Your CSS automatically handles these breakpoints:

| Breakpoint | Device |
|-----------|--------|
| 320px - 480px | Mobile phones |
| 481px - 768px | Tablets (portrait) |
| 769px - 1024px | Tablets (landscape) |
| 1025px+ | Desktop |

**Mobile-first approach**: Design for mobile first, then expand.

---

## Animation & Transitions

All transitions use these variables:
```css
--transition-fast:  150ms   /* Micro-interactions */
--transition-base:  250ms   /* Standard transitions */
--transition-slow:  350ms   /* Complex animations */
--easing-out:       ease-out /* Exit animations */
--easing-inout:     ease-inout /* General transitions */
```

**No custom CSS needed** — smooth transitions are built-in for borders, shadows, colors.

---

## Header / Page Title Pattern

```html
<section class="hero" style="padding-bottom: 1rem;">
  <h1 class="hero-title" style="font-size: 2.5rem;">Page Title</h1>
  <p class="hero-subtitle">Supporting description or context</p>
</section>
```

---

## Tab Pattern (Like scan_center.html)

```html
<div role="tablist" style="display:flex; gap:1.5rem; border-bottom:1px solid var(--border-subtle);">
  <button role="tab" aria-selected="true" onclick="switchTab('tab1')">
    Tab 1
  </button>
  <button role="tab" aria-selected="false" onclick="switchTab('tab2')">
    Tab 2
  </button>
</div>

<div role="tabpanel" id="tabpanel-1">Tab 1 Content</div>
<div role="tabpanel" id="tabpanel-2" style="display:none;">Tab 2 Content</div>
```

---

## Data Table Best Practices

```html
<table class="findings-table">
  <thead>
    <tr>
      <th>Certificate</th>
      <th>Status</th>
      <th>Expiry</th>
      <th>Action</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>leaf.example.com</code></td>
      <td><span class="badge success">Valid</span></td>
      <td>2025-12-31</td>
      <td><button class="button sm">View</button></td>
    </tr>
  </tbody>
</table>
```

---

## Quick Implementation Checklist

When updating existing templates:

- [ ] Replace inline styles with CSS classes
- [ ] Use `class="form-input"` for all inputs
- [ ] Use `class="button"` with variants (secondary, danger, outline)
- [ ] Use `class="glass-card"` for card containers
- [ ] Use `.card` for composed cards (header/body/footer)
- [ ] Use `.badge` for status indicators
- [ ] Use `.alert` for messages
- [ ] Add proper labels with `<label>` elements
- [ ] Use semantic HTML (`<section>`, `<header>`, `<main>`)
- [ ] Test mobile responsiveness (768px breakpoint)
- [ ] Verify keyboard navigation (Tab key)
- [ ] Check color contrast (should pass WCAG AAA)

---

## Dark/Light Mode Support

Your CSS automatically supports system preference:
```html
<!-- No changes needed! CSS respects prefers-color-scheme -->
```

Users can override in settings via JavaScript:
```javascript
document.documentElement.setAttribute('data-theme', 'dark');
// or
document.documentElement.setAttribute('data-theme', 'light');
```

---

## File Locations

- **Main CSS**: `web/static/css/style.css` (updated with new variables & classes)
- **Typography**: `web/static/css/style.css` (Inter + JetBrains Mono)
- **Template Base**: `web/templates/base.html` (includes all CSS imports)
- **Example Updated**: `web/templates/scan_center.html` (shows best practices)

---

## Support & Resources

- **WCAG Guidelines**: https://www.w3.org/WAI/WCAG21/quickref/
- **Accessibility Lab**: Test all forms with keyboard navigation
- **Color Contrast**: https://webaim.org/resources/contrastchecker/
- **Responsive Testing**: Chrome DevTools → Toggle Device Toolbar (Ctrl+Shift+M)

---

**Design System Version**: 1.0  
**Last Updated**: 2026-03-22  
**Compatibility**: HTML5, CSS3, Modern Browsers (Chrome 90+, Firefox 88+, Safari 14+, Edge 90+)
