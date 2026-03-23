# QuantumShield UI Component Library

This directory contains reusable React components that follow the **QuantumShield Design System** specification.

## 📦 Components

### Button Component
```tsx
import { Button } from './ui';

<Button variant="primary" size="md" onClick={handleClick}>
  Scan Now
</Button>

// Variants: 'primary' | 'secondary' | 'outline' | 'danger'
// Sizes: 'sm' | 'md' | 'lg'
// Props: variant, size, disabled, loading, onClick, className
```

**Usage Examples:**
- Primary CTA: `<Button variant="primary">Submit Scan</Button>`
- Loading state: `<Button loading>Scanning...</Button>`
- Danger action: `<Button variant="danger">Delete</Button>`

### Card Component
```tsx
import { Card, CardHeader, CardBody, CardFooter } from './ui';

<Card>
  <CardHeader>
    <h3>Asset Inventory</h3>
  </CardHeader>
  <CardBody>
    {/* Content here */}
  </CardBody>
  <CardFooter>
    <Button>Export</Button>
  </CardFooter>
</Card>
```

### Input Component
```tsx
import { Input } from './ui';

<Input
  label="Domain or IP Address"
  type="url"
  placeholder="example.com"
  value={domain}
  onChange={(e) => setDomain(e.target.value)}
  helpText="Enter a domain name or IP address to scan"
  error={error}
  required
/>
```

**Input Types:** `text` | `email` | `password` | `number` | `url` | `tel`

### Badge Component
```tsx
import { Badge, PQCReadyBadge, LegacyBadge } from './ui';

<Badge variant="success">✓ PQC Ready</Badge>
<Badge variant="warning">⚠ Legacy Crypto</Badge>
<Badge variant="info">NIST FIPS 203</Badge>

// QuantumShield-specific badges:
<PQCReadyBadge />
<LegacyBadge />
<ComplianceBadge fips="203" />
```

### Modal Component
```tsx
import { Modal } from './ui';

const [open, setOpen] = useState(false);

<Modal
  open={open}
  title="Confirm Action"
  onClose={() => setOpen(false)}
  actions={
    <>
      <Button variant="outline" onClick={() => setOpen(false)}>
        Cancel
      </Button>
      <Button variant="danger">Delete</Button>
    </>
  }
>
  Are you sure you want to proceed?
</Modal>
```

## 🎨 Design Tokens

### Colors
```css
--color-primary: #2563EB        /* Trust blue */
--color-secondary: #3B82F6      /* Light blue */
--color-cta: #F97316            /* Orange for CTAs */
--color-background: #F8FAFC     /* Light background */
--color-text: #1E293B           /* Dark text */

/* Status colors */
--color-success: #10B981        /* Success green */
--color-warning: #F59E0B        /* Warning amber */
--color-error: #EF4444          /* Error red */
--color-info: #3B82F6           /* Info blue */
```

### Spacing
```css
--space-xs: 4px
--space-sm: 8px
--space-md: 16px
--space-lg: 24px
--space-xl: 32px
--space-2xl: 48px
--space-3xl: 64px
```

### Shadows
```css
--shadow-sm: 0 1px 2px rgba(0,0,0,0.05)         /* Subtle */
--shadow-md: 0 4px 6px rgba(0,0,0,0.1)          /* Cards */
--shadow-lg: 0 10px 15px rgba(0,0,0,0.1)        /* Modals */
--shadow-xl: 0 20px 25px rgba(0,0,0,0.15)       /* Featured */
```

### Typography
```css
--font-size-xs: 12px
--font-size-sm: 14px
--font-size-base: 16px
--font-size-lg: 18px
--font-size-xl: 24px
--font-size-2xl: 32px

--line-height-tight: 1.25
--line-height-base: 1.5
--line-height-relaxed: 1.75

--font-weight-light: 300
--font-weight-normal: 400
--font-weight-medium: 500
--font-weight-semibold: 600
--font-weight-bold: 700
```

## 📋 Accessibility Features

All components include:
- ✅ WCAG AAA contrast ratios (4.5:1 minimum)
- ✅ Keyboard navigation support
- ✅ Focus visible states
- ✅ ARIA labels and roles
- ✅ Screen reader support
- ✅ Respects `prefers-reduced-motion`

## 🎯 Best Practices

### Responsive Design
- Mobile-first breakpoint: 375px
- Tablet: 768px
- Desktop: 1024px
- Wide: 1440px

### Touch Targets
- Minimum 44×44px for interactive elements
- 8px minimum spacing between touch targets

### Animations
- Duration: 150–300ms
- Easing: ease (standard)
- Hover effects on buttons and cards
- Loading states with spinner

### Form Validation
- Validate on blur (not keystroke)
- Show errors below the field
- Help text for complex inputs
- Clear success/error messaging

## 🚀 Usage Example: Scanner Page

```tsx
import React, { useState } from 'react';
import { Button, Input, Card, CardHeader, CardBody, Badge } from './ui';

export const ScannerPage: React.FC = () => {
  const [domain, setDomain] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleScan = async () => {
    if (!domain) {
      setError('Please enter a domain or IP address');
      return;
    }

    setLoading(true);
    try {
      const response = await fetch(`/api/scan?target=${domain}`);
      if (!response.ok) throw new Error('Scan failed');
      // Navigate to results page
    } catch (err) {
      setError('Scan failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <h1>Scan for Quantum-Safe Crypto</h1>
        <p>Discover cryptographic assets and validate NIST PQC compliance</p>
      </CardHeader>
      <CardBody>
        <Input
          label="Domain or IP Address"
          type="url"
          placeholder="example.com"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          helpText="Enter a domain or IP address to scan"
          error={error}
          required
        />
      </CardBody>
      <div style={{ paddingTop: '16px' }}>
        <Button
          variant="primary"
          size="lg"
          loading={loading}
          onClick={handleScan}
        >
          {loading ? 'Scanning...' : 'Scan Now'}
        </Button>
      </div>
    </Card>
  );
};
```

## 📚 File Structure

```
src/ui/
├── Button.tsx           # Primary, secondary, outline, danger buttons
├── Card.tsx             # Card container with header, body, footer
├── Input.tsx            # Text, email, password, tel, url inputs
├── Badge.tsx            # Status badges (success, warning, error, info)
├── Modal.tsx            # Dialog with focus trap and Escape handling
├── styles.css           # Global styles, CSS variables, animations
└── index.ts             # Exports all components
```

## 🔗 Integration with Design System

These components implement the specifications from:
- `design-system/quantumshield/MASTER.md` — Global design rules
- `design-system/quantumshield/pages/[page].md` — Page-specific overrides

## 📖 Related Documentation

- [Design System Guide](../DESIGN_SYSTEM_GUIDE.md)
- [Component Breakdown](../COMPONENT_BREAKDOWN.md)
- [Quick Reference](../DESIGN_SYSTEM_QUICK_REFERENCE.md)

---

**Ready to use!** Import components and follow the design specifications for pixel-perfect UI consistency.
