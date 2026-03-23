# QuantumShield Design System — Quick Reference Card

## 🎨 Colors

```
PRIMARY:     #2563EB (Trust blue)
SECONDARY:   #3B82F6 (Light blue)
CTA:         #F97316 (Orange accent)
BACKGROUND: #F8FAFC (Slate light)
TEXT:        #1E293B (Dark slate)
```

## 📝 Typography

**Font:** Inter (all headings & body)  
**Mood:** Dark, technical, precision, cinematic  
**Line Height:** 1.5–1.75 on body text  
**Size Scale:** 12 → 14 → 16 → 18 → 24 → 32

```css
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
```

## 📐 Spacing

| Token | Value | Use |
|-------|-------|-----|
| xs | 4px | Tight gaps |
| sm | 8px | Icon gaps |
| md | 16px | Standard padding |
| lg | 24px | Section padding |
| xl | 32px | Large gaps |
| 2xl | 48px | Section margins |
| 3xl | 64px | Hero padding |

## 🔘 Buttons

```css
/* Primary Button */
background: #F97316;
color: white;
padding: 12px 24px;
border-radius: 8px;
font-weight: 600;
transition: all 200ms ease;
cursor: pointer;

/* On Hover */
opacity: 0.9;
transform: translateY(-1px);
```

## 📏 Shadows

| Level | Value |
|-------|-------|
| sm | 0 1px 2px rgba(0,0,0,0.05) |
| md | 0 4px 6px rgba(0,0,0,0.1) |
| lg | 0 10px 15px rgba(0,0,0,0.1) |
| xl | 0 20px 25px rgba(0,0,0,0.15) |

## ✅ Checklist

- [ ] 4.5:1 contrast ratio (WCAG AA)
- [ ] Focus visible on interactions
- [ ] SVG icons only (not emoji)
- [ ] cursor: pointer on clickable
- [ ] Hover 150–300ms smooth transitions
- [ ] Touch targets ≥44×44dp
- [ ] prefers-reduced-motion respected
- [ ] Responsive: 375, 768, 1024, 1440px

## 📄 Page Hierarchies

1. Check `pages/[page-name].md` first
2. If exists → use those rules (override Master)
3. If not → use `MASTER.md` only

**Pages:** dashboard.md | scanner.md | results.md

## 🎯 Design Pattern

**Trust & Authority** (with Conversion focus)
- Hero (mission/credibility)
- Proof (logos, certs, stats)
- Solution overview
- Clear CTA path

## 📊 Charts & Data

- Use contrast muted → vibrant
- Success green for compliance
- Metric pulse animations
- Smooth stat reveals
- Accessible color + patterns (not color-only meaning)

## 🚀 Performance

- WebP/AVIF images
- Lazy load below-fold
- CLS < 0.1 (no layout shift)
- Animations smooth (60fps)
- Icons: Heroicons or Lucide

## 🔗 Resources

- Colors: vars → `--color-primary`, etc.
- Fonts: https://fonts.google.com/share?selection.family=Inter:wght@300;400;500;600;700
- Icons: https://heroicons.com/ or https://lucide.dev/
- A11y Check: https://webaim.org/resources/contrastchecker/

---

**Your style:** Dark Mode (OLED) | **Target:** Developer/Security | **Accessibility:** WCAG AAA
