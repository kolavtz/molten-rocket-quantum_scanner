
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

