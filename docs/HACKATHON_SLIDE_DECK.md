# QuantumShield Presentation Deck
*Content for the PNB Cybersecurity Hackathon 2026 Showcase*

---

## Slide 1: Welcome & Title
**Title:** QuantumShield: Quantum-Ready Cybersecurity for Future-Safe Banking
**Subtitle:** PNB Cybersecurity Hackathon 2026
**Visual Idea:** Background showing digital banking nodes, with the modern, glass-morphic QuantumShield Logo.

**Speaker Notes:**
> "Welcome judges. The digital landscape of banking has changed. We are demanding 24x7x365 availability and shifting massive amounts of critical data to public-facing environments. While this drives convenience today, it creates a systemic vulnerability for tomorrow. We recognized this threat and built **QuantumShield**—an enterprise-wide software scanner designed to secure our cryptographic future."

---

## Slide 2: The Evolving Threat Landscape
**Headline:** The "Harvest Now, Decrypt Later" (HNDL) Reality
**Bullet Points:**
*   Adversaries are actively storing our encrypted internet traffic **today**.
*   Cryptanalytically Relevant Quantum Computers (CRQCs) will easily break RSA and Elliptic Curve Cryptography using Shor's Algorithm.
*   Once CRQCs arrive, all historical data captured today will be exposed instantly.
*   **The Problem:** We don't know *what* algorithms we are currently using across our public-facing internet legacy endpoints.

**Speaker Notes:**
> "The threat is not a distant possibility; it's happening right now. It's called 'Harvest Now, Decrypt Later'. Attackers record our secure banking communications today, encrypted with current standards like RSA and Diffie-Hellman. When quantum computers arrive, they will use Shor's Algorithm to shatter these legacy systems in mere seconds, exposing years of historical intellectual property and financial data. To defend against this, we first need to understand our exposure. We literally don't know what we don't know."

---

## Slide 3: Our Solution: QuantumShield
**Headline:** The Enterprise Software Scanner
**Bullet Points:**
*   **Discover & Inventory:** Actively scans endpoints, VPNs, and APIs yielding detailed TLS, Key Exchange, and Digital Signature maps.
*   **Assess:** Validates assets strictly against NIST FIPS 203 (ML-KEM), 204 (ML-DSA), and 205 (SLH-DSA). 
*   **HNDL Risk Scoring:** Automatically tags endpoints as Critical, High, or Low Risk depending on what data they protect.
*   **CBOM Generation:** Compiles a standard CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) for CI/CD integrations.
*   **Digital Certificates:** Dynamically generates tamper-proof "Fully Quantum Safe" labels.

**Speaker Notes:**
> "Our solution solves the prompt directly: QuantumShield is an enterprise-wide scanner that validates deployments of quantum-proof ciphers. It crawls your infrastructure, parses complex TLS handshakes, identifies exactly what encryption is running, and evaluates its readiness against the newly finalized August 2024 NIST FIPS standards. Not only does it flag vulnerabilities, but it issues standardized Cryptographic Bill of Materials and hands out digital certification labels to compliant systems."

---

## Slide 4: Central Console Management
**Headline:** Executive Dashboarding
**Visual Idea:** (Insert Screenshot of the Enterprise Operations Console with the Total Assets, Quantum Safe %, and Critical Findings metric cards)
**Bullet Points:**
*   **Complete Visibility:** A centralized view of the organization's total attack surface.
*   **Bulk Target Discovery:** Accepts massive lists of URLs, IPs, or whole CIDR subnets.
*   **Actionable Metrics:** Visual tracking of our journey toward 100% PQC Compliance over time.
*   **Remediation Native:** Generates immediate code fixes for Nginx, HAProxy, and Apache.

**Speaker Notes:**
> "QuantumShield isn't just a command-line script. It's built for the enterprise. We've included a Central Operations Console that gives the CISO an instant, high-level overview. You can enter an entire CIDR block into the Bulk Discovery Engine, and QuantumShield will map those targets sequentially, aggregating their risk profiles into real-time metrics. It tells us not just *if* we are failing, but exactly *how* to fix it, supplying ready-to-deploy configuration snippets for multiple servers."

---

## Slide 5: The Underlying Architecture
**Headline:** Built on Python, Flask, and Advanced TLS Analysis
**Visual Idea:** (Include the Mermaid flowchart from the Architecture Guide)
**Bullet Points:**
*   **Network Discovery:** Asynchronous socket sweeping bypassing strict API dependencies.
*   **TLS Parser Engine:** Deep packet introspection via `ssl` and `pyOpenSSL` intercepts the server's handshake parameters.
*   **CBOM Module:** Utilizes `cyclonedx-python-lib` to construct enterprise-grade JSON schemas usable by devops pipelines.
*   **Sleek UI:** Flask Backend attached to a modern, dynamic Data-Viz frontend.

**Speaker Notes:**
> "Under the hood, the architecture is robust and extensible. QuantumShield operates across multiple dedicated modules: network discovery, TLS parsing, PQC alignment, and CycloneDX CBOM generation. By natively communicating through raw sockets and deep TLS handshake inspection, the tool requires zero prior knowledge of the target—it discovers and analyzes public-facing endpoints entirely dynamically."

---

## Slide 6: Summary & Impact
**Headline:** Quantum-Ready Cybersecurity, Delivered.
**Bullet Points:**
*   Addresses PNB's objective for resilient, 24x7x365 banking infrastructure.
*   Mitigates the massive, systemic risk of HNDL attacks immediately.
*   Equips the enterprise with actionable, standardized (CBOM) inventories.
*   Ready to deploy via Docker for continuous scanning.

**Speaker Notes:**
> "In conclusion, QuantumShield is not just a scanner; it's a strategic roadmap for PNB's transition to a post-quantum world. We provide discovery, strict validation, compliance mapping, actionable remediation, and enterprise reporting. We secure the future of banking data today."

---

## Slide 7: Q&A and Demo
**Headline:** Live Demonstration
*(Queue up `http://localhost:5000` to run a live scan against `test.openquantumsafe.org` or `google.com` to show the real-time HNDL risk cards, PQC labels, and Enterprise dashboard updating in real-time).*
