# QuantumShield: Architecture & Quantum-Safe Cybersecurity Guide

This document provides a deep dive into the architecture of **QuantumShield**, the underlying principles of "Quantum-Safe" cryptography, and the specific cybersecurity threats this project mitigates for the PNB Cybersecurity Hackathon.

---

## 1. What is "Quantum-Safe" Cryptography?

**Quantum-Safe Cryptography** (also known as Post-Quantum Cryptography or PQC) refers to cryptographic algorithms (usually public-key algorithms) that are thought to be secure against an attack by a quantum computer. 

### The Systemic Threat
Currently, the internet relies heavily on RSA, Diffie-Hellman (DH), and Elliptic Curve Cryptography (ECC) for:
1.  **Key Exchange** (e.g., establishing a secure TLS session)
2.  **Digital Signatures** (e.g., proving a server is who it claims to be via certificates)

A cryptanalytically relevant quantum computer (CRQC) running **Shor's Algorithm** can easily factor large primes and solve discrete logarithms, rendering RSA, DH, and ECC completely broken.

### The "Harvest Now, Decrypt Later" (HNDL) Threat
Even though CRQCs do not exist today, adversaries (like nation-states) are actively recording and storing encrypted internet traffic. When quantum computers arrive, they will use them to decrypt this historical data. This poses an immediate, critical threat to banking data, state secrets, and long-term intellectual property.

**Therefore, transitioning to Quantum-Safe algorithms for Key Exchange is an immediate priority today.**

### The NIST Standards (FIPS 203, 204, 205)
In August 2024, the National Institute of Standards and Technology (NIST) finalized the primary standards for PQC:
*   **FIPS 203 (ML-KEM / Kyber):** A Module-Lattice-Based Key-Encapsulation Mechanism. Represents the future of key exchange.
*   **FIPS 204 (ML-DSA / Dilithium):** A Module-Lattice-Based Digital Signature Algorithm. General-purpose digital signatures.
*   **FIPS 205 (SLH-DSA / SPHINCS+):** A Stateless Hash-Based Digital Signature Algorithm. A highly conservative fallback.

---

## 2. QuantumShield: Project Architecture

QuantumShield is an enterprise-wide software scanner designed to discover public-facing cryptographic assets, validate their quantum resilience, and generate actionable compliance reports.

### Architecture Diagram

```mermaid
graph TD
    UI[Web UI Dashboard] --> API[/scan Endpoint]
    API --> ND[Network Discovery Module]
    
    subgraph Scanner Engine
        ND --> |Raw Sockets & Ports| TA[TLS Analyzer]
        TA --> |OpenSSL TLS Handshake| PD[PQC Detector]
    end
    
    PD --> |Algorithm & Config Data| VE[Validation Engine]
    
    subgraph Processing
        VE --> QC[Quantum-Safe Checker]
        VE --> CI[Certificate Issuer]
        QC --> |FIPS Compliant?| RepH[Reporting Hub]
        CI --> |Digital Badge| RepH
    end
    
    RepH --> CBOM[CBOM Builder/CycloneDX]
    RepH --> RE[Recommendation Engine]
    
    CBOM --> JSON[CBOM JSON Output]
    RE --> HTML[Web Dashboard / HTML Report]
```

### Module Deep-Dive

**1. Network Discovery Module (`src/scanner/network_discovery.py`)**
*   **Purpose:** Sweep IP ranges, domains, and custom ports for active services.
*   **Technique:** Uses asynchronous-friendly socket connections to detect open ports and attempts protocol banner grabbing. 
*   **Hackathon Rule Alignment:** Ensures scanning of "public-facing" apps. It filters out internal RFC-1918 IPs by default to prevent scanning introspective networks.

**2. TLS Analyzer (`src/scanner/tls_analyzer.py`)**
*   **Purpose:** Extract cryptographic controls from endpoints.
*   **Technique:** Initiates full TLS 1.2 / TLS 1.3 handshakes using Python's `ssl` and `pyOpenSSL`. It intercepts the server's negotiated cipher suite, protocol version, and certificate chain.
*   **Detail:** Extracts the Certificate Subject Alternative Names (SAN), Serial Number, Signature Algorithm, and computes the SHA-256 fingerprint.

**3. PQC Detector (`src/scanner/pqc_detector.py`)**
*   **Purpose:** Identify if the negotiated parameters utilize Next-Gen or Legacy cryptography.
*   **Technique:** Compares the extracted Key Exchange algorithms (e.g., `X25519`, `secp256r1`, `x25519_kyber768`) and Signature algorithms (e.g., `RSA-PSS`, `ML-DSA-65`) against hardcoded, NIST-validated reference lists.

**4. CBOM Builder & Generator (`src/cbom/*`)**
*   **Purpose:** Fulfill the "Cryptographic Bill of Material inventory" requirement.
*   **Technique:** Translates the findings into CycloneDX 1.6 format, the official SBOM standard that recently added Cryptographic Bill of Materials extensions. Outputs strictly formatted JSON for enterprise CI/CD and compliance toolchains.

**5. Validation & Certificate Issuer (`src/validator/*`)**
*   **Purpose:** Assess risk and issue digital proof.
*   **Technique:** 
    *   **Quantum Safe Checker:** Scores the endpoint (0-100) based on the presence of vulnerable algorithms. Assesses the "HNDL Risk" (High/Medium/Low) based on the specific service type and algorithm strength.
    *   **Certificate Issuer:** Generates tamper-proof digital labels ("Fully Quantum Safe", "PQC Ready", "Partial") complete with SHA-256 checksums, validity periods, and visual badge colors.

**6. Enterprise Operations Console (`web/app.py` & `web/templates/index.html`)**
*   **Purpose:** Central management interface for CISO and Security teams.
*   **Technique:** Flask-based backend with a dynamic, glassmorphism frontend using vanilla JS and Chart.js.
*   **Bulk Scanning Engine:** Allows the submission of multiple domains/subnets simultaneously, running the pipeline sequentially, and aggregating the metrics into global charts (Total Assets, PQC Compliance Average, Risk Distribution).

---

## 3. Threat Modeling & Recommendations

QuantumShield not only identifies the problems but provides the solutions via its **Recommendation Engine**.

### Common Identified Vulnerabilities:
1.  **RSA Key Exchange / Diffie-Hellman:** Highly vulnerable to CRQCs. HNDL risk is Critical.
2.  **Elliptic Curve (ECDHE / X25519):** Also vulnerable to Shor's Algorithm via CRQCs. HNDL risk is High.
3.  **TLS 1.2 or prior:** Lacks agility for modern PQC algorithms out-of-the-box.

### Automated Remediation Strategies (Provided by QuantumShield):
*   **Hybrid Key Exchange:** Recommends implementing `X25519MLKEM768`. This combines classical elliptic curve (X25519) with post-quantum ML-KEM. Even if the PQC math is somehow flawed, the classical math remains secure against classical computers. **This is the current industry best practice.**
*   **Configuration Snippets:** QuantumShield generates precise configuration directives for Nginx, Apache, and HAProxy (e.g., `ssl_ecdh_curve X25519MLKEM768;`) so SysAdmins can patch systems immediately.

## 4. Why This Tool Wins the Hackathon

1.  **Directly Addresses the Core Problem:** Solves the HNDL threat explicitly outlined in the PNB prompt.
2.  **Standards-Compliant:** Outputs CycloneDX 1.6 CBOM standards; validates against fresh NIST FIPS 203/204/205 specs.
3.  **Enterprise Readiness:** Features a "Central Console", Bulk Scanning, Risk Scoring, and actionable code snippets for mitigation.
4.  **UI/UX Excellence:** Modern, premium dashboard designed to "Wow" stakeholders, featuring real-time charting, micro-interactions, and visual certificate labels.
