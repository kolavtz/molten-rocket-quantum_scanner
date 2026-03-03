# Software Requirement Specification (SRS)

## PSB Hackathon 2026

________________________________________

## Software Requirement Specification

**Version:** 1.0  
**Project Name:** QuantumShield — Quantum-Proof Systems Scanner  
**Team Name:** ___________________________  
**Institute Name:** ___________________________  
**Date:** March 03, 2026  

________________________________________

## Revision History

| Version No | Date | Prepared by / Modified by | Significant Changes |
|------------|------------|---------------------------|---------------------|
| Draft V1.0 | 2026-03-03 | QuantumShield Team | Initial SRS draft covering all functional, non-functional, security, and technological requirements for the Quantum-Proof Systems Scanner. |
| | | | |

________________________________________

## Declaration

The purpose of this Software Requirements Specification (SRS) document is to identify and document the user requirements for the **QuantumShield — Quantum-Proof Systems Scanner**. The end deliverable software that will be supplied by the QuantumShield Team will comprise of all the requirements documented in the current document and will be operated in the manner specified in the document. The Source code will be developed subsequently based on these requirements and will formally go through code review during testing process.

________________________________________

## Mentor Details (if any)

| Field | Details |
|-------|---------|
| **Name & Title** | Assistant Professor / Associate / Professor |
| **Institute Name** | (Institute Name) |
| **Signature** | |
| **Date** | |

________________________________________

## Team Member Details

| Member | Name & Title | Institute Name | Signature & Date |
|--------|--------------|----------------|------------------|
| Team Lead | | (Institute Name) | |
| Member 1 — Developer | | (Institute Name) | |
| Member 2 | | (Institute Name) | |
| Member 3 — Tester | | (Institute Name) | |

________________________________________

## Table of Contents

1. Introduction  
   1.1 Purpose  
   1.2 Scope  
   1.3 Intended Audience  
2. Overall Description  
   2.1 Product Perspective  
   2.2 Product Functions  
   2.3 User Classes and Characteristics  
   2.4 Operating Environment  
   2.5 Design and Implementation Constraints  
   2.6 Assumptions and Dependencies  
3. Specific Requirements  
   3.1 Functional Requirements  
   3.2 External Interface Requirements  
   — 3.2.1 User Interfaces  
   — 3.2.2 Hardware Interfaces  
   — 3.2.3 Software / Communication Interfaces  
   3.3 System Features  
   3.4 Non-functional Requirements  
   — 3.4.1 Performance Requirements  
   — 3.4.2 Software Quality Attributes  
   — 3.4.3 Other Non-functional Requirements  
4. Technological Requirements  
   4.1 Technologies used in development of the web application  
   4.2 I.D.E. (Integrated Development Environment)  
   4.3 Database Management Software  
5. Security Requirements  
Annexure-A (CERT-IN CBOM Elements)

________________________________________

## 1. Introduction

### 1.1 Purpose

The purpose of this Software Requirements Specification (SRS) document is to identify and document the user requirements for the **QuantumShield — Quantum-Proof Systems Scanner**. This document is prepared with the following objectives:

- To provide the behaviour of the system, covering discovery, analysis, validation, and reporting workflows.
- To provide Process Flow charts describing how data moves from network discovery through PQC assessment to final report generation.

**Process Flow:**

```
┌────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  User enters   │───>│  Network         │───>│  TLS Analyzer   │
│  target(s) via │    │  Discovery       │    │  (Handshake     │
│  Web UI / CLI  │    │  (Port Sweep)    │    │  Inspection)    │
└────────────────┘    └──────────────────┘    └────────┬────────┘
                                                       │
                      ┌──────────────────┐             │
                      │  PQC Detector    │<────────────┘
                      │  (Algorithm      │
                      │  Classification) │
                      └────────┬─────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                    │
          ▼                    ▼                    ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│ Quantum-Safe     │ │ CBOM Builder     │ │ Recommendation   │
│ Checker          │ │ (CycloneDX 1.6)  │ │ Engine           │
│ (NIST Validate)  │ │                  │ │ (Migration Fix)  │
└────────┬─────────┘ └────────┬─────────┘ └────────┬─────────┘
         │                    │                    │
         ▼                    ▼                    ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│ Certificate /    │ │ CBOM JSON Export │ │ Server Config    │
│ Label Issuer     │ │ (Download)       │ │ Snippets         │
└────────┬─────────┘ └──────────────────┘ └──────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│          Enterprise Dashboard / Report Generator             │
│  (Charts, HNDL Risk Banner, PQC Labels, CBOM Summary)       │
└──────────────────────────────────────────────────────────────┘
```

### 1.2 Scope

The QuantumShield scanner covers the following capabilities:

- **Discover cryptographic inventory** (TLS certificates, VPN endpoints, APIs) across user-specified targets including domains, IPs, CIDR ranges, and full URLs.
- **Identify cryptographic controls** (cipher suites, key exchange mechanisms, digital signature algorithms, TLS protocol versions) via deep TLS handshake inspection.
- **Validate whether deployed algorithms are quantum-safe** by checking against NIST FIPS 203 (ML-KEM / Kyber), FIPS 204 (ML-DSA / Dilithium), and FIPS 205 (SLH-DSA / SPHINCS+).
- **Generate actionable recommendations** for non-PQC-ready assets, including server-specific configuration snippets for Nginx, Apache, and HAProxy.
- **Issue digital labels**: "Fully Quantum Safe", "PQC Ready", "Partial", or "Non-Compliant" with tamper-proof SHA-256 checksums and validity periods.
- **Enterprise-wide console for Central management**: A GUI console to display status of scanned systems (public-facing applications) covering details mentioned in Appendix-A (CERT-IN CBOM Elements). As per the variation of score (High, Medium, Low rating) for any public applications, the dashboard displays that change as well via real-time aggregate metrics.

### 1.3 Intended Audience

The intended audience of this document is business and technical users from PNB, including:

- **CISO / Security Leadership**: For understanding the overall system capability and compliance posture.
- **IT Security Operations**: For day-to-day scanning, monitoring, and remediation workflows.
- **Compliance Auditors**: For reviewing CBOM outputs and PQC certification labels.
- **Development Teams**: For understanding the technical architecture and integration points.

________________________________________

## 2. Overall Description

### 2.1 Product Perspective

QuantumShield is a **standalone, self-hosted security assessment platform** designed to help banking institutions identify and mitigate the emerging threat of quantum computing on their existing cryptographic infrastructure. The tool sits outside the production environment and performs **non-intrusive, read-only scans** by initiating standard TLS handshakes with public-facing endpoints.

The product addresses the systemic **"Harvest Now, Decrypt Later" (HNDL)** threat — where adversaries intercept and store encrypted data today with the intent to decrypt it once Cryptanalytically Relevant Quantum Computers (CRQCs) become available. By inventorying existing algorithms and validating them against NIST's Post-Quantum Cryptography (PQC) standards finalized in August 2024, QuantumShield provides a clear roadmap for banks to migrate their cryptographic estate before quantum computers render it obsolete.

### 2.2 Product Functions

| # | Function | Description |
|---|----------|-------------|
| PF-1 | **Network Discovery** | Discovers active services on specified domains, IPs, or CIDR ranges by sweeping 20+ common ports (443, 8443, 636, 993, 3306, 5432, etc.). |
| PF-2 | **TLS Handshake Analysis** | Performs full TLS 1.2 / 1.3 handshakes using pyOpenSSL to extract negotiated cipher suites, key exchange algorithms, signature algorithms, and full certificate chains. |
| PF-3 | **PQC Classification** | Classifies every discovered algorithm as "Quantum Safe", "Quantum Vulnerable", or "Hybrid" based on NIST FIPS 203/204/205 reference lists. |
| PF-4 | **HNDL Risk Scoring** | Calculates a risk score (Critical / High / Medium / Low) for each endpoint based on algorithm vulnerability, data sensitivity, and certificate expiry. |
| PF-5 | **Compliance Scoring** | Computes a 0–100% PQC compliance score per endpoint and an aggregate score across the organization. |
| PF-6 | **CBOM Generation** | Produces CycloneDX 1.6-compliant Cryptographic Bill of Materials in JSON format for each scan. |
| PF-7 | **Label / Certificate Issuance** | Issues tamper-proof digital labels with SHA-256 checksums, validity periods, and badge colors. Labels include: "Fully Quantum Safe" (100% score, zero critical findings), "PQC Ready", "Partial", and "Non-Compliant". |
| PF-8 | **Recommendation Engine** | Generates server-specific migration guidance including Nginx `ssl_ecdh_curve` directives, Apache `SSLOpenSSLConfCmd`, and HAProxy `ssl-default-bind-ciphersuites` configurations for enabling hybrid PQC key exchange. |
| PF-9 | **Enterprise Dashboard** | Central console aggregating Total Assets Scanned, Quantum Safe %, Vulnerable Assets, and Critical Findings across all historical scans. |
| PF-10 | **Bulk Scanning** | Accepts comma-separated or newline-separated lists of targets for batch processing. |
| PF-11 | **CLI Scanner** | Command-line interface (`scan.py`) with `--json` and `--cbom` output flags for CI/CD pipeline integration. |

### 2.3 User Classes and Characteristics

- **Primary Users**: Bank cybersecurity teams and IT administrators responsible for managing the PKI and TLS estate across public-facing infrastructure.
- **Secondary Users**: Compliance auditors and risk managers who require machine-readable reports for regulatory adherence and audit trails.

Users are expected to have technical knowledge of cryptography, networking protocols, and TLS infrastructure.

| User at | User Type | Menus for User |
|---------|-----------|----------------|
| PNB / IIT Kanpur officials | Admin User | Enterprise Dashboard, Bulk Scan, System Config, All Reports, CBOM Export, Label Management |
| PNB Security Teams | Checker / Operator | Single Scan, View Results, Download CBOM, View Labels |

### 2.4 Operating Environment

The operating environment for **QuantumShield** is as listed below:

**Server system:**
- **Operating System**: Windows 10/11/Server 2022, Linux (Ubuntu 22.04 LTS, Debian 12, RHEL 9), macOS 13+
- **Database**: JSON flat-file storage (hackathon); extensible to SQLite / PostgreSQL for production
- **Platform**: Python 3.10+ with CPython runtime
- **Technology**: Flask 3.0 (Web Framework), pyOpenSSL 24.0 (TLS Analysis), cryptography 42.0 (Crypto Primitives), Chart.js 4.4 (Data Visualization), Jinja2 3.1 (Templating), CycloneDX Python Lib 7.0 (CBOM)
- **API**: RESTful HTTP API (`GET /api/scan?target=<host>`) returning JSON scan results

### 2.5 Design and Implementation Constraints

**1. Technical Constraints (For Deployment)**
- **Network Configuration**: The application requires outbound TCP connectivity to target ports (443, 8443, etc.) from the host machine. If deployed on an intranet, appropriate firewall rules must allow egress to public-facing endpoints being scanned.
- **Hosting Environment**: Can be deployed on intranet for internal access or as a Docker container behind a reverse proxy for external access. The application binds to `0.0.0.0:5000` by default.

**2. Security Constraints**
- **Non-Intrusive Scanning**: The scanner performs only standard TLS handshakes and protocol negotiation — no exploit payloads, no vulnerability exploitation, no data exfiltration.
- **Data Encryption**: All communication between the scanner and target endpoints uses TLS. The web dashboard itself should be served over HTTPS in production (via reverse proxy).
- **Access Control**: Production deployments should implement RBAC (Role-Based Access Control) via Flask-Login or an API gateway.

**3. Performance Constraints**
- **Scan Timeout**: Individual endpoint scans timeout after 10 seconds to prevent blocking on unresponsive hosts.
- **Sequential Bulk Scanning**: Bulk scans process targets sequentially to avoid overwhelming the network or triggering rate-limiting on target hosts. This ensures banking services are not disrupted.

**4. User Interface Constraints**
- **User Experience Consistency**: The web dashboard uses a dark-mode glassmorphism design system with consistent color tokens, spacing, and typography (Inter font family) across all pages.
- **Responsive Layout**: Dashboard renders correctly on desktop (1280px+) and tablet (768px+) viewports.

**Additional Constraints:**
- Must comply with NIST PQC standards (FIPS 203, 204, 205).
- Must operate only on public-facing applications (RFC 1918 private IPs are flagged).
- Must not disrupt live banking services (read-only handshakes only).
- Must generate reports in machine-readable formats (JSON for CBOM, HTML for dashboard).

### 2.6 Assumptions and Dependencies

**Assumptions:**
- **Standard Browser Support**: End users will access the application using HTML5-compliant browsers such as Google Chrome (v90+), Microsoft Edge, or Mozilla Firefox.
- **TLS Communication**: Target public-facing applications use standard TLS 1.2 or TLS 1.3 handshake protocols.
- **Internet Connectivity**: The scanning host has internet connectivity to reach public-facing endpoints.
- **No PQC Hardware Required**: The scanner validates PQC readiness by analyzing negotiated parameters; it does not require quantum hardware or PQC-capable TLS libraries to perform the assessment.

**Dependencies:**
- **OpenSSL / LibreSSL**: The application depends on the host system's OpenSSL library (bundled via pyOpenSSL) for TLS handshake capabilities. OpenSSL 3.0+ is recommended for maximum protocol coverage.
- **Python 3.10+**: Required for modern type hints, `match` statements, and `ssl` module improvements.
- **Network Access**: Access to target ports (443, 8443, 636, etc.) must not be blocked by intermediate WAFs, DDoS protection systems, or corporate firewalls.
- **NIST PQC Algorithms**: Depends on NIST PQC algorithms being standardized (completed August 2024 with FIPS 203/204/205) and recognized by the scanner's internal reference lists.

________________________________________

## 3. Specific Requirements

### 3.1 Functional Requirements

| Req ID | Requirement | Priority | Description |
|--------|-------------|----------|-------------|
| FR-01 | **Target Input & Sanitization** | High | The system shall accept targets as hostnames, IP addresses, CIDR ranges (`/24` max), or full URLs (`https://example.com/path`). All input shall be sanitized to extract the hostname, reject invalid formats, and prevent injection attacks. |
| FR-02 | **Port Discovery** | High | The system shall scan a configurable list of ports (default: 443, 8443, 636, 993, 995, 465, 5061, 80, 22, 3306, 5432, 8080) on each target to discover active services. |
| FR-03 | **Service Identification** | High | For each open port, the system shall identify the running service type (HTTPS, HTTP, SSH, SMTP, Database, VPN) and determine whether TLS is available. |
| FR-04 | **TLS Handshake Analysis** | Critical | For each TLS-capable endpoint, the system shall perform a full TLS handshake and extract: negotiated protocol version, cipher suite name, key exchange algorithm, key size, signature algorithm, and the complete certificate chain. |
| FR-05 | **Certificate Parsing** | High | The system shall extract from each certificate: Subject (CN), Issuer, Serial Number, Validity dates, Signature Algorithm, Public Key Type and Size, Subject Alternative Names (SAN), and SHA-256 Fingerprint. |
| FR-06 | **PQC Algorithm Classification** | Critical | The system shall classify every extracted algorithm into "Quantum Safe" (e.g., ML-KEM-768, ML-DSA-65) or "Quantum Vulnerable" (e.g., RSA-2048, ECDHE-P256, X25519) based on NIST FIPS 203/204/205 reference lists. |
| FR-07 | **HNDL Risk Assessment** | High | The system shall assign an HNDL risk level (Critical / High / Medium / Low) to each endpoint based on: the use of vulnerable key exchange algorithms, presence of long-lived encryption keys, and the sensitivity of the service type. |
| FR-08 | **Compliance Scoring** | High | The system shall compute a PQC compliance score (0–100%) for each endpoint, factoring in the ratio of quantum-safe to quantum-vulnerable algorithms in use. |
| FR-09 | **CBOM Generation** | Critical | The system shall generate a Cryptographic Bill of Materials in CycloneDX 1.6 JSON format, listing all discovered cryptographic assets with their properties as specified in Annexure-A. |
| FR-10 | **Digital Label Issuance** | High | The system shall issue digital labels: "Fully Quantum Safe" (score=100%, zero critical/high findings), "PQC Ready" (score≥80%), "Partial" (score≥50%), or "Non-Compliant" (score<50%). Each label includes a SHA-256 checksum, validity period, and badge color. |
| FR-11 | **Remediation Recommendations** | Medium | The system shall generate prioritized migration recommendations with server-specific configuration snippets (Nginx, Apache, HAProxy) for enabling hybrid PQC key exchange (e.g., `X25519MLKEM768`). |
| FR-12 | **Enterprise Dashboard** | High | The system shall display an Enterprise Operations Console with aggregate metrics: Total Assets Scanned, Quantum Safe %, Vulnerable Assets Count, Critical Findings Count, and Average PQC Compliance Score. |
| FR-13 | **Bulk Target Scanning** | Medium | The system shall accept multiple targets (comma or newline separated) and process each sequentially through the full scan pipeline. |
| FR-14 | **CBOM Export / Download** | Medium | The system shall provide a download endpoint for the CBOM JSON file associated with each scan. |
| FR-15 | **Recent Scans History** | Low | The system shall display the 10 most recent scans with their ID, target, status, asset count, compliance score, and timestamp. |

### 3.2 External Interface Requirements

#### 3.2.1 User Interfaces

The application shall provide a **web-based user interface** accessible via modern web browsers (Google Chrome, Microsoft Edge, Mozilla Firefox). The UI comprises:

1. **Dashboard Page** (`/`): Hero section, Enterprise Operations Console (aggregate metrics), Bulk Scan textarea input, Custom Ports input, Quick Scan buttons, Recent Scans table, NIST Standards reference cards.

2. **Results Page** (`/results/<scan_id>`): HNDL Threat banner, Overview metric cards (Total Assets, Quantum Safe, Quantum Vulnerable, Compliance Score), Donut and Bar charts (Quantum Readiness, Severity Breakdown, HNDL Risk Distribution), Discovered Services table with service-type labels, PQC Assessment cards per endpoint with per-algorithm breakdown, Security Findings with NIST references, Migration Recommendations with config snippets, TLS Endpoint Details (SAN, Serial, Fingerprint), CBOM Summary with download link, and Quantum-Safe Certification Labels.

3. **Error Page** (`/error`): Displays error ID, message, and traceback for debugging.

4. **CLI Interface** (`scan.py`): `python scan.py <target> [--json] [--cbom] [--output <file>]`

#### 3.2.2 Hardware Interfaces

- **Standard Server Hardware**: x86_64 architecture with a minimum of 2 CPU cores and 2 GB RAM.
- **Network Interface**: Standard Ethernet NIC for TCP/IP communication with target endpoints.
- No specialized quantum computing hardware, HSMs, or cryptographic accelerators are required.

#### 3.2.3 Software / Communication Interfaces

| Interface | Protocol | Description |
|-----------|----------|-------------|
| **Target Scanning** | TCP / TLS 1.2 / TLS 1.3 | Raw socket connections for port probing, followed by full TLS handshakes for analysis. |
| **Web Dashboard** | HTTP / HTTPS | Flask serves the web UI on port 5000. Production deployments use a reverse proxy (Nginx) with HTTPS. |
| **REST API** | HTTP GET | `GET /api/scan?target=<host>&ports=<ports>` returns JSON scan results for CI/CD integration. |
| **CBOM Export** | HTTP GET | `GET /cbom/<scan_id>` returns CycloneDX 1.6 JSON as a downloadable file. |
| **Chart Rendering** | CDN (Chart.js) | Chart.js 4.4 loaded from `cdn.jsdelivr.net` for client-side chart rendering. |

### 3.3 System Features

| Feature ID | Feature | Description |
|------------|---------|-------------|
| SF-01 | **Automated PQC Labeling** | Issues digital badges/certificates automatically based on 100% compliance with NIST FIPS 203/204/205 standards. Labels are tamper-evident via SHA-256 checksums. |
| SF-02 | **HNDL Threat Context Banner** | Every results page includes an educational banner explaining the "Harvest Now, Decrypt Later" risk specific to banking systems, including NIST migration timelines. |
| SF-03 | **Interactive Charts** | Three real-time charts: Quantum Readiness Donut (safe vs. vulnerable), Finding Severity Bar (Critical/High/Medium/Low/Info), HNDL Risk Distribution Donut. |
| SF-04 | **Service Type Detection** | Identifies and labels services as TLS, HTTP, VPN, Database, or API with colored badges in the Discovered Services table. |
| SF-05 | **Crypto Inventory Table** | Tabular view of all cryptographic algorithms in use with their quantum safety status, NIST standard reference, and category (KEM, Signature, Cipher, Hash). |
| SF-06 | **Dockerized Deployment** | Single-command deployment via `docker build -t quantumshield . && docker run -p 5000:5000 quantumshield`. |

### 3.4 Non-functional Requirements

#### 3.4.1 Performance Requirements

- **Single Scan Latency**: A single-target scan (including TLS handshake and PQC assessment) shall complete in under 15 seconds under normal network conditions.
- **Bulk Scan Throughput**: The system shall process bulk scans at a rate of 4–6 targets per minute.
- **Dashboard Load Time**: The web dashboard shall render within 2 seconds, including Chart.js visualization.
- **Concurrent Users**: The Flask development server supports 1 concurrent user; production deployment with Gunicorn supports 10+ concurrent users.

#### 3.4.2 Software Quality Attributes

- **Maintainability**: Modular Python package architecture (`src/scanner/`, `src/cbom/`, `src/validator/`, `src/reporting/`) enables independent updates to algorithm reference lists as NIST publishes new standards.
- **Testability**: 74+ automated unit tests with `pytest` covering all modules. Test coverage includes mocked TLS handshakes, algorithm classification logic, CBOM generation, and Flask route validation.
- **Portability**: Uses `requirements.txt` for dependency management; runs on Windows, Linux, and macOS without platform-specific code.
- **Reliability**: Scan failures on individual endpoints are gracefully handled without crashing the pipeline. Partial results are still reported.
- **Usability**: Intuitive web dashboard with a clean, premium design; quick-scan buttons for common targets; inline help text and tooltips.

#### 3.4.3 Other Non-functional Requirements

- **Compliance**: Validated against NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA).
- **Localization**: English-only for v1.0.
- **Licensing**: Open-source (Hackathon). All dependencies are MIT, BSD, or Apache 2.0 licensed.

________________________________________

## 4. Technological Requirements

### 4.1 Technologies used in development of the web application

| Layer | Technology | Version | Purpose |
|-------|-----------|---------|---------|
| **Backend** | Python | 3.10+ | Core programming language |
| **Web Framework** | Flask | 3.0+ | HTTP routing, templating, REST API |
| **TLS Inspection** | pyOpenSSL | 24.0+ | Deep TLS handshake analysis and certificate chain parsing |
| **Crypto Primitives** | cryptography | 42.0+ | X.509 certificate parsing, hash computation |
| **CBOM Standard** | cyclonedx-python-lib | 7.0+ | CycloneDX 1.6 JSON CBOM generation |
| **Templating** | Jinja2 | 3.1+ | HTML template rendering |
| **Frontend Charts** | Chart.js | 4.4 | Interactive donut and bar chart visualizations |
| **Frontend Styling** | Vanilla CSS | — | Glassmorphism dark-mode design system |
| **Frontend Logic** | JavaScript (ES6+) | — | Form handling, chart initialization, DOM manipulation |
| **Testing** | pytest | 8.0+ | Unit and integration testing framework |
| **Containerization** | Docker | — | Production deployment via `Dockerfile` |

### 4.2 I.D.E. (Integrated Development Environment)

- **Visual Studio Code** with Pylance (Python IntelliSense) and Jinja2 Template (syntax highlighting) extensions.

### 4.3 Database Management Software

- **Hackathon**: JSON flat-file storage in a local `results/` directory. Each scan generates `<scan_id>_report.json` and `<scan_id>_cbom.json`.
- **Production**: Extensible to **SQLite** (embedded) or **PostgreSQL** (enterprise) for persistent, queryable storage of scan history and trend data.

________________________________________

## 5. Security Requirements

The following security requirements apply to the QuantumShield system:

**Compatibility of the proposed system with current IT setup. Impact on existing systems should be estimated.**
> QuantumShield operates as a standalone scanning tool that communicates with targets over standard TLS. It does not install agents, modify configurations, or inject traffic into existing systems. **Impact on existing systems: NONE.** The scanner behaves identically to a standard web browser performing an HTTPS connection.

**Audit Trails for all important events capturing details like user ID, time and date, event etc.**
> Every scan is logged with: Scan ID (UUID), Target hostname/IP, Timestamp (UTC ISO 8601), Scan Status (complete/error/no_endpoints), Number of Assets discovered, Compliance Score, and all Findings. Logs are persisted to both the in-memory scan store and JSON files on disk.

**Control Access to Information and computing facilities based on principals like 'segregation of duty', 'need-to-know', etc.**
> - The web dashboard is accessible to authenticated operators. In production, Flask-Login or an API gateway (e.g., Kong, AWS API Gateway) enforces RBAC.
> - The `/api/scan` REST endpoint should be protected via API keys in production.
> - CBOM JSON files containing sensitive infrastructure details are stored in a restricted directory with filesystem-level permissions (chmod 600).

**Recoverability of Application in case of Failure**
> - All scan results are durably persisted to JSON files on disk immediately after computation.
> - The Docker container can be restarted without data loss; JSON files survive container restarts via volume mounts.
> - A production deployment should use a PostgreSQL database with automated daily backups for Disaster Recovery (DR).

**Compliance with any legal, statutory and contractual obligations**
> - The tool follows responsible scanning practices: read-only TLS handshakes, no exploit payloads, no data exfiltration.
> - CBOM output adheres to the CycloneDX 1.6 open standard maintained by OWASP.
> - PQC validation aligns with NIST SP 800-208 and FIPS 203/204/205 as of August 2024.

**Security vulnerabilities involved when connecting with other systems and applications**
> - The scanner only initiates outbound TLS connections. It does not expose any listening services to external targets.
> - The web dashboard port (5000) should be firewalled to internal networks only in production.
> - All third-party dependencies are pinned to specific minimum versions in `requirements.txt` and should be audited with `pip audit`.

**Operating environment security**
> - TLS 1.2 minimum is enforced for all scanner-to-target communications via Python's `ssl` module.
> - The Flask `SECRET_KEY` must be set to a cryptographically random value in production (via `QSS_SECRET_KEY` environment variable). The default dev key is for development only.

**Cost of providing security to the system over its life cycle (includes hardware, software, personnel and training).**
> - **Hardware**: Standard server (2 vCPU, 2 GB RAM). Estimated cost: ₹500/month on cloud.
> - **Software**: All dependencies are open-source (zero licensing cost). Docker is free for non-commercial and small-scale use.
> - **Personnel**: 1 security engineer for quarterly algorithm list updates and dependency patching.
> - **Training**: Minimal — the web dashboard is self-explanatory; a User Guide (`docs/USER_GUIDE.md`) is provided.

________________________________________

## Annexure-A (CERT-IN CBOM Elements)

The QuantumShield CBOM output conforms to the **CERT-IN Minimum Elements pertaining to Cryptographic Assets** specification. The following tables define the mandatory elements for each cryptographic asset type.

### Table A-1: Algorithms

| Element | Description | QuantumShield Field |
|---------|-------------|---------------------|
| **Name** | The name of the cryptographic algorithm or asset. For example, "AES-128-GCM" refers to the AES algorithm with a 128-bit key in Galois/Counter Mode (GCM). | `algorithm.name` |
| **Asset Type** | Specifies the type of cryptographic asset. For algorithms, the asset type is "algorithm". | `algorithm.asset_type` = `"algorithm"` |
| **Primitive** | Describes the cryptographic primitive. For "SHA512withRSA", the primitive is "signature" as it's used for digital signing. For "AES-128-GCM", it is "block-cipher". | `algorithm.primitive` |
| **Mode** | The operational mode used by the algorithm. For example, "gcm" refers to the Galois/Counter Mode used with AES encryption. | `algorithm.mode` |
| **Crypto Functions** | The cryptographic functions supported by the asset. For example, in the case of "AES-128-GCM" they are key generation, encryption, decryption, and authentication tag generation. | `algorithm.crypto_functions` |
| **Classical Security Level** | The classical security level represents the strength of the cryptographic asset in terms of its resistance to attacks using classical (non-quantum) methods. For AES-128, it's 128 bits. | `algorithm.classical_security_level` |
| **OID** | The Object Identifier (OID) is a globally unique identifier used to refer to the algorithm. It helps in distinguishing algorithms across different systems. For example, "2.16.840.1.101.3.4.1.6" for AES-128-GCM, "1.2.840.113549.1.1.13" for SHA512withRSA. | `algorithm.oid` |
| **List** | Lists the cryptographic algorithms employed by the quantum device or system, allowing for an assessment of its security capabilities, especially in the context of post-quantum encryption standards. | `algorithm.quantum_safe_status` |

### Table A-2: Keys

| Element | Description | QuantumShield Field |
|---------|-------------|---------------------|
| **Name** | The name of the key, which is a unique identifier for the key used in cryptographic operations. | `key.name` |
| **Asset Type** | Defines the type of cryptographic asset. For keys, the asset type is typically "key". | `key.asset_type` = `"key"` |
| **id** | A unique identifier for the key, such as a key ID or reference number. | `key.id` |
| **state** | The state of the key, such as whether it is active, revoked, or expired. | `key.state` |
| **size** | The size of the key, typically measured in bits. For example, a 128-bit key or a 2048-bit RSA key. | `key.size` |
| **Creation Date** | The date when the key was created. | `key.creation_date` |
| **Activation Date** | The date when the key became operational or was first used. | `key.activation_date` |

### Table A-3: Protocols

| Element | Description | QuantumShield Field |
|---------|-------------|---------------------|
| **Name** | The name of the cryptographic protocol, such as TLS, IPsec, or SSH. | `protocol.name` |
| **Asset Type** | Defines the type of cryptographic asset. In this case, it would be a "protocol". | `protocol.asset_type` = `"protocol"` |
| **Version** | The version of the protocol used, such as TLS 1.2 or TLS 1.3. | `protocol.version` |
| **Cipher Suites** | The set of cryptographic algorithms and parameters supported by the protocol for tasks like encryption, key exchange, and integrity checking. | `protocol.cipher_suites` |
| **OID** | The Object Identifier (OID) associated with the protocol, identifying its unique specifications. | `protocol.oid` |

### Table A-4: Certificates

| Element | Description | QuantumShield Field |
|---------|-------------|---------------------|
| **Name** | The name of the certificate, typically referring to its subject or the entity it represents (e.g., a website). | `certificate.name` |
| **Asset Type** | Defines the type of cryptographic asset. For certificates, the asset type is "certificate". | `certificate.asset_type` = `"certificate"` |
| **Subject Name** | This refers to the Distinguished Name (DN) of the entity that the certificate represents. It typically contains information about the organization, domain name. | `certificate.subject_name` |
| **Issuer Name** | The issuer is the Certificate Authority (CA) that issued and signed the certificate. This field contains the DN of the CA that verified and issued the certificate. | `certificate.issuer_name` |
| **Not Valid Before** | This specifies the date and time from which the certificate is valid. | `certificate.not_valid_before` |
| **Not Valid After** | This specifies the expiration date and time of the certificate. The certificate becomes invalid after this timestamp. | `certificate.not_valid_after` |
| **Signature Algorithm Reference** | This refers to the cryptographic algorithm used to sign the certificate. It provides a reference to the algorithm and its OID (Object Identifier). | `certificate.signature_algorithm_ref` |
| **Subject Public Key Reference** | This points to the public key used by the subject (the entity being identified in the certificate). It provides a reference to the key's details, including the algorithm. | `certificate.subject_public_key_ref` |
| **Certificate Format** | Specifies the format of the certificate. Common formats include X.509, which is the most widely used format for certificates. | `certificate.format` = `"X.509"` |
| **Certificate Extension** | This refers to the file extension associated with the certificate. It is commonly .crt for certificates in the X.509 format. | `certificate.extension` = `".crt"` |

