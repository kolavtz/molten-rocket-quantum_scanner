"""
Quantum-Safe TLS Scanner — Central Configuration

All constants, algorithm lists, port definitions, and risk weights
used across the application are defined here.
"""

import os

# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
APP_NAME = "Quantum-Safe TLS Scanner"
APP_VERSION = "1.0.0"
SECRET_KEY = os.environ.get("QSS_SECRET_KEY", "dev-secret-change-in-production")
DEBUG = os.environ.get("QSS_DEBUG", "true").lower() == "true"

# ---------------------------------------------------------------------------
# Network Discovery — Default Ports
# ---------------------------------------------------------------------------
DEFAULT_TLS_PORTS = [
    443,    # HTTPS
    8443,   # HTTPS (alt)
    636,    # LDAPS
    989,    # FTPS data
    990,    # FTPS control
    992,    # TelnetS
    993,    # IMAPS
    995,    # POP3S
    465,    # SMTPS (submission)
    5061,   # SIP-TLS
]

# Extended port list for broad service discovery
# These are probed to find ANY running service, then TLS is attempted
EXTENDED_DISCOVERY_PORTS = [
    21,     # FTP
    22,     # SSH
    25,     # SMTP
    53,     # DNS
    80,     # HTTP
    110,    # POP3
    143,    # IMAP
    443,    # HTTPS
    445,    # SMB
    465,    # SMTPS
    587,    # SMTP submission
    636,    # LDAPS
    993,    # IMAPS
    995,    # POP3S
    1433,   # MSSQL
    1521,   # Oracle DB
    3306,   # MySQL
    3389,   # RDP
    5432,   # PostgreSQL
    5900,   # VNC
    6379,   # Redis
    8080,   # HTTP-Proxy
    8443,   # HTTPS-Alt
    8888,   # HTTP-Alt
    9090,   # Prometheus
    9200,   # Elasticsearch
    27017,  # MongoDB
]

PORT_SERVICE_MAP = {
    21:    "FTP",
    22:    "SSH",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    465:   "SMTPS",
    587:   "SMTP-Submission",
    636:   "LDAPS",
    989:   "FTPS-Data",
    990:   "FTPS-Control",
    992:   "TelnetS",
    993:   "IMAPS",
    995:   "POP3S",
    1433:  "MSSQL",
    1521:  "OracleDB",
    3306:  "MySQL",
    3389:  "RDP",
    5061:  "SIP-TLS",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    8080:  "HTTP-Proxy",
    8443:  "HTTPS-Alt",
    8888:  "HTTP-Alt",
    9090:  "Prometheus",
    9200:  "Elasticsearch",
    27017: "MongoDB",
}

SCAN_TIMEOUT_SECONDS = 5
HANDSHAKE_TIMEOUT_SECONDS = 10

# ---------------------------------------------------------------------------
# NIST Post-Quantum Cryptography — Approved Algorithms
# ---------------------------------------------------------------------------
# Key Encapsulation Mechanisms (FIPS 203 — ML-KEM / Kyber)
NIST_APPROVED_KEMS = {
    "ML-KEM-512",   "ML-KEM-768",   "ML-KEM-1024",
    "KYBER512",     "KYBER768",     "KYBER1024",       # alias names
    "X25519MLKEM768",                                   # hybrid
}

# Digital Signature Algorithms (FIPS 204 — ML-DSA / Dilithium)
NIST_APPROVED_SIGNATURES = {
    "ML-DSA-44",    "ML-DSA-65",    "ML-DSA-87",
    "DILITHIUM2",   "DILITHIUM3",   "DILITHIUM5",      # alias names
}

# Stateless Hash-Based Signatures (FIPS 205 — SLH-DSA / SPHINCS+)
NIST_APPROVED_HASH_SIGNATURES = {
    "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
    "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
    "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
    "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f",
    "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f",
    "SPHINCS+-SHA2-128f-simple", "SPHINCS+-SHA2-128s-simple",
    "SPHINCS+-SHA2-192f-simple", "SPHINCS+-SHA2-192s-simple",
    "SPHINCS+-SHA2-256f-simple", "SPHINCS+-SHA2-256s-simple",
    "SPHINCS+-SHAKE-128f-simple", "SPHINCS+-SHAKE-128s-simple",
    "SPHINCS+-SHAKE-192f-simple", "SPHINCS+-SHAKE-192s-simple",
    "SPHINCS+-SHAKE-256f-simple", "SPHINCS+-SHAKE-256s-simple",
}

# Draft / Backup Standards
DRAFT_PQC_ALGORITHMS = {
    "FN-DSA-512",  "FN-DSA-1024",                      # Falcon (draft)
    "FALCON512",   "FALCON1024",                        # alias names
    "HQC-128",     "HQC-192",     "HQC-256",           # HQC KEM (draft 2026)
}

# Combined set of all quantum-safe algorithms
ALL_PQC_ALGORITHMS = (
    NIST_APPROVED_KEMS
    | NIST_APPROVED_SIGNATURES
    | NIST_APPROVED_HASH_SIGNATURES
    | DRAFT_PQC_ALGORITHMS
)

# ---------------------------------------------------------------------------
# Quantum-Vulnerable Algorithms
# ---------------------------------------------------------------------------
QUANTUM_VULNERABLE_KEY_EXCHANGES = {
    "RSA",
    "DH", "DHE",
    "ECDH", "ECDHE",
    "X25519", "X448",           # Curve-based, quantum-vulnerable
}

QUANTUM_VULNERABLE_SIGNATURES = {
    "RSA", "RSASSA-PSS",
    "DSA",
    "ECDSA",
    "Ed25519", "Ed448",
}

QUANTUM_VULNERABLE_ALGORITHMS = (
    QUANTUM_VULNERABLE_KEY_EXCHANGES | QUANTUM_VULNERABLE_SIGNATURES
)

# ---------------------------------------------------------------------------
# TLS Cipher Suite → Key Exchange Mapping (common patterns)
# ---------------------------------------------------------------------------
CIPHER_KEX_PATTERNS = {
    "ECDHE": "ECDHE",
    "DHE":   "DHE",
    "RSA":   "RSA",       # static RSA key exchange (no PFS)
    "KYBER": "ML-KEM",
    "X25519MLKEM768": "X25519MLKEM768",
}

# ---------------------------------------------------------------------------
# Risk Scoring — HNDL (Harvest Now, Decrypt Later)
# ---------------------------------------------------------------------------
HNDL_RISK_WEIGHTS = {
    "HIGH": {
        "description": "Financial APIs, authentication endpoints, PII in transit",
        "keywords": ["api", "auth", "login", "payment", "banking", "token"],
        "score": 9,
    },
    "MEDIUM": {
        "description": "Customer data APIs, internal services with sensitive data",
        "keywords": ["customer", "data", "user", "admin", "internal"],
        "score": 6,
    },
    "LOW": {
        "description": "Public content CDNs, static assets, marketing sites",
        "keywords": ["cdn", "static", "public", "blog", "marketing", "www"],
        "score": 3,
    },
}

# ---------------------------------------------------------------------------
# CBOM / CycloneDX
# ---------------------------------------------------------------------------
CBOM_SPEC_VERSION = "1.6"
CBOM_SERIAL_PREFIX = "urn:uuid:"

# ---------------------------------------------------------------------------
# Web / Flask
# ---------------------------------------------------------------------------
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "scan_results")
