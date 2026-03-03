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
# CERT-IN CBOM — Algorithm OID Mappings (ITU-T X.660)
# ---------------------------------------------------------------------------
ALGORITHM_OID_MAP = {
    # Symmetric Ciphers
    "AES-128-GCM":    "2.16.840.1.101.3.4.1.6",
    "AES-256-GCM":    "2.16.840.1.101.3.4.1.46",
    "AES-128-CBC":    "2.16.840.1.101.3.4.1.2",
    "AES-256-CBC":    "2.16.840.1.101.3.4.1.42",
    "CHACHA20-POLY1305": "1.2.840.113549.1.9.16.3.18",
    "3DES-CBC":       "1.2.840.113549.3.7",
    # Signature Algorithms
    "SHA256withRSA":  "1.2.840.113549.1.1.11",
    "SHA384withRSA":  "1.2.840.113549.1.1.12",
    "SHA512withRSA":  "1.2.840.113549.1.1.13",
    "SHA256withECDSA":"1.2.840.10045.4.3.2",
    "SHA384withECDSA":"1.2.840.10045.4.3.3",
    "RSASSA-PSS":     "1.2.840.113549.1.1.10",
    "Ed25519":        "1.3.101.112",
    "Ed448":          "1.3.101.113",
    # Key Exchange
    "RSA":            "1.2.840.113549.1.1.1",
    "ECDH":           "1.3.132.1.12",
    "ECDHE":          "1.3.132.1.12",
    "X25519":         "1.3.101.110",
    "X448":           "1.3.101.111",
    "DH":             "1.2.840.113549.1.3.1",
    "DHE":            "1.2.840.113549.1.3.1",
    # Hash Functions
    "SHA-256":        "2.16.840.1.101.3.4.2.1",
    "SHA-384":        "2.16.840.1.101.3.4.2.2",
    "SHA-512":        "2.16.840.1.101.3.4.2.3",
    "SHA-1":          "1.3.14.3.2.26",
    # PQC (NIST draft OIDs)
    "ML-KEM-512":     "2.16.840.1.101.3.4.4.1",
    "ML-KEM-768":     "2.16.840.1.101.3.4.4.2",
    "ML-KEM-1024":    "2.16.840.1.101.3.4.4.3",
    "ML-DSA-44":      "2.16.840.1.101.3.4.3.17",
    "ML-DSA-65":      "2.16.840.1.101.3.4.3.18",
    "ML-DSA-87":      "2.16.840.1.101.3.4.3.19",
}

# ---------------------------------------------------------------------------
# CERT-IN CBOM — Algorithm Metadata (Primitive, Mode, Functions, Security)
# ---------------------------------------------------------------------------
ALGORITHM_METADATA = {
    "AES-128-GCM":    {"primitive": "block-cipher", "mode": "gcm", "crypto_functions": ["keygen", "encrypt", "decrypt", "auth-tag"], "classical_security_bits": 128},
    "AES-256-GCM":    {"primitive": "block-cipher", "mode": "gcm", "crypto_functions": ["keygen", "encrypt", "decrypt", "auth-tag"], "classical_security_bits": 256},
    "AES-128-CBC":    {"primitive": "block-cipher", "mode": "cbc", "crypto_functions": ["keygen", "encrypt", "decrypt"], "classical_security_bits": 128},
    "AES-256-CBC":    {"primitive": "block-cipher", "mode": "cbc", "crypto_functions": ["keygen", "encrypt", "decrypt"], "classical_security_bits": 256},
    "CHACHA20-POLY1305": {"primitive": "stream-cipher", "mode": "aead", "crypto_functions": ["keygen", "encrypt", "decrypt", "auth-tag"], "classical_security_bits": 256},
    "3DES-CBC":       {"primitive": "block-cipher", "mode": "cbc", "crypto_functions": ["keygen", "encrypt", "decrypt"], "classical_security_bits": 112},
    "RSA":            {"primitive": "asymmetric", "mode": "pkcs1", "crypto_functions": ["keygen", "encrypt", "decrypt", "sign", "verify"], "classical_security_bits": 112},
    "ECDHE":          {"primitive": "key-agreement", "mode": "ephemeral", "crypto_functions": ["keygen", "key-agreement"], "classical_security_bits": 128},
    "ECDH":           {"primitive": "key-agreement", "mode": "static", "crypto_functions": ["keygen", "key-agreement"], "classical_security_bits": 128},
    "X25519":         {"primitive": "key-agreement", "mode": "ephemeral", "crypto_functions": ["keygen", "key-agreement"], "classical_security_bits": 128},
    "X448":           {"primitive": "key-agreement", "mode": "ephemeral", "crypto_functions": ["keygen", "key-agreement"], "classical_security_bits": 224},
    "DHE":            {"primitive": "key-agreement", "mode": "ephemeral", "crypto_functions": ["keygen", "key-agreement"], "classical_security_bits": 112},
    "SHA256withRSA":  {"primitive": "signature", "mode": "pkcs1v15", "crypto_functions": ["sign", "verify"], "classical_security_bits": 112},
    "SHA384withRSA":  {"primitive": "signature", "mode": "pkcs1v15", "crypto_functions": ["sign", "verify"], "classical_security_bits": 112},
    "SHA512withRSA":  {"primitive": "signature", "mode": "pkcs1v15", "crypto_functions": ["sign", "verify"], "classical_security_bits": 112},
    "SHA256withECDSA":{"primitive": "signature", "mode": "ecdsa", "crypto_functions": ["sign", "verify"], "classical_security_bits": 128},
    "SHA384withECDSA":{"primitive": "signature", "mode": "ecdsa", "crypto_functions": ["sign", "verify"], "classical_security_bits": 192},
    "RSASSA-PSS":     {"primitive": "signature", "mode": "pss", "crypto_functions": ["sign", "verify"], "classical_security_bits": 112},
    "Ed25519":        {"primitive": "signature", "mode": "eddsa", "crypto_functions": ["sign", "verify"], "classical_security_bits": 128},
    "SHA-256":        {"primitive": "hash", "mode": "none", "crypto_functions": ["digest"], "classical_security_bits": 128},
    "SHA-384":        {"primitive": "hash", "mode": "none", "crypto_functions": ["digest"], "classical_security_bits": 192},
    "SHA-512":        {"primitive": "hash", "mode": "none", "crypto_functions": ["digest"], "classical_security_bits": 256},
    "ML-KEM-768":     {"primitive": "kem", "mode": "lattice", "crypto_functions": ["keygen", "encapsulate", "decapsulate"], "classical_security_bits": 192},
    "ML-KEM-512":     {"primitive": "kem", "mode": "lattice", "crypto_functions": ["keygen", "encapsulate", "decapsulate"], "classical_security_bits": 128},
    "ML-KEM-1024":    {"primitive": "kem", "mode": "lattice", "crypto_functions": ["keygen", "encapsulate", "decapsulate"], "classical_security_bits": 256},
    "ML-DSA-44":      {"primitive": "signature", "mode": "lattice", "crypto_functions": ["keygen", "sign", "verify"], "classical_security_bits": 128},
    "ML-DSA-65":      {"primitive": "signature", "mode": "lattice", "crypto_functions": ["keygen", "sign", "verify"], "classical_security_bits": 192},
    "ML-DSA-87":      {"primitive": "signature", "mode": "lattice", "crypto_functions": ["keygen", "sign", "verify"], "classical_security_bits": 256},
    "X25519MLKEM768": {"primitive": "hybrid-kem", "mode": "lattice+ecdh", "crypto_functions": ["keygen", "encapsulate", "decapsulate", "key-agreement"], "classical_security_bits": 192},
}

# Protocol OIDs
PROTOCOL_OID_MAP = {
    "TLSv1.2": "1.3.6.1.5.5.7.1",
    "TLSv1.3": "1.3.6.1.5.5.7.1",
    "SSLv3":   "1.3.6.1.5.5.7.1",
}


# ---------------------------------------------------------------------------
# Web / Flask
# ---------------------------------------------------------------------------
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "scan_results")
