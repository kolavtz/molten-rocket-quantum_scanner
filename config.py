"""
Quantum-Safe TLS Scanner — Central Configuration

All constants, algorithm lists, port definitions, and risk weights
used across the application are defined here.
"""

import os
from dotenv import load_dotenv  # type: ignore

# Load user's .env file if present
load_dotenv()

# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
APP_NAME = "Quantum-Safe TLS Scanner"
APP_VERSION = "1.0.0"
SECRET_KEY = os.environ.get("QSS_SECRET_KEY", "dev-secret-change-in-production")
DEBUG = os.environ.get("QSS_DEBUG", "true").lower() == "true"
SESSION_COOKIE_NAME = os.environ.get("QSS_SESSION_COOKIE_NAME", "quantumshield_session")

# ---------------------------------------------------------------------------
# Network Scanning — Security & Scope
# ---------------------------------------------------------------------------
# Allow scanning of private/local networks (RFC 1918, loopback)
# Set to 'false' only if you want to restrict scanning to public IPs
ALLOW_LOCAL_SCANS = os.environ.get("ALLOW_LOCAL_SCANS", "true").lower() == "true"

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

# Autodiscovery — exhaustive port list for deep private-network scans
# Includes all of the above + enterprise infra, middleware, IoT, CI/CD
AUTODISCOVERY_PORTS = sorted(set(EXTENDED_DISCOVERY_PORTS + [
    # Additional Web / API
    81,     # HTTP-Alt
    3000,   # Node.js / Grafana
    4443,   # HTTPS-Alt
    5000,   # Flask / Docker Registry
    5001,   # Synology / iperf3
    7443,   # HTTPS-Alt
    8000,   # Django / SimpleHTTP
    8008,   # HTTP-Alt
    8081,   # HTTP-Alt
    8082,   # HTTP-Alt
    8181,   # HTTP-Alt
    8444,   # HTTPS-Alt
    8880,   # Sun Proxy Admin
    9000,   # SonarQube / Portainer
    9443,   # HTTPS-Alt / vSphere
    # Databases
    1434,   # MSSQL Browser
    3307,   # MySQL-Alt
    5433,   # PostgreSQL-Alt
    6380,   # Redis-Alt (TLS)
    7001,   # Cassandra
    7199,   # Cassandra JMX
    9042,   # Cassandra CQL
    26257,  # CockroachDB
    28015,  # RethinkDB
    # Message Queues & Middleware
    1883,   # MQTT
    4369,   # Erlang Port Mapper (RabbitMQ)
    5671,   # AMQP-TLS (RabbitMQ)
    5672,   # AMQP (RabbitMQ)
    6443,   # Kubernetes API
    8883,   # MQTT-TLS
    9092,   # Apache Kafka
    9093,   # Kafka-TLS
    15671,  # RabbitMQ Management TLS
    15672,  # RabbitMQ Management
    61613,  # STOMP
    61614,  # STOMP-TLS
    # CI/CD & DevOps
    2376,   # Docker TLS
    2377,   # Docker Swarm
    8888,   # Jupyter Notebook
    10250,  # Kubelet
    10443,  # Rancher
    # Monitoring
    9100,   # Node Exporter
    9115,   # Blackbox Exporter
    9093,   # Alertmanager
    3100,   # Loki
    8200,   # Vault
    # Mail / Directory
    389,    # LDAP (non-TLS)
    1636,   # LDAPS-Alt
    4190,   # ManageSieve
    # VPN / Tunnel
    500,    # IKE
    1194,   # OpenVPN
    4500,   # IPSec NAT-T
    1701,   # L2TP
    1723,   # PPTP
    # SSH / Remote
    2222,   # SSH-Alt
    5985,   # WinRM HTTP
    5986,   # WinRM HTTPS
    # IoT / ICS
    502,    # Modbus
    102,    # S7Comm (Siemens)
    2404,   # IEC 60870-5-104
    47808,  # BACnet
    44818,  # EtherNet/IP
]))


PORT_SERVICE_MAP = {
    21:    "FTP",
    22:    "SSH",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    81:    "HTTP-Alt",
    102:   "S7Comm",
    110:   "POP3",
    143:   "IMAP",
    389:   "LDAP",
    443:   "HTTPS",
    445:   "SMB",
    465:   "SMTPS",
    500:   "IKE",
    502:   "Modbus",
    587:   "SMTP-Submission",
    636:   "LDAPS",
    989:   "FTPS-Data",
    990:   "FTPS-Control",
    992:   "TelnetS",
    993:   "IMAPS",
    995:   "POP3S",
    1194:  "OpenVPN",
    1433:  "MSSQL",
    1434:  "MSSQL-Browser",
    1521:  "OracleDB",
    1636:  "LDAPS-Alt",
    1701:  "L2TP",
    1723:  "PPTP",
    1883:  "MQTT",
    2222:  "SSH-Alt",
    2376:  "Docker-TLS",
    2377:  "Docker-Swarm",
    2404:  "IEC-104",
    3000:  "Grafana",
    3100:  "Loki",
    3306:  "MySQL",
    3307:  "MySQL-Alt",
    3389:  "RDP",
    4190:  "ManageSieve",
    4369:  "EPMD",
    4443:  "HTTPS-Alt",
    4500:  "IPSec-NAT",
    5000:  "Flask",
    5001:  "Synology",
    5061:  "SIP-TLS",
    5432:  "PostgreSQL",
    5433:  "PostgreSQL-Alt",
    5671:  "AMQP-TLS",
    5672:  "AMQP",
    5900:  "VNC",
    5985:  "WinRM",
    5986:  "WinRM-TLS",
    6379:  "Redis",
    6380:  "Redis-TLS",
    6443:  "K8s-API",
    7001:  "Cassandra",
    7199:  "Cassandra-JMX",
    7443:  "HTTPS-Alt",
    8000:  "HTTP-Alt",
    8008:  "HTTP-Alt",
    8080:  "HTTP-Proxy",
    8081:  "HTTP-Alt",
    8082:  "HTTP-Alt",
    8181:  "HTTP-Alt",
    8200:  "Vault",
    8443:  "HTTPS-Alt",
    8444:  "HTTPS-Alt",
    8880:  "Proxy-Admin",
    8883:  "MQTT-TLS",
    8888:  "HTTP-Alt",
    9000:  "SonarQube",
    9042:  "Cassandra-CQL",
    9090:  "Prometheus",
    9092:  "Kafka",
    9093:  "Kafka-TLS",
    9100:  "NodeExporter",
    9115:  "BlackboxExp",
    9200:  "Elasticsearch",
    9443:  "HTTPS-Alt",
    10250: "Kubelet",
    10443: "Rancher",
    15671: "RabbitMQ-TLS",
    15672: "RabbitMQ-Mgmt",
    26257: "CockroachDB",
    27017: "MongoDB",
    28015: "RethinkDB",
    44818: "EtherNetIP",
    47808: "BACnet",
    61613: "STOMP",
    61614: "STOMP-TLS",
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
# MySQL — Redundant Storage
# ---------------------------------------------------------------------------
# Support for user's custom .env keys
_sql_url = os.environ.get("sql_server_url_with_port", "")
if ":" in _sql_url:
    _sql_host, _sql_port = _sql_url.split(":", 1)
else:
    _sql_host = _sql_url or "localhost"
    _sql_port = "3306"

MYSQL_HOST     = os.environ.get("MYSQL_HOST", _sql_host)
MYSQL_PORT     = int(os.environ.get("MYSQL_PORT", _sql_port))
MYSQL_USER     = os.environ.get("MYSQL_USER", os.environ.get("sql_user", "root"))
MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", os.environ.get("sql_password", ""))
MYSQL_DATABASE = os.environ.get("MYSQL_DATABASE", "quantumshield")

from urllib.parse import quote_plus
# Derived ORM Configuration Pattern
_orm_host = str(MYSQL_HOST or "localhost").strip()
if ":" in _orm_host and not _orm_host.startswith("["):
    _orm_host = f"[{_orm_host}]"

SQLALCHEMY_DATABASE_URI = (
    f"mysql+pymysql://{quote_plus(MYSQL_USER)}:{quote_plus(MYSQL_PASSWORD)}"
    f"@{_orm_host}:{MYSQL_PORT}/{quote_plus(MYSQL_DATABASE)}"
)

# ---------------------------------------------------------------------------
# Web / Flask / Security
# ---------------------------------------------------------------------------
# Determine project root (for constructing absolute paths)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Flexible port handling for production (e.g. Heroku/Azure use $PORT)
FLASK_PORT = int(os.environ.get("PORT", os.environ.get("FLASK_PORT", "5000")))
FLASK_HOST = os.environ.get("FLASK_HOST", "127.0.0.1")

RESULTS_DIR = os.path.join(BASE_DIR, "scan_results")

# Security Hardening
# Limit payload sizes to prevent DoS via massive JSON/CSV uploads
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB

# Session Security
# These should be strictly locked down in production
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE   = not DEBUG  # Only send over HTTPS if not in debug mode
SESSION_COOKIE_SAMESITE = "Lax"
PERMANENT_SESSION_LIFETIME = 3600    # 1 hour
SESSION_IDLE_TIMEOUT_SECONDS = int(os.environ.get("QSS_SESSION_IDLE_TIMEOUT_SECONDS", str(PERMANENT_SESSION_LIFETIME)))

# HTTPS / proxy hardening
FORCE_HTTPS = os.environ.get("QSS_FORCE_HTTPS", str(not DEBUG)).lower() == "true"
TRUST_PROXY_SSL_HEADER = os.environ.get("QSS_TRUST_PROXY_SSL", "true").lower() == "true"
HSTS_SECONDS = int(os.environ.get("QSS_HSTS_SECONDS", "31536000"))
# Backward-compatible lockout threshold key:
# - Preferred: QSS_INVALID_USERNAME_LOCKOUT_ATTEMPTS
# - Legacy:    QSS_MAX_LOGIN_ATTEMPTS
MAX_LOGIN_ATTEMPTS = int(
    os.environ.get(
        "QSS_INVALID_USERNAME_LOCKOUT_ATTEMPTS",
        os.environ.get("QSS_MAX_LOGIN_ATTEMPTS", "5"),
    )
)
LOGIN_LOCKOUT_MINUTES = int(os.environ.get("QSS_LOGIN_LOCKOUT_MINUTES", "15"))

# ---------------------------------------------------------------------------
# SMTP / Email
# ---------------------------------------------------------------------------
MAIL_SERVER = os.environ.get("MAIL_SERVER", os.environ.get("SMTP_SERVER", "smtp.gmail.com"))
MAIL_PORT = int(os.environ.get("MAIL_PORT", os.environ.get("SMTP_PORT", 587)))
MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", os.environ.get("SMTP_USE_TLS", "true")).lower() == "true"
MAIL_USE_SSL = os.environ.get("MAIL_USE_SSL", os.environ.get("SMTP_USE_SSL", "false")).lower() == "true"
MAIL_USERNAME = os.environ.get("MAIL_USERNAME", os.environ.get("SMTP_USERNAME"))
MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", os.environ.get("SMTP_PASSWORD"))
MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", os.environ.get("SMTP_FROM", MAIL_USERNAME))

# ---------------------------------------------------------------------------
# Audit / Tamper-Evident Logging
# ---------------------------------------------------------------------------
AUDIT_HASH_SECRET = os.environ.get("QSS_AUDIT_HASH_SECRET", SECRET_KEY)
AUDIT_LOG_PAGE_SIZE = int(os.environ.get("QSS_AUDIT_LOG_PAGE_SIZE", "100"))

# ---------------------------------------------------------------------------
# Bootstrap / Production Placeholders
# ---------------------------------------------------------------------------
QSS_ADMIN_USERNAME = os.environ.get("QSS_ADMIN_USERNAME", "admin")
QSS_ADMIN_EMAIL = os.environ.get("QSS_ADMIN_EMAIL", "admin@localhost")
QSS_ADMIN_EMPLOYEE_ID = os.environ.get("QSS_ADMIN_EMPLOYEE_ID", "ADMIN-001")
QSS_ADMIN_PASSWORD = os.environ.get("QSS_ADMIN_PASSWORD", "Admin@12345678")

# ---------------------------------------------------------------------------
# Data Security (Encryption at Rest)
# ---------------------------------------------------------------------------
# Must be a 32-url-safe-base64-encoded bytes string for Fernet
# Generate one via: cryptography.fernet.Fernet.generate_key()
ENCRYPTION_KEY = os.environ.get("QSS_ENCRYPTION_KEY")

# ---------------------------------------------------------------------------
# Security Hardening (Harden Phase)
# ---------------------------------------------------------------------------
# Rate Limiting
RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
RATELIMIT_ENABLED = os.environ.get("RATELIMIT_ENABLED", "true").lower() == "true"
# Format: comma-separated list of limits (e.g., "200 per day, 50 per hour")
RATELIMIT_DEFAULT_LIMITS_STR = os.environ.get("RATELIMIT_DEFAULT_LIMITS", "200 per day,50 per hour")
RATELIMIT_DEFAULT_LIMITS = [limit.strip() for limit in RATELIMIT_DEFAULT_LIMITS_STR.split(",")]

# Content Security Policy (Simple restrictive policy)
# Allows self, Google Fonts, and inline styles for the glassmorphism effects
CSP_CONFIG = {
    'default-src': ["'self'"],
    'style-src': ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://cdnjs.cloudflare.com', 'https://unpkg.com'],
    'font-src': ["'self'", 'https://fonts.gstatic.com', 'https://cdnjs.cloudflare.com'],
    'img-src': ["'self'", 'data:', 'https://*'],
    'script-src': ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", 'https://unpkg.com'], # app.js, inline scripts and Chart.js
}

# ---------------------------------------------------------------------------
# Automated / Scheduled Scans
# ---------------------------------------------------------------------------
AUTOMATED_SCAN_ENABLED = os.environ.get("AUTOMATED_SCAN_ENABLED", "false").lower() == "true"
AUTOMATED_SCAN_INTERVAL_HOURS = int(os.environ.get("AUTOMATED_SCAN_INTERVAL_HOURS", "24"))

# ===============================================
# PHASE 1: MATH-BASED KPI SYSTEM CONFIGURATION
# ===============================================
# All constants used in PQC scoring, risk calculations, and digital label assignments
# Based on math-definition-for-quantumshield-app.md

# ---------------------------------------------------------------------------
# Risk Penalty Calculation (Math Section 5.1)
# ---------------------------------------------------------------------------
# Weight per finding severity: Σ(severity × weight)
RISK_WEIGHTS = {
    'critical': float(os.environ.get('RISK_WEIGHT_CRITICAL', '10.0')),
    'high': float(os.environ.get('RISK_WEIGHT_HIGH', '5.0')),
    'medium': float(os.environ.get('RISK_WEIGHT_MEDIUM', '2.0')),
    'low': float(os.environ.get('RISK_WEIGHT_LOW', '0.5')),
}

# Alpha scaling factor for risk penalty impact on cyber score
# Formula: max(0, pqc_score - PENALTY_ALPHA * risk_penalty)
PENALTY_ALPHA = float(os.environ.get('PENALTY_ALPHA', '0.5'))

# ---------------------------------------------------------------------------
# PQC Score Thresholds (Math Section 3.3 - Asset Classification)
# ---------------------------------------------------------------------------
# Classification tiers based on PQC score ranges
PQC_THRESHOLDS = {
    'elite': int(os.environ.get('PQC_THRESHOLD_ELITE', '90')),        # ≥ 90
    'standard': int(os.environ.get('PQC_THRESHOLD_STANDARD', '70')),  # 70-89
    'legacy': int(os.environ.get('PQC_THRESHOLD_LEGACY', '40')),      # 40-69
    'critical': int(os.environ.get('PQC_THRESHOLD_CRITICAL', '0')),   # < 40
}

# ---------------------------------------------------------------------------
# Cyber Rating Tiers (Math Section 5.4 - Enterprise Score 0-1000)
# ---------------------------------------------------------------------------
# Enterprise-level tiers based on average asset cyber scores
CYBER_RATING_TIERS = {
    'tier1_elite': int(os.environ.get('CYBER_TIER_ELITE', '700')),       # ≥ 700
    'tier2_standard': int(os.environ.get('CYBER_TIER_STANDARD', '400')), # 400-699
    'tier3_legacy': int(os.environ.get('CYBER_TIER_LEGACY', '0')),       # 0-399
}

# ---------------------------------------------------------------------------
# Cryptographic Weakness Thresholds
# ---------------------------------------------------------------------------
# Weak key length threshold (bits) - RFC 3394, NIST guidelines
WEAK_KEY_LENGTH_BITS = int(os.environ.get('WEAK_KEY_LENGTH_BITS', '2048'))

# Weak TLS versions (version < this value is considered weak)
WEAK_TLS_VERSIONS = [
    'SSLv2', 'SSLv3', 'TLS 1.0', 'TLS 1.1'
]

# Expired certificate threshold (days) - auto-flag if expiring within this period
EXPIRING_CERT_THRESHOLD_DAYS = int(os.environ.get('EXPIRING_CERT_THRESHOLD', '30'))

# ---------------------------------------------------------------------------
# Certificate Expiry Buckets (Math Section 2.5 - Distribution)
# ---------------------------------------------------------------------------
# Defines ranges for certificate expiry timeline visualization
CERT_EXPIRY_BUCKETS = {
    'bucket_0_30_days': (0, 30),           # Expiring soon - alert
    'bucket_31_60_days': (31, 60),         # Expiring soon - caution
    'bucket_61_90_days': (61, 90),         # Expiring - plan renewal
    'bucket_greater_90_days': (91, 36500), # Safe - no action
}

# ---------------------------------------------------------------------------
# Digital Label Classification (Feature: Asset Labels)
# ---------------------------------------------------------------------------
# Asset classification labels based on PQC score + findings + enterprise score
# Used in inventory and home dashboards

DIGITAL_LABELS_CONFIG = {
    'Quantum-Safe': {
        'description': 'Fully quantum-safe with no critical findings',
        'min_pqc_score': 90,
        'max_critical_findings': 0,
        'confidence_weight': 1.0,
    },
    'PQC Ready': {
        'description': 'Post-quantum cryptography ready, minimal findings',
        'min_pqc_score': 70,
        'max_findings': 3,
        'max_critical_findings': 0,
        'confidence_weight': 0.8,
    },
    'Fully Quantum Safe': {
        'description': 'Quantum-safe with zero findings and high enterprise score',
        'min_pqc_score': 90,
        'max_findings': 0,
        'max_critical_findings': 0,
        'min_enterprise_score': 700,
        'confidence_weight': 1.0,
    },
    'At Risk': {
        'description': 'Non-compliant with PQC standards or contains critical findings',
        'max_pqc_score': 40,
        'min_critical_findings': 1,
        'confidence_weight': 0.9,
    },
}

# ---------------------------------------------------------------------------
# Finding Severity Mapping (Math Section 5.1 - Findings & Issues)
# ---------------------------------------------------------------------------
# Maps issue types to default severity levels
FINDING_SEVERITY_MAP = {
    'weak_tls_version': 'high',             # TLS < 1.2
    'weak_cipher': 'high',                  # Deprecated ciphers (SSLv3, RC4, etc.)
    'weak_key_length': 'high',              # Key < WEAK_KEY_LENGTH_BITS
    'expiring_certificate': 'medium',       # Expires within EXPIRING_CERT_THRESHOLD
    'expired_certificate': 'critical',      # Already expired
    'self_signed_cert': 'medium',           # Public endpoint with self-signed cert
    'mismatched_hostname': 'high',          # Cert CN doesn't match domain
    'weak_signature_algorithm': 'medium',   # MD5, SHA1 signatures
}

# ---------------------------------------------------------------------------
# Dashboard Metric Refresh Intervals (Background Jobs)
# ---------------------------------------------------------------------------
# How often to refresh various summary metrics (in hours)
ORG_PQC_METRICS_REFRESH_HOURS = int(os.environ.get('ORG_METRICS_REFRESH_HOURS', '24'))  # Daily snapshot
CERT_EXPIRY_BUCKETS_REFRESH_HOURS = int(os.environ.get('CERT_EXPIRY_REFRESH_HOURS', '24'))  # Daily
ASSET_METRICS_REFRESH_POST_SCAN = os.environ.get('ASSET_METRICS_REFRESH_POST_SCAN', 'true').lower() == 'true'  # After each scan
DIGITAL_LABELS_REFRESH_POST_SCAN = os.environ.get('DIGITAL_LABELS_REFRESH_POST_SCAN', 'true').lower() == 'true'  # After each scan

# ---------------------------------------------------------------------------
# API Response Configuration
# ---------------------------------------------------------------------------
# Pagination defaults for dashboard APIs
DEFAULT_PAGE_SIZE = int(os.environ.get('DEFAULT_PAGE_SIZE', '50'))
MAX_PAGE_SIZE = int(os.environ.get('MAX_PAGE_SIZE', '500'))

# Trend chart history depth (days)
TREND_HISTORY_DAYS = int(os.environ.get('TREND_HISTORY_DAYS', '90'))
