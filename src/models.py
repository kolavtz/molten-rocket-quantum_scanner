# pyre-ignore-all-errors
from sqlalchemy import Column, Integer, BigInteger, String, Boolean, DateTime, ForeignKey, Float, Text, event, Enum, Date, Numeric
from sqlalchemy.types import TypeDecorator
from sqlalchemy.orm import declarative_base, relationship, synonym
from sqlalchemy.sql import func
import datetime
import uuid

Base = declarative_base()

from sqlalchemy.ext.declarative import declared_attr


class DeletedByUserIdType(TypeDecorator):
    """Audit user id type that keeps UUID support and normalizes numeric values."""

    impl = String
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        text = str(value).strip()
        if text.isdigit():
            return int(text)
        return text

class SoftDeleteMixin:
    @declared_attr
    def is_deleted(cls):
        return Column(Boolean, default=False, nullable=False, index=True)

    @declared_attr
    def deleted_at(cls):
        return Column(DateTime, nullable=True)
    
    @declared_attr
    def deleted_by_user_id(cls):
        return Column(DeletedByUserIdType(), ForeignKey('users.id'), nullable=True)

class User(Base):
    __tablename__ = 'users'
    id = Column(String(36), primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    role = Column(String(50), default="Viewer")
    password_hash = Column(String(255), default='')

class Asset(Base, SoftDeleteMixin):
    __tablename__ = 'assets'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    asset_key = Column(String(255), unique=True, nullable=True, index=True)
    target = Column(String(255), nullable=False, unique=True, index=True)
    name = synonym('target')
    url = Column(String(255), nullable=True)
    ipv4 = Column(String(50), nullable=True)
    ipv6 = Column(String(50), nullable=True)
    asset_type = Column(String(50), nullable=False)
    owner = Column(String(100), nullable=True)
    risk_level = Column(String(50), nullable=True)
    notes = Column(Text, nullable=True)

    last_scan_id = Column(BigInteger, ForeignKey('scans.id', ondelete='SET NULL'), nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    discovery_domains = relationship("DiscoveryDomain", back_populates="asset", cascade="all, delete-orphan", passive_deletes=True)
    discovery_ssl = relationship("DiscoverySSL", back_populates="asset", cascade="all, delete-orphan", passive_deletes=True)
    discovery_ips = relationship("DiscoveryIP", back_populates="asset", cascade="all, delete-orphan", passive_deletes=True)
    discovery_software = relationship("DiscoverySoftware", back_populates="asset", cascade="all, delete-orphan", passive_deletes=True)
    certificates = relationship("Certificate", back_populates="asset", cascade="all, delete-orphan", passive_deletes=True)
    pqc_classifications = relationship("PQCClassification", back_populates="asset", cascade="all, delete-orphan", passive_deletes=True)
    cbom_entries = relationship("CBOMEntry", back_populates="asset", cascade="all, delete-orphan", passive_deletes=True)
    compliance_scores = relationship("ComplianceScore", back_populates="asset", cascade="all, delete-orphan", passive_deletes=True)


@event.listens_for(Asset, "before_insert")
def _asset_before_insert(_mapper, _connection, target):
    canonical = str(getattr(target, "target", "") or "").strip().lower()
    if canonical and not str(getattr(target, "asset_key", "") or "").strip():
        target.asset_key = canonical
    elif not str(getattr(target, "asset_key", "") or "").strip():
        target.asset_key = f"asset-{uuid.uuid4().hex}"

class Scan(Base, SoftDeleteMixin):
    __tablename__ = 'scans'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    scan_uid = Column(String(36), unique=True, nullable=True, index=True)
    scan_id = Column(String(36), unique=True, nullable=False, index=True)
    requested_target = Column(String(512), nullable=True)
    normalized_target = Column(String(512), nullable=True, index=True)
    target = Column(String(255), nullable=False, index=True)
    asset_class = Column(String(64), nullable=True)
    status = Column(String(50), nullable=False)
    scan_kind = Column(String(32), nullable=True)
    initiated_by = Column(String(36), nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    scanned_at = Column(DateTime, nullable=True)
    total_assets = Column(Integer, default=0)
    compliance_score = Column(Integer, default=0)
    overall_pqc_score = Column(Float, nullable=True)
    quantum_safe = Column(Integer, default=0)
    quantum_vuln = Column(Integer, default=0)
    cbom_path = Column(String(500), nullable=True)
    add_to_inventory = Column(Boolean, default=False, nullable=False)
    error_message = Column(Text, nullable=True)
    report_json = Column(Text, nullable=False)
    is_encrypted = Column(Boolean, default=False)
    total_discovered = Column(Integer, default=0)
    total_promoted = Column(Integer, default=0)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    deleted_by = Column(String(36), nullable=True)
    # Tracing & versioning (Sprint 1)
    correlation_id = Column(String(36), nullable=True, index=True)
    scanner_version = Column(String(50), nullable=True)
    
    # Relationships
    cbom_summary = relationship("CBOMSummary", back_populates="scan", uselist=False, cascade="all, delete-orphan", passive_deletes=True)
    discovery_domains = relationship("DiscoveryDomain", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)
    discovery_ssl = relationship("DiscoverySSL", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)
    discovery_ips = relationship("DiscoveryIP", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)
    discovery_software = relationship("DiscoverySoftware", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)
    cbom_entries = relationship("CBOMEntry", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)
    certificates = relationship("Certificate", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)
    pqc_classifications = relationship("PQCClassification", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)


def _normalize_scan_status(value):
    text = str(value or "").strip().lower()
    aliases = {
        "completed": "complete",
        "in_progress": "running",
        "in-progress": "running",
    }
    return aliases.get(text, text or "queued")


@event.listens_for(Scan, "before_insert")
@event.listens_for(Scan, "before_update")
def _scan_before_save(_mapper, _connection, target):
    scan_id = str(getattr(target, "scan_id", "") or "").strip()
    scan_uid = str(getattr(target, "scan_uid", "") or "").strip()
    canonical_scan_id = scan_id or scan_uid or f"scan-{uuid.uuid4().hex[:12]}"
    target.scan_id = canonical_scan_id
    target.scan_uid = canonical_scan_id

    requested_target = str(getattr(target, "requested_target", "") or "").strip()
    canonical_target = str(getattr(target, "target", "") or requested_target).strip()
    target.target = canonical_target
    target.requested_target = requested_target or canonical_target
    target.normalized_target = str(getattr(target, "normalized_target", "") or canonical_target).strip().lower()
    target.status = _normalize_scan_status(getattr(target, "status", None))
    target.scan_kind = str(getattr(target, "scan_kind", "") or "manual").strip().lower() or "manual"



class DiscoveryDomain(Base, SoftDeleteMixin):
    __tablename__ = 'discovery_domains'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    scan_id = Column(BigInteger, ForeignKey('scans.id', ondelete='CASCADE'), nullable=False)
    asset_id = Column(BigInteger, ForeignKey('assets.id', ondelete='SET NULL'), nullable=True)
    domain = Column(String(512), nullable=False)
    registrar = Column(String(255))
    registration_date = Column(Date)
    status = Column(Enum('new', 'confirmed', 'ignored', 'false_positive'), default='new')
    promoted_to_inventory = Column(Boolean, default=False)
    promoted_at = Column(DateTime)
    promoted_by = Column(String(36), ForeignKey('users.id', ondelete='SET NULL'))

    asset = relationship("Asset", back_populates="discovery_domains")
    scan = relationship("Scan", back_populates="discovery_domains")

class DiscoverySSL(Base, SoftDeleteMixin):
    __tablename__ = 'discovery_ssl'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    scan_id = Column(BigInteger, ForeignKey('scans.id', ondelete='CASCADE'), nullable=False)
    asset_id = Column(BigInteger, ForeignKey('assets.id', ondelete='SET NULL'), nullable=True)
    endpoint = Column(String(512), nullable=False)
    tls_version = Column(String(50))
    cipher_suite = Column(String(255))
    key_exchange = Column(String(120))
    key_length = Column(Integer)
    subject_cn = Column(String(255))
    issuer = Column(String(255))
    valid_until = Column(DateTime)
    pqc_score = Column(Float, nullable=True)
    pqc_assessment = Column(String(50), nullable=True, index=True)
    status = Column(Enum('new', 'confirmed', 'ignored', 'false_positive'), default='new')
    promoted_to_inventory = Column(Boolean, default=False)
    promoted_at = Column(DateTime)
    promoted_by = Column(String(36), ForeignKey('users.id', ondelete='SET NULL'))

    asset = relationship("Asset", back_populates="discovery_ssl")
    scan = relationship("Scan", back_populates="discovery_ssl")

class DiscoveryIP(Base, SoftDeleteMixin):
    __tablename__ = 'discovery_ips'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    scan_id = Column(BigInteger, ForeignKey('scans.id', ondelete='CASCADE'), nullable=False)
    asset_id = Column(BigInteger, ForeignKey('assets.id', ondelete='SET NULL'), nullable=True)
    ip_address = Column(String(80), nullable=False)
    subnet = Column(String(80))
    asn = Column(String(80))
    netname = Column(String(255))
    location = Column(String(255))
    status = Column(Enum('new', 'confirmed', 'ignored', 'false_positive'), default='new')
    promoted_to_inventory = Column(Boolean, default=False)
    promoted_at = Column(DateTime)
    promoted_by = Column(String(36), ForeignKey('users.id', ondelete='SET NULL'))

    asset = relationship("Asset", back_populates="discovery_ips")
    scan = relationship("Scan", back_populates="discovery_ips")

class DiscoverySoftware(Base, SoftDeleteMixin):
    __tablename__ = 'discovery_software'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    scan_id = Column(BigInteger, ForeignKey('scans.id', ondelete='CASCADE'), nullable=False)
    asset_id = Column(BigInteger, ForeignKey('assets.id', ondelete='SET NULL'), nullable=True)
    product = Column(String(255), nullable=False)
    version = Column(String(120))
    category = Column(String(80))
    cpe = Column(String(255))
    status = Column(Enum('new', 'confirmed', 'ignored', 'false_positive'), default='new')
    promoted_to_inventory = Column(Boolean, default=False)
    promoted_at = Column(DateTime)
    promoted_by = Column(String(36), ForeignKey('users.id', ondelete='SET NULL'))

    asset = relationship("Asset", back_populates="discovery_software")
    scan = relationship("Scan", back_populates="discovery_software")

class Certificate(Base, SoftDeleteMixin):
    __tablename__ = 'certificates'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    asset_id = Column(BigInteger, ForeignKey('assets.id', ondelete='CASCADE'), nullable=False, index=True)
    scan_id = Column(BigInteger, ForeignKey('scans.id', ondelete='CASCADE'), nullable=False, index=True)
    endpoint = Column(String(512), nullable=True, index=True)
    port = Column(Integer, nullable=True)
    
    # Certificate identifying fields
    issuer = Column(String(500), nullable=True, index=True)
    subject = Column(String(500), nullable=True)
    subject_cn = Column(String(255), nullable=True, index=True)  # Common Name from subject
    subject_o = Column(String(255), nullable=True)
    subject_ou = Column(String(255), nullable=True)
    issuer_cn = Column(String(255), nullable=True, index=True)
    issuer_o = Column(String(255), nullable=True)
    issuer_ou = Column(String(255), nullable=True)
    serial = Column(String(255), nullable=True, index=True)  # NOT globally unique; wildcard certs share serial across assets
    company_name = Column(String(255), nullable=True, index=True)  # Organization name
    
    # Certificate validity
    valid_from = Column(DateTime, nullable=True)
    valid_until = Column(DateTime, nullable=True, index=True)
    expiry_days = Column(Integer, nullable=True)  # Days remaining (calculated on save)
    
    # Technical details
    fingerprint_sha256 = Column(String(64), nullable=True, index=True)  # NOT globally unique; index only
    fingerprint_sha1 = Column(String(40), nullable=True, index=True)
    fingerprint_md5 = Column(String(32), nullable=True, index=True)
    public_key_fingerprint_sha256 = Column(String(64), nullable=True, index=True)
    certificate_version = Column(String(50), nullable=True)
    certificate_format = Column(String(50), nullable=True)
    # For idempotent inserts we compute a SHA-256 of asset_id + ':' + dedup_value
    dedup_algorithm = Column(String(20), nullable=True)
    dedup_value = Column(String(128), nullable=True, index=True)
    dedup_hash = Column(String(64), nullable=True, index=True)
    tls_version = Column(String(50), nullable=True, index=True)
    key_length = Column(Integer, nullable=True)
    key_algorithm = Column(String(100), nullable=True)
    public_key_type = Column(String(100), nullable=True)
    public_key_pem = Column(Text, nullable=True)
    cipher_suite = Column(String(255), nullable=True)
    signature_algorithm = Column(String(100), nullable=True)
    ca = Column(String(255), nullable=True, index=True)
    ca_name = Column(String(255), nullable=True)
    san_domains = Column(Text, nullable=True)
    cert_chain_length = Column(Integer, nullable=True)
    
    # Status tracking
    is_self_signed = Column(Boolean, default=False)
    is_expired = Column(Boolean, default=False)
    # is_current: True = this is the latest certificate for the asset (only ONE per asset should be True)
    is_current = Column(Boolean, default=False, nullable=False, index=True)
    
    # Historical tracking (Sprint 1)
    first_seen_at = Column(DateTime, nullable=True)  # When this cert fingerprint was first captured
    last_seen_at = Column(DateTime, nullable=True)   # Updated each time the same fingerprint is re-observed
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    # Raw certificate details (JSON serialized X.509 information)
    certificate_details = Column(Text, nullable=True)
    
    # Relationships
    asset = relationship("Asset", back_populates="certificates")
    scan = relationship("Scan", back_populates="certificates")
    pqc_classifications = relationship("PQCClassification", back_populates="certificate", cascade="all, delete-orphan", passive_deletes=True)


class PQCClassification(Base, SoftDeleteMixin):
    __tablename__ = 'pqc_classification'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    certificate_id = Column(BigInteger, ForeignKey('certificates.id', ondelete='CASCADE'), nullable=True, index=True)
    asset_id = Column(BigInteger, ForeignKey('assets.id', ondelete='CASCADE'), nullable=False, index=True)
    scan_id = Column(BigInteger, ForeignKey('scans.id', ondelete='CASCADE'), nullable=False, index=True)
    
    # Algorithm classification
    algorithm_name = Column(String(100), nullable=True, index=True)
    algorithm_type = Column(String(100), nullable=True)  # symmetric, asymmetric, hash
    quantum_safe_status = Column(String(50), nullable=True, index=True)  # safe, unsafe, migration_advised
    nist_category = Column(String(50), nullable=True, index=True)  # NIST category (1-5 for quantum resistance)
    pqc_score = Column(Float, nullable=True)  # 0-100 score
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    asset = relationship("Asset", back_populates="pqc_classifications")
    scan = relationship("Scan", back_populates="pqc_classifications")
    certificate = relationship("Certificate", back_populates="pqc_classifications")


class CBOMSummary(Base, SoftDeleteMixin):
    __tablename__ = 'cbom_summary'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    asset_id = Column(BigInteger, ForeignKey('assets.id', ondelete='CASCADE'), nullable=True, index=True)
    scan_id = Column(BigInteger, ForeignKey('scans.id', ondelete='CASCADE'), nullable=False, unique=True)
    total_components = Column(Integer, default=0)
    weak_crypto_count = Column(Integer, default=0)
    cert_issues_count = Column(Integer, default=0)
    json_path = Column(String(500))
    scan = relationship("Scan", back_populates="cbom_summary")

class CBOMEntry(Base, SoftDeleteMixin):
    __tablename__ = 'cbom_entries'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    scan_id = Column(BigInteger, ForeignKey('scans.id', ondelete='CASCADE'), nullable=False)
    asset_id = Column(BigInteger, ForeignKey('assets.id', ondelete='CASCADE'), nullable=True)
    algorithm_name = Column(String(100))
    category = Column(String(50))
    asset_type = Column(String(50), nullable=True, index=True)
    element_name = Column(String(255), nullable=True)
    primitive = Column(String(100), nullable=True)
    mode = Column(String(100), nullable=True)
    crypto_functions = Column(Text, nullable=True)
    classical_security_level = Column(Integer, nullable=True)
    oid = Column(String(255), nullable=True, index=True)
    element_list = Column(Text, nullable=True)

    key_id = Column(String(255), nullable=True)
    key_state = Column(String(50), nullable=True)
    key_size = Column(Integer, nullable=True)
    key_creation_date = Column(DateTime, nullable=True)
    key_activation_date = Column(DateTime, nullable=True)

    protocol_name = Column(String(100), nullable=True)
    protocol_version_name = Column(String(50), nullable=True)
    cipher_suites = Column(Text, nullable=True)

    subject_name = Column(String(500), nullable=True)
    issuer_name = Column(String(500), nullable=True)
    not_valid_before = Column(DateTime, nullable=True)
    not_valid_after = Column(DateTime, nullable=True)
    signature_algorithm_reference = Column(String(255), nullable=True)
    subject_public_key_reference = Column(String(255), nullable=True)
    certificate_format = Column(String(100), nullable=True)
    certificate_extension = Column(String(32), nullable=True)

    key_length = Column(Integer)
    protocol_version = Column(String(50))
    nist_status = Column(String(50))
    quantum_safe_flag = Column(Boolean, default=False)
    hndl_level = Column(String(50))
    asset = relationship("Asset", back_populates="cbom_entries")
    scan = relationship("Scan", back_populates="cbom_entries")

class ComplianceScore(Base, SoftDeleteMixin):
    __tablename__ = 'compliance_scores'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    asset_id = Column(BigInteger, ForeignKey('assets.id', ondelete='CASCADE'), nullable=False)
    scan_id = Column(BigInteger, ForeignKey('scans.id', ondelete='CASCADE'), nullable=False)
    score_type = Column("score_type", String(50)) # pqc, tls, overall
    type = synonym("score_type")
    score_value = Column(Float)
    tier = Column(String(50)) # elite, standard, legacy, critical
    asset = relationship("Asset", back_populates="compliance_scores")

class CyberRating(Base, SoftDeleteMixin):
    __tablename__ = 'cyber_rating'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    asset_id = Column(BigInteger, ForeignKey('assets.id', ondelete='CASCADE'), nullable=True, index=True)
    organization_id = synonym("asset_id")
    scan_id = Column(BigInteger, ForeignKey('scans.id', ondelete='CASCADE'), nullable=False)
    enterprise_score = Column(Float)
    rating_tier = Column(String(50))
    generated_at = Column(DateTime, default=func.now())


# ===============================================
# PHASE 1: NEW MODELS FOR MATH-BASED KPI SYSTEM
# ===============================================

class Finding(Base, SoftDeleteMixin):
    __tablename__ = 'findings'
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    finding_id = Column(String(36), unique=True, nullable=False, index=True)
    asset_id = Column(BigInteger, ForeignKey('assets.id', ondelete='CASCADE'), nullable=False, index=True)
    scan_id = Column(BigInteger, ForeignKey('scans.id', ondelete='CASCADE'), nullable=False, index=True)
    
    # Finding Classification
    issue_type = Column(String(100), nullable=False, index=True)  # weak_cipher, expiring_cert, etc.
    severity = Column(String(50), nullable=False, index=True)      # critical, high, medium, low
    description = Column(Text, nullable=False)
    
    # Context (JSON for flexibility)
    metadata_json = Column(Text, nullable=True)  # JSON-serialized metadata
    
    # Related Entities
    certificate_id = Column(BigInteger, ForeignKey('certificates.id', ondelete='SET NULL'), nullable=True)
    cbom_entry_id = Column(BigInteger, ForeignKey('cbom_entries.id', ondelete='SET NULL'), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    asset = relationship("Asset")
    scan = relationship("Scan")
    certificate = relationship("Certificate")


@event.listens_for(Finding, "before_insert")
def _finding_before_insert(_mapper, _connection, target):
    if not getattr(target, "finding_id", None):
        target.finding_id = f"finding-{uuid.uuid4().hex[:12]}"


class AssetMetric(Base):
    """
    Materialized view of asset-level KPIs.
    Based on Math Spec Sections 2, 3, 5 (PQC, Risk, Cyber Score).
    Refreshed after each scan or via batch job.
    """
    __tablename__ = 'asset_metrics'
    
    asset_id = Column(BigInteger, ForeignKey('assets.id', ondelete='CASCADE'), primary_key=True)
    
    # PQC Scoring (Math Section 3.1-3.2)
    pqc_score = Column(Float, default=0, nullable=False)           # 0-100, weighted average
    pqc_score_timestamp = Column(DateTime, nullable=True)
    
    # Risk Penalties (Math Section 5.1)
    risk_penalty = Column(Float, default=0, nullable=False)        # Σ(severity × weight)
    total_findings_count = Column(Integer, default=0)
    critical_findings_count = Column(Integer, default=0)
    
    # Classification & Labeling (Math Section 3.3)
    pqc_class_tier = Column(String(50), nullable=True, index=True)  # Elite, Standard, Legacy, Critical
    digital_label = Column(String(50), nullable=True, index=True)   # Quantum-Safe, PQC Ready, etc.
    has_critical_findings = Column(Boolean, default=False)
    
    # Asset-level Cyber Score (Math Section 5.2)
    asset_cyber_score = Column(Float, default=0)                   # max(0, pqc_score - penalty)
    
    # Timestamps
    calculated_at = Column(DateTime, default=func.now())
    last_updated = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Foreign Keys and Relationships
    asset = relationship("Asset")


class OrgPQCMetric(Base):
    """
    Daily snapshot of organization-wide PQC metrics.
    Based on Math Spec Section 7.1 (Home Dashboard KPIs).
    Populated by daily batch job for trend analysis.
    """
    __tablename__ = 'org_pqc_metrics'
    
    id = Column(BigInteger, primary_key=True)
    metric_date = Column(DateTime, nullable=False, unique=True, index=True)
    
    # Counts (Math Section 2.1)
    total_assets = Column(Integer, default=0)
    total_endpoints = Column(Integer, default=0)
    total_certificates = Column(Integer, default=0)
    
    # PQC Distribution (Math Section 3.4)
    elite_assets_count = Column(Integer, default=0)
    standard_assets_count = Column(Integer, default=0)
    legacy_assets_count = Column(Integer, default=0)
    critical_assets_count = Column(Integer, default=0)
    
    # Percentages (Math Section 2.2)
    pct_elite = Column(Float, default=0)
    pct_standard = Column(Float, default=0)
    pct_legacy = Column(Float, default=0)
    pct_critical = Column(Float, default=0)
    
    # Aggregate Scores
    avg_pqc_score = Column(Float, default=0)
    min_pqc_score = Column(Float, default=0)
    max_pqc_score = Column(Float, default=0)
    
    # Findings Summary
    total_findings_count = Column(Integer, default=0)
    total_critical_findings = Column(Integer, default=0)
    total_high_findings = Column(Integer, default=0)
    total_medium_findings = Column(Integer, default=0)
    total_low_findings = Column(Integer, default=0)
    
    # Quantum-Safe Status
    quantum_safe_assets_count = Column(Integer, default=0)
    quantum_safe_pct = Column(Float, default=0)
    vulnerable_assets_count = Column(Integer, default=0)
    vulnerable_pct = Column(Float, default=0)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())


class CertExpiryBucket(Base):
    """
    Summary of certificate expiry distribution.
    Based on Math Spec Section 2.5 (Cert Expiry Buckets).
    Supports expiry timeline charts: 0-30, 31-60, 61-90, >90 days.
    """
    __tablename__ = 'cert_expiry_buckets'
    
    id = Column(BigInteger, primary_key=True)
    bucket_date = Column(DateTime, nullable=False, unique=True, index=True)
    
    # Expiry Bucket Counts (Math Section 2.5)
    count_0_to_30_days = Column(Integer, default=0)      # Expiring soon
    count_31_to_60_days = Column(Integer, default=0)
    count_61_to_90_days = Column(Integer, default=0)
    count_greater_90_days = Column(Integer, default=0)
    count_expired = Column(Integer, default=0)
    
    # Summary
    total_active_certs = Column(Integer, default=0)
    total_expired_certs = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())


class TLSComplianceScore(Base):
    """
    TLS-specific compliance metrics per asset.
    Based on Math Spec Section 4 (CBOM Metrics).
    Tracks weak cipher/TLS versions and calculates TLS compliance score.
    """
    __tablename__ = 'tls_compliance_scores'
    
    asset_id = Column(BigInteger, ForeignKey('assets.id', ondelete='CASCADE'), primary_key=True)
    
    # TLS Score (0-100)
    tls_score = Column(Float, default=0, nullable=False)
    
    # Breakdown (JSON for flexibility)
    score_breakdown_json = Column(Text, nullable=True)  # {weak_count, deprecated_count, good_count}
    
    # Weak Elements Counts
    weak_tls_version_count = Column(Integer, default=0)    # TLS < 1.2
    weak_cipher_count = Column(Integer, default=0)         # Deprecated
    weak_key_length_count = Column(Integer, default=0)     # Key < threshold
    
    # Summary
    total_endpoints_scanned = Column(Integer, default=0)
    
    # Timestamps
    calculated_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Foreign Keys
    asset = relationship("Asset")


class DigitalLabel(Base):
    """
    Digital label classification per asset.
    Based on Feature Requirement: "Digital Labels" (Quantum-Safe, PQC Ready, Fully Quantum Safe).
    Denormalized for fast dashboard lookup and filtering.
    """
    __tablename__ = 'digital_labels'
    
    asset_id = Column(BigInteger, ForeignKey('assets.id', ondelete='CASCADE'), primary_key=True)
    
    # Label Classification
    label = Column(String(100), nullable=False, index=True)  # Quantum-Safe, PQC Ready, Fully Quantum Safe, At Risk
    label_reason_json = Column(Text, nullable=True)          # {reason, confidence_score, thresholds}
    confidence_score = Column(Integer, default=0)            # 0-100, confidence in label
    
    # Label Derivation Info
    based_on_pqc_score = Column(Float, default=0)
    based_on_finding_count = Column(Integer, default=0)
    based_on_critical_findings = Column(Boolean, default=False)
    based_on_enterprise_score = Column(Float, default=0)
    
    # Timestamps
    label_generated_at = Column(DateTime, default=func.now())
    label_updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Foreign Keys
    asset = relationship("Asset")


# =============================================================================
# SPRINT 1: CBOM HARDENING MODELS
# =============================================================================

class DomainCurrentState(Base):
    """
    Canonical pointer to the latest-known-good state per monitored asset/domain.

    Rules:
    - Exactly ONE row per asset. Created on first successful scan.
    - Updated atomically after each successful SSL/TLS ingestion.
    - If a scan fails, freshness_status is set to 'degraded' but existing
      ssl/tls pointers are NOT cleared (last-good-data principle).
    - Never deleted; instead set freshness_status = 'stale' if asset is removed.
    """
    __tablename__ = 'domain_current_state'

    asset_id = Column(BigInteger, ForeignKey('assets.id', ondelete='CASCADE'), primary_key=True)
    latest_scan_id = Column(BigInteger, ForeignKey('scans.id', ondelete='SET NULL'), nullable=True)
    current_ssl_certificate_id = Column(BigInteger, ForeignKey('certificates.id', ondelete='SET NULL'), nullable=True)

    # Risk aggregates (denormalized for fast dashboard reads)
    current_risk_score = Column(Float, default=0.0, nullable=False)
    current_risk_level = Column(String(50), nullable=True)   # Low / Medium / High / Critical

    # Scan health tracking
    last_successful_scan_at = Column(DateTime, nullable=True)
    last_failed_scan_at = Column(DateTime, nullable=True)
    last_rendered_at = Column(DateTime, nullable=True)

    # Freshness tracking
    # 'fresh'    = last scan succeeded within expected interval
    # 'stale'    = last scan is older than expected interval but succeeded
    # 'degraded' = last scan failed; showing stale data
    freshness_status = Column(String(20), default='fresh', nullable=False, index=True)
    render_status = Column(String(20), nullable=True)  # 'ok' | 'error' | 'partial'
    render_error_message = Column(Text, nullable=True)

    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    # Relationships
    asset = relationship("Asset")
    latest_scan = relationship("Scan", foreign_keys=[latest_scan_id])
    current_ssl_certificate = relationship("Certificate", foreign_keys=[current_ssl_certificate_id])


class AssetSSLProfile(Base, SoftDeleteMixin):
    """
    Historical snapshot of TLS/SSL configuration per scan.

    One row per scan. The row with is_current=True is the latest profile.
    Historical rows are NEVER overwritten; use is_current to distinguish.
    """
    __tablename__ = 'asset_ssl_profiles'

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    asset_id = Column(BigInteger, ForeignKey('assets.id', ondelete='CASCADE'), nullable=False, index=True)
    scan_id = Column(BigInteger, ForeignKey('scans.id', ondelete='CASCADE'), nullable=False, index=True)

    # TLS version support (probed at scan time)
    supports_tls_1_0 = Column(Boolean, default=False, nullable=False)
    supports_tls_1_1 = Column(Boolean, default=False, nullable=False)
    supports_tls_1_2 = Column(Boolean, default=True, nullable=False)
    supports_tls_1_3 = Column(Boolean, default=False, nullable=False)

    # Cipher & key exchange
    preferred_cipher = Column(String(255), nullable=True)
    cipher_list_json = Column(Text, nullable=True)   # JSON array of observed cipher suites
    weak_cipher_count = Column(Integer, default=0)
    insecure_protocol_count = Column(Integer, default=0)  # TLS < 1.2 count

    # Security headers
    hsts_enabled = Column(Boolean, default=False, nullable=False)
    hsts_max_age = Column(Integer, nullable=True)

    # Current-state flag (only ONE per asset should be True)
    is_current = Column(Boolean, default=False, nullable=False, index=True)

    # Historical tracking
    first_seen_at = Column(DateTime, nullable=True)
    last_seen_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now())

    # Relationships
    asset = relationship("Asset")
    scan = relationship("Scan")


class DomainEvent(Base):
    """
    Immutable append-only audit log for per-domain security events.

    Events are NEVER updated or deleted. They form an ordered timeline.
    Populated by SSLCaptureService and CurrentStateService.
    """
    __tablename__ = 'domain_events'

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    asset_id = Column(BigInteger, ForeignKey('assets.id', ondelete='CASCADE'), nullable=False, index=True)
    scan_id = Column(BigInteger, ForeignKey('scans.id', ondelete='SET NULL'), nullable=True)

    # Event classification
    # Examples: cert_renewed, cert_expired, cert_expiring_soon, issuer_changed,
    #           tls_version_added, tls_version_removed, risk_score_changed,
    #           scan_failed, scan_succeeded, weak_cipher_detected
    event_type = Column(String(80), nullable=False, index=True)
    event_title = Column(String(255), nullable=False)
    event_description = Column(Text, nullable=True)

    # Change data capture (JSON)
    old_value_json = Column(Text, nullable=True)   # Previous state snapshot
    new_value_json = Column(Text, nullable=True)   # New state snapshot

    # Severity for timeline UI coloring
    severity = Column(String(20), nullable=True, index=True)  # info / warning / critical

    # Tracing
    correlation_id = Column(String(36), nullable=True, index=True)

    created_at = Column(DateTime, default=func.now(), index=True)

    # Relationships
    asset = relationship("Asset")
    scan = relationship("Scan", foreign_keys=[scan_id])
