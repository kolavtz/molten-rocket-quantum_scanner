# pyre-ignore-all-errors
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Float, Text
from sqlalchemy.types import TypeDecorator
from sqlalchemy.orm import declarative_base, relationship, synonym
from sqlalchemy.sql import func
import datetime

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
        return Column(DeletedByUserIdType(length=128), ForeignKey('users.id'), nullable=True)

class User(Base):
    __tablename__ = 'users'
    id = Column(String(36), primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    role = Column(String(50), default="Viewer")

class Asset(Base, SoftDeleteMixin):
    __tablename__ = 'assets'
    id = Column(Integer, primary_key=True)
    target = Column(String(255), nullable=False, unique=True, index=True)
    name = synonym('target')
    url = Column(String(255), nullable=True)
    ipv4 = Column(String(50), nullable=True)
    ipv6 = Column(String(50), nullable=True)
    asset_type = Column(String(50), nullable=False)
    owner = Column(String(100), nullable=True)
    risk_level = Column(String(50), nullable=True)
    notes = Column(Text, nullable=True)

    last_scan_id = Column(Integer, ForeignKey('scans.id', ondelete='SET NULL'), nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    discovery_items = relationship("DiscoveryItem", back_populates="asset", cascade="all, delete-orphan", passive_deletes=True)
    certificates = relationship("Certificate", back_populates="asset", cascade="all, delete-orphan", passive_deletes=True)
    pqc_classifications = relationship("PQCClassification", back_populates="asset", cascade="all, delete-orphan", passive_deletes=True)
    cbom_entries = relationship("CBOMEntry", back_populates="asset", cascade="all, delete-orphan", passive_deletes=True)
    compliance_scores = relationship("ComplianceScore", back_populates="asset", cascade="all, delete-orphan", passive_deletes=True)

class Scan(Base, SoftDeleteMixin):
    __tablename__ = 'scans'
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(36), unique=True, nullable=False, index=True)
    target = Column(String(255), nullable=False, index=True)
    asset_class = Column(String(64), nullable=True)
    status = Column(String(50), nullable=False)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    scanned_at = Column(DateTime, nullable=True)
    total_assets = Column(Integer, default=0)
    compliance_score = Column(Integer, default=0)
    overall_pqc_score = Column(Float, nullable=True)
    quantum_safe = Column(Integer, default=0)
    quantum_vuln = Column(Integer, default=0)
    cbom_path = Column(String(500), nullable=True)
    report_json = Column(Text, nullable=False)
    is_encrypted = Column(Boolean, default=False)
    created_at = Column(DateTime, default=func.now())
    
    # Relationships
    cbom_summary = relationship("CBOMSummary", back_populates="scan", uselist=False, cascade="all, delete-orphan", passive_deletes=True)
    discovery_items = relationship("DiscoveryItem", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)
    cbom_entries = relationship("CBOMEntry", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)
    certificates = relationship("Certificate", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)
    pqc_classifications = relationship("PQCClassification", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)


class DiscoveryItem(Base, SoftDeleteMixin):
    __tablename__ = 'discovery_items'
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id', ondelete='CASCADE'), nullable=False)
    asset_id = Column(Integer, ForeignKey('assets.id', ondelete='CASCADE'), nullable=True)
    type = Column(String(50), nullable=False) # domain, ssl, ip, software
    status = Column(String(50), nullable=False) # new, confirmed, ignored, false_positive
    detection_date = Column(DateTime, default=func.now())
    # JSON or arbitrary fields can be mapped here or as EAV, but leaving structural context
    asset = relationship("Asset", back_populates="discovery_items")
    scan = relationship("Scan", back_populates="discovery_items")

class Certificate(Base, SoftDeleteMixin):
    __tablename__ = 'certificates'
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey('assets.id', ondelete='CASCADE'), nullable=False, index=True)
    scan_id = Column(Integer, ForeignKey('scans.id', ondelete='CASCADE'), nullable=False, index=True)
    
    # Certificate identifying fields
    issuer = Column(String(500), nullable=True, index=True)
    subject = Column(String(500), nullable=True)
    subject_cn = Column(String(255), nullable=True, index=True)  # Common Name from subject
    serial = Column(String(255), nullable=True, unique=True, index=True)
    company_name = Column(String(255), nullable=True, index=True)  # Organization name
    
    # Certificate validity
    valid_from = Column(DateTime, nullable=True)
    valid_until = Column(DateTime, nullable=True, index=True)
    expiry_days = Column(Integer, nullable=True)  # Days remaining (calculated on save)
    
    # Technical details
    fingerprint_sha256 = Column(String(64), nullable=True, unique=True, index=True)
    tls_version = Column(String(50), nullable=True, index=True)
    key_length = Column(Integer, nullable=True)
    key_algorithm = Column(String(100), nullable=True)
    cipher_suite = Column(String(255), nullable=True)
    signature_algorithm = Column(String(100), nullable=True)
    ca = Column(String(255), nullable=True, index=True)
    ca_name = Column(String(255), nullable=True)
    
    # Status tracking
    is_self_signed = Column(Boolean, default=False)
    is_expired = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    asset = relationship("Asset", back_populates="certificates")
    scan = relationship("Scan", back_populates="certificates")
    pqc_classifications = relationship("PQCClassification", back_populates="certificate", cascade="all, delete-orphan", passive_deletes=True)


class PQCClassification(Base, SoftDeleteMixin):
    __tablename__ = 'pqc_classification'
    id = Column(Integer, primary_key=True)
    certificate_id = Column(Integer, ForeignKey('certificates.id', ondelete='CASCADE'), nullable=True, index=True)
    asset_id = Column(Integer, ForeignKey('assets.id', ondelete='CASCADE'), nullable=False, index=True)
    scan_id = Column(Integer, ForeignKey('scans.id', ondelete='CASCADE'), nullable=False, index=True)
    
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
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id', ondelete='CASCADE'), nullable=False, unique=True)
    total_components = Column(Integer, default=0)
    weak_crypto_count = Column(Integer, default=0)
    cert_issues_count = Column(Integer, default=0)
    json_path = Column(String(500))
    scan = relationship("Scan", back_populates="cbom_summary")

class CBOMEntry(Base, SoftDeleteMixin):
    __tablename__ = 'cbom_entries'
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id', ondelete='CASCADE'), nullable=False)
    asset_id = Column(Integer, ForeignKey('assets.id', ondelete='CASCADE'), nullable=True)
    algorithm_name = Column(String(100))
    category = Column(String(50))
    key_length = Column(Integer)
    protocol_version = Column(String(50))
    nist_status = Column(String(50))
    quantum_safe_flag = Column(Boolean, default=False)
    hndl_level = Column(String(50))
    asset = relationship("Asset", back_populates="cbom_entries")
    scan = relationship("Scan", back_populates="cbom_entries")

class ComplianceScore(Base, SoftDeleteMixin):
    __tablename__ = 'compliance_scores'
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey('assets.id', ondelete='CASCADE'), nullable=False)
    scan_id = Column(Integer, ForeignKey('scans.id', ondelete='CASCADE'), nullable=False)
    type = Column(String(50)) # pqc, tls, overall
    score_value = Column(Float)
    tier = Column(String(50)) # elite, standard, legacy, critical
    asset = relationship("Asset", back_populates="compliance_scores")

class CyberRating(Base, SoftDeleteMixin):
    __tablename__ = 'cyber_rating'
    id = Column(Integer, primary_key=True)
    organization_id = Column(String(100))
    scan_id = Column(Integer, ForeignKey('scans.id', ondelete='CASCADE'), nullable=False)
    enterprise_score = Column(Float)
    rating_tier = Column(String(50))
    generated_at = Column(DateTime, default=func.now())
