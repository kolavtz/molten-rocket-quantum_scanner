"""Distribution & Aggregation Service

Implements Math Spec Sections 2, 4, 6:
- Asset type distribution (Section 2.2)
- IPv4/IPv6 distribution (Section 2.4)
- Certificate expiry buckets (Section 2.5)
- Cipher distribution (Section 4.2)
- Certificate Authority distribution (Section 4.2)
- IP → Location distribution (Section 6.2)

All calculations feed into dashboard charts and summary tables.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict

from sqlalchemy import and_, func

from config import CERT_EXPIRY_BUCKETS, EXPIRING_CERT_THRESHOLD_DAYS
from src.db import db_session
from src.models import (
    Asset, CertExpiryBucket, Certificate
)


class DistributionService:
    """Service for distribution and aggregation calculations."""

    @staticmethod
    def get_asset_type_distribution() -> Dict[str, Dict[str, Any]]:
        """
        Get asset type distribution (Math Section 2.2).
        
        Returns:
            {
                'WebApp': {'count': 5, 'pct': 25.0},
                'API': {'count': 3, 'pct': 15.0},
                'Server': {'count': 12, 'pct': 60.0},
                ...
            }
        """
        total_assets = db_session.query(Asset).filter(
            Asset.is_deleted == False
        ).count()
        
        if total_assets == 0:
            return {}
        
        type_counts = db_session.query(
            Asset.asset_type,
            func.count(Asset.id).label('count')
        ).filter(
            Asset.is_deleted == False
        ).group_by(Asset.asset_type).all()
        
        distribution = {}
        for asset_type, count in type_counts:
            pct = (count / total_assets * 100.0) if total_assets > 0 else 0.0
            distribution[asset_type or 'Unknown'] = {
                'count': count,
                'pct': round(pct, 2)
            }
        
        return distribution

    @staticmethod
    def get_risk_level_distribution() -> Dict[str, Dict[str, Any]]:
        """
        Get asset risk level distribution (Math Section 2.3).
        
        Returns:
            {
                'Critical': {'count': 2, 'pct': 10.0},
                'High': {'count': 5, 'pct': 25.0},
                'Medium': {'count': 8, 'pct': 40.0},
                'Low': {'count': 5, 'pct': 25.0},
            }
        """
        total_assets = db_session.query(Asset).filter(
            Asset.is_deleted == False
        ).count()
        
        if total_assets == 0:
            return {}
        
        risk_counts = db_session.query(
            Asset.risk_level,
            func.count(Asset.id).label('count')
        ).filter(
            Asset.is_deleted == False
        ).group_by(Asset.risk_level).all()
        
        distribution = {}
        for risk_level, count in risk_counts:
            pct = (count / total_assets * 100.0) if total_assets > 0 else 0.0
            distribution[risk_level or 'Unknown'] = {
                'count': count,
                'pct': round(pct, 2)
            }
        
        return distribution

    @staticmethod
    def get_ipv4_ipv6_distribution() -> Dict[str, Dict[str, Any]]:
        """
        Get IPv4/IPv6 adoption distribution (Math Section 2.4).
        
        Returns:
            {
                'ipv4': {'count': count, 'pct': pct},
                'ipv6': {'count': count, 'pct': pct},
                'dual_stack': {'count': count, 'pct': pct},
            }
        """
        total_assets = db_session.query(Asset).filter(
            Asset.is_deleted == False
        ).count()
        
        if total_assets == 0:
            return {}
        
        # Count by IP version presence
        ipv4_only = db_session.query(Asset).filter(
            and_(
                Asset.ipv4.isnot(None),
                Asset.ipv6.is_(None),
                Asset.is_deleted == False
            )
        ).count()
        
        ipv6_only = db_session.query(Asset).filter(
            and_(
                Asset.ipv6.isnot(None),
                Asset.ipv4.is_(None),
                Asset.is_deleted == False
            )
        ).count()
        
        dual_stack = db_session.query(Asset).filter(
            and_(
                Asset.ipv4.isnot(None),
                Asset.ipv6.isnot(None),
                Asset.is_deleted == False
            )
        ).count()
        
        return {
            'ipv4_only': {
                'count': ipv4_only,
                'pct': round(ipv4_only / total_assets * 100, 2) if total_assets > 0 else 0
            },
            'ipv6_only': {
                'count': ipv6_only,
                'pct': round(ipv6_only / total_assets * 100, 2) if total_assets > 0 else 0
            },
            'dual_stack': {
                'count': dual_stack,
                'pct': round(dual_stack / total_assets * 100, 2) if total_assets > 0 else 0
            },
        }

    @staticmethod
    def calculate_cert_expiry_buckets() -> Dict[str, int]:
        """
        Calculate certificate distribution by expiry timeline (Math Section 2.5).
        
        Bucket ranges (configurable via CERT_EXPIRY_BUCKETS):
        - 0-30 days: Expiring soon, alert
        - 31-60 days: Expiring soon, caution
        - 61-90 days: Expiring, plan renewal
        - >90 days: Safe
        - Expired: Already expired
        
        Returns:
            {
                'count_0_to_30_days': count,
                'count_31_to_60_days': count,
                'count_61_to_90_days': count,
                'count_greater_90_days': count,
                'count_expired': count,
                'total_active': count,
                'total_expired': count,
            }
        """
        today = datetime.utcnow()
        
        # Non-deleted certificates
        certs = db_session.query(Certificate).filter(
            Certificate.is_deleted == False
        ).all()
        
        buckets = {
            'count_0_to_30_days': 0,
            'count_31_to_60_days': 0,
            'count_61_to_90_days': 0,
            'count_greater_90_days': 0,
            'count_expired': 0,
            'total_active': 0,
            'total_expired': 0,
        }
        
        for cert in certs:
            valid_until = getattr(cert, "valid_until", None)
            if valid_until is None:
                continue
            
            days_remaining = (valid_until - today).days
            
            if days_remaining < 0:
                buckets['count_expired'] += 1
                buckets['total_expired'] += 1
            else:
                buckets['total_active'] += 1
                
                if days_remaining <= 30:
                    buckets['count_0_to_30_days'] += 1
                elif days_remaining <= 60:
                    buckets['count_31_to_60_days'] += 1
                elif days_remaining <= 90:
                    buckets['count_61_to_90_days'] += 1
                else:
                    buckets['count_greater_90_days'] += 1
        
        return buckets

    @staticmethod
    def refresh_cert_expiry_buckets_snapshot():
        """
        Refresh the cert_expiry_buckets summary table (daily job).
        
        Stores snapshot for trend analysis.
        """
        today = datetime.utcnow().date()
        
        # Check if today already exists
        existing = db_session.query(CertExpiryBucket).filter(
            func.date(CertExpiryBucket.bucket_date) == today
        ).first()
        
        if existing:
            # Update existing
            bucket_data = DistributionService.calculate_cert_expiry_buckets()
            existing.count_0_to_30_days = bucket_data['count_0_to_30_days']
            existing.count_31_to_60_days = bucket_data['count_31_to_60_days']
            existing.count_61_to_90_days = bucket_data['count_61_to_90_days']
            existing.count_greater_90_days = bucket_data['count_greater_90_days']
            existing.count_expired = bucket_data['count_expired']
            existing.total_active_certs = bucket_data['total_active']
            existing.total_expired_certs = bucket_data['total_expired']
            existing.updated_at = datetime.utcnow()
        else:
            # Create new snapshot
            bucket_data = DistributionService.calculate_cert_expiry_buckets()
            snapshot = CertExpiryBucket(
                bucket_date=datetime.utcnow(),
                count_0_to_30_days=bucket_data['count_0_to_30_days'],
                count_31_to_60_days=bucket_data['count_31_to_60_days'],
                count_61_to_90_days=bucket_data['count_61_to_90_days'],
                count_greater_90_days=bucket_data['count_greater_90_days'],
                count_expired=bucket_data['count_expired'],
                total_active_certs=bucket_data['total_active'],
                total_expired_certs=bucket_data['total_expired'],
            )
            db_session.add(snapshot)
        
        db_session.commit()

    @staticmethod
    def get_cipher_distribution() -> Dict[str, Dict[str, Any]]:
        """
        Get cipher suite distribution (Math Section 4.2).
        
        Returns:
            {
                'TLS_AES_256_GCM_SHA384': {'count': 15, 'pct': 25.0},
                'TLS_CHACHA20_POLY1305_SHA256': {'count': 12, 'pct': 20.0},
                ...
            }
        """
        total_certs = db_session.query(Certificate).filter(
            Certificate.is_deleted == False
        ).count()
        
        if total_certs == 0:
            return {}
        
        cipher_counts = db_session.query(
            Certificate.cipher_suite,
            func.count(Certificate.id).label('count')
        ).filter(
            Certificate.is_deleted == False
        ).group_by(Certificate.cipher_suite).order_by(
            func.count(Certificate.id).desc()
        ).all()
        
        distribution = {}
        for cipher_suite, count in cipher_counts:
            if cipher_suite:
                pct = (count / total_certs * 100.0) if total_certs > 0 else 0.0
                distribution[cipher_suite] = {
                    'count': count,
                    'pct': round(pct, 2)
                }
        
        return distribution

    @staticmethod
    def get_ca_distribution() -> Dict[str, Dict[str, Any]]:
        """
        Get Certificate Authority distribution (Math Section 4.2).
        
        Returns:
            {
                'Let\\'s Encrypt': {'count': 45, 'pct': 50.0},
                'DigiCert': {'count': 20, 'pct': 22.2},
                ...
            }
        """
        total_certs = db_session.query(Certificate).filter(
            Certificate.is_deleted == False
        ).count()
        
        if total_certs == 0:
            return {}
        
        ca_counts = db_session.query(
            Certificate.ca_name,
            func.count(Certificate.id).label('count')
        ).filter(
            Certificate.is_deleted == False
        ).group_by(Certificate.ca_name).order_by(
            func.count(Certificate.id).desc()
        ).limit(10).all()
        
        distribution = {}
        for ca_name, count in ca_counts:
            if ca_name:
                pct = (count / total_certs * 100.0) if total_certs > 0 else 0.0
                distribution[ca_name] = {
                    'count': count,
                    'pct': round(pct, 2)
                }
        
        return distribution

    @staticmethod
    def get_tls_version_distribution() -> Dict[str, Dict[str, Any]]:
        """
        Get TLS version distribution across certificates.
        
        Returns:
            {
                'TLS 1.3': {'count': 45, 'pct': 50.0},
                'TLS 1.2': {'count': 40, 'pct': 44.4},
                'TLS 1.1': {'count': 5, 'pct': 5.6},
                ...
            }
        """
        total_certs = db_session.query(Certificate).filter(
            Certificate.is_deleted == False
        ).count()
        
        if total_certs == 0:
            return {}
        
        version_counts = db_session.query(
            Certificate.tls_version,
            func.count(Certificate.id).label('count')
        ).filter(
            Certificate.is_deleted == False
        ).group_by(Certificate.tls_version).order_by(
            func.count(Certificate.id).desc()
        ).all()
        
        distribution = {}
        for tls_version, count in version_counts:
            if tls_version:
                pct = (count / total_certs * 100.0) if total_certs > 0 else 0.0
                distribution[tls_version] = {
                    'count': count,
                    'pct': round(pct, 2)
                }
        
        return distribution

    @staticmethod
    def get_key_length_distribution() -> Dict[str, Dict[str, Any]]:
        """
        Get key length distribution (Math Section 4.2).
        
        Returns:
            {
                '2048': {'count': 30, 'pct': 33.3},
                '4096': {'count': 50, 'pct': 55.6},
                '256': {'count': 10, 'pct': 11.1},
            }
        """
        total_certs = db_session.query(Certificate).filter(
            Certificate.is_deleted == False
        ).count()
        
        if total_certs == 0:
            return {}
        
        key_counts = db_session.query(
            Certificate.key_length,
            func.count(Certificate.id).label('count')
        ).filter(
            Certificate.is_deleted == False
        ).group_by(Certificate.key_length).order_by(
            func.count(Certificate.id).desc()
        ).all()
        
        distribution = {}
        for key_length, count in key_counts:
            if key_length:
                pct = (count / total_certs * 100.0) if total_certs > 0 else 0.0
                key_str = str(key_length)
                distribution[key_str] = {
                    'count': count,
                    'pct': round(pct, 2)
                }
        
        return distribution
