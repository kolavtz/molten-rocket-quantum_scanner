"""
PQC Dashboard Query Helpers

Provides reusable SQLAlchemy query builders for Asset → Certificate → PQC dashboard analytics.
All queries filter by soft-delete flag (is_deleted=False) to exclude deleted records.

Example usage:
    assets = get_assets_with_certificate_details(asset_id_filter=None, limit=100)
    for asset in assets:
        print(asset.asset_name, asset.certificates)  # Access relationships
        
    pqc_data = get_pqc_classification_by_asset(asset_id=42)
    expiry_timeline = get_certificate_expiry_timeline()
    issuer_breakdown = get_issuer_breakdown()
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from sqlalchemy import func, and_, or_
from sqlalchemy.orm import Query

from src.db import db_session
from src.models import Asset, Certificate, PQCClassification, ComplianceScore


# ===============================================================================
# Asset + Certificate Joins (Main PQC Dashboard)
# ===============================================================================

def get_assets_with_certificate_details(
    asset_id_filter: Optional[int] = None,
    limit: int = 1000,
    include_expired: bool = False
) -> List[Tuple[Asset, Certificate, Optional[PQCClassification]]]:
    """
    Retrieve all assets with their latest certificates and PQC classifications.
    
    Joins:
        assets → certificates → pqc_classification
        
    Args:
        asset_id_filter: If provided, filter to one specific asset
        limit: Max results to return
        include_expired: If False, exclude expired certificates
        
    Returns:
        List of (Asset, Certificate, PQCClassification) tuples
        
    Query Plan:
        1. SELECT assets where is_deleted=False
        2. JOIN certificates where asset_id matches, is_deleted=False
        3. LEFT JOIN pqc_classification on certificate_id
    """
    query = db_session.query(
        Asset,
        Certificate,
        PQCClassification
    ).join(
        Certificate, and_(
            Asset.id == Certificate.asset_id,
            Certificate.is_deleted == False
        ),
        isouter=False
    ).outerjoin(
        PQCClassification, and_(
            Certificate.id == PQCClassification.certificate_id,
            PQCClassification.is_deleted == False
        )
    ).filter(
        Asset.is_deleted == False
    )
    
    if asset_id_filter:
        query = query.filter(Asset.id == asset_id_filter)
    
    if not include_expired:
        query = query.filter(
            or_(
                Certificate.valid_until >= func.now(),
                Certificate.valid_until.is_(None)
            )
        )
    
    return query.limit(limit).all()


def get_per_asset_certificate_table(asset_id: int) -> List[Dict]:
    """
    Get certificate details for one asset, formatted for dashboard table.
    
    Returns:
        List of dicts with certificate details:
        [
            {
                'common_name': 'example.com',
                'issuer': 'Let's Encrypt',
                'company_name': 'ACME Corp',
                'valid_until': datetime(2025, 12, 31),
                'expiry_days': 314,
                'tls_version': 'TLS 1.3',
                'key_length': 2048,
                'is_expired': False,
                'is_self_signed': False,
                'pqc_status': 'safe' | 'unsafe' | None,
                'pqc_score': 85.5
            }
        ]
    """
    certs = db_session.query(
        Certificate.subject_cn,
        Certificate.issuer,
        Certificate.company_name,
        Certificate.valid_until,
        Certificate.expiry_days,
        Certificate.tls_version,
        Certificate.key_length,
        Certificate.is_expired,
        Certificate.is_self_signed,
        PQCClassification.quantum_safe_status,
        PQCClassification.pqc_score
    ).filter(
        Certificate.asset_id == asset_id,
        Certificate.is_deleted == False
    ).outerjoin(
        PQCClassification,
        Certificate.id == PQCClassification.certificate_id
    ).all()
    
    result = []
    for cert in certs:
        result.append({
            'common_name': cert.subject_cn or 'N/A',
            'issuer': cert.issuer or 'N/A',
            'company_name': cert.company_name or 'N/A',
            'valid_until': cert.valid_until,
            'expiry_days': cert.expiry_days,
            'tls_version': cert.tls_version,
            'key_length': cert.key_length,
            'is_expired': cert.is_expired,
            'is_self_signed': cert.is_self_signed,
            'pqc_status': cert.quantum_safe_status,
            'pqc_score': cert.pqc_score
        })
    
    return result


# ===============================================================================
# Certificate Expiry Analysis
# ===============================================================================

def get_certificate_expiry_timeline() -> Dict[str, int]:
    """
    Calculate certificate expiry distribution across all active assets.
    
    Returns:
        {
            '0-30': 5,      # Expiring in 0-30 days
            '30-60': 12,    # Expiring in 30-60 days
            '60-90': 23,    # Expiring in 60-90 days
            '>90': 156      # Expiring in 90+ days
        }
    """
    now = datetime.utcnow()
    
    # 0-30 days
    count_0_30 = db_session.query(func.count(Certificate.id)).filter(
        Certificate.is_deleted == False,
        Certificate.valid_until >= now,
        Certificate.valid_until <= now + timedelta(days=30)
    ).scalar() or 0
    
    # 30-60 days
    count_30_60 = db_session.query(func.count(Certificate.id)).filter(
        Certificate.is_deleted == False,
        Certificate.valid_until > now + timedelta(days=30),
        Certificate.valid_until <= now + timedelta(days=60)
    ).scalar() or 0
    
    # 60-90 days
    count_60_90 = db_session.query(func.count(Certificate.id)).filter(
        Certificate.is_deleted == False,
        Certificate.valid_until > now + timedelta(days=60),
        Certificate.valid_until <= now + timedelta(days=90)
    ).scalar() or 0
    
    # >90 days
    count_over_90 = db_session.query(func.count(Certificate.id)).filter(
        Certificate.is_deleted == False,
        Certificate.valid_until > now + timedelta(days=90)
    ).scalar() or 0
    
    return {
        '0-30': int(count_0_30),
        '30-60': int(count_30_60),
        '60-90': int(count_60_90),
        '>90': int(count_over_90)
    }


# ===============================================================================
# Issuer + Company Breakdown
# ===============================================================================

def get_issuer_breakdown(limit: int = 20) -> List[Dict]:
    """
    Get certificate distribution by issuer (CA).
    
    Returns:
        [
            {'issuer': 'Let\'s Encrypt', 'count': 45},
            {'issuer': 'DigiCert', 'count': 12},
            ...
        ]
    """
    results = db_session.query(
        Certificate.issuer,
        func.count(Certificate.id).label('count')
    ).filter(
        Certificate.is_deleted == False
    ).group_by(
        Certificate.issuer
    ).order_by(
        func.count(Certificate.id).desc()
    ).limit(limit).all()
    
    return [
        {'issuer': r.issuer or 'Unknown', 'count': r.count}
        for r in results
    ]


def get_company_breakdown(limit: int = 20) -> List[Dict]:
    """
    Get certificate distribution by company (organization).
    
    Returns:
        [
            {'company': 'ACME Corp', 'count': 23},
            {'company': 'Tech Inc', 'count': 18},
            ...
        ]
    """
    results = db_session.query(
        Certificate.company_name,
        func.count(Certificate.id).label('count')
    ).filter(
        Certificate.is_deleted == False
    ).group_by(
        Certificate.company_name
    ).order_by(
        func.count(Certificate.id).desc()
    ).limit(limit).all()
    
    return [
        {'company': r.company_name or 'Unknown', 'count': r.count}
        for r in results
    ]


# ===============================================================================
# PQC Status Analysis
# ===============================================================================

def get_pqc_classification_by_asset(asset_id: int) -> List[Dict]:
    """
    Get all PQC classifications for one asset across all certificates.
    
    Returns:
        [
            {
                'algorithm_name': 'RSA',
                'quantum_safe_status': 'unsafe',
                'pqc_score': 45.0,
                'nist_category': '??',
                'certificate_cn': 'example.com'
            }
        ]
    """
    results = db_session.query(
        PQCClassification.algorithm_name,
        PQCClassification.quantum_safe_status,
        PQCClassification.pqc_score,
        PQCClassification.nist_category,
        Certificate.subject_cn
    ).filter(
        PQCClassification.asset_id == asset_id,
        PQCClassification.is_deleted == False
    ).outerjoin(
        Certificate,
        PQCClassification.certificate_id == Certificate.id
    ).all()
    
    return [
        {
            'algorithm_name': r.algorithm_name or 'Unknown',
            'quantum_safe_status': r.quantum_safe_status,
            'pqc_score': r.pqc_score,
            'nist_category': r.nist_category,
            'certificate_cn': r.subject_cn or 'N/A'
        }
        for r in results
    ]


def get_pqc_status_summary() -> Dict[str, int]:
    """
    Get enterprise-wide PQC algorithm safety distribution.
    
    Returns:
        {
            'safe': 127,
            'unsafe': 45,
            'migration_advised': 12,
            'unknown': 8
        }
    """
    results = db_session.query(
        PQCClassification.quantum_safe_status,
        func.count(PQCClassification.id).label('count')
    ).filter(
        PQCClassification.is_deleted == False
    ).group_by(
        PQCClassification.quantum_safe_status
    ).all()
    
    summary = {'safe': 0, 'unsafe': 0, 'migration_advised': 0, 'unknown': 0}
    for status, count in results:
        status_key = status.lower() if status else 'unknown'
        if status_key in summary:
            summary[status_key] = count
        else:
            summary['unknown'] += count
    
    return summary


def get_quantum_safe_percentage() -> float:
    """
    Calculate percentage of algorithms classified as quantum-safe.
    
    Returns:
        Float between 0.0 and 100.0
    """
    safe_count = db_session.query(func.count(PQCClassification.id)).filter(
        PQCClassification.is_deleted == False,
        PQCClassification.quantum_safe_status == 'safe'
    ).scalar() or 0
    
    total_count = db_session.query(func.count(PQCClassification.id)).filter(
        PQCClassification.is_deleted == False
    ).scalar() or 1  # Avoid division by zero
    
    if total_count == 0:
        return 0.0
    
    return (float(safe_count) / float(total_count)) * 100.0


# ===============================================================================
# TLS + Cryptographic Summary
# ===============================================================================

def get_tls_version_distribution() -> List[Dict]:
    """
    Get usage distribution of TLS versions.
    
    Returns:
        [
            {'version': 'TLS 1.3', 'count': 234},
            {'version': 'TLS 1.2', 'count': 112},
            ...
        ]
    """
    results = db_session.query(
        Certificate.tls_version,
        func.count(Certificate.id).label('count')
    ).filter(
        Certificate.is_deleted == False
    ).group_by(
        Certificate.tls_version
    ).order_by(
        func.count(Certificate.id).desc()
    ).all()
    
    return [
        {'version': r.tls_version or 'Unknown', 'count': r.count}
        for r in results
    ]


def get_key_length_distribution() -> List[Dict]:
    """
    Get distribution of RSA/DSA key lengths.
    
    Returns:
        [
            {'length': 4096, 'count': 23},
            {'length': 2048, 'count': 189},
            {'length': 1024, 'count': 3},
            ...
        ]
    """
    results = db_session.query(
        Certificate.key_length,
        func.count(Certificate.id).label('count')
    ).filter(
        Certificate.is_deleted == False,
        Certificate.key_length.isnot(None)
    ).group_by(
        Certificate.key_length
    ).order_by(
        Certificate.key_length.desc()
    ).all()
    
    return [
        {'length': r.key_length, 'count': r.count}
        for r in results
    ]


def get_self_signed_count() -> int:
    """Get count of self-signed certificates."""
    return db_session.query(func.count(Certificate.id)).filter(
        Certificate.is_deleted == False,
        Certificate.is_self_signed == True
    ).scalar() or 0


def get_expired_count() -> int:
    """Get count of expired certificates."""
    return db_session.query(func.count(Certificate.id)).filter(
        Certificate.is_deleted == False,
        Certificate.is_expired == True
    ).scalar() or 0


# ===============================================================================
# Dashboard Aggregation (All-in-One)
# ===============================================================================

def get_pqc_dashboard_aggregated_data() -> Dict:
    """
    Get all PQC dashboard data in one query batch (efficient for caching).
    
    Returns optimized dict for template rendering:
    {
        'kpis': {
            'total_assets': 42,
            'total_certificates': 87,
            'quantum_safe_percent': 65.4,
            'expired_count': 3,
            'self_signed_count': 7
        },
        'expiry_timeline': {'0-30': 5, '30-60': 12, '60-90': 23, '>90': 156},
        'issuer_breakdown': [{'issuer': '...', 'count': ...}, ...],
        'company_breakdown': [{'company': '...', 'count': ...}, ...],
        'pqc_status': {'safe': 127, 'unsafe': 45, ...},
        'tls_versions': [{'version': '...', 'count': ...}, ...],
        'key_lengths': [{'length': ..., 'count': ...}, ...],
        'assets_with_certs': [
            {
                'asset_id': 1,
                'asset_name': 'example.com',
                'certificate_count': 3,
                'has_expired': False,
                'quantum_safe_pct': 66.7
            },
            ...
        ]
    }
    """
    # Assets with certificate counts
    assets_with_cert_counts = db_session.query(
        Asset.id,
        Asset.target,
        func.count(Certificate.id).label('cert_count'),
        func.sum(
            func.if_(Certificate.is_expired == True, 1, 0)
        ).label('expired_count')
    ).outerjoin(
        Certificate,
        and_(Asset.id == Certificate.asset_id, Certificate.is_deleted == False)
    ).filter(
        Asset.is_deleted == False
    ).group_by(
        Asset.id,
        Asset.target
    ).all()
    
    assets_list = []
    for asset in assets_with_cert_counts:
        assets_list.append({
            'asset_id': asset.id,
            'asset_name': asset.target,
            'certificate_count': asset.cert_count or 0,
            'has_expired': (asset.expired_count or 0) > 0,
            'quantum_safe_pct': 0  # Updated per-asset via get_pqc_classification_by_asset
        })
    
    return {
        'kpis': {
            'total_assets': db_session.query(func.count(Asset.id)).filter(
                Asset.is_deleted == False
            ).scalar() or 0,
            'total_certificates': db_session.query(func.count(Certificate.id)).filter(
                Certificate.is_deleted == False
            ).scalar() or 0,
            'quantum_safe_percent': round(get_quantum_safe_percentage(), 1),
            'expired_count': get_expired_count(),
            'self_signed_count': get_self_signed_count()
        },
        'expiry_timeline': get_certificate_expiry_timeline(),
        'issuer_breakdown': get_issuer_breakdown(limit=15),
        'company_breakdown': get_company_breakdown(limit=15),
        'pqc_status': get_pqc_status_summary(),
        'tls_versions': get_tls_version_distribution(),
        'key_lengths': get_key_length_distribution(),
        'assets_with_certs': assets_list[:100]  # Top 100 assets
    }
