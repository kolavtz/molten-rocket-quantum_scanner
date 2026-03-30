"""
PQC Dashboard Routes

Flask routes for certificate and PQC posture dashboards.
Uses live MySQL queries via pqc_dashboard_queries helper module.

Endpoints:
- /pqc-posture - Main PQC posture dashboard (overview + timeline + breakdowns)
- /pqc-asset/<asset_id> - Per-asset certificate details and PQC classifications
- /api/pqc-dashboard - JSON API endpoint for dashboard data (caching-friendly)
"""

import logging
from datetime import datetime
from flask import Blueprint, render_template, request, jsonify, current_app
from functools import wraps
from typing import Optional

from src.db import db_session
from src.models import Asset, Certificate, PQCClassification, ComplianceScore
from src.services.pqc_dashboard_queries import (
    get_assets_with_certificate_details,
    get_per_asset_certificate_table,
    get_certificate_expiry_timeline,
    get_issuer_breakdown,
    get_company_breakdown,
    get_pqc_classification_by_asset,
    get_pqc_status_summary,
    get_quantum_safe_percentage,
    get_tls_version_distribution,
    get_key_length_distribution,
    get_self_signed_count,
    get_expired_count,
    get_pqc_dashboard_aggregated_data
)

logger = logging.getLogger(__name__)
pqc_bp = Blueprint('pqc', __name__, url_prefix='/pqc')


# ===============================================================================
# Helper Decorators & Utilities
# ===============================================================================

def login_required(f):
    """Simple login check (integrate with your auth system)."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check session or bearer token
        # For now, assume authenticated if accessed
        return f(*args, **kwargs)
    return decorated_function


def format_certificate_for_display(cert: Certificate, pqc: Optional[PQCClassification] = None) -> dict:
    """Convert Certificate model to display-ready dict."""
    return {
        'id': cert.id,
        'common_name': cert.subject_cn or 'Unknown',
        'issuer': cert.issuer or 'Unknown',
        'company': cert.company_name or 'Unknown',
        'valid_from': cert.valid_from.isoformat() if cert.valid_from is not None else None,
        'valid_until': cert.valid_until.isoformat() if cert.valid_until is not None else None,
        'expiry_days': cert.expiry_days,
        'days_remaining': (cert.valid_until - datetime.utcnow()).days if cert.valid_until is not None else None,
        'is_expired': cert.is_expired,
        'is_self_signed': cert.is_self_signed,
        'tls_version': cert.tls_version,
        'key_length': cert.key_length,
        'key_algorithm': cert.key_algorithm,
        'signature_algorithm': cert.signature_algorithm,
        'fingerprint_sha256': cert.fingerprint_sha256,
        'pqc_status': pqc.quantum_safe_status if pqc else None,
        'pqc_score': pqc.pqc_score if pqc else None,
        'algorithm_name': pqc.algorithm_name if pqc else None
    }


# ===============================================================================
# PQC Posture Dashboard (Main View)
# ===============================================================================

@pqc_bp.route('/posture', methods=['GET'])
@login_required
def pqc_posture_dashboard():
    """
    Main PQC posture dashboard view.
    
    Displays:
    - KPI cards: Total assets, total certs, quantum-safe %, expired count, self-signed count
    - Expiry timeline: 0-30, 30-60, 60-90, >90 days
    - Issuer breakdown: Top 15 CAs by certificate count
    - Company breakdown: Top 15 organizations by certificate count
    - PQC algorithm status: safe/unsafe/migration_advised distribution
    - TLS version distribution
    - Key length distribution
    - Asset list with certificate counts
    """
    try:
        # Get all dashboard data in one batch (efficient for caching)
        dashboard_data = get_pqc_dashboard_aggregated_data()
        
        vm = {
            'kpis': dashboard_data['kpis'],
            'expiry_timeline': dashboard_data['expiry_timeline'],
            'issuer_breakdown': dashboard_data['issuer_breakdown'],
            'company_breakdown': dashboard_data['company_breakdown'],
            'pqc_status': dashboard_data['pqc_status'],
            'tls_versions': dashboard_data['tls_versions'],
            'key_lengths': dashboard_data['key_lengths'],
            'assets': dashboard_data['assets_with_certs'],
            'empty': dashboard_data['kpis']['total_assets'] == 0,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        page_data = {
            'total_assets': dashboard_data['kpis']['total_assets'],
            'page': 1,
            'page_size': len(dashboard_data['assets_with_certs'])
        }
        
        return render_template('pqc_posture.html', vm=vm, page_data=page_data)
    
    except Exception as e:
        logger.error(f"PQC posture dashboard error: {e}", exc_info=True)
        # Graceful fallback with empty data
        vm = {
            'kpis': {
                'total_assets': 0,
                'total_certificates': 0,
                'quantum_safe_percent': 0.0,
                'expired_count': 0,
                'self_signed_count': 0
            },
            'expiry_timeline': {'0-30': 0, '30-60': 0, '60-90': 0, '>90': 0},
            'issuer_breakdown': [],
            'company_breakdown': [],
            'pqc_status': {'safe': 0, 'unsafe': 0, 'migration_advised': 0, 'unknown': 0},
            'tls_versions': [],
            'key_lengths': [],
            'assets': [],
            'empty': True,
            'error': 'Failed to load dashboard data'
        }
        return render_template('pqc_posture.html', vm=vm, page_data={})


# ===============================================================================
# Per-Asset Certificate Details
# ===============================================================================

@pqc_bp.route('/asset/<int:asset_id>', methods=['GET'])
@login_required
def pqc_asset_details(asset_id: int):
    """
    Certificate details and PQC classification for one specific asset.
    
    Displays:
    - Asset metadata (name, type, owner, risk level, last scan)
    - Certificate details table (CN, issuer, company, expiry, TLS version, key length)
    - PQC classifications per certificate (algorithm, status, score, NIST category)
    - Compliance score (if available)
    - Quick actions (rescan, export, add to report)
    """
    try:
        # Get asset
        asset = db_session.query(Asset).filter(
            Asset.id == asset_id,
            Asset.is_deleted == False
        ).first()
        
        if not asset:
            current_app.logger.warning(f"Asset {asset_id} not found or deleted")
            return render_template('pqc_asset_notfound.html', asset_id=asset_id), 404
        
        # Get certificates for this asset
        certificates = db_session.query(Certificate).filter(
            Certificate.asset_id == asset_id,
            Certificate.is_deleted == False
        ).order_by(Certificate.valid_until.desc()).all()
        
        # Get PQC classifications
        pqc_data = get_pqc_classification_by_asset(asset_id)
        
        # Get compliance score (if exists)
        compliance_score = db_session.query(ComplianceScore).filter(
            ComplianceScore.asset_id == asset_id,
            ComplianceScore.type.in_(['pqc', 'overall']),
            ComplianceScore.is_deleted == False
        ).order_by(ComplianceScore.created_at.desc()).first()
        
        # Format certificate list
        certificate_list = []
        pqc_by_cert_id = {pqc['certificate_cn']: pqc for pqc in pqc_data}
        
        for cert in certificates:
            formatted = format_certificate_for_display(cert)
            # Merge PQC data if available
            if cert.subject_cn in pqc_by_cert_id:
                formatted.update({
                    'pqc_status': pqc_by_cert_id[cert.subject_cn].get('quantum_safe_status'),
                    'pqc_score': pqc_by_cert_id[cert.subject_cn].get('pqc_score'),
                })
            certificate_list.append(formatted)
        
        vm = {
            'asset': {
                'id': asset.id,
                'name': asset.target or asset.name,
                'asset_type': asset.asset_type,
                'owner': asset.owner,
                'risk_level': asset.risk_level,
                'url': asset.url or asset.target,
                'created_at': asset.created_at.isoformat() if asset.created_at is not None else None,
                'updated_at': asset.updated_at.isoformat() if asset.updated_at is not None else None
            },
            'certificates': certificate_list,
            'pqc_summary': {
                'total_certs': len(certificate_list),
                'expired': sum(1 for c in certificate_list if c['is_expired']),
                'self_signed': sum(1 for c in certificate_list if c['is_self_signed']),
                'quantum_safe': sum(1 for c in certificate_list if c.get('pqc_status') == 'safe'),
                'avg_pqc_score': round(
                    sum(c['pqc_score'] or 0 for c in certificate_list) / len(certificate_list),
                    1
                ) if certificate_list else 0
            },
            'compliance_score': {
                'value': compliance_score.score_value if compliance_score else None,
                'tier': compliance_score.tier if compliance_score else None
            } if compliance_score else None,
            'empty': len(certificate_list) == 0
        }
        
        page_data = {'asset_id': asset_id}
        return render_template('pqc_asset_details.html', vm=vm, page_data=page_data)
    
    except Exception as e:
        logger.error(f"PQC asset details error for asset {asset_id}: {e}", exc_info=True)
        return render_template('error.html', error='Failed to load asset details'), 500


# ===============================================================================
# JSON API Endpoints (for AJAX/caching)
# ===============================================================================

@pqc_bp.route('/api/dashboard', methods=['GET'])
@login_required
def api_pqc_dashboard():
    """
    JSON API for PQC dashboard data.
    
    Caching-friendly endpoint for frontend SPA or dashboard widgets.
    
    Query params:
    - format=json|csv
    - assets_only=true|false - Return only asset list
    """
    try:
        format_type = request.args.get('format', 'json')
        assets_only = request.args.get('assets_only', 'false').lower() == 'true'
        
        dashboard_data = get_pqc_dashboard_aggregated_data()
        
        if assets_only:
            return jsonify({
                'success': True,
                'data': {
                    'assets': dashboard_data['assets_with_certs'],
                    'timestamp': datetime.utcnow().isoformat()
                }
            })
        
        return jsonify({
            'success': True,
            'data': dashboard_data,
            'timestamp': datetime.utcnow().isoformat()
        })
    
    except Exception as e:
        logger.error(f"PQC API dashboard error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@pqc_bp.route('/api/asset/<int:asset_id>/certificates', methods=['GET'])
@login_required
def api_asset_certificates(asset_id: int):
    """
    JSON API for asset certificate list (table-friendly format).
    
    Returns:
        {
            'success': True,
            'data': [
                {
                    'common_name': 'example.com',
                    'issuer': 'Let\'s Encrypt',
                    'valid_until': '2025-12-31T23:59:59',
                    'expiry_days': 314,
                    'is_expired': False,
                    'pqc_status': 'safe',
                    'pqc_score': 85.5
                }
            ]
        }
    """
    try:
        certs = get_per_asset_certificate_table(asset_id)
        
        # Convert datetime objects to ISO strings
        for cert in certs:
            if cert['valid_until']:
                cert['valid_until'] = cert['valid_until'].isoformat()
        
        return jsonify({
            'success': True,
            'data': certs,
            'timestamp': datetime.utcnow().isoformat()
        })
    
    except Exception as e:
        logger.error(f"PQC API certificate list error for asset {asset_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@pqc_bp.route('/api/expiry-timeline', methods=['GET'])
@login_required
def api_expiry_timeline():
    """JSON API for certificate expiry timeline."""
    try:
        timeline = get_certificate_expiry_timeline()
        return jsonify({'success': True, 'data': timeline})
    except Exception as e:
        logger.error(f"Expiry timeline API error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@pqc_bp.route('/api/issuer-breakdown', methods=['GET'])
@login_required
def api_issuer_breakdown():
    """JSON API for issuer breakdown (pie/bar chart data)."""
    try:
        breakdown = get_issuer_breakdown(limit=15)
        return jsonify({'success': True, 'data': breakdown})
    except Exception as e:
        logger.error(f"Issuer breakdown API error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@pqc_bp.route('/api/pqc-status', methods=['GET'])
@login_required
def api_pqc_status():
    """JSON API for PQC algorithm status summary."""
    try:
        status = get_pqc_status_summary()
        quantum_safe_pct = get_quantum_safe_percentage()
        return jsonify({
            'success': True,
            'data': {
                'status_distribution': status,
                'quantum_safe_percentage': round(quantum_safe_pct, 1)
            }
        })
    except Exception as e:
        logger.error(f"PQC status API error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ===============================================================================
# Route Registration
# ===============================================================================

def register_pqc_routes(app):
    """Register PQC blueprint with Flask app."""
    app.register_blueprint(pqc_bp)
    logger.info("PQC dashboard routes registered")
