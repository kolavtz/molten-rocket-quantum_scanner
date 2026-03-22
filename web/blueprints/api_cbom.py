"""
API CBOM Dashboard - /api/cbom/* endpoints
Returns CBOM metrics and entries.
"""

from flask import Blueprint, request, jsonify
from flask_login import login_required
from src.db import SessionLocal
from src.models import CBOMEntry, Certificate, Asset
from utils.api_helper import (
    paginated_response, api_response, extract_pagination_params,
    validate_pagination_params, format_cbom_entry_row, format_datetime
)
from sqlalchemy import func

api_cbom = Blueprint("api_cbom", __name__, url_prefix="/api/cbom")


@api_cbom.route("/metrics", methods=["GET"])
@login_required
def get_cbom_metrics():
    """
    GET /api/cbom/metrics
    Returns CBOM KPIs.
    
    Response:
    {
        "success": true,
        "data": {
            "kpis": {
                "total_apps": 120,
                "sites_surveyed": 45,
                "total_certs": 156,
                "weak_crypto_count": 12,
                "cert_issues": 8
            }
        }
    }
    """
    try:
        db = SessionLocal()
        
        # Count total CBOM entries (as apps)
        total_apps = db.query(func.count(CBOMEntry.id)).filter(
            CBOMEntry.is_deleted == False
        ).scalar() or 0
        
        # Count unique assets (as sites surveyed)
        sites_surveyed = db.query(func.count(func.distinct(CBOMEntry.asset_id))).filter(
            CBOMEntry.is_deleted == False
        ).scalar() or 0
        
        # Count total certificates
        total_certs = db.query(func.count(Certificate.id)).filter(
            Certificate.is_deleted == False
        ).scalar() or 0
        
        # Count weak crypto (key_length < 2048)
        weak_crypto_count = db.query(func.count(CBOMEntry.id)).filter(
            CBOMEntry.is_deleted == False,
            CBOMEntry.key_length < 2048
        ).scalar() or 0
        
        # Count certificate issues (expired or self-signed)
        cert_issues = db.query(func.count(Certificate.id)).filter(
            Certificate.is_deleted == False,
            (Certificate.is_expired == True) | (Certificate.is_self_signed == True)
        ).scalar() or 0
        
        db.close()
        
        return api_response(
            success=True,
            data={
                "kpis": {
                    "total_apps": int(total_apps),
                    "sites_surveyed": int(sites_surveyed),
                    "total_certs": int(total_certs),
                    "weak_crypto_count": int(weak_crypto_count),
                    "cert_issues": int(cert_issues)
                }
            }
        )[0], 200
    
    except Exception as e:
        return api_response(success=False, message=str(e), status_code=500)[0], 500


@api_cbom.route("/entries", methods=["GET"])
@login_required
def get_cbom_entries():
    """
    GET /api/cbom/entries?page=1&page_size=25&sort=key_length&order=desc
    
    Returns CBOM entries (crypto algorithms and configurations).
    """
    try:
        db = SessionLocal()
        params = extract_pagination_params()
        page, page_size = validate_pagination_params(params["page"], params["page_size"])
        
        # Build query
        query = db.query(CBOMEntry).filter(CBOMEntry.is_deleted == False)
        
        # Get total
        total = query.count()
        
        # Apply sorting
        allowed_sorts = {
            "key_length": CBOMEntry.key_length,
            "algorithm_name": CBOMEntry.algorithm_name,
            "category": CBOMEntry.category,
            "nist_status": CBOMEntry.nist_status
        }
        
        sort_field = params["sort"] or "key_length"
        if sort_field in allowed_sorts:
            sort_col = allowed_sorts[sort_field]
            if params["order"].lower() == "desc":
                query = query.order_by(sort_col.desc())
            else:
                query = query.order_by(sort_col.asc())
        
        # Apply pagination
        offset = (page - 1) * page_size
        items = query.offset(offset).limit(page_size).all()
        
        # Format items
        items_data = [format_cbom_entry_row(entry) for entry in items]
        
        db.close()
        
        return paginated_response(
            items=items_data,
            total=total,
            page=page,
            page_size=page_size,
            filters={
                "sort": params["sort"] or "key_length",
                "order": params["order"],
                "search": params["search"]
            }
        )[0], 200
    
    except Exception as e:
        return api_response(success=False, message=str(e), status_code=500)[0], 500


@api_cbom.route("/summary", methods=["GET"])
@login_required
def get_cbom_summary():
    """
    GET /api/cbom/summary?scan_id=123
    
    Returns summary of CBOM for a specific scan.
    
    Query Parameters:
        scan_id (int): Scan ID
    """
    try:
        scan_id = request.args.get("scan_id", None, type=int)
        
        if not scan_id:
            return api_response(
                success=False,
                message="scan_id parameter required",
                status_code=400
            )[0], 400
        
        db = SessionLocal()
        
        # Get summary stats for this scan
        entries = db.query(CBOMEntry).filter(
            CBOMEntry.scan_id == scan_id,
            CBOMEntry.is_deleted == False
        ).all()
        
        weak_crypto = len([e for e in entries if e.key_length and e.key_length < 2048])
        total_algorithms = len(set([e.algorithm_name for e in entries]))
        
        summary = {
            "scan_id": scan_id,
            "total_entries": len(entries),
            "weak_crypto_count": weak_crypto,
            "unique_algorithms": total_algorithms,
            "entries": [format_cbom_entry_row(e) for e in entries[:50]]  # First 50
        }
        
        db.close()
        
        return api_response(success=True, data=summary)[0], 200
    
    except Exception as e:
        return api_response(success=False, message=str(e), status_code=500)[0], 500
