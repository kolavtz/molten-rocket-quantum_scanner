"""
API Home Dashboard - /api/home/metrics endpoint
Returns KPIs for the home dashboard.
"""

from flask import Blueprint, request, jsonify
from flask_login import login_required
from src.db import SessionLocal
from src.models import Asset, Scan
from utils.api_helper import (
    paginated_response, api_response, apply_soft_delete_filter,
    extract_pagination_params, validate_pagination_params
)
from sqlalchemy import func

api_home = Blueprint("api_home", __name__, url_prefix="/api/home")


@api_home.route("/metrics", methods=["GET"])
@login_required
def get_home_metrics():
    """
    GET /api/home/metrics
    Returns KPIs for the home dashboard.
    
    Response:
    {
        "success": true,
        "data": {
            "kpis": {
                "total_assets": 150,
                "total_scans": 42,
                "quantum_safe_pct": 78.5,
                "vulnerable_assets": 23,
                "avg_pqc_score": 82.3
            }
        }
    }
    """
    try:
        db = SessionLocal()
        
        # Count total assets (not deleted)
        total_assets = db.query(func.count(Asset.id)).filter(
            Asset.is_deleted == False
        ).scalar() or 0
        
        # Count total scans (not deleted)
        total_scans = db.query(func.count(Scan.id)).filter(
            Scan.is_deleted == False
        ).scalar() or 0
        
        # Calculate quantum safe percentage (using overall_pqc_score > 70 as proxy for quantum safe)
        quantum_safe_count = db.query(func.count(Scan.id)).filter(
            Scan.is_deleted == False,
            Scan.overall_pqc_score >= 70
        ).scalar() or 0
        
        quantum_safe_pct = (quantum_safe_count / total_scans * 100) if total_scans > 0 else 0
        
        # Count vulnerable assets (risk_level = 'High' or 'Critical')
        vulnerable_count = db.query(func.count(Asset.id)).filter(
            Asset.is_deleted == False,
            Asset.risk_level.in_(["High", "Critical"])
        ).scalar() or 0
        
        # Average PQC score across scans
        avg_pqc_score = db.query(func.avg(Scan.overall_pqc_score)).filter(
            Scan.is_deleted == False
        ).scalar() or 0
        
        if avg_pqc_score:
            avg_pqc_score = round(float(avg_pqc_score), 1)
        
        kpis = {
            "total_assets": int(total_assets),
            "total_scans": int(total_scans),
            "quantum_safe_pct": round(float(quantum_safe_pct), 1),
            "vulnerable_assets": int(vulnerable_count),
            "avg_pqc_score": avg_pqc_score
        }
        
        db.close()
        
        return jsonify({
            "success": True,
            "data": {
                "kpis": kpis
            }
        }), 200
    
    except Exception as e:
        return api_response(success=False, message=str(e), status_code=500)
