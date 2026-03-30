"""
API Reports - /api/reports/* endpoints
Returns scheduled and on-demand report information.
"""

from flask import Blueprint, request, jsonify
from flask_login import login_required
from src.db import db_session as SessionLocal
from src.models import Scan
from utils.api_helper import (
    api_response, paginated_response, extract_pagination_params,
    validate_pagination_params, format_datetime
)
from sqlalchemy import desc
from datetime import datetime

api_reports = Blueprint("api_reports", __name__, url_prefix="/api/reports")


@api_reports.route("/scheduled", methods=["GET"])
@login_required
def get_scheduled_reports():
    """
    GET /api/reports/scheduled?page=1&page_size=25
    
    Returns list of scheduled report configurations.
    
    Response:
    {
        "success": true,
        "data": {
            "items": [
                {
                    "id": 1,
                    "name": "Weekly PQC Report",
                    "frequency": "weekly",
                    "day_of_week": "Monday",
                    "time": "09:00",
                    "recipients": ["admin@example.com"],
                    "enabled": true,
                    "last_generated": "2026-03-22 09:00:00"
                }
            ],
            "total": 1,
            "page": 1,
            "page_size": 25,
            "total_pages": 1
        }
    }
    """
    try:
        params = extract_pagination_params()
        page, page_size = validate_pagination_params(params["page"], params["page_size"])
        
        # In a real implementation, this would query a reports_schedule table
        # For now, return mock data structure
        scheduled_reports = [
            {
                "id": 1,
                "name": "Weekly PQC Report",
                "frequency": "weekly",
                "day_of_week": "Monday",
                "time": "09:00",
                "recipients": ["admin@example.com"],
                "enabled": True,
                "last_generated": format_datetime(datetime.utcnow())
            },
            {
                "id": 2,
                "name": "Monthly Cyber Rating",
                "frequency": "monthly",
                "day_of_month": 1,
                "time": "00:00",
                "recipients": ["ciso@example.com", "admin@example.com"],
                "enabled": True,
                "last_generated": format_datetime(datetime.utcnow())
            }
        ]
        
        total = len(scheduled_reports)
        offset = (page - 1) * page_size
        items = scheduled_reports[offset:offset + page_size]
        
        return paginated_response(
            items=items,
            total=total,
            page=page,
            page_size=page_size
        )[0], 200
    
    except Exception as e:
        return api_response(success=False, message=str(e), status_code=500)[0], 500


@api_reports.route("/ondemand", methods=["GET"])
@login_required
def get_ondemand_reports():
    """
    GET /api/reports/ondemand?page=1&page_size=25&sort=generated_at&order=desc
    
    Returns history of on-demand reports.
    
    Response:
    {
        "success": true,
        "data": {
            "items": [
                {
                    "id": 1,
                    "type": "pqc_posture",
                    "scan_id": 42,
                    "generated_by": "admin",
                    "generated_at": "2026-03-22 07:18:12",
                    "status": "completed",
                    "file_path": "/reports/pqc_2026-03-22.pdf"
                }
            ],
            "total": 15,
            "page": 1,
            "page_size": 25,
            "total_pages": 1
        }
    }
    """
    try:
        db = SessionLocal()
        params = extract_pagination_params()
        page, page_size = validate_pagination_params(params["page"], params["page_size"])
        
        # Get recent scans as proxy for reports
        query = db.query(Scan).filter(
            Scan.is_deleted == False
        ).order_by(desc(Scan.completed_at))
        
        total = query.count()
        
        offset = (page - 1) * page_size
        scans = query.offset(offset).limit(page_size).all()
        
        items = []
        report_types = ["cbom", "pqc_posture", "cyber_rating", "tls_assessment"]
        
        for i, scan in enumerate(scans):
            item = {
                "id": scan.id,
                "type": report_types[i % len(report_types)],
                "scan_id": scan.scan_id,
                "generated_by": "system",
                "generated_at": format_datetime(scan.completed_at),
                "status": scan.status,
                "file_path": f"/reports/scan_{scan.scan_id}.json"
            }
            items.append(item)
        
        db.close()
        
        return paginated_response(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            filters={
                "sort": params["sort"] or "generated_at",
                "order": params["order"]
            }
        )[0], 200
    
    except Exception as e:
        return api_response(success=False, message=str(e), status_code=500)[0], 500


@api_reports.route("/<int:report_id>", methods=["GET"])
@login_required
def get_report_detail(report_id):
    """
    GET /api/reports/<report_id>
    Returns detailed information about a specific report.
    """
    try:
        db = SessionLocal()
        
        # In a real implementation, this would query the reports table
        # For now, return mock data
        report = {
            "id": report_id,
            "type": "pqc_posture",
            "title": "PQC Posture Assessment Report",
            "generated_at": format_datetime(datetime.utcnow()),
            "scan_id": report_id,
            "summary": {
                "total_assets": 150,
                "quantum_safe_pct": 78.5,
                "elite_pct": 45,
                "standard_pct": 30,
                "legacy_pct": 20,
                "critical_pct": 5
            },
            "recommendations": [
                "Upgrade 12 weak crypto implementations to 2048-bit RSA",
                "Migrate to NIST-approved post-quantum algorithms by 2030",
                "Implement certificate pinning on 5 critical domains"
            ]
        }
        
        db.close()
        
        return api_response(success=True, data=report)[0], 200
    
    except Exception as e:
        return api_response(success=False, message=str(e), status_code=500)[0], 500
