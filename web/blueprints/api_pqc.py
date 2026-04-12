"""
API PQC Posture - /api/pqc-posture/* endpoints
Returns post-quantum cryptography readiness metrics and assets.
"""

from flask import Blueprint, request, jsonify
from flask_login import login_required
from src.db import db_session as SessionLocal
from src.models import Asset, PQCClassification, ComplianceScore
from utils.api_helper import (
    paginated_response, api_response, extract_pagination_params,
    validate_pagination_params, format_datetime
)
from sqlalchemy import func

api_pqc = Blueprint("api_pqc", __name__, url_prefix="/api/pqc-posture")


@api_pqc.route("/metrics", methods=["GET"])
@login_required
def get_pqc_metrics():
    """
    GET /api/pqc-posture/metrics
    Returns PQC posture distribution.
    
    Response:
    {
        "success": true,
        "data": {
            "kpis": {
                "elite_pct": 45.0,
                "standard_pct": 30.0,
                "legacy_pct": 20.0,
                "critical_pct": 5.0,
                "total_assets": 100
            }
        }
    }
    """
    try:
        db = SessionLocal()
        
        # Count assets by compliance tier
        elite = db.query(func.count(ComplianceScore.id)).filter(
            ComplianceScore.is_deleted == False,
            ComplianceScore.type == "pqc",
            ComplianceScore.tier == "elite"
        ).scalar() or 0
        
        standard = db.query(func.count(ComplianceScore.id)).filter(
            ComplianceScore.is_deleted == False,
            ComplianceScore.type == "pqc",
            ComplianceScore.tier == "standard"
        ).scalar() or 0
        
        legacy = db.query(func.count(ComplianceScore.id)).filter(
            ComplianceScore.is_deleted == False,
            ComplianceScore.type == "pqc",
            ComplianceScore.tier == "legacy"
        ).scalar() or 0
        
        critical = db.query(func.count(ComplianceScore.id)).filter(
            ComplianceScore.is_deleted == False,
            ComplianceScore.type == "pqc",
            ComplianceScore.tier == "critical"
        ).scalar() or 0
        
        total = elite + standard + legacy + critical
        
        # Calculate percentages
        elite_pct = (elite / total * 100) if total > 0 else 0
        standard_pct = (standard / total * 100) if total > 0 else 0
        legacy_pct = (legacy / total * 100) if total > 0 else 0
        critical_pct = (critical / total * 100) if total > 0 else 0
        
        db.close()
        
        return api_response(
            success=True,
            data={
                "kpis": {
                    "elite_pct": round(elite_pct, 1),
                    "standard_pct": round(standard_pct, 1),
                    "legacy_pct": round(legacy_pct, 1),
                    "critical_pct": round(critical_pct, 1),
                    "total_assets": int(total),
                    "elite_count": int(elite),
                    "standard_count": int(standard),
                    "legacy_count": int(legacy),
                    "critical_count": int(critical)
                }
            }
        )[0], 200
    
    except Exception as e:
        return api_response(success=False, message=str(e), status_code=500)[0], 500


@api_pqc.route("/assets", methods=["GET"])
@login_required
def get_pqc_assets():
    """
    GET /api/pqc-posture/assets?page=1&page_size=25&sort=pqc_score&order=desc
    
    Returns assets with PQC classification and scores.
    
    Response items include:
    {
        "id": 1,
        "asset_name": "example.com",
        "ip": "192.168.1.1",
        "pqc_support": true,
        "pqc_score": 85.5,
        "tier": "elite",
        "algorithms": ["RSA-2048", "ECDSA"]
    }
    """
    try:
        db = SessionLocal()
        params = extract_pagination_params()
        page, page_size = validate_pagination_params(params["page"], params["page_size"])
        
        # Get assets with PQC classifications
        assets = db.query(Asset).filter(
            Asset.is_deleted == False
        ).all()
        
        items_data = []
        
        for asset in assets:
            # Get PQC classifications for this asset
            pqc_clas = db.query(PQCClassification).filter(
                PQCClassification.asset_id == asset.id,
                PQCClassification.is_deleted == False
            ).all()
            
            # Get compliance score
            comp_score = db.query(ComplianceScore).filter(
                ComplianceScore.asset_id == asset.id,
                ComplianceScore.type == "pqc",
                ComplianceScore.is_deleted == False
            ).first()
            
            pqc_support = any(
                p.quantum_safe_status == "safe" for p in pqc_clas
            )
            
            item = {
                "id": asset.id,
                "asset_name": asset.target,
                "ip": asset.ipv4 or asset.ipv6 or "",
                "pqc_support": pqc_support,
                "pqc_score": comp_score.score_value if comp_score else 0.0,
                "tier": comp_score.tier if comp_score else "unknown",
                "algorithms": list(set([p.algorithm_name for p in pqc_clas]))
            }
            items_data.append(item)
        
        # Sort items
        sort_key = {
            "pqc_score": lambda x: x["pqc_score"],
            "asset_name": lambda x: x["asset_name"],
            "tier": lambda x: x["tier"]
        }.get(params["sort"], lambda x: x["pqc_score"])
        
        reverse_sort = params["order"].lower() == "desc"
        items_data = sorted(items_data, key=sort_key, reverse=reverse_sort)
        
        # Apply pagination
        total = len(items_data)
        offset = (page - 1) * page_size
        items_page = items_data[offset:offset + page_size]
        
        db.close()
        
        return paginated_response(
            items=items_page,
            total=total,
            page=page,
            page_size=page_size,
            filters={
                "sort": params["sort"] or "pqc_score",
                "order": params["order"],
                "search": params["search"]
            }
        )[0], 200
    
    except Exception as e:
        return api_response(success=False, message=str(e), status_code=500)[0], 500


# ── Sprint 3: HNDL Risk Endpoint ─────────────────────────────────────

@api_pqc.route("/hndl", methods=["GET"])
@login_required
def get_hndl_summary():
    """
    GET /api/pqc-posture/hndl

    Returns organisation-wide Harvest-Now-Decrypt-Later (HNDL) exposure.

    Response:
    {
      "success": true,
      "data": {
        "total_exposed": 5,
        "avg_hndl_score": 62.3,
        "top_flags": [{"flag": "weak_rsa_2048bit", "count": 3}],
        "exposed_assets": [{"asset_id": 1, "score": 90.0, "flags": [...]}],
        "banner": {
          "show": true,
          "severity": "high",
          "message": "5 assets are exposed to HNDL attacks. Migrate RSA keys to 3072+ bits."
        }
      }
    }
    """
    try:
        from src.services.pqc_calculation_service import PQCCalculationService

        summary = PQCCalculationService.get_org_hndl_summary()

        total_exposed = int(summary.get("total_exposed", 0))
        avg_score = float(summary.get("avg_hndl_score", 0.0))

        # Build actionable banner message
        if total_exposed == 0:
            banner = {
                "show": False,
                "severity": "none",
                "message": "No HNDL exposure detected. All scanned assets use quantum-safe key sizes.",
            }
        elif avg_score >= 70:
            banner = {
                "show": True,
                "severity": "critical",
                "message": (
                    f"{total_exposed} asset(s) have critical HNDL exposure (avg score {avg_score:.0f}/100). "
                    "Attackers can harvest encrypted traffic today for future quantum decryption. "
                    "Migrate RSA/ECC keys to NIST PQC algorithms immediately."
                ),
            }
        elif avg_score >= 40:
            banner = {
                "show": True,
                "severity": "high",
                "message": (
                    f"{total_exposed} asset(s) are exposed to HNDL risk (avg score {avg_score:.0f}/100). "
                    "Prioritise migration to RSA-3072+ or ECDSA P-384+ before 2030."
                ),
            }
        else:
            banner = {
                "show": True,
                "severity": "medium",
                "message": (
                    f"{total_exposed} asset(s) have low-level HNDL indicators. "
                    "Review certificate validity periods and TLS cipher configurations."
                ),
            }

        return api_response(
            success=True,
            data={
                **summary,
                "banner": banner,
            },
        )[0], 200

    except Exception as exc:
        return api_response(success=False, message=str(exc), status_code=500)[0], 500
