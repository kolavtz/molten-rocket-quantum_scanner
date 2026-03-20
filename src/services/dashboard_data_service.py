"""
Unified Dashboard Data Service

Provides consistent, aggregated data from MySQL for all dashboards.
Ensures data consistency across asset inventory, CBOM, PQC posture, 
cyber rating, discovery, and main dashboard.

All thresholds and scoring logic centralized here for easy configuration.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from collections import Counter

from src import database as db
from src.db import db_session
from src.models import Asset, Scan, Certificate, PQCClassification

# ─────────────────────────────────────────────────────────────────────────
# Risk & Compliance Thresholds (Centralized Configuration)
# ─────────────────────────────────────────────────────────────────────────

RISK_SCORE_THRESHOLDS = {
    "low": 700,
    "medium": 400,
    "high": 200,
    "critical": 0,
}

PQC_POSTURE_TIERS = {
    "elite": 80,
    "standard": 60,
    "legacy": 40,
    "critical": 0,
}

CYBER_RATING_GRADES = {
    "A": 90,
    "B": 80,
    "C": 70,
    "D": 60,
    "F": 0,
}

WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1"}
WEAK_KEY_LENGTH_BITS = 2048


class DashboardDataService:
    """Unified data accessor for all dashboards."""

    @staticmethod
    def _score_to_risk(score: float) -> str:
        """Convert compliance score (0-1000) to risk level."""
        score = float(score or 0)
        if score >= RISK_SCORE_THRESHOLDS["low"]:
            return "Low"
        elif score >= RISK_SCORE_THRESHOLDS["medium"]:
            return "Medium"
        elif score >= RISK_SCORE_THRESHOLDS["high"]:
            return "High"
        return "Critical"

    @staticmethod
    def _score_to_pqc_tier(score: float) -> str:
        """Convert PQC score (0-100) to posture tier."""
        score = float(score or 0)
        if score >= PQC_POSTURE_TIERS["elite"]:
            return "Elite"
        elif score >= PQC_POSTURE_TIERS["standard"]:  
            return "Standard"
        elif score >= PQC_POSTURE_TIERS["legacy"]:
            return "Legacy"
        return "Critical"

    @staticmethod
    def _score_to_cyber_grade(score: float) -> str:
        """Convert cyber score (0-100) to letter grade."""
        score = float(score or 0)
        if score >= CYBER_RATING_GRADES["A"]:
            return "A"
        elif score >= CYBER_RATING_GRADES["B"]:
            return "B"
        elif score >= CYBER_RATING_GRADES["C"]:
            return "C"
        elif score >= CYBER_RATING_GRADES["D"]:
            return "D"
        return "F"

    @staticmethod
    def get_all_scans_aggregated() -> Dict[str, Any]:
        """
        Get all scans from MySQL with full aggregation.
        Data is returned from the DB layer directly for high performance.
        """
        try:
            metrics = db.get_enterprise_metrics()
            return {
                "status": "success",
                "total_scans": metrics.get("scan_count", 0),
                "scans": [],  # For paginated scan list, use API or separate endpoint
                "aggregated_kpis": {
                    "total_assets": metrics.get("total_assets", 0),
                    "quantum_safe": metrics.get("quantum_safe", 0),
                    "quantum_vulnerable": metrics.get("quantum_vulnerable", 0),
                    "average_compliance_score": metrics.get("avg_score", 0),
                    "expiring_certificates": metrics.get("ssl_expiry", {}).get("0-30", 0),
                    "high_risk_assets": metrics.get("risk_distribution", {}).get("Critical", 0) + metrics.get("risk_distribution", {}).get("High", 0),
                },
                "distributions": {
                    "risk": metrics.get("risk_distribution", {}),
                    "tls_versions": {},  # populate from a dedicated query if desired
                    "key_lengths": {},  # populate from dedicated query if desired
                    "cas": {},  # populate from dedicated query if desired
                }
            }
        except Exception as e:
            logger.exception("Error aggregating scans from DB: %s", e)
            return {
                "status": "error",
                "message": str(e),
                "total_scans": 0,
                "scans": [],
                "aggregated_kpis": {},
                "distributions": {},
            }

    @staticmethod
    def get_asset_details(asset_id: int) -> Optional[Dict[str, Any]]:
        """Get full details for a specific asset including all scan history."""
        try:
            asset = db_session.query(Asset).filter_by(id=asset_id, is_deleted=False).first()
            if not asset:
                return None
            
            # Get all scans for this asset
            asset_name = getattr(asset, "name", None)
            if asset_name:
                scans = db_session.query(Scan).filter(
                    Scan.target == asset_name
                ).order_by(Scan.started_at.desc()).all()
            else:
                scans = []
            
            if not scans:
                return {
                    "asset_id": asset_id,
                    "name": str(getattr(asset, "name", "")),
                    "type": str(getattr(asset, "asset_type", "")),
                    "owner": str(getattr(asset, "owner", "")),
                    "scans": [],
                    "latest_scan": None,
                }
            
            latest = scans[0] if scans else None
            latest_score = float(getattr(latest, "overall_pqc_score", 0) or 0) if latest else 0
            
            return {
                "asset_id": asset_id,
                "name": str(getattr(asset, "name", "")),
                "type": str(getattr(asset, "asset_type", "")),
                "owner": str(getattr(asset, "owner", "")),
                "risk_level": DashboardDataService._score_to_risk(latest_score * 10),
                "pqc_tier": DashboardDataService._score_to_pqc_tier(latest_score),
                "scan_count": len(scans),
                "latest_scan": {
                    "scan_id": getattr(latest, "id", ""),
                    "started_at": getattr(latest, "started_at", "").isoformat() if getattr(latest, "started_at", None) else "",
                    "completed_at": getattr(latest, "completed_at", "").isoformat() if getattr(latest, "completed_at", None) else "",
                    "score": latest_score,
                } if latest else None,
                "scans": [
                    {
                        "scan_id": getattr(s, "id", ""),
                        "started_at": getattr(s, "started_at", "").isoformat() if getattr(s, "started_at", None) else "",
                        "score": float(getattr(s, "overall_pqc_score", 0) or 0),
                    }
                    for s in scans[-10:]  # Last 10 scans
                ]
            }
        except Exception as e:
            logger.exception(f"Error getting asset details: {e}")
            return None


# Import logging
import logging
logger = logging.getLogger(__name__)
