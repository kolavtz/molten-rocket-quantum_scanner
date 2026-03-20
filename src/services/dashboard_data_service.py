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
        This is the master data source for all dashboards.
        """
        try:
            scans = db_session.query(Scan).filter(Scan.status == "complete").all()
            
            if not scans:
                return {
                    "status": "success",
                    "total_scans": 0,
                    "scans": [],
                    "aggregated_kpis": {
                        "total_assets": 0,
                        "quantum_safe": 0,
                        "quantum_vulnerable": 0,
                        "average_compliance_score": 0,
                        "expiring_certificates": 0,
                        "high_risk_assets": 0,
                    },
                    "distributions": {
                        "risk": {},
                        "tls_versions": {},
                        "key_lengths": {},
                        "cas": {},
                    }
                }
            
            # Aggregate all scans
            risk_dist = Counter()
            tls_dist = Counter()
            key_dist = Counter()
            ca_dist = Counter()
            
            total_score = 0
            high_risk_count = 0
            expiring_cert_count = 0
            quantum_safe_count = 0
            quantum_vulnerable_count = 0
            
            scan_list = []
            
            for scan in scans:
                target = str(getattr(scan, "target", "Unknown"))
                overall_score = float(getattr(scan, "overall_pqc_score", 0) or 0)
                total_score += overall_score
                
                risk_level = DashboardDataService._score_to_risk(overall_score * 10)  # Scale 0-1000
                risk_dist[risk_level] += 1
                
                if risk_level in {"High", "Critical"}:
                    high_risk_count += 1
                
                if risk_level == "Low":
                    quantum_safe_count += 1
                else:
                    quantum_vulnerable_count += 1
                
                # Get certificates for this scan
                scan_id = getattr(scan, "scan_id", None) or getattr(scan, "id", None)
                if scan_id:
                    certs = db_session.query(Certificate).filter(
                        Certificate.scan_id == scan_id
                    ).all()
                else:
                    certs = []
                
                for cert in certs:
                    tls = str(getattr(cert, "tls_version", "") or "Unknown")
                    key_len = int(getattr(cert, "key_length", 0) or 0)
                    ca = str(getattr(cert, "ca", "") or "Unknown")
                    
                    tls_dist[tls] += 1
                    if key_len >= 4096:
                        key_dist["4096+"] += 1
                    elif key_len >= 2048:
                        key_dist["2048-4095"] += 1
                    elif key_len > 0:
                        key_dist["<2048"] += 1
                    
                    ca_dist[ca[:20]] += 1  # Truncate long CA names
                    
                    # Count expiring certs
                    if tls in WEAK_TLS_VERSIONS or key_len < WEAK_KEY_LENGTH_BITS:
                        expiring_cert_count += 1
                
                started = getattr(scan, "started_at", None)
                completed = getattr(scan, "completed_at", None)
                
                scan_list.append({
                    "scan_id": scan_id,
                    "target": target,
                    "status": "complete",
                    "started_at": started.isoformat() if started else "",
                    "completed_at": completed.isoformat() if completed else "",
                    "overall_pqc_score": overall_score,
                    "risk_level": risk_level,
                })
            
            avg_score = total_score / max(len(scans), 1)
            
            return {
                "status": "success",
                "total_scans": len(scans),
                "scans": scan_list,
                "aggregated_kpis": {
                    "total_assets": len(scans),
                    "quantum_safe": quantum_safe_count,
                    "quantum_vulnerable": quantum_vulnerable_count,
                    "average_compliance_score": round(avg_score, 2),
                    "expiring_certificates": expiring_cert_count,
                    "high_risk_assets": high_risk_count,
                },
                "distributions": {
                    "risk": dict(risk_dist),
                    "tls_versions": dict(tls_dist),
                    "key_lengths": dict(key_dist),
                    "cas": dict(ca_dist.most_common(5)),
                }
            }
        except Exception as e:
            logger.exception(f"Error aggregating scans: {e}")
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
