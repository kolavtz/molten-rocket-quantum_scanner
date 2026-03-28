"""Cyber Rating Service

Implements the user-specified 0-1000 scoring logic.
Based on Cyber Rating Tier table:
- Elite (Tier-1): > 700
- Standard (Tier-2): 400 - 700
- Legacy (Tier-3): < 400
- Critical: Insecure/exploitable

Calculates ratings for organization and single assets.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

from sqlalchemy import and_, func

from src.db import db_session
from src.models import Asset, AssetMetric, CyberRating, Scan, Finding


class CyberRatingService:
    """Service for calculating and tracking 0-1000 Cyber Ratings."""

    TIER_MAPPING = {
        "Elite": {
            "min_score": 700,
            "tier_label": "Tier-1 Elite",
            "security_level": "Modern best-practice",
            "compliance_criteria": "TLS 1.2/1.3 only; Strong Ciphers; Forward Secrecy; Cert > 2048-bit; HSTS",
            "priority_action": "Maintain configuration; periodic monitoring"
        },
        "Standard": {
            "min_score": 400,
            "tier_label": "Tier-2 Standard",
            "security_level": "Acceptable enterprise",
            "compliance_criteria": "TLS 1.2 supported but legacy allowed; Key > 2048-bit; Mostly strong ciphers",
            "priority_action": "Improve gradually; disable legacy protocols"
        },
        "Legacy": {
            "min_score": 0,
            "tier_label": "Tier-3 Legacy",
            "security_level": "Weak but operational",
            "compliance_criteria": "TLS 1.0/1.1 enabled; weak ciphers; FS missing; Key < 2048-bit",
            "priority_action": "Remediation required; upgrade TLS stack; rotate certs"
        },
        "Critical": {
            "min_score": 0,
            "tier_label": "Critical",
            "security_level": "Insecure/exploitable",
            "compliance_criteria": "SSLv2/v3 enabled; Key < 1024-bit; Weak ciphers (< 112-bit security)",
            "priority_action": "Immediate action; block or isolate service"
        }
    }

    @staticmethod
    def calculate_cyber_rating_1000(asset_id: int) -> Dict[str, Any]:
        """
        Calculate the 0-1000 rating for a specific asset.
        
        Logic:
        1. Get the 0-100 cyber score from AssetMetric (which is pqc_score - penalties).
        2. Scale to 0-1000.
        3. Determine tier based on thresholds and critical findings.
        
        Args:
            asset_id: Asset ID
        
        Returns:
            Dict containing score, tier, and justification.
        """
        metric = db_session.query(AssetMetric).filter(
            AssetMetric.asset_id == asset_id
        ).first()

        if not metric:
            return {"score": 0, "tier": "Legacy", "label": "No Data"}

        # Scale 0-100 to 0-1000
        raw_score = float(getattr(metric, "asset_cyber_score", 0) or 0)
        score_1000 = min(1000.0, max(0.0, raw_score * 10.0))

        # Determine Tier
        # Critical overwrites score-based tier if certain findings exist
        is_critical = getattr(metric, "has_critical_findings", False)
        
        if is_critical or score_1000 < 200: # Below 200 is always critical in this mapping
            tier_key = "Critical"
        elif score_1000 < 400:
            tier_key = "Legacy"
        elif score_1000 <= 700:
            tier_key = "Standard"
        else:
            tier_key = "Elite"

        tier_data = CyberRatingService.TIER_MAPPING.get(tier_key, CyberRatingService.TIER_MAPPING["Legacy"])

        return {
            "score": round(score_1000, 2),
            "tier": tier_key,
            "tier_label": tier_data["tier_label"],
            "security_level": tier_data["security_level"],
            "compliance_criteria": tier_data["compliance_criteria"],
            "priority_action": tier_data["priority_action"],
            "calculated_at": datetime.utcnow()
        }

    @staticmethod
    def get_overall_rating() -> Dict[str, Any]:
        """Wrapper for calculate_org_cyber_rating for API consistency."""
        return CyberRatingService.calculate_org_cyber_rating()

    @staticmethod
    def calculate_org_cyber_rating() -> Dict[str, Any]:
        """
        Calculate organization-wide rating (average of all assets).
        """
        metrics = db_session.query(AssetMetric).all()
        
        if not metrics:
            return {"score": 0, "tier": "Legacy", "label": "No Data"}

        scores = [float(getattr(m, "asset_cyber_score", 0) or 0) * 10.0 for m in metrics]
        avg_score = sum(scores) / len(scores)
        
        # Determine Org Tier
        if avg_score < 400:
            tier_key = "Legacy"
        elif avg_score <= 700:
            tier_key = "Standard"
        else:
            tier_key = "Elite"
            
        # If any high % of assets are critical, pull down the org tier?
        critical_count = sum(1 for m in metrics if getattr(m, "has_critical_findings", False))
        if critical_count > len(metrics) * 0.1: # More than 10% critical
            tier_key = "Legacy" # Or "Critical" if logic allows

        tier_data = CyberRatingService.TIER_MAPPING.get(tier_key, CyberRatingService.TIER_MAPPING["Legacy"])

        return {
            "score": round(avg_score, 2),
            "tier": tier_key,
            "tier_label": tier_data["tier_label"],
            "security_level": tier_data["security_level"],
            "compliance_criteria": tier_data["compliance_criteria"],
            "priority_action": tier_data["priority_action"],
            "total_assets": len(metrics),
            "critical_assets": critical_count,
            "calculated_at": datetime.utcnow()
        }

    @staticmethod
    def get_tier_table_data() -> List[Dict[str, str]]:
        """Returns the static tier table data for the UI."""
        return [
            {
                "tier": "Tier-1 Elite",
                "security_level": "Modern best-practice crypto posture",
                "compliance_criteria": "TLS 1.2/ 1.3 only; Strong Ciphers; Forward Secrecy; Cert > 2048-bit; HSTS",
                "priority_action": "Maintain Configuration; periodic monitoring"
            },
            {
                "tier": "Tier-2 Standard",
                "security_level": "Acceptable enterprise configuration",
                "compliance_criteria": "TLS 1.2 supported but legacy allowed; Key > 2048-bit; Mostly strong ciphers",
                "priority_action": "Improve gradually; disable legacy protocols"
            },
            {
                "tier": "Tier-3 Legacy",
                "security_level": "Weak but still operational",
                "compliance_criteria": "TLS 1.0/TLS 1.1 enabled; weak ciphers; FS missing; Key 1024-bit",
                "priority_action": "Remediation required; upgrade TLS stack; rotate certs"
            },
            {
                "tier": "Critical",
                "security_level": "Insecure/exploitable",
                "compliance_criteria": "SSL V2/V3 enabled; Key < 1024-bit; weak cipher suites; Known vulnerabilities",
                "priority_action": "Immediate action; block or isolate service"
            }
        ]

    @staticmethod
    def get_rating_history(asset_id: Optional[int] = None, days: int = 30) -> List[Dict[str, Any]]:
        """
        Get historical rating data for trend charts.
        """
        since = datetime.utcnow() - timedelta(days=days)
        
        if asset_id:
            ratings = db_session.query(CyberRating).filter(
                and_(
                    CyberRating.asset_id == asset_id,
                    CyberRating.generated_at >= since
                )
            ).order_by(CyberRating.generated_at.asc()).all()
        else:
            # Org-level history (average of all assets per day)
            ratings = db_session.query(CyberRating).filter(
                and_(
                    CyberRating.asset_id.is_(None),
                    CyberRating.generated_at >= since
                )
            ).order_by(CyberRating.generated_at.asc()).all()

        return [
            {
                "date": r.generated_at.strftime("%Y-%m-%d"),
                "score": round(r.enterprise_score, 2),
                "tier": r.rating_tier
            }
            for r in ratings
        ]
