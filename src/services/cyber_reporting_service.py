"""Cyber rating and reporting aggregation service.

Single source of truth for cyber metrics:
- Includes only active assets from assets table.
- Excludes orphaned scan/compliance rows not mapped to active assets.
- Aggregates readiness tiers by asset (Elite/Standard/Legacy/Critical).
- Provides reporting summary strings for /reporting dashboard.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from sqlalchemy import and_, func, or_

from src.db import db_session
from src.models import Asset, Certificate, ComplianceScore, PQCClassification, Scan


class CyberReportingService:
    """Service for cyber-rating and reporting view-model data."""

    TIERS = {
        "elite": 80.0,
        "standard": 60.0,
        "legacy": 40.0,
        "critical": 0.0,
    }

    @staticmethod
    def _score_to_tier(score: float) -> str:
        score = float(score or 0)
        if score >= CyberReportingService.TIERS["elite"]:
            return "Elite"
        if score >= CyberReportingService.TIERS["standard"]:
            return "Standard"
        if score >= CyberReportingService.TIERS["legacy"]:
            return "Legacy"
        return "Critical"

    @staticmethod
    def _build_active_asset_query(asset_id: Optional[int] = None):
        query = db_session.query(Asset).filter(Asset.is_deleted == False)
        if asset_id is not None:
            query = query.filter(Asset.id == asset_id)
        return query

    @staticmethod
    def _build_date_filters(start_date: Optional[str], end_date: Optional[str]) -> Tuple[Optional[datetime], Optional[datetime]]:
        parsed_start = None
        parsed_end = None
        if start_date:
            try:
                parsed_start = datetime.fromisoformat(str(start_date))
            except Exception:
                parsed_start = None
        if end_date:
            try:
                parsed_end = datetime.fromisoformat(str(end_date))
            except Exception:
                parsed_end = None
        return parsed_start, parsed_end

    @staticmethod
    def get_cyber_rating_data(
        asset_id: Optional[int] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        limit: int = 200,
    ) -> Dict:
        """Return cyber-rating metrics and telemetry table based on active assets only."""

        assets = CyberReportingService._build_active_asset_query(asset_id=asset_id).order_by(Asset.target.asc()).all()
        if not assets:
            return CyberReportingService._empty_cyber_rating()

        active_asset_ids = [a.id for a in assets]
        asset_by_id = {a.id: a for a in assets}
        score_by_asset: Dict[int, float] = {}
        scan_time_by_asset: Dict[int, Optional[datetime]] = {}

        parsed_start, parsed_end = CyberReportingService._build_date_filters(start_date, end_date)

        # Primary source: compliance_scores tied to active assets and complete active scans.
        compliance_query = (
            db_session.query(ComplianceScore, Scan)
            .join(Asset, ComplianceScore.asset_id == Asset.id)
            .join(Scan, ComplianceScore.scan_id == Scan.id)
            .filter(
                Asset.is_deleted == False,
                Scan.is_deleted == False,
                Scan.status == "complete",
                ComplianceScore.is_deleted == False,
                ComplianceScore.asset_id.in_(active_asset_ids),
                or_(
                    ComplianceScore.type == "overall",
                    ComplianceScore.type == "pqc",
                    ComplianceScore.type == "tls",
                    ComplianceScore.type.is_(None),
                ),
            )
            .order_by(ComplianceScore.asset_id.asc(), Scan.completed_at.desc(), ComplianceScore.id.desc())
        )

        if parsed_start is not None:
            compliance_query = compliance_query.filter(Scan.completed_at >= parsed_start)
        if parsed_end is not None:
            compliance_query = compliance_query.filter(Scan.completed_at <= parsed_end)

        for compliance_row, scan_row in compliance_query.all():
            aid = compliance_row.asset_id
            if aid in score_by_asset:
                continue
            raw = float(compliance_row.score_value or 0)
            # normalize if source is in 0-1000 band
            normalized = raw / 10.0 if raw > 100 else raw
            score_by_asset[aid] = max(0.0, min(100.0, normalized))
            scan_time_by_asset[aid] = getattr(scan_row, "completed_at", None) or getattr(scan_row, "started_at", None)

        # Fallback source: latest scan.overall_pqc_score joined by target to active assets.
        fallback_rows = (
            db_session.query(Asset.id, Scan.overall_pqc_score, Scan.completed_at, Scan.started_at)
            .join(Scan, func.lower(Asset.target) == func.lower(Scan.target))
            .filter(
                Asset.is_deleted == False,
                Scan.is_deleted == False,
                Scan.status == "complete",
                Asset.id.in_(active_asset_ids),
            )
            .order_by(Asset.id.asc(), Scan.completed_at.desc(), Scan.id.desc())
            .all()
        )

        for aid, overall_pqc_score, completed_at, started_at in fallback_rows:
            if aid in score_by_asset:
                continue
            score_by_asset[aid] = max(0.0, min(100.0, float(overall_pqc_score or 0)))
            scan_time_by_asset[aid] = completed_at or started_at

        # Assets without any live telemetry are scored 0 (Critical) but remain visible because they exist in inventory.
        tier_counts = Counter()
        telemetry_rows: List[Dict] = []
        for asset in assets:
            asset_id_int = int(getattr(asset, "id", 0) or 0)
            score = float(score_by_asset.get(asset_id_int, 0.0))
            tier = CyberReportingService._score_to_tier(score)
            tier_counts[tier] += 1

            telemetry_rows.append(
                {
                    "asset_id": asset_id_int,
                    "target": asset.target,
                    "score": round(score, 1),
                    "tier": tier,
                    "last_seen": scan_time_by_asset.get(asset_id_int),
                }
            )

        telemetry_rows = telemetry_rows[: max(1, int(limit or 200))]

        total_assets = len(assets)
        elite = tier_counts.get("Elite", 0)
        standard = tier_counts.get("Standard", 0)
        legacy = tier_counts.get("Legacy", 0)
        critical = tier_counts.get("Critical", 0)

        elite_pct = round((elite / total_assets) * 100.0, 1)
        standard_pct = round((standard / total_assets) * 100.0, 1)
        legacy_pct = round((legacy / total_assets) * 100.0, 1)
        critical_pct = round((critical / total_assets) * 100.0, 1)

        avg_score = round(
            sum(float(score_by_asset.get(int(getattr(a, "id", 0) or 0), 0.0)) for a in assets) / total_assets,
            1,
        )
        recommendations = CyberReportingService._build_recommendations(
            total_assets=total_assets,
            avg_score=avg_score,
            critical_count=critical,
            legacy_count=legacy,
        )

        return {
            "kpis": {
                "elite_pct": elite_pct,
                "standard_pct": standard_pct,
                "legacy_pct": legacy_pct,
                "critical_count": critical,
                "avg_score": avg_score,
            },
            "grade_counts": {
                "Elite": elite,
                "Standard": standard,
                "Legacy": legacy,
                "Critical": critical,
            },
            "status_distribution": {
                "Elite": elite_pct,
                "Standard": standard_pct,
                "Legacy": legacy_pct,
                "Critical": critical_pct,
            },
            "risk_heatmap": [
                {"x": "Cyber Tier", "y": "Elite", "value": elite},
                {"x": "Cyber Tier", "y": "Standard", "value": standard},
                {"x": "Cyber Tier", "y": "Legacy", "value": legacy},
                {"x": "Cyber Tier", "y": "Critical", "value": critical},
            ],
            "recommendations": recommendations,
            "applications": telemetry_rows,
            "meta": {
                "total_assets": total_assets,
                "scored_assets": len(score_by_asset),
                "orphan_policy": "Excluded by active-asset join (Asset.is_deleted=0)",
            },
        }

    @staticmethod
    def get_reporting_summary() -> Dict[str, str]:
        """Return summary cards for /reporting based on active assets and live DB data."""

        active_assets_count = db_session.query(func.count(Asset.id)).filter(Asset.is_deleted == False).scalar() or 0

        scans_query = (
            db_session.query(Scan)
            .join(Asset, func.lower(Scan.target) == func.lower(Asset.target))
            .filter(Scan.is_deleted == False, Scan.status == "complete", Asset.is_deleted == False)
        )
        complete_scans = scans_query.all()
        complete_scan_count = len(complete_scans)

        cert_count = (
            db_session.query(func.count(Certificate.id))
            .join(Asset, Certificate.asset_id == Asset.id)
            .join(Scan, Certificate.scan_id == Scan.id)
            .filter(Certificate.is_deleted == False, Asset.is_deleted == False, Scan.is_deleted == False, Scan.status == "complete")
            .scalar()
            or 0
        )

        weak_certs = (
            db_session.query(func.count(Certificate.id))
            .join(Asset, Certificate.asset_id == Asset.id)
            .join(Scan, Certificate.scan_id == Scan.id)
            .filter(
                Certificate.is_deleted == False,
                Asset.is_deleted == False,
                Scan.is_deleted == False,
                Scan.status == "complete",
                Certificate.tls_version.in_(["TLS 1.0", "TLS 1.1", "SSLv3", "SSLv2"]),
            )
            .scalar()
            or 0
        )

        cyber = CyberReportingService.get_cyber_rating_data()

        return {
            "discovery": f"Targets: {active_assets_count} | Complete Scans: {complete_scan_count} | Assessed Endpoints: {complete_scan_count}",
            "pqc": f"Assessed endpoints: {complete_scan_count} | Average PQC Score: {cyber['kpis']['avg_score']}%",
            "cbom": f"Total certificates: {cert_count} | Weak cryptography: {weak_certs}",
            "cyber_rating": f"Average enterprise score: {cyber['kpis']['avg_score']}/100",
            "inventory": f"Assets: {active_assets_count} | Critical Apps: {cyber['kpis']['critical_count']} | Legacy: {cyber['grade_counts']['Legacy']}",
        }

    @staticmethod
    def get_orphan_cleanup_sql_examples() -> List[str]:
        """Manual SQL snippets for cleanup (documentation aid, not auto-executed)."""
        return [
            (
                "DELETE cs FROM compliance_scores cs "
                "LEFT JOIN assets a ON a.id = cs.asset_id "
                "WHERE a.id IS NULL OR COALESCE(a.is_deleted, 0) = 1;"
            ),
            (
                "DELETE s FROM scans s "
                "LEFT JOIN assets a ON LOWER(a.target) = LOWER(s.target) "
                "WHERE a.id IS NULL OR COALESCE(a.is_deleted, 0) = 1;"
            ),
            (
                "DELETE p FROM pqc_classification p "
                "LEFT JOIN assets a ON a.id = p.asset_id "
                "WHERE a.id IS NULL OR COALESCE(a.is_deleted, 0) = 1;"
            ),
        ]

    @staticmethod
    def _build_recommendations(total_assets: int, avg_score: float, critical_count: int, legacy_count: int) -> List[str]:
        recs: List[str] = [
            f"Total active assets assessed: {total_assets}",
            f"Average cyber readiness: {avg_score}%",
            f"Critical applications: {critical_count}",
        ]
        if legacy_count > 0:
            recs.append(f"Legacy applications pending uplift: {legacy_count}")
        if avg_score < 50:
            recs.append("Immediate remediation required for weak/legacy cryptography.")
        elif avg_score < 80:
            recs.append("Prioritize migration to modern PQC and TLS baselines.")
        else:
            recs.append("Maintain posture with continuous control monitoring.")
        return recs

    @staticmethod
    def _empty_cyber_rating() -> Dict:
        return {
            "kpis": {
                "elite_pct": 0,
                "standard_pct": 0,
                "legacy_pct": 0,
                "critical_count": 0,
                "avg_score": 0,
            },
            "grade_counts": {"Elite": 0, "Standard": 0, "Legacy": 0, "Critical": 0},
            "status_distribution": {"Elite": 0, "Standard": 0, "Legacy": 0, "Critical": 0},
            "risk_heatmap": [
                {"x": "Cyber Tier", "y": "Elite", "value": 0},
                {"x": "Cyber Tier", "y": "Standard", "value": 0},
                {"x": "Cyber Tier", "y": "Legacy", "value": 0},
                {"x": "Cyber Tier", "y": "Critical", "value": 0},
            ],
            "recommendations": ["Run scans to populate cyber posture."],
            "applications": [],
            "meta": {"total_assets": 0, "scored_assets": 0},
        }
