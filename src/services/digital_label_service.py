"""Digital label calculation service for Phase 3.

Assigns user-facing digital labels based on PQC metrics, findings, and
enterprise score context, then persists them into `digital_labels` and
`asset_metrics.digital_label`.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Dict, Tuple

from sqlalchemy import and_
from sqlalchemy.exc import IntegrityError

from config import DIGITAL_LABELS_CONFIG
from src.db import db_session
from src.models import AssetMetric, CyberRating, DigitalLabel, Finding


class DigitalLabelService:
    """Assign and persist digital labels for scanned assets."""

    @staticmethod
    def _get_or_create_asset_metric(asset_id: int) -> AssetMetric:
        """Get or create AssetMetric row safely under concurrent writes."""
        metric = db_session.query(AssetMetric).filter(AssetMetric.asset_id == asset_id).first()
        if metric:
            return metric

        savepoint = db_session.begin_nested()
        try:
            metric = AssetMetric(asset_id=asset_id)
            db_session.add(metric)
            db_session.flush()
            savepoint.commit()
            return metric
        except IntegrityError:
            savepoint.rollback()
            existing = db_session.query(AssetMetric).filter(AssetMetric.asset_id == asset_id).first()
            if existing:
                return existing
            raise

    @staticmethod
    def assign_label(
        pqc_score: float,
        total_findings: int,
        critical_findings: int,
        enterprise_score: float,
    ) -> Tuple[str, Dict]:
        """Assign a label using configured thresholds.

        Priority order:
        1) At Risk
        2) Fully Quantum Safe
        3) Quantum-Safe
        4) PQC Ready
        5) At Risk (fallback)
        """
        score = float(pqc_score or 0.0)
        findings = int(total_findings or 0)
        critical = int(critical_findings or 0)
        enterprise = float(enterprise_score or 0.0)

        at_risk_cfg = DIGITAL_LABELS_CONFIG.get("At Risk", {})
        if critical >= int(at_risk_cfg.get("min_critical_findings", 1)) or score <= float(at_risk_cfg.get("max_pqc_score", 40)):
            return "At Risk", {
                "reason": "Contains critical findings or PQC score is below safe threshold",
                "thresholds": {
                    "max_pqc_score": at_risk_cfg.get("max_pqc_score", 40),
                    "min_critical_findings": at_risk_cfg.get("min_critical_findings", 1),
                },
            }

        full_cfg = DIGITAL_LABELS_CONFIG.get("Fully Quantum Safe", {})
        if (
            score >= float(full_cfg.get("min_pqc_score", 90))
            and findings <= int(full_cfg.get("max_findings", 0))
            and critical <= int(full_cfg.get("max_critical_findings", 0))
            and enterprise >= float(full_cfg.get("min_enterprise_score", 700))
        ):
            return "Fully Quantum Safe", {
                "reason": "High PQC score, zero findings, and strong enterprise posture",
                "thresholds": {
                    "min_pqc_score": full_cfg.get("min_pqc_score", 90),
                    "max_findings": full_cfg.get("max_findings", 0),
                    "min_enterprise_score": full_cfg.get("min_enterprise_score", 700),
                },
            }

        safe_cfg = DIGITAL_LABELS_CONFIG.get("Quantum-Safe", {})
        if score >= float(safe_cfg.get("min_pqc_score", 90)) and critical <= int(safe_cfg.get("max_critical_findings", 0)):
            return "Quantum-Safe", {
                "reason": "High PQC score with no critical findings",
                "thresholds": {
                    "min_pqc_score": safe_cfg.get("min_pqc_score", 90),
                    "max_critical_findings": safe_cfg.get("max_critical_findings", 0),
                },
            }

        ready_cfg = DIGITAL_LABELS_CONFIG.get("PQC Ready", {})
        if (
            score >= float(ready_cfg.get("min_pqc_score", 70))
            and findings <= int(ready_cfg.get("max_findings", 3))
            and critical <= int(ready_cfg.get("max_critical_findings", 0))
        ):
            return "PQC Ready", {
                "reason": "Acceptable PQC posture with limited findings",
                "thresholds": {
                    "min_pqc_score": ready_cfg.get("min_pqc_score", 70),
                    "max_findings": ready_cfg.get("max_findings", 3),
                    "max_critical_findings": ready_cfg.get("max_critical_findings", 0),
                },
            }

        return "At Risk", {
            "reason": "Did not satisfy Quantum-Safe or PQC Ready thresholds",
            "thresholds": {},
        }

    @staticmethod
    def calculate_confidence_score(
        label: str,
        pqc_score: float,
        total_findings: int,
        critical_findings: int,
    ) -> int:
        """Compute confidence score (0-100) for assigned label."""
        cfg = DIGITAL_LABELS_CONFIG.get(label, {})
        base_weight = float(cfg.get("confidence_weight", 0.8))

        normalized_pqc = max(0.0, min(100.0, float(pqc_score or 0.0))) / 100.0
        finding_penalty = min(0.4, int(total_findings or 0) * 0.05)
        critical_penalty = min(0.5, int(critical_findings or 0) * 0.25)

        confidence = (base_weight + 0.4 * normalized_pqc) - finding_penalty - critical_penalty
        return int(max(0, min(100, round(confidence * 100))))

    @staticmethod
    def _resolve_enterprise_score(asset_id: int, scan_id: int, fallback_asset_cyber_score: float) -> float:
        """Resolve enterprise score for labeling, with safe fallback."""
        rating = db_session.query(CyberRating).filter(
            and_(
                CyberRating.asset_id == asset_id,
                CyberRating.scan_id == scan_id,
                CyberRating.is_deleted == False,
            )
        ).order_by(CyberRating.generated_at.desc(), CyberRating.id.desc()).first()

        if rating and getattr(rating, "enterprise_score", None) is not None:
            return float(getattr(rating, "enterprise_score", 0.0) or 0.0)

        # Compatibility fallback: convert 0-100 asset cyber score to 0-1000 range.
        return max(0.0, min(1000.0, float(fallback_asset_cyber_score or 0.0) * 10.0))

    @staticmethod
    def calculate_and_store_digital_label(asset_id: int, scan_id: int, auto_commit: bool = True) -> Dict:
        """Calculate and persist digital label for a single asset/scan."""
        metric = DigitalLabelService._get_or_create_asset_metric(asset_id)

        findings_count = db_session.query(Finding).filter(
            and_(
                Finding.asset_id == asset_id,
                Finding.scan_id == scan_id,
                Finding.is_deleted == False,
            )
        ).count()

        critical_findings_count = db_session.query(Finding).filter(
            and_(
                Finding.asset_id == asset_id,
                Finding.scan_id == scan_id,
                Finding.is_deleted == False,
                Finding.severity == "critical",
            )
        ).count()

        pqc_score = float(getattr(metric, "pqc_score", 0.0) or 0.0)
        asset_cyber_score = float(getattr(metric, "asset_cyber_score", 0.0) or 0.0)
        enterprise_score = DigitalLabelService._resolve_enterprise_score(
            asset_id=asset_id,
            scan_id=scan_id,
            fallback_asset_cyber_score=asset_cyber_score,
        )

        label, reason = DigitalLabelService.assign_label(
            pqc_score=pqc_score,
            total_findings=int(findings_count or 0),
            critical_findings=int(critical_findings_count or 0),
            enterprise_score=enterprise_score,
        )
        confidence_score = DigitalLabelService.calculate_confidence_score(
            label=label,
            pqc_score=pqc_score,
            total_findings=int(findings_count or 0),
            critical_findings=int(critical_findings_count or 0),
        )

        record = db_session.query(DigitalLabel).filter(DigitalLabel.asset_id == asset_id).first()
        if not record:
            record = DigitalLabel(asset_id=asset_id)
            db_session.add(record)

        reason_payload = {
            **reason,
            "pqc_score": pqc_score,
            "findings_count": int(findings_count or 0),
            "critical_findings_count": int(critical_findings_count or 0),
            "enterprise_score": enterprise_score,
        }

        record.label = label
        record.label_reason_json = json.dumps(reason_payload)
        record.confidence_score = confidence_score
        record.based_on_pqc_score = pqc_score
        record.based_on_finding_count = int(findings_count or 0)
        record.based_on_critical_findings = int(critical_findings_count or 0) > 0
        record.based_on_enterprise_score = enterprise_score
        record.label_generated_at = datetime.utcnow()
        record.label_updated_at = datetime.utcnow()

        metric.digital_label = label
        metric.last_updated = datetime.utcnow()

        if auto_commit:
            db_session.commit()

        return {
            "asset_id": int(asset_id),
            "scan_id": int(scan_id),
            "digital_label": label,
            "confidence_score": int(confidence_score),
            "enterprise_score": float(enterprise_score),
        }
