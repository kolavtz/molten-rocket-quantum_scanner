"""PQC Score Calculation Service

Implements Math Spec Sections 3.1-3.3:
- Endpoint-level PQC scoring (weighted algorithms)
- Asset-level PQC scoring (average endpoints)
- Asset Classification (Elite/Standard/Legacy/Critical)

All calculations persist to asset_metrics table.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, Optional

from sqlalchemy import and_, func
from sqlalchemy.exc import IntegrityError

from config import (
    PQC_THRESHOLDS, RISK_WEIGHTS, PENALTY_ALPHA
)
from src.db import db_session
from src.models import (
    Asset, AssetMetric, Certificate, ComplianceScore,
    Finding, PQCClassification
)


class PQCCalculationService:
    """Service for PQC score calculations per Math Spec Section 3."""

    @staticmethod
    def _get_or_create_asset_metric(asset_id: int) -> AssetMetric:
        """Get or create AssetMetric row safely under concurrent writes."""
        metric = db_session.query(AssetMetric).filter(
            AssetMetric.asset_id == asset_id
        ).first()
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
            # Another transaction likely created this row concurrently.
            savepoint.rollback()
            existing = db_session.query(AssetMetric).filter(
                AssetMetric.asset_id == asset_id
            ).first()
            if existing:
                return existing
            raise

    @staticmethod
    def calculate_endpoint_pqc_score(asset_id: int, scan_id: int) -> float:
        """
        Calculate endpoint-level PQC score (0-100).
        
        Formula (Math Section 3.1):
            pqc_score = (quantum_safe_count / total_algorithms) * 100
            
        Args:
            asset_id: Asset ID
            scan_id: Scan ID
            
        Returns:
            PQC score 0-100 (float)
        """
        query = db_session.query(PQCClassification).filter(
            and_(
                PQCClassification.asset_id == asset_id,
                PQCClassification.scan_id == scan_id,
                PQCClassification.is_deleted == False
            )
        ).all()
        
        if not query:
            return 0.0
        
        # Count quantum-safe algorithms
        quantum_safe_count = sum(
            1
            for pqc in query
            if str(getattr(pqc, "quantum_safe_status", "") or "").lower() in {"safe", "quantum_safe"}
        )
        
        total_count = len(query)
        if total_count == 0:
            return 0.0
        
        score = (quantum_safe_count / total_count) * 100.0
        return min(100.0, max(0.0, score))

    @staticmethod
    def calculate_asset_pqc_score(asset_id: int, scan_id: Optional[int] = None) -> float:
        """
        Calculate asset-level PQC score (0-100).
        
        Formula (Math Section 3.2):
            pqc_score = avg(endpoint_pqc_scores) for all endpoints
            
        If scan_id not provided, uses most recent scan.
        
        Args:
            asset_id: Asset ID
            scan_id: Optional specific scan ID
            
        Returns:
            PQC score 0-100 (float)
        """
        # Get scan if not provided
        if scan_id is None:
            asset = db_session.query(Asset).filter(Asset.id == asset_id).first()
            if not asset:
                return 0.0
            last_scan_id = int(getattr(asset, "last_scan_id", 0) or 0)
            if last_scan_id <= 0:
                return 0.0
            scan_id = last_scan_id
        
        # Get all endpoints for this asset in the scan
        endpoints = db_session.query(
            func.distinct(Certificate.endpoint)
        ).filter(
            and_(
                Certificate.asset_id == asset_id,
                Certificate.scan_id == scan_id,
                Certificate.is_deleted == False
            )
        ).all()
        
        if not endpoints:
            return 0.0
        
        # Calculate score per endpoint and average
        endpoint_scores = []
        for endpoint_row in endpoints:
            endpoint = endpoint_row[0]
            if not endpoint:
                continue
            
            # Get PQC classifications for this endpoint
            pqc_rows = db_session.query(PQCClassification).filter(
                and_(
                    PQCClassification.asset_id == asset_id,
                    PQCClassification.scan_id == scan_id,
                    PQCClassification.is_deleted == False
                )
            ).all()
            
            if not pqc_rows:
                endpoint_scores.append(0.0)
                continue
            
            quantum_safe_count = sum(
                1
                for pqc in pqc_rows
                if str(getattr(pqc, "quantum_safe_status", "") or "").lower() in {"safe", "quantum_safe"}
            )
            
            endpoint_score = (quantum_safe_count / len(pqc_rows)) * 100.0
            endpoint_scores.append(endpoint_score)
        
        if not endpoint_scores:
            return 0.0
        
        # Return average
        avg_score = sum(endpoint_scores) / len(endpoint_scores)
        return min(100.0, max(0.0, avg_score))

    @staticmethod
    def classify_asset_pqc_tier(
        pqc_score: float,
        has_critical_findings: bool,
        has_legacy_config: bool = False
    ) -> str:
        """
        Classify asset into PQC tier (Elite/Standard/Legacy/Critical).
        
        Logic (Math Section 3.3):
        - Elite: pqc_score >= 90 AND no critical findings
        - Standard: 70 <= pqc_score < 90
        - Legacy: 40 <= pqc_score < 70 OR has_legacy_config
        - Critical: pqc_score < 40 OR has_critical_findings
        
        Args:
            pqc_score: PQC score 0-100
            has_critical_findings: Whether asset has critical findings
            has_legacy_config: Whether asset uses legacy TLS/protocol
            
        Returns:
            Tier string: 'Elite', 'Standard', 'Legacy', or 'Critical'
        """
        if has_critical_findings or pqc_score < PQC_THRESHOLDS['critical']:
            return 'Critical'
        
        if has_legacy_config or pqc_score < PQC_THRESHOLDS['legacy']:
            return 'Legacy'
        
        if pqc_score < PQC_THRESHOLDS['standard']:
            return 'Standard'
        
        if pqc_score >= PQC_THRESHOLDS['elite'] and not has_critical_findings:
            return 'Elite'
        
        return 'Standard'

    @staticmethod
    def calculate_and_store_pqc_metrics(asset_id: int, scan_id: int, auto_commit: bool = True) -> AssetMetric:
        """
        Calculate all PQC metrics and persist to asset_metrics table.
        
        Computes:
        - pqc_score
        - pqc_class_tier
        - risk_penalty (from findings)
        - critical_findings_count
        - asset_cyber_score
        
        Args:
            asset_id: Asset ID
            scan_id: Scan ID
            
        Returns:
            AssetMetric object (persisted)
        """
        pqc_score = PQCCalculationService.calculate_asset_pqc_score(asset_id, scan_id)
        
        # Count findings by severity
        findings = db_session.query(Finding).filter(
            and_(
                Finding.asset_id == asset_id,
                Finding.scan_id == scan_id,
                Finding.is_deleted == False
            )
        ).all()
        
        total_findings = len(findings)
        critical_findings = sum(
            1 for f in findings if str(getattr(f, "severity", "") or "").lower() == "critical"
        )
        
        # Calculate risk penalty (Σ severity_weight)
        risk_penalty = sum(
            RISK_WEIGHTS.get(str(getattr(f, "severity", "") or "").lower(), 0)
            for f in findings
        )
        
        has_critical = critical_findings > 0
        has_legacy = any(str(getattr(f, "issue_type", "") or "") == "weak_tls_version" for f in findings)
        
        # Classify tier
        tier = PQCCalculationService.classify_asset_pqc_tier(
            pqc_score,
            has_critical,
            has_legacy
        )
        
        # Calculate asset cyber score: max(0, pqc_score - alpha * risk_penalty)
        asset_cyber_score = max(0.0, pqc_score - PENALTY_ALPHA * risk_penalty)
        
        # Upsert to asset_metrics
        metric = PQCCalculationService._get_or_create_asset_metric(asset_id)
        
        metric.pqc_score = pqc_score
        metric.pqc_score_timestamp = datetime.utcnow()
        metric.risk_penalty = risk_penalty
        metric.total_findings_count = total_findings
        metric.critical_findings_count = critical_findings
        metric.pqc_class_tier = tier
        metric.has_critical_findings = has_critical
        metric.asset_cyber_score = asset_cyber_score
        metric.calculated_at = datetime.utcnow()
        
        if auto_commit:
            db_session.commit()
        
        return metric

    @staticmethod
    def store_pqc_compliance_score(
        asset_id: int,
        scan_id: int,
        pqc_score: float,
        tier: str,
        score_type: str = 'pqc',
        auto_commit: bool = True,
    ) -> ComplianceScore:
        """
        Persist PQC score to compliance_scores table.
        
        Args:
            asset_id: Asset ID
            scan_id: Scan ID
            pqc_score: PQC score 0-100
            tier: Tier (Elite/Standard/Legacy/Critical)
            score_type: Score type (default 'pqc')
            
        Returns:
            ComplianceScore object
        """
        # Upsert compliance score
        score_record = db_session.query(ComplianceScore).filter(
            and_(
                ComplianceScore.asset_id == asset_id,
                ComplianceScore.scan_id == scan_id,
                ComplianceScore.score_type == score_type
            )
        ).first()
        
        if not score_record:
            score_record = ComplianceScore(
                asset_id=asset_id,
                scan_id=scan_id,
                score_type=score_type
            )
            db_session.add(score_record)
        
        score_record.score_value = pqc_score
        score_record.tier = tier
        
        if auto_commit:
            db_session.commit()
        
        return score_record

    @staticmethod
    def get_pqc_distribution(scan_id: Optional[int] = None) -> Dict[str, int]:
        """
        Get distribution of assets by PQC tier.
        
        Returns:
            {"Elite": count, "Standard": count, "Legacy": count, "Critical": count}
        """
        metrics = db_session.query(AssetMetric).all()
        
        distribution = {
            'Elite': 0,
            'Standard': 0,
            'Legacy': 0,
            'Critical': 0,
        }
        
        for metric in metrics:
            tier = str(getattr(metric, "pqc_class_tier", "") or "Standard")
            distribution[tier] = distribution.get(tier, 0) + 1
        
        return distribution
