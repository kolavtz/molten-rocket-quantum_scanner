"""Risk Penalty Calculation Service

Implements Math Spec Section 5.1:
- Risk penalty aggregation per asset
- Finding severity weighting
- Asset cyber score calculation (pqc_score - penalty)

All calculations persist to asset_metrics table.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List

from sqlalchemy import and_
from sqlalchemy.exc import IntegrityError

from config import RISK_WEIGHTS, PENALTY_ALPHA
from src.db import db_session
from src.models import Asset, AssetMetric, Finding, Scan


class RiskCalculationService:
    """Service for risk penalty calculations per Math Spec Section 5."""

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
            savepoint.rollback()
            existing = db_session.query(AssetMetric).filter(
                AssetMetric.asset_id == asset_id
            ).first()
            if existing:
                return existing
            raise

    @staticmethod
    def calculate_finding_severity_weight(severity: str) -> float:
        """
        Get weight multiplier for finding severity.
        
        From config.RISK_WEIGHTS:
        - critical: 10.0
        - high: 5.0
        - medium: 2.0
        - low: 0.5
        
        Args:
            severity: Finding severity ('critical', 'high', 'medium', 'low')
            
        Returns:
            Weight float value
        """
        normalized_severity = (severity or '').lower().strip()
        return RISK_WEIGHTS.get(normalized_severity, 0.0)

    @staticmethod
    def calculate_risk_penalty(asset_id: int, scan_id: int) -> float:
        """
        Calculate total risk penalty for an asset.
        
        Formula (Math Section 5.1):
            risk_penalty = Σ(finding.severity_weight) for all findings
            
        Args:
            asset_id: Asset ID
            scan_id: Scan ID
            
        Returns:
            Risk penalty float value
        """
        findings = db_session.query(Finding).filter(
            and_(
                Finding.asset_id == asset_id,
                Finding.scan_id == scan_id,
                Finding.is_deleted == False
            )
        ).all()
        
        total_penalty = 0.0
        
        for finding in findings:
            weight = RiskCalculationService.calculate_finding_severity_weight(
                finding.severity
            )
            total_penalty += weight
        
        return total_penalty

    @staticmethod
    def calculate_asset_cyber_score(pqc_score: float, risk_penalty: float) -> float:
        """
        Calculate asset-level cyber score (0-100).
        
        Formula (Math Section 5.2):
            asset_cyber_score = max(0, pqc_score - PENALTY_ALPHA * risk_penalty)
            
        Where PENALTY_ALPHA is a scaling factor (default 0.5).
        
        Args:
            pqc_score: PQC score 0-100
            risk_penalty: Risk penalty (from calculate_risk_penalty)
            
        Returns:
            Cyber score 0-100 (float)
        """
        penalty_impact = PENALTY_ALPHA * risk_penalty
        cyber_score = pqc_score - penalty_impact
        
        # Clamp to 0-100 range
        return max(0.0, min(100.0, cyber_score))

    @staticmethod
    def calculate_and_store_risk_metrics(asset_id: int, scan_id: int, auto_commit: bool = True) -> Dict:
        """
        Calculate risk metrics and update asset_metrics.
        
        Updates:
        - risk_penalty
        - critical_findings_count
        - total_findings_count
        - asset_cyber_score
        
        Args:
            asset_id: Asset ID
            scan_id: Scan ID
            
        Returns:
            Dict with calculated metrics
        """
        # Get or create asset_metrics row
        metric = RiskCalculationService._get_or_create_asset_metric(asset_id)
        
        # Calculate penalties
        risk_penalty = RiskCalculationService.calculate_risk_penalty(asset_id, scan_id)
        
        # Count findings by severity
        findings = db_session.query(Finding).filter(
            and_(
                Finding.asset_id == asset_id,
                Finding.scan_id == scan_id,
                Finding.is_deleted == False
            )
        ).all()
        
        total_findings = len(findings)
        critical_findings = sum(1 for f in findings if f.severity == 'critical')
        
        # Update metrics
        metric.risk_penalty = risk_penalty
        metric.total_findings_count = total_findings
        metric.critical_findings_count = critical_findings
        metric.has_critical_findings = critical_findings > 0
        
        # Recalculate cyber score using existing PQC score
        pqc_score = metric.pqc_score or 0.0
        metric.asset_cyber_score = RiskCalculationService.calculate_asset_cyber_score(
            pqc_score,
            risk_penalty
        )
        
        metric.last_updated = datetime.utcnow()
        
        if auto_commit:
            db_session.commit()
        
        return {
            'risk_penalty': risk_penalty,
            'total_findings': total_findings,
            'critical_findings': critical_findings,
            'asset_cyber_score': metric.asset_cyber_score,
        }

    @staticmethod
    def get_risk_distributions(scan_id: int) -> Dict[str, Dict[str, int]]:
        """
        Get risk distribution for all assets affected in a scan.
        
        Returns:
            {
                'by_severity': {'critical': count, 'high': count, ...},
                'by_asset': {asset_id: {critical: count, high: count, ...}},
            }
        """
        findings = db_session.query(Finding).filter(
            and_(
                Finding.scan_id == scan_id,
                Finding.is_deleted == False
            )
        ).all()
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        by_asset = {}
        
        for finding in findings:
            severity = (finding.severity or 'low').lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            if finding.asset_id not in by_asset:
                by_asset[finding.asset_id] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            
            by_asset[finding.asset_id][severity] += 1
        
        return {
            'by_severity': severity_counts,
            'by_asset': by_asset,
        }

    @staticmethod
    def classify_risk_level(asset_cyber_score: float) -> str:
        """
        Classify overall risk level from cyber score.
        
        Levels:
        - Critical: cyber_score < 25
        - High: cyber_score 25-49
        - Medium: cyber_score 50-74
        - Low: cyber_score >= 75
        
        Args:
            asset_cyber_score: Cyber score 0-100
            
        Returns:
            Risk level: 'Critical', 'High', 'Medium', or 'Low'
        """
        score = float(asset_cyber_score or 0)
        
        if score < 25:
            return 'Critical'
        elif score < 50:
            return 'High'
        elif score < 75:
            return 'Medium'
        else:
            return 'Low'

    @staticmethod
    def get_vulnerability_summary() -> Dict:
        """
        Get org-wide vulnerability summary.
        
        Returns:
            {
                'total_findings': int,
                'critical_count': int,
                'high_count': int,
                'medium_count': int,
                'low_count': int,
                'assets_with_critical': int,
            }
        """
        all_findings = db_session.query(Finding).filter(
            Finding.is_deleted == False
        ).all()
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        assets_with_critical = set()
        
        for finding in all_findings:
            severity = (finding.severity or 'low').lower()
            severity_counts[severity] += 1
            
            if severity == 'critical':
                assets_with_critical.add(finding.asset_id)
        
        return {
            'total_findings': len(all_findings),
            'critical_count': severity_counts['critical'],
            'high_count': severity_counts['high'],
            'medium_count': severity_counts['medium'],
            'low_count': severity_counts['low'],
            'assets_with_critical': len(assets_with_critical),
        }
