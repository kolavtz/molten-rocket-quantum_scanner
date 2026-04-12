"""Risk Penalty Calculation Service

Implements Math Spec Section 5.1:
- Risk penalty aggregation per asset
- Finding severity weighting
- Asset cyber score calculation (pqc_score - penalty)

All calculations persist to asset_metrics table.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
logger = logging.getLogger(__name__)
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
        """Get or create AssetMetric row safely without session rollbacks."""
        # 1. Check identity map
        metric = db_session.get(AssetMetric, asset_id)
        if metric:
            return metric

        # 2. Check pending objects in session
        for m in db_session.new:
            if isinstance(m, AssetMetric) and getattr(m, 'asset_id', None) == asset_id:
                return m

        # 3. Create and add defensively
        metric = AssetMetric(asset_id=asset_id)
        db_session.add(metric)
        return metric

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
        
        metric.last_updated = datetime.now(timezone.utc)
        
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

    # ── Sprint 4: TLS Resilience Tier ────────────────────────────────────────

    @staticmethod
    def calculate_tls_resilience(asset_id: int, scan_id: int, auto_commit: bool = True) -> str:
        """
        Calculate TLS Resilience Tier for an asset based on its latest scan data.

        Tier Logic:
        - critical (red):  TLS 1.0/1.1, RC4/3DES ciphers, self-signed cert,
                           expired cert, RSA < 2048, no PFS.
        - medium  (amber): TLS 1.2 only, SHA-1 signature, cert expiry < 30 days,
                           RSA 2048–3071.
        - low     (green): TLS 1.3, strong cipher, cert valid > 30 days,
                           RSA ≥ 3072 or ECC ≥ 384.

        Args:
            asset_id:    Asset primary key.
            scan_id:     Scan primary key.
            auto_commit: Commit session after writing.

        Returns:
            Tier string: 'critical' | 'medium' | 'low'
        """
        from src.models import Certificate, TLSComplianceScore
        from sqlalchemy.exc import IntegrityError

        _INSECURE_TLS = {"TLSv1", "TLSv1.0", "TLS 1.0", "1.0",
                         "TLSv1.1", "TLS 1.1", "1.1"}
        _WEAK_CIPHERS = {"RC4", "3DES", "DES", "NULL", "EXPORT", "ANON"}
        _NO_PFS_HINT = {"RSA_WITH", "_RSA_"}

        certs = db_session.query(
            Certificate.tls_version,
            Certificate.cipher_suite,
            Certificate.signature_algorithm,
            Certificate.key_algorithm,
            Certificate.key_length,
            Certificate.is_self_signed,
            Certificate.is_expired,
            Certificate.valid_until,
        ).filter(
            and_(
                Certificate.asset_id == asset_id,
                Certificate.scan_id == scan_id,
                Certificate.is_deleted == False,
            )
        ).all()

        if not certs:
            tier = "medium"  # No data: default to amber (unknown is not safe)
        else:
            is_critical = False
            is_medium = False

            for cert in certs:
                tls_ver = str(cert.tls_version or "").strip()
                cipher = str(cert.cipher_suite or "").upper()
                sig_algo = str(cert.signature_algorithm or "").upper()
                key_algo = str(cert.key_algorithm or "").upper()
                key_len = int(cert.key_length or 0)
                self_signed = bool(cert.is_self_signed)
                expired = bool(cert.is_expired)
                valid_until = cert.valid_until

                # ── Critical conditions ────────────────────────────────────
                if tls_ver in _INSECURE_TLS:
                    is_critical = True
                if any(w in cipher for w in _WEAK_CIPHERS):
                    is_critical = True
                if self_signed:
                    is_critical = True
                if expired:
                    is_critical = True
                if "RSA" in key_algo and 0 < key_len < 2048:
                    is_critical = True
                if not any(pfs in cipher for pfs in ("ECDHE", "DHE")):
                    if any(hint in cipher for hint in _NO_PFS_HINT):
                        is_critical = True

                # ── Medium conditions (only if not already critical) ────────
                if not is_critical:
                    if tls_ver in ("TLSv1.2", "TLS 1.2", "1.2"):
                        is_medium = True
                    if "SHA1" in sig_algo or "SHA-1" in sig_algo:
                        is_medium = True
                    if valid_until:
                        days_remaining = (valid_until - datetime.now(timezone.utc)).days
                        if days_remaining < 30:
                            is_medium = True
                    if "RSA" in key_algo and 2048 <= key_len < 3072:
                        is_medium = True

            if is_critical:
                tier = "critical"
            elif is_medium:
                tier = "medium"
            else:
                tier = "low"

        # ── Persist to tls_compliance_scores ──────────────────────────────
        try:
            tls_score = db_session.get(TLSComplianceScore, asset_id)
            if not tls_score:
                # Check session.new
                for m in db_session.new:
                    if isinstance(m, TLSComplianceScore) and getattr(m, 'asset_id', None) == asset_id:
                        tls_score = m
                        break
                
                if not tls_score:
                    tls_score = TLSComplianceScore(asset_id=asset_id)
                    db_session.add(tls_score)
            
            tls_score.resilience_tier = tier  # type: ignore[assignment]
            if auto_commit:
                db_session.commit()
        except Exception as e:
            # Removed rollback to avoid session poisoning.
            logger.warning(f"Failed to update risk metrics for asset {asset_id}: {e}")

        return tier
