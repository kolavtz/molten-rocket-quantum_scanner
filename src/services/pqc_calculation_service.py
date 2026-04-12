"""PQC Score Calculation Service

Implements Math Spec Sections 3.1-3.3:
- Endpoint-level PQC scoring (weighted algorithms)
- Asset-level PQC scoring (average endpoints)
- Asset Classification (Elite/Standard/Legacy/Critical)

All calculations persist to asset_metrics table.
"""

from __future__ import annotations

from datetime import datetime, timezone
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
        # Note: We avoid try/except IntegrityError + rollback because it poisons
        # the session for the caller. If a race condition occurs, the caller
        # will hit the exception on final commit.
        metric = AssetMetric(asset_id=asset_id)
        db_session.add(metric)
        return metric

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
        metric.pqc_score_timestamp = datetime.now(timezone.utc)
        metric.risk_penalty = risk_penalty
        metric.total_findings_count = total_findings
        metric.critical_findings_count = critical_findings
        metric.pqc_class_tier = tier
        metric.has_critical_findings = has_critical
        metric.asset_cyber_score = asset_cyber_score
        metric.calculated_at = datetime.now(timezone.utc)
        
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

    # ── Sprint 3: HNDL Detection ────────────────────────────────────────────

    @staticmethod
    def detect_hndl_risk(asset_id: int, scan_id: int, auto_commit: bool = True) -> dict:
        """
        Detect Harvest-Now-Decrypt-Later (HNDL) exposure for an asset.

        Detection criteria:
        - RSA key size < 3072 bits (NIST minimum for long-term quantum safety)
        - ECC key size < 384 bits  (P-384 minimum for post-2030 quantum safety)
        - TLS 1.2 only without Perfect Forward Secrecy (PFS) ciphers
        - Certificate validity extending beyond 2030-01-01

        Args:
            asset_id: Asset primary key.
            scan_id:  Scan primary key.
            auto_commit: Commit session after writing.

        Returns:
            dict with keys: hndl_risk_score (float 0-100), flags (list[str])
        """
        import json as _json
        from src.models import Certificate

        _HNDL_YEAR_CUTOFF = datetime(2030, 1, 1)
        _RSA_MIN_BITS = 3072
        _ECC_MIN_BITS = 384
        _PFS_CIPHER_KEYWORDS = {"ECDHE", "DHE", "ECDH", "DH"}
        _flags: list[str] = []

        # ── Analyse certificates for this asset/scan ───────────────────────
        certs = db_session.query(
            Certificate.key_algorithm,
            Certificate.key_length,
            Certificate.tls_version,
            Certificate.cipher_suite,
            Certificate.valid_until,
        ).filter(
            and_(
                Certificate.asset_id == asset_id,
                Certificate.scan_id == scan_id,
                Certificate.is_deleted == False,
            )
        ).all()

        for cert in certs:
            key_algo = str(cert.key_algorithm or "").upper()
            key_len = int(cert.key_length or 0)
            tls_ver = str(cert.tls_version or "").strip()
            cipher = str(cert.cipher_suite or "").upper()
            valid_until = cert.valid_until

            # Flag 1: Weak RSA key
            if "RSA" in key_algo and key_len > 0 and key_len < _RSA_MIN_BITS:
                _flags.append(f"weak_rsa_{key_len}bit")

            # Flag 2: Weak ECC key
            if any(k in key_algo for k in ("ECC", "ECDSA", "EC")) and key_len > 0 and key_len < _ECC_MIN_BITS:
                _flags.append(f"weak_ecc_{key_len}bit")

            # Flag 3: TLS 1.2 without PFS
            if tls_ver in ("TLSv1.2", "TLS 1.2", "1.2") and not any(kw in cipher for kw in _PFS_CIPHER_KEYWORDS):
                _flags.append("tls12_no_pfs")

            # Flag 4: Certificate valid beyond 2030
            if valid_until and valid_until > _HNDL_YEAR_CUTOFF:
                _flags.append(f"cert_valid_post_2030:{valid_until.strftime('%Y-%m-%d')}")

        # ── Deduplicate flag categories ────────────────────────────────────
        seen: set[str] = set()
        unique_flags: list[str] = []
        for f in _flags:
            # Normalise to category prefix only for dedup
            cat = f.split(":")[0].rstrip("0123456789_")
            if cat not in seen:
                seen.add(cat)
                unique_flags.append(f)

        # ── Score calculation (additive penalty model) ─────────────────────
        # Each distinct flag category contributes a penalty.
        _PENALTY_MAP = {
            "weak_rsa": 40.0,
            "weak_ecc": 35.0,
            "tls12_no_pfs": 30.0,
            "cert_valid_post_2030": 20.0,
        }
        total_penalty = 0.0
        for flag in unique_flags:
            for prefix, penalty in _PENALTY_MAP.items():
                if flag.startswith(prefix):
                    total_penalty += penalty
                    break

        hndl_score = min(100.0, total_penalty)

        # ── Persist to asset_metrics ───────────────────────────────────────
        try:
            metric = PQCCalculationService._get_or_create_asset_metric(asset_id)
            metric.hndl_risk_score = hndl_score
            metric.hndl_flags = _json.dumps(unique_flags)
            if auto_commit:
                db_session.commit()
        except Exception as e:
            # Removed rollback to avoid session poisoning. 
            # The caller handles final transaction state.
            logger.warning(f"Failed to update asset metrics for {asset_id}: {e}")

        return {
            "hndl_risk_score": hndl_score,
            "flags": unique_flags,
            "flag_count": len(unique_flags),
            "is_hndl_exposed": hndl_score > 0,
        }

    @staticmethod
    def get_org_hndl_summary() -> dict:
        """
        Return organisation-wide HNDL exposure summary from asset_metrics.

        Returns:
            dict with total_exposed, avg_hndl_score, top_flags, exposed_assets list.
        """
        import json as _json

        metrics = db_session.query(
            AssetMetric.asset_id,
            AssetMetric.hndl_risk_score,
            AssetMetric.hndl_flags,
        ).filter(
            AssetMetric.hndl_risk_score.isnot(None),
            AssetMetric.hndl_risk_score > 0,
        ).all()

        if not metrics:
            return {
                "total_exposed": 0,
                "avg_hndl_score": 0.0,
                "top_flags": [],
                "exposed_assets": [],
            }

        scores = [float(m.hndl_risk_score or 0) for m in metrics]
        flag_counts: Dict[str, int] = {}
        exposed: list[dict] = []

        for m in metrics:
            flags = []
            try:
                if m.hndl_flags:
                    flags = _json.loads(m.hndl_flags)
            except Exception:
                pass
            for f in flags:
                cat = f.split(":")[0]
                flag_counts[cat] = flag_counts.get(cat, 0) + 1
            exposed.append({"asset_id": m.asset_id, "score": float(m.hndl_risk_score or 0), "flags": flags})

        top_flags = sorted(flag_counts.items(), key=lambda x: x[1], reverse=True)
        return {
            "total_exposed": len(metrics),
            "avg_hndl_score": round(sum(scores) / len(scores), 2),
            "top_flags": [{"flag": k, "count": v} for k, v in top_flags[:5]],
            "exposed_assets": sorted(exposed, key=lambda x: x["score"], reverse=True)[:20],
        }
