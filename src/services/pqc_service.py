"""PQC (Post-Quantum Cryptography) Posture Service.

Provides unified interface for calculating quantum-safe readiness metrics
from PQC classifications and asset inventory, ensuring:
- Only active (non-deleted) assets are included
- Metrics aggregated by asset (not scan count)
- Correct percentage calculations (e.g., "% of assets in Elite tier")
- Single source of truth: Asset table joined with PQCClassification
"""

from typing import Dict, List, Optional, Tuple
from collections import Counter, defaultdict
from sqlalchemy import func, asc, desc
from datetime import datetime
import json

from src.db import db_session
from src.models import Asset, PQCClassification, Scan, Certificate


class PQCService:
    """Service for PQC posture metrics and asset readiness calculations."""

    # PQC posture tier thresholds (based on overall asset quantum-safe score)
    PQC_POSTURE_TIERS = {
        "elite": 80,      # Score ≥ 80% (all algorithms quantum-safe)
        "standard": 60,   # Score ≥ 60% and < 80% (mostly quantum-safe)
        "legacy": 40,     # Score ≥ 40% and < 60% (some quantum-safe)
        "critical": 0,    # Score < 40% (mostly quantum-vulnerable)
    }

    _SAFE_STATUSES = {"safe", "quantum_safe", "quantum-safe"}
    _UNSAFE_STATUSES = {"unsafe", "quantum_vulnerable", "quantum-vulnerable", "vulnerable", "migration_advised", "migration-advised", "migration advised"}
    _WEAK_TRANSPORT_MARKERS = {"sslv2", "sslv3", "tls1.0", "tls1.1", "tlsv1", "tlsv1.0", "tlsv1.1"}
    _PLAINTEXT_MARKERS = {"", "unknown", "none", "plaintext", "http"}

    @staticmethod
    def _score_to_pqc_tier(score: float) -> str:
        """Convert PQC score (0-100) to posture tier."""
        score = float(score or 0)
        if score >= PQCService.PQC_POSTURE_TIERS["elite"]:
            return "Elite"
        elif score >= PQCService.PQC_POSTURE_TIERS["standard"]:
            return "Standard"
        elif score >= PQCService.PQC_POSTURE_TIERS["legacy"]:
            return "Legacy"
        return "Critical"

    @staticmethod
    def _normalize_status(value: object) -> str:
        return str(value or "").strip().lower().replace(" ", "_")

    @staticmethod
    def _normalize_tier(value: object) -> str:
        normalized = str(value or "").strip().lower()
        if normalized == "elite":
            return "Elite"
        if normalized == "standard":
            return "Standard"
        if normalized == "legacy":
            return "Legacy"
        if normalized == "critical":
            return "Critical"
        return ""

    @staticmethod
    def get_pqc_dashboard_data(
        asset_id: Optional[int] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
        page: int = 1,
        page_size: int = 100,
        sort_field: str = "asset_name",
        sort_order: str = "asc",
        search_term: str = "",
        status_filter: str = "",
        pqc_ready_only: bool = False,
    ) -> Dict:
        """
        Build comprehensive PQC posture dashboard metrics.

        Aggregates PQC classifications by *asset* (not scan count), ensuring:
        - Only active (is_deleted=False) assets included
        - Metrics based on unique asset counts
        - Correct percentages, distributions, risk heatmap, recommendations

        Args:
            asset_id: Filter to single asset (optional)
            start_date: Filter scans after this date (optional)
            end_date: Filter scans before this date (optional)
            limit: Max rows for telemetry table (default 100)

        Returns:
            Dict with keys:
            - kpis: elite_pct, standard_pct, legacy_pct, critical_count, avg_score
            - grade_counts: {Elite, Standard, Legacy, Critical}
            - status_distribution: {Elite: pct, Standard: pct, ...}
            - risk_heatmap: list of {x, y, value}
            - recommendations: list of strings
            - applications: list of asset records with PQC data
            - meta: {total_assets, scanned_assets}
        """

        try:
            # ===== Query 1: Get all active assets (asset_id optional filter) =====
            asset_query = db_session.query(Asset).filter(Asset.is_deleted == False)
            if asset_id:
                asset_query = asset_query.filter(Asset.id == asset_id)
            assets = asset_query.all()
            total_assets = len(assets)

            if total_assets == 0:
                return PQCService._build_empty_response()

            # ===== Query 2: Get PQC classifications for active assets =====
            pqc_query = (
                db_session.query(PQCClassification)
                .filter(
                    PQCClassification.is_deleted == False,
                    PQCClassification.asset_id.in_([a.id for a in assets])
                )
                .order_by(PQCClassification.asset_id, PQCClassification.pqc_score.desc())
            )

            # Apply date filters on joined Scan table
            if start_date or end_date:
                pqc_query = pqc_query.join(Scan)
                if start_date:
                    pqc_query = pqc_query.filter(Scan.completed_at >= start_date)
                if end_date:
                    pqc_query = pqc_query.filter(Scan.completed_at <= end_date)

            pqc_records = pqc_query.all()

            # ===== Aggregate PQC records by asset =====
            asset_classifications = defaultdict(list)  # asset_id -> [classifications]

            for pqc_record in pqc_records:
                asset_classifications[pqc_record.asset_id].append(pqc_record)
            # ===== Build applications/telemetry table (asset-based, not scan-based) =====
            # Build with full asset set first so KPI math and table rows stay consistent.
            applications = PQCService._build_applications_table(
                assets,
                asset_classifications,
                max(int(limit or 0), len(assets)) if assets else int(limit or 0),
            )

            # Search + sort + pagination for posture support telemetry table.
            search_term = (search_term or "").strip().lower()
            if search_term:
                applications = [
                    r
                    for r in applications
                    if search_term in str(r.get("asset_name", "")).lower()
                    or search_term in str(r.get("status", "")).lower()
                    or search_term in str(r.get("scan_kind", "")).lower()
                    or search_term in str(r.get("pqc_algorithms_display", "")).lower()
                    or search_term in str(r.get("classical_algorithms_display", "")).lower()
                    or search_term in str(r.get("crypto_profile", "")).lower()
                ]

            normalized_status_filter = PQCService._normalize_tier(status_filter)
            if normalized_status_filter:
                applications = [
                    r for r in applications
                    if str(r.get("status") or "") == normalized_status_filter
                ]

            if pqc_ready_only:
                applications = [r for r in applications if bool(r.get("supports_pqc"))]

            # ===== Calculate percentages and metrics from final, consistently filtered rows =====
            effective_total = len(applications)
            tier_counts = Counter(str(row.get("status") or "Critical") for row in applications)
            elite_count = int(tier_counts.get("Elite", 0))
            standard_count = int(tier_counts.get("Standard", 0))
            legacy_count = int(tier_counts.get("Legacy", 0))
            critical_count = int(tier_counts.get("Critical", 0))

            elite_pct = round((elite_count / effective_total * 100), 1) if effective_total > 0 else 0
            standard_pct = round((standard_count / effective_total * 100), 1) if effective_total > 0 else 0
            legacy_pct = round((legacy_count / effective_total * 100), 1) if effective_total > 0 else 0
            critical_pct = round((critical_count / effective_total * 100), 1) if effective_total > 0 else 0

            scores = [float(row.get("score") or 0) for row in applications]
            avg_score = (sum(scores) / len(scores)) if scores else 0

            # ===== Build risk heatmap (asset counts per tier) =====
            risk_heatmap = [
                {"x": "PQC Grade", "y": "Elite", "value": elite_count},
                {"x": "PQC Grade", "y": "Standard", "value": standard_count},
                {"x": "PQC Grade", "y": "Legacy", "value": legacy_count},
                {"x": "PQC Grade", "y": "Critical", "value": critical_count},
            ]

            recommendations = PQCService._build_recommendations(
                effective_total, elite_count, standard_count, legacy_count, critical_count, avg_score
            )

            sort_field = (sort_field or "asset_name").strip().lower()
            sort_order = (sort_order or "asc").strip().lower()
            sort_key_map = {
                "target": lambda r: str(r.get("asset_name") or "").lower(),
                "asset_name": lambda r: str(r.get("asset_name") or "").lower(),
                "status": lambda r: str(r.get("status") or "").lower(),
                "score": lambda r: float(r.get("score") or 0),
                "last_scan": lambda r: str(r.get("last_scan") or ""),
                "scan_kind": lambda r: str(r.get("scan_kind") or "").lower(),
            }
            sort_key = sort_key_map.get(sort_field, sort_key_map["asset_name"])
            applications = sorted(applications, key=sort_key, reverse=(sort_order == "desc"))

            page = max(1, int(page or 1))
            page_size = max(1, min(int(page_size or 100), 250))
            total_count = len(applications)
            total_pages = max(1, (total_count + page_size - 1) // page_size)
            if page > total_pages:
                page = total_pages
            offset = (page - 1) * page_size
            applications_page = applications[offset:offset + page_size]

            # ===== Count scanned assets (assets with crypto telemetry evidence) =====
            scanned_assets = sum(1 for row in applications if bool(row.get("telemetry_available")))

            return {
                "kpis": {
                    "elite_pct": elite_pct,
                    "standard_pct": standard_pct,
                    "legacy_pct": legacy_pct,
                    "critical_count": critical_count,
                    "avg_score": round(avg_score, 1),
                },
                "grade_counts": {
                    "Elite": elite_count,
                    "Standard": standard_count,
                    "Legacy": legacy_count,
                    "Critical": critical_count,
                },
                "status_distribution": {
                    "Elite": elite_pct,
                    "Standard": standard_pct,
                    "Legacy": legacy_pct,
                    "Critical": critical_pct,
                },
                "risk_heatmap": risk_heatmap,
                "recommendations": recommendations,
                "applications": applications_page,
                "page_data": {
                    "items": applications_page,
                    "total_count": total_count,
                    "page": page,
                    "page_size": page_size,
                    "total_pages": total_pages,
                    "has_next": page < total_pages,
                    "has_prev": page > 1,
                },
                "meta": {
                    "total_assets": effective_total,
                    "scanned_assets": scanned_assets,
                },
            }

        except Exception as e:
            print(f"PQCService.get_pqc_dashboard_data error: {e}")
            return PQCService._build_empty_response()

    @staticmethod
    def _build_empty_response() -> Dict:
        """Build empty state response when no assets or PQC data available."""
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
                {"x": "PQC Grade", "y": "Elite", "value": 0},
                {"x": "PQC Grade", "y": "Standard", "value": 0},
                {"x": "PQC Grade", "y": "Legacy", "value": 0},
                {"x": "PQC Grade", "y": "Critical", "value": 0},
            ],
            "recommendations": ["Run scans to populate PQC posture."],
            "applications": [],
            "page_data": {
                "items": [],
                "total_count": 0,
                "page": 1,
                "page_size": 0,
                "total_pages": 1,
                "has_next": False,
                "has_prev": False,
            },
            "meta": {"total_assets": 0, "scanned_assets": 0},
        }

    @staticmethod
    def _build_recommendations(
        total_assets: int, elite: int, standard: int, legacy: int, critical: int, avg_score: float
    ) -> List[str]:
        """Build contextual recommendations based on PQC posture."""
        recs = []

        if total_assets == 0:
            return ["No active assets to assess."]

        recs.append(f"Total scanned assets: {total_assets}")
        recs.append(f"Average PQC readiness: {round(avg_score, 1)}%")

        if critical > 0:
            recs.append(f"Critical applications requiring migration: {critical}")

        if legacy > 0:
            recs.append(f"Legacy applications to upgrade: {legacy}")

        if avg_score < 50:
            recs.append("Priority: Assess and transition to quantum-safe algorithms.")
        elif avg_score < 80:
            recs.append("Recommended: Upgrade remaining legacy systems to NIST-approved PQC.")
        else:
            recs.append("Status: Most assets use quantum-safe cryptography. Maintain compliance.")

        return recs

    @staticmethod
    def _build_applications_table(
        assets: List[Asset],
        asset_classifications: Dict[int, List[PQCClassification]],
        limit: int
    ) -> List[Dict]:
        """Build telemetry table with asset-level PQC data.

        Args:
            assets: List of active assets
            asset_tier_map: asset_id -> (tier, score)
            asset_classifications: asset_id -> [PQCClassification records]
            limit: Max rows to return

        Returns:
            List of dicts with keys: target, status, score, tier, quantum_safe_count, vulnerable_count
        """
        rows = []

        from src.models import Scan as ScanModel

        # Preload latest complete active scan per asset target
        asset_targets = [str(getattr(a, "target", "") or "").strip().lower() for a in assets]
        latest_scan_by_target: Dict[str, ScanModel] = {}
        if asset_targets:
            try:
                scan_rows = (
                    db_session.query(ScanModel)
                    .filter(
                        ScanModel.is_deleted == False,
                        ScanModel.status == "complete",
                        func.lower(ScanModel.target).in_(asset_targets),
                    )
                    .order_by(
                        ScanModel.target.asc(),
                        func.coalesce(ScanModel.scanned_at, ScanModel.completed_at, ScanModel.started_at).desc(),
                        ScanModel.id.desc(),
                    )
                    .all()
                )
            except Exception:
                scan_rows = []

            for s in scan_rows:
                t = str(getattr(s, "target", "") or "").strip().lower()
                if t and t not in latest_scan_by_target:
                    latest_scan_by_target[t] = s

        # Preload latest certificate per asset for TLS/cipher context on posture cards.
        latest_cert_by_asset: Dict[int, Certificate] = {}
        asset_ids = [int(getattr(a, "id", 0) or 0) for a in assets if int(getattr(a, "id", 0) or 0) > 0]
        if asset_ids:
            try:
                cert_rows = (
                    db_session.query(Certificate)
                    .filter(Certificate.is_deleted == False, Certificate.asset_id.in_(asset_ids))
                    .order_by(Certificate.asset_id.asc(), Certificate.valid_until.desc(), Certificate.id.desc())
                    .all()
                )
            except Exception:
                cert_rows = []

            for cert in cert_rows:
                aid = int(getattr(cert, "asset_id", 0) or 0)
                if aid > 0 and aid not in latest_cert_by_asset:
                    latest_cert_by_asset[aid] = cert

        max_rows = len(assets) if int(limit or 0) <= 0 else min(int(limit or 0), len(assets))
        for asset in assets[:max_rows]:
            asset_id = int(getattr(asset, "id", 0) or 0)
            target_key = str(getattr(asset, "target", "") or "").strip().lower()
            latest_scan = latest_scan_by_target.get(target_key)
            latest_cert = latest_cert_by_asset.get(asset_id)
            last_scan = None
            scan_kind = "N/A"
            if latest_scan is not None:
                last_scan = (
                    getattr(latest_scan, "scanned_at", None)
                    or getattr(latest_scan, "completed_at", None)
                    or getattr(latest_scan, "started_at", None)
                )
                raw_report = getattr(latest_scan, "report_json", None)
                if isinstance(raw_report, str):
                    try:
                        report_payload = json.loads(raw_report)
                        if isinstance(report_payload, dict):
                            scan_kind = str(report_payload.get("scan_kind") or "N/A")
                    except Exception:
                        scan_kind = "N/A"

            # Count quantum-safe vs vulnerable algorithms for this asset
            classifications = asset_classifications.get(asset_id, [])
            safe_algorithms: List[str] = []
            classical_algorithms: List[str] = []
            for c in classifications:
                status = PQCService._normalize_status(getattr(c, "quantum_safe_status", ""))
                algo_name = str(getattr(c, "algorithm_name", "") or "").strip()
                normalized_algo = algo_name or str(getattr(c, "algorithm_type", "") or "").strip() or "Unknown"
                if status in PQCService._SAFE_STATUSES:
                    if normalized_algo not in safe_algorithms:
                        safe_algorithms.append(normalized_algo)
                elif status in PQCService._UNSAFE_STATUSES or status:
                    if normalized_algo not in classical_algorithms:
                        classical_algorithms.append(normalized_algo)

            safe_count = len(safe_algorithms)
            vulnerable_count = len(classical_algorithms)

            tls_version = str(getattr(latest_cert, "tls_version", "") or "Unknown") if latest_cert else "Unknown"
            cipher_suite = str(getattr(latest_cert, "cipher_suite", "") or "Unknown") if latest_cert else "Unknown"
            key_length = int(getattr(latest_cert, "key_length", 0) or 0) if latest_cert else 0
            key_algorithm = str(getattr(latest_cert, "key_algorithm", "") or "Unknown") if latest_cert else "Unknown"
            signature_algorithm = str(getattr(latest_cert, "signature_algorithm", "") or "Unknown") if latest_cert else "Unknown"

            normalized_tls = tls_version.strip().lower().replace(" ", "")
            has_pqc = safe_count > 0
            has_telemetry = bool(classifications) or latest_cert is not None
            plaintext_or_no_crypto = normalized_tls in PQCService._PLAINTEXT_MARKERS or not has_telemetry
            weak_transport = normalized_tls in PQCService._WEAK_TRANSPORT_MARKERS
            strong_transport = normalized_tls.startswith("tls1.2") or normalized_tls.startswith("tls1.3")

            signature_norm = signature_algorithm.lower()
            classical_standard = (
                ("sha256" in signature_norm or "sha384" in signature_norm or "sha512" in signature_norm)
                or key_length >= 128
            )

            score = 0.0
            if has_pqc:
                score += 70.0
            if strong_transport:
                score += 15.0
            elif weak_transport:
                score += 5.0

            if key_length >= 256:
                score += 10.0
            elif key_length >= 128:
                score += 8.0
            elif key_length > 0:
                score += 4.0

            if classical_standard:
                score += 7.0

            if vulnerable_count > 0:
                score -= min(35.0, float(vulnerable_count * 8))

            if plaintext_or_no_crypto:
                score -= 55.0

            score = max(0.0, min(100.0, score))

            if plaintext_or_no_crypto:
                tier = "Critical"
            elif has_pqc and score >= 80:
                tier = "Elite"
            elif weak_transport or (0 < key_length < 128) or vulnerable_count > 0:
                tier = "Legacy" if score >= 40 else "Critical"
            elif classical_standard and strong_transport:
                tier = "Standard"
            elif score >= 60:
                tier = "Standard"
            elif score >= 40:
                tier = "Legacy"
            else:
                tier = "Critical"

            if tier == "Elite":
                recommendation = "PQC-ready posture detected. Maintain controls and continuously monitor algorithm inventory."
            elif tier == "Standard":
                recommendation = "Strong classical cryptography detected. Plan migration to NIST-approved PQC algorithms."
            elif tier == "Legacy":
                recommendation = "Legacy or vulnerable crypto present. Prioritize TLS/cipher upgrades before phased PQC rollout."
            else:
                recommendation = "Critical exposure: missing/weak cryptography or plaintext transport. Immediate remediation required."

            pqc_algorithms_display = ", ".join(safe_algorithms[:4]) if safe_algorithms else "None detected"
            classical_algorithms_display = ", ".join(classical_algorithms[:4]) if classical_algorithms else "None detected"
            crypto_profile = f"TLS {tls_version} | {key_algorithm} {key_length if key_length > 0 else '--'} | {signature_algorithm}"

            rows.append({
                "target": asset.target,
                "asset_name": asset.name or asset.target,
                "name": asset.name or asset.target,
                "domain": asset.target,
                "status": tier,
                "score": round(score, 1),
                "readiness": "YES" if tier in {"Elite", "Standard"} else "NO",
                "quantum_safe_algorithms": safe_count,
                "quantum_vulnerable_algorithms": vulnerable_count,
                "pqc_algorithms": safe_algorithms,
                "vulnerable_algorithms": classical_algorithms,
                "pqc_algorithms_display": pqc_algorithms_display,
                "classical_algorithms_display": classical_algorithms_display,
                "tls_version": tls_version,
                "cipher_suite": cipher_suite,
                "key_length": key_length,
                "key_algorithm": key_algorithm,
                "signature_algorithm": signature_algorithm,
                "crypto_profile": crypto_profile,
                "supports_pqc": has_pqc,
                "telemetry_available": has_telemetry,
                "plaintext_or_no_crypto": plaintext_or_no_crypto,
                "recommendation": recommendation,
                "last_scan": last_scan.isoformat() if hasattr(last_scan, "isoformat") and last_scan else "",
                "scan_kind": scan_kind,
                "asset_id": asset_id,
            })

        return rows

    @staticmethod
    def get_pqc_inventory(
        asset_id: Optional[int] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Tuple[List[Dict], int]:
        """Get paginated list of asset PQC classifications (for API endpoint).

        Args:
            asset_id: Filter to single asset (optional)
            limit: Rows per page
            offset: Pagination offset

        Returns:
            Tuple of (rows, total_count)
        """
        try:
            # Only active assets
            asset_query = db_session.query(Asset).filter(Asset.is_deleted == False)
            if asset_id:
                asset_query = asset_query.filter(Asset.id == asset_id)

            assets = asset_query.all()
            asset_ids = [a.id for a in assets]

            if not asset_ids:
                return [], 0

            # Count total PQC records for these assets
            total_count = (
                db_session.query(func.count(PQCClassification.id))
                .filter(
                    PQCClassification.is_deleted == False,
                    PQCClassification.asset_id.in_(asset_ids)
                )
                .scalar() or 0
            )

            # Get paginated records
            pqc_records = (
                db_session.query(PQCClassification)
                .filter(
                    PQCClassification.is_deleted == False,
                    PQCClassification.asset_id.in_(asset_ids)
                )
                .order_by(PQCClassification.asset_id, PQCClassification.id.desc())
                .limit(limit)
                .offset(offset)
                .all()
            )

            rows = [
                {
                    "asset_id": pqc.asset_id,
                    "asset_name": pqc.asset.target if pqc.asset else "Unknown",
                    "algorithm_name": pqc.algorithm_name,
                    "algorithm_type": pqc.algorithm_type,
                    "quantum_safe_status": pqc.quantum_safe_status,
                    "nist_category": pqc.nist_category,
                    "pqc_score": pqc.pqc_score,
                }
                for pqc in pqc_records
            ]

            return rows, total_count

        except Exception as e:
            print(f"PQCService.get_pqc_inventory error: {e}")
            return [], 0
