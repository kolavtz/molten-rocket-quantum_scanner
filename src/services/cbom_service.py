"""
CBOM Service layer for Cryptographic Bill of Materials dashboard and API.

Encapsulates query logic in one service for reusability and easier unit tests.
"""

from datetime import datetime
from typing import Dict, List, Any, Optional

from src.db import db_session
from src.models import Asset, Scan, Certificate, CBOMEntry, CBOMSummary
from sqlalchemy import func, distinct, desc, asc


class CbomService:
    WEAK_TLS_VERSIONS = ["SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1"]

    @staticmethod
    def _build_scan_filters(start_date: Optional[str] = None, end_date: Optional[str] = None) -> List[Any]:
        filters = [
            Asset.is_deleted == False,
            Scan.is_deleted == False,
            Scan.status == "complete",
        ]
        scan_time_expr = func.coalesce(Scan.scanned_at, Scan.completed_at, Scan.started_at)
        if start_date:
            try:
                filters.append(scan_time_expr >= datetime.fromisoformat(start_date))
            except ValueError:
                pass
        if end_date:
            try:
                filters.append(scan_time_expr <= datetime.fromisoformat(end_date))
            except ValueError:
                pass
        return filters

    @staticmethod
    def _build_cert_filters(asset_id: Optional[int] = None) -> List[Any]:
        filters = [
            Asset.is_deleted == False,
            Scan.is_deleted == False,
            Scan.status == "complete",
            Certificate.is_deleted == False,
        ]
        if asset_id is not None:
            filters.append(Certificate.asset_id == asset_id)
        return filters

    @staticmethod
    def _build_applications_query(
        asset_id: Optional[int],
        start_date: Optional[str],
        end_date: Optional[str],
        search_term: str,
    ):
        scan_filters = CbomService._build_scan_filters(start_date, end_date)
        q = (
            db_session.query(Certificate, Asset, Scan)
            .join(Asset, Certificate.asset_id == Asset.id)
            .join(Scan, Certificate.scan_id == Scan.id)
            .filter(*scan_filters)
        )
        if asset_id is not None:
            q = q.filter(Asset.id == asset_id)
        search_term = (search_term or "").strip()
        if search_term:
            like = f"%{search_term}%"
            q = q.filter(
                Asset.target.ilike(like)
                | Certificate.ca.ilike(like)
                | Certificate.cipher_suite.ilike(like)
                | Certificate.tls_version.ilike(like)
            )
        return q

    @classmethod
    def get_cbom_dashboard_data(
        cls,
        asset_id: Optional[int] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        limit: int = 200,
        page: int = 1,
        page_size: int = 100,
        sort_field: str = "asset_name",
        sort_order: str = "asc",
        search_term: str = "",
    ) -> Dict[str, Any]:
        scan_filters = cls._build_scan_filters(start_date, end_date)
        cert_filters = cls._build_cert_filters(asset_id)

        scan_query = (
            db_session.query(Scan, Asset)
            .join(Asset, func.lower(Asset.target) == func.lower(Scan.target))
            .filter(*scan_filters)
        )
        cert_query = (
            db_session.query(Certificate)
            .join(Asset, Certificate.asset_id == Asset.id)
            .join(Scan, Certificate.scan_id == Scan.id)
            .filter(*cert_filters)
        )

        now = datetime.now()

        scan_count = scan_query.count()
        total_applications = cert_query.with_entities(func.count(distinct(Certificate.asset_id))).scalar() or 0

        cert_count = cert_query.count()
        active_certificates = cert_query.filter(Certificate.valid_until != None, Certificate.valid_until >= now).count()
        weak_tls_count = cert_query.filter(Certificate.tls_version.in_(cls.WEAK_TLS_VERSIONS)).count()
        weak_key_count = cert_query.filter(Certificate.key_length != None, Certificate.key_length < 2048).count()
        expired_count = cert_query.filter(Certificate.valid_until != None, Certificate.valid_until < now).count()
        self_signed_count = cert_query.filter(Certificate.issuer != None, Certificate.subject != None, Certificate.issuer == Certificate.subject).count()

        cbom_entry_issue_count = (
            db_session.query(func.count(CBOMEntry.id))
            .join(Scan, CBOMEntry.scan_id == Scan.id)
            .join(Asset, func.lower(Asset.target) == func.lower(Scan.target))
            .filter(Asset.is_deleted == False, Scan.is_deleted == False, Scan.status == "complete", CBOMEntry.quantum_safe_flag == False)
        )
        if asset_id is not None:
            cbom_entry_issue_count = cbom_entry_issue_count.filter(Asset.id == asset_id)
        if start_date or end_date:
            for f in cls._build_scan_filters(start_date, end_date):
                cbom_entry_issue_count = cbom_entry_issue_count.filter(f)
        cbom_entry_issue_count = cbom_entry_issue_count.scalar() or 0

        cbom_summary_issue_sum = (
            db_session.query(func.sum(CBOMSummary.cert_issues_count))
            .join(Scan, CBOMSummary.scan_id == Scan.id)
            .join(Asset, func.lower(Asset.target) == func.lower(Scan.target))
            .filter(Asset.is_deleted == False, Scan.is_deleted == False, Scan.status == "complete")
        )
        if asset_id is not None:
            cbom_summary_issue_sum = cbom_summary_issue_sum.filter(Asset.id == asset_id)
        if start_date or end_date:
            for f in cls._build_scan_filters(start_date, end_date):
                cbom_summary_issue_sum = cbom_summary_issue_sum.filter(f)
        cbom_summary_issue_sum = int(cbom_summary_issue_sum.scalar() or 0)

        weak_cryptography_total = weak_tls_count + weak_key_count + expired_count + self_signed_count
        cbom_issue_total = cbom_entry_issue_count + cbom_summary_issue_sum
        certificate_issues = max(weak_cryptography_total, cbom_issue_total)

        site_count = cert_query.with_entities(func.count(distinct(Certificate.asset_id))).scalar() or 0

        # Distributions
        key_length_dist = {
            str(int(k)) if k is not None else "Unknown": v
            for k, v in db_session.query(Certificate.key_length, func.count(Certificate.id))
            .join(Asset, Certificate.asset_id == Asset.id)
            .join(Scan, Certificate.scan_id == Scan.id)
            .filter(*cert_filters)
            .group_by(Certificate.key_length)
            .all()
        }
        if not key_length_dist:
            key_length_dist = {"No Data": 0}

        cipher_dist = {
            str(k or "Unknown")[:40]: v
            for k, v in db_session.query(Certificate.cipher_suite, func.count(Certificate.id))
            .join(Asset, Certificate.asset_id == Asset.id)
            .join(Scan, Certificate.scan_id == Scan.id)
            .filter(*cert_filters)
            .group_by(Certificate.cipher_suite)
            .order_by(func.count(Certificate.id).desc())
            .limit(10)
            .all()
        }
        if not cipher_dist:
            cipher_dist = {"No Data": 0}

        ca_dist = {
            str(k or "Unknown")[:40]: v
            for k, v in db_session.query(Certificate.ca, func.count(Certificate.id))
            .join(Asset, Certificate.asset_id == Asset.id)
            .join(Scan, Certificate.scan_id == Scan.id)
            .filter(*cert_filters)
            .group_by(Certificate.ca)
            .order_by(func.count(Certificate.id).desc())
            .limit(10)
            .all()
        }
        if not ca_dist:
            ca_dist = {"No Data": 0}

        tls_dist = {
            str(k or "Unknown"): v
            for k, v in db_session.query(Certificate.tls_version, func.count(Certificate.id))
            .join(Asset, Certificate.asset_id == Asset.id)
            .join(Scan, Certificate.scan_id == Scan.id)
            .filter(*cert_filters)
            .group_by(Certificate.tls_version)
            .order_by(func.count(Certificate.id).desc())
            .limit(10)
            .all()
        }
        if not tls_dist:
            tls_dist = {"No Data": 0}

        app_query = cls._build_applications_query(
            asset_id=asset_id,
            start_date=start_date,
            end_date=end_date,
            search_term=search_term,
        )

        sort_field = (sort_field or "asset_name").strip().lower()
        sort_order = (sort_order or "asc").strip().lower()
        sort_map = {
            "asset_name": Asset.target,
            "asset_id": Asset.target,
            "key_length": Certificate.key_length,
            "cipher_suite": Certificate.cipher_suite,
            "ca": Certificate.ca,
            "tls_version": Certificate.tls_version,
            "valid_until": Certificate.valid_until,
            "last_scan": func.coalesce(Scan.scanned_at, Scan.completed_at, Scan.started_at),
        }
        sort_col = sort_map.get(sort_field, Asset.target)
        app_query = app_query.order_by(desc(sort_col) if sort_order == "desc" else asc(sort_col))

        page = max(1, int(page or 1))
        page_size = max(1, min(int(page_size or 100), 250))
        total_count = app_query.count()
        total_pages = max(1, (total_count + page_size - 1) // page_size)
        if page > total_pages:
            page = total_pages
        offset = (page - 1) * page_size

        rows_result = app_query.offset(offset).limit(page_size).all()
        if isinstance(rows_result, list):
            rows = rows_result
        else:
            try:
                rows = list(rows_result)
            except TypeError:
                rows = []
        applications = []
        for cert, asset, scan in rows:
            applications.append(
                {
                    "asset_id": int(getattr(asset, "id", 0) or 0),
                    "asset_name": str(getattr(asset, "target", "") or "Unknown Asset"),
                    "key_length": int(getattr(cert, "key_length", 0) or 0),
                    "cipher_suite": str(getattr(cert, "cipher_suite", "") or "Unknown"),
                    "ca": str(getattr(cert, "ca", "") or getattr(cert, "issuer", "") or "Unknown"),
                    "tls_version": str(getattr(cert, "tls_version", "") or "Unknown"),
                    "valid_until": getattr(cert, "valid_until", None),
                    "last_scan": (
                        getattr(scan, "scanned_at", None)
                        or getattr(scan, "completed_at", None)
                        or getattr(scan, "started_at", None)
                    ),
                }
            )

        if limit:
            applications = applications[: max(1, int(limit))]

        weakness_heatmap = [
            {"x": "Transport", "y": "Weak TLS", "value": weak_tls_count},
            {"x": "Transport", "y": "Weak Keys", "value": weak_key_count},
            {"x": "Lifecycle", "y": "Expired", "value": expired_count},
            {"x": "Identity", "y": "Self-Signed", "value": self_signed_count},
            {"x": "CBOM", "y": "Entry Issues", "value": cbom_entry_issue_count},
            {"x": "CBOM", "y": "Summary Issues", "value": cbom_summary_issue_sum},
        ]

        return {
            "kpis": {
                "total_applications": total_applications,
                "sites_surveyed": site_count,
                "active_certificates": active_certificates,
                "weak_cryptography": weak_cryptography_total,
                "certificate_issues": certificate_issues,
            },
            "key_length_distribution": key_length_dist,
            "cipher_usage": cipher_dist,
            "top_cas": ca_dist,
            "protocols": tls_dist,
            "weakness_heatmap": weakness_heatmap,
            "applications": applications,
            "page_data": {
                "items": applications,
                "total_count": total_count,
                "page": page,
                "page_size": page_size,
                "total_pages": total_pages,
                "has_next": page < total_pages,
                "has_prev": page > 1,
            },
            "meta": {
                "scan_count": scan_count,
                "certificate_count": cert_count,
            },
        }
