from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from flask import Blueprint, Response, request
from flask_login import login_required
from sqlalchemy import func, inspect, or_, text

from middleware.api_auth import api_guard
from src import database as db
from src.db import db_session
from src.models import (
    Asset,
    AssetMetric,
    CBOMEntry,
    CBOMSummary,
    Certificate,
    ComplianceScore,
    DiscoveryDomain,
    DiscoveryIP,
    DiscoverySoftware,
    DiscoverySSL,
    DigitalLabel,
    PQCClassification,
    Scan,
)
from src.services.cbom_service import CbomService
from src.services.cyber_reporting_service import CyberReportingService
from src.services.distribution_service import DistributionService
from src.services.pqc_service import PQCService
from src.services.risk_calculation_service import RiskCalculationService
from src.services.asset_service import AssetService
from src.services.geo_service import GeoService
from utils.api_helper import (
    apply_sort,
    build_data_envelope,
    error_response,
    parse_paging_args,
    success_response,
    to_iso,
)

api_dashboards_bp = Blueprint("api_dashboards", __name__)

PQC_STATUS_EXPLANATIONS = {
    "safe": "Algorithms or certificates currently classified as quantum-safe.",
    "unsafe": "Cryptography currently classified as not quantum-safe.",
    "migration_advised": "Still operational but migration to stronger/PQC alternatives is advised.",
    "unknown": "Insufficient telemetry to confidently classify PQC status.",
}

PQC_TIER_EXPLANATIONS = {
    "elite": "PQC-ready workloads using post-quantum algorithms with strong transport posture.",
    "standard": "Strong classical cryptography (e.g., SHA-2/modern key sizes) but PQC migration still pending.",
    "legacy": "Weak or aging cryptographic posture that requires prioritized upgrade and migration planning.",
    "critical": "No trustworthy crypto telemetry, plaintext exposure, or critically weak cryptography requiring immediate action.",
}

asset_service = AssetService()
geo_service = GeoService()


def _safe_ratio(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 0.0
    return round((numerator / denominator) * 100.0, 2)


def _filters_payload(params: dict[str, Any], extra: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = {
        "sort": params.get("sort", "id"),
        "order": params.get("order", "asc"),
        "search": params.get("search", ""),
    }
    if extra:
        payload.update(extra)
    return payload


def _table_exists(table_name: str) -> bool:
    try:
        bind = db_session.get_bind()
        return bool(bind is not None and inspect(bind).has_table(table_name))
    except Exception:
        return False


def _coerce_int(value: Any) -> int | None:
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _split_discovery_tab_query(tab: str, params: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    config = {
        "domains": {
            "table": "discovery_domains",
            "value_col": "domain",
            "name_expr": "d.domain",
            "search_cols": ["d.domain", "a.target", "a.owner"],
            "sort_map": {
                "id": "d.id",
                "name": "d.domain",
                "detection_date": "COALESCE(d.updated_at, d.created_at)",
                "status": "d.status",
            },
        },
        "ips": {
            "table": "discovery_ips",
            "value_col": "ip_address",
            "name_expr": "d.ip_address",
            "search_cols": ["d.ip_address", "d.location", "a.target", "a.owner"],
            "sort_map": {
                "id": "d.id",
                "name": "d.ip_address",
                "detection_date": "COALESCE(d.updated_at, d.created_at)",
                "status": "d.status",
            },
        },
        "software": {
            "table": "discovery_software",
            "value_col": "product",
            "name_expr": "CONCAT(COALESCE(d.product, ''), CASE WHEN COALESCE(d.version, '') = '' THEN '' ELSE CONCAT(' ', d.version) END)",
            "search_cols": ["d.product", "d.version", "d.category", "a.target", "a.owner"],
            "sort_map": {
                "id": "d.id",
                "name": "d.product",
                "detection_date": "COALESCE(d.updated_at, d.created_at)",
                "status": "d.status",
            },
        },
        "subdomains": {
            "table": "subdomains",
            "value_col": "subdomain",
            "name_expr": "d.subdomain",
            "search_cols": ["d.subdomain", "a.target", "a.owner"],
            "sort_map": {
                "id": "d.id",
                "name": "d.subdomain",
                "detection_date": "d.discovered_at",
                "status": "''", # Subdomains don't have a status column yet in the schema provided
            },
        },
    }.get(tab)
    if not config or not _table_exists(config["table"]):
        return [], 0

    like = f"%{params['search']}%" if params.get("search") else None
    where_parts = ["COALESCE(d.is_deleted, 0) = 0"]
    sql_params: dict[str, Any] = {
        "limit": params["page_size"],
        "offset": (params["page"] - 1) * params["page_size"],
    }
    if like:
        search_clauses = []
        for idx, column_name in enumerate(config["search_cols"]):
            key = f"search_{idx}"
            sql_params[key] = like
            search_clauses.append(f"{column_name} LIKE :{key}")
        where_parts.append("(" + " OR ".join(search_clauses) + ")")

    where_sql = " AND ".join(where_parts)
    sort_sql = config["sort_map"].get(params.get("sort") or "", config["sort_map"]["detection_date"])
    order_sql = "DESC" if str(params.get("order", "asc")).lower() == "desc" else "ASC"
    query_sql = f"""
        SELECT
            d.id,
            {config["name_expr"]} AS name,
            d.status,
            COALESCE(d.updated_at, d.created_at) AS detection_date,
            a.id AS asset_id,
            a.target AS asset_name,
            a.owner AS owner
        FROM {config["table"]} d
        LEFT JOIN assets a
            ON a.id = d.asset_id
           AND COALESCE(a.is_deleted, 0) = 0
        WHERE {where_sql}
        ORDER BY {sort_sql} {order_sql}, d.id DESC
        LIMIT :limit OFFSET :offset
    """
    count_sql = f"SELECT COUNT(*) FROM {config['table']} d LEFT JOIN assets a ON a.id = d.asset_id AND COALESCE(a.is_deleted, 0) = 0 WHERE {where_sql}"

    rows = db_session.execute(text(query_sql), sql_params).mappings().all()
    total = int(db_session.execute(text(count_sql), sql_params).scalar() or 0)
    items = [
        {
            "id": _coerce_int(row.get("id")) or 0,
            "tab": tab,
            "detection_date": to_iso(row.get("detection_date")),
            "name": str(row.get("name") or "").strip() or None,
            "status": row.get("status"),
            "asset_id": _coerce_int(row.get("asset_id")),
            "asset_name": row.get("asset_name"),
            "owner": row.get("owner"),
        }
        for row in rows
    ]
    return items, total


def _ssl_discovery_query(params: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    # Prefer the canonical certificate table for SSL discovery and only fallback to legacy view.
    base = (
        db_session.query(Certificate, Asset)
        .join(Asset, Certificate.asset_id == Asset.id)
        .filter(Certificate.is_deleted == False, Asset.is_deleted == False)
    )

    if params.get("search"):
        q = params.get("search")
        like = f"%{q}%"
        base = base.filter(
            or_(
                Asset.target.ilike(like),
                Certificate.issuer.ilike(like),
                Certificate.cipher_suite.ilike(like),
                Certificate.subject_cn.ilike(like),
            )
        )

    sort_map = {
        "id": Certificate.id,
        "name": Asset.target,
        "valid_until": Certificate.valid_until,
        "issuer": Certificate.issuer,
        "key_length": Certificate.key_length,
    }
    base = apply_sort(base, params["sort"], params["order"], sort_map, Certificate.id)
    total = int(base.count())
    rows = base.offset((params["page"] - 1) * params["page_size"]).limit(params["page_size"]).all()

    if rows:
        return (
            [
                {
                    "id": int(cert.id),
                    "tab": "ssl",
                    "name": str(asset.target),
                    "issuer": cert.issuer,
                    "subject_cn": cert.subject_cn,
                    "valid_until": to_iso(cert.valid_until),
                    "key_length": cert.key_length,
                    "tls_version": cert.tls_version,
                    "cipher_suite": cert.cipher_suite,
                    "status": "Expired" if cert.is_expired else "Valid",
                    "asset_id": int(asset.id) if asset else None,
                    "owner": asset.owner if asset else None,
                }
                for cert, asset in rows
            ],
            total,
        )

    # Legacy fallback for mixed-schema environments
    if _table_exists("discovery_ssl"):
        like = f"%{params['search']}%" if params.get("search") else None
        where_parts = ["COALESCE(d.is_deleted, 0) = 0"]
        sql_params: dict[str, Any] = {
            "limit": params["page_size"],
            "offset": (params["page"] - 1) * params["page_size"],
        }
        if like:
            for idx, column_name in enumerate(("d.endpoint", "d.issuer", "d.subject_cn", "d.cipher_suite", "a.target", "a.owner")):
                key = f"search_{idx}"
                sql_params[key] = like
            search_clauses = [f"{column_name} LIKE :search_{idx}" for idx, column_name in enumerate(("d.endpoint", "d.issuer", "d.subject_cn", "d.cipher_suite", "a.target", "a.owner"))]
            where_parts.append("(" + " OR ".join(search_clauses) + ")")
        where_sql = " AND ".join(where_parts)
        sort_sql = {
            "id": "d.id",
            "name": "d.endpoint",
            "valid_until": "d.valid_until",
            "issuer": "d.issuer",
            "key_length": "d.key_length",
        }.get(params.get("sort") or "", "COALESCE(d.updated_at, d.created_at)")
        order_sql = "DESC" if str(params.get("order", "asc")).lower() == "desc" else "ASC"
        query_sql = f"""
            SELECT
                d.id,
                d.endpoint AS name,
                d.issuer,
                d.subject_cn,
                d.valid_until,
                d.key_length,
                d.tls_version,
                d.cipher_suite,
                d.status,
                a.id AS asset_id,
                a.owner AS owner
            FROM discovery_ssl d
            LEFT JOIN assets a
                ON a.id = d.asset_id
               AND COALESCE(a.is_deleted, 0) = 0
            WHERE {where_sql}
            ORDER BY {sort_sql} {order_sql}, d.id DESC
            LIMIT :limit OFFSET :offset
        """
        count_sql = f"SELECT COUNT(*) FROM discovery_ssl d LEFT JOIN assets a ON a.id = d.asset_id AND COALESCE(a.is_deleted, 0) = 0 WHERE {where_sql}"
        rows = db_session.execute(text(query_sql), sql_params).mappings().all()
        total = int(db_session.execute(text(count_sql), sql_params).scalar() or 0)
        return (
            [
                {
                    "id": _coerce_int(row.get("id")) or 0,
                    "tab": "ssl",
                    "name": row.get("name"),
                    "issuer": row.get("issuer"),
                    "subject_cn": row.get("subject_cn"),
                    "valid_until": to_iso(row.get("valid_until")),
                    "key_length": _coerce_int(row.get("key_length")) or 0,
                    "tls_version": row.get("tls_version"),
                    "cipher_suite": row.get("cipher_suite"),
                    "status": row.get("status"),
                    "asset_id": _coerce_int(row.get("asset_id")),
                    "owner": row.get("owner"),
                }
                for row in rows
            ],
            total,
        )

    return [], 0


def _discovery_kpis() -> dict[str, int]:
    table_counts = {}
    for table_name, key in (
        ("discovery_domains", "domains"),
        ("discovery_ips", "ips"),
        ("discovery_software", "software"),
        ("discovery_ssl", "ssl"),
    ):
        if _table_exists(table_name):
            count_sql = text(f"SELECT COUNT(*) FROM {table_name} WHERE COALESCE(is_deleted, 0) = 0")
            table_counts[key] = int(db_session.execute(count_sql).scalar() or 0)
        else:
            table_counts[key] = 0

    if table_counts["ssl"] == 0:
        table_counts["ssl"] = int(
            db_session.query(func.count(Certificate.id))
            .join(Asset, Certificate.asset_id == Asset.id)
            .filter(Certificate.is_deleted == False, Asset.is_deleted == False)
            .scalar()
            or 0
        )

    return {
        "total_discovery_records": int(sum(table_counts.values())),
        "domains": int(table_counts["domains"]),
        "ssl": int(table_counts["ssl"]),
        "ips": int(table_counts["ips"]),
        "software": int(table_counts["software"]),
    }


def _normalize_distribution_items(raw_distribution: dict[str, dict[str, Any]], label_key: str = "name") -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for key, value in (raw_distribution or {}).items():
        if isinstance(value, dict):
            count = int(value.get("count") or 0)
            pct = round(float(value.get("pct") or 0), 2)
        else:
            count = int(value or 0)
            pct = 0.0
        items.append(
            {
                label_key: key,
                "count": count,
                "pct": pct,
            }
        )
    return items


def _paginate_distribution_items(items: list[dict[str, Any]], params: dict[str, Any], label_key: str = "name") -> tuple[list[dict[str, Any]], int]:
    search_value = str(params.get("search") or "").strip().lower()
    filtered_items = items
    if search_value:
        filtered_items = [
            item
            for item in items
            if search_value in str(item.get(label_key, "")).lower()
        ]

    sort_key = str(params.get("sort") or "count").lower()
    reverse = str(params.get("order") or "desc").lower() == "desc"
    if sort_key in {"count", "pct"}:
        filtered_items = sorted(filtered_items, key=lambda row: float(row.get(sort_key) or 0), reverse=reverse)
    else:
        filtered_items = sorted(filtered_items, key=lambda row: str(row.get(label_key, "")).lower(), reverse=reverse)

    total = len(filtered_items)
    offset = (params["page"] - 1) * params["page_size"]
    paged_items = filtered_items[offset : offset + params["page_size"]]
    return paged_items, total


@api_dashboards_bp.app_errorhandler(404)
def api_not_found(_err):
    if request.path.startswith("/api/"):
        return error_response("API endpoint not found.", 404, hint="Check endpoint path and parameters.")
    return _err


@api_dashboards_bp.app_errorhandler(500)
def api_internal_error(_err):
    if request.path.startswith("/api/"):
        return error_response("Unexpected API error.", 500, hint="Please retry. If it persists, contact administrator.")
    return _err


@api_dashboards_bp.route("/api/home/metrics", methods=["GET"])
@login_required
@api_guard
def api_home_metrics():
    try:
        total_assets = (
            db_session.query(func.count(Asset.id)).filter(Asset.is_deleted == False).scalar() or 0
        )
        total_scans = (
            db_session.query(func.count(Scan.id)).filter(Scan.is_deleted == False).scalar() or 0
        )
        quantum_safe_pct = (
            db_session.query(func.avg(PQCClassification.pqc_score))
            .filter(
                PQCClassification.is_deleted == False,
                func.lower(PQCClassification.quantum_safe_status).in_(("safe", "quantum_safe", "quantum-safe")),
            )
            .scalar()
            or 0
        )
        vulnerable_assets = (
            db_session.query(func.count(Asset.id))
            .filter(
                Asset.is_deleted == False,
                func.lower(Asset.risk_level).in_(("critical", "high")),
            )
            .scalar()
            or 0
        )
        avg_pqc_score = (
            db_session.query(func.avg(ComplianceScore.score_value))
            .filter(ComplianceScore.is_deleted == False, func.lower(ComplianceScore.type) == "pqc")
            .scalar()
            or 0
        )

        data = build_data_envelope(
            items=[],
            total=0,
            params={"page": 1, "page_size": 25},
            kpis={
                "total_assets": int(total_assets),
                "total_scans": int(total_scans),
                "quantum_safe_pct": round(float(quantum_safe_pct), 1),
                "vulnerable_assets": int(vulnerable_assets),
                "avg_pqc_score": round(float(avg_pqc_score), 1),
            },
        )
        return success_response(data, filters={})
    except Exception as exc:
        return error_response(f"Failed to load home metrics: {exc}", 500)


@api_dashboards_bp.route("/api/distributions/asset-types", methods=["GET"])
@login_required
@api_guard
def api_distribution_asset_types():
    params = parse_paging_args(default_sort="count")
    distribution = DistributionService.get_asset_type_distribution()
    all_items = _normalize_distribution_items(distribution, label_key="asset_type")
    items, total = _paginate_distribution_items(all_items, params, label_key="asset_type")
    total_assets = sum(int(row.get("count") or 0) for row in all_items)

    data = build_data_envelope(
        items,
        total,
        params,
        {
            "total_assets": int(total_assets),
            "categories": int(len(all_items)),
        },
    )
    return success_response(data, filters=_filters_payload(params))


@api_dashboards_bp.route("/api/distributions/risk-levels", methods=["GET"])
@login_required
@api_guard
def api_distribution_risk_levels():
    params = parse_paging_args(default_sort="count")
    distribution = DistributionService.get_risk_level_distribution()
    all_items = _normalize_distribution_items(distribution, label_key="risk_level")
    items, total = _paginate_distribution_items(all_items, params, label_key="risk_level")
    total_assets = sum(int(row.get("count") or 0) for row in all_items)

    data = build_data_envelope(
        items,
        total,
        params,
        {
            "total_assets": int(total_assets),
            "levels": int(len(all_items)),
            "critical_assets": int(next((row.get("count") for row in all_items if str(row.get("risk_level", "")).lower() == "critical"), 0) or 0),
        },
    )
    return success_response(data, filters=_filters_payload(params))


@api_dashboards_bp.route("/api/distributions/ip-versions", methods=["GET"])
@login_required
@api_guard
def api_distribution_ip_versions():
    params = parse_paging_args(default_sort="count")
    distribution = DistributionService.get_ipv4_ipv6_distribution()
    all_items = [
        {
            "ip_version": key,
            "count": int((value or {}).get("count") or 0),
            "pct": round(float((value or {}).get("pct") or 0), 2),
        }
        for key, value in (distribution or {}).items()
    ]
    items, total = _paginate_distribution_items(all_items, params, label_key="ip_version")
    total_assets = sum(int(row.get("count") or 0) for row in all_items)

    data = build_data_envelope(
        items,
        total,
        params,
        {
            "total_assets": int(total_assets),
            "dual_stack": int(next((row.get("count") for row in all_items if row.get("ip_version") == "dual_stack"), 0) or 0),
        },
    )
    return success_response(data, filters=_filters_payload(params))


@api_dashboards_bp.route("/api/distributions/cert-expiry", methods=["GET"])
@login_required
@api_guard
def api_distribution_cert_expiry():
    params = parse_paging_args(default_sort="count")
    buckets = DistributionService.calculate_cert_expiry_buckets()
    total_certificates = int((buckets or {}).get("total_active", 0) or 0) + int((buckets or {}).get("total_expired", 0) or 0)

    bucket_items = [
        {"bucket": "0-30_days", "count": int((buckets or {}).get("count_0_to_30_days", 0) or 0)},
        {"bucket": "31-60_days", "count": int((buckets or {}).get("count_31_to_60_days", 0) or 0)},
        {"bucket": "61-90_days", "count": int((buckets or {}).get("count_61_to_90_days", 0) or 0)},
        {"bucket": ">90_days", "count": int((buckets or {}).get("count_greater_90_days", 0) or 0)},
        {"bucket": "expired", "count": int((buckets or {}).get("count_expired", 0) or 0)},
    ]
    for row in bucket_items:
        row["pct"] = round((float(row["count"]) / total_certificates) * 100.0, 2) if total_certificates > 0 else 0.0

    items, total = _paginate_distribution_items(bucket_items, params, label_key="bucket")
    data = build_data_envelope(
        items,
        total,
        params,
        {
            "total_certificates": int(total_certificates),
            "total_active": int((buckets or {}).get("total_active", 0) or 0),
            "total_expired": int((buckets or {}).get("total_expired", 0) or 0),
        },
    )
    return success_response(data, filters=_filters_payload(params))


@api_dashboards_bp.route("/api/assets/distribution/by-type", methods=["GET"])
@login_required
@api_guard
def api_assets_distribution_by_type():
    distribution = DistributionService.get_asset_type_distribution()
    items = [
        {
            "asset_type": key,
            "count": int((value or {}).get("count", 0) or 0),
            "pct": float((value or {}).get("pct", 0) or 0.0),
        }
        for key, value in distribution.items()
    ]
    total = sum(int(item["count"]) for item in items)
    return success_response(
        {
            "items": items,
            "total": len(items),
            "kpis": {
                "total_assets": int(total),
                "categories": int(len(items)),
            },
        },
        filters={},
    )


@api_dashboards_bp.route("/api/assets/distribution/by-risk", methods=["GET"])
@login_required
@api_guard
def api_assets_distribution_by_risk():
    distribution = DistributionService.get_risk_level_distribution()
    order = ["Critical", "High", "Medium", "Low"]
    items = [
        {
            "risk_level": level,
            "count": int((distribution.get(level) or {}).get("count", 0) or 0),
            "pct": float((distribution.get(level) or {}).get("pct", 0) or 0.0),
        }
        for level in order
    ]
    total = sum(int(item["count"]) for item in items)
    return success_response(
        {
            "items": items,
            "total": len(items),
            "kpis": {
                "total_assets": int(total),
                "critical": int((distribution.get("Critical") or {}).get("count", 0) or 0),
                "high": int((distribution.get("High") or {}).get("count", 0) or 0),
            },
        },
        filters={},
    )


@api_dashboards_bp.route("/api/assets/risk-percentage", methods=["GET"])
@login_required
@api_guard
def api_assets_risk_percentage():
    metrics = DistributionService.get_high_risk_metrics()
    return success_response(
        {
            "items": [
                {
                    "high_risk_count": int(metrics.get("high_risk_count", 0) or 0),
                    "total_assets": int(metrics.get("total_assets", 0) or 0),
                    "high_risk_pct": float(metrics.get("high_risk_pct", 0.0) or 0.0),
                    "distribution": metrics.get("distribution", {}),
                }
            ],
            "total": 1,
            "kpis": {
                "high_risk_pct": float(metrics.get("high_risk_pct", 0.0) or 0.0),
            },
        },
        filters={},
    )


@api_dashboards_bp.route("/api/certificates/expiry-timeline", methods=["GET"])
@login_required
@api_guard
def api_certificates_expiry_timeline():
    buckets = DistributionService.calculate_cert_expiry_buckets()
    items = [
        {
            "bucket": "0-30",
            "count": int(buckets.get("count_0_to_30_days", 0) or 0),
        },
        {
            "bucket": "30-60",
            "count": int(buckets.get("count_31_to_60_days", 0) or 0),
        },
        {
            "bucket": "60-90",
            "count": int(buckets.get("count_61_to_90_days", 0) or 0),
        },
        {
            "bucket": "90+",
            "count": int(buckets.get("count_greater_90_days", 0) or 0),
        },
    ]
    return success_response(
        {
            "items": items,
            "total": len(items),
            "kpis": {
                "total_active": int(buckets.get("total_active", 0) or 0),
                "total_expired": int(buckets.get("total_expired", 0) or 0),
                "expiring_30_days": int(buckets.get("count_0_to_30_days", 0) or 0),
            },
        },
        filters={},
    )


@api_dashboards_bp.route("/api/assets/high-risk", methods=["GET"])
@login_required
@api_guard
def api_assets_high_risk():
    limit = max(1, min(request.args.get("limit", default=10, type=int), 100))
    rows = [
        asset
        for asset in asset_service.load_combined_assets()
        if str(asset.get("risk_level") or "").strip() in {"Critical", "High"}
    ]
    rows = sorted(rows, key=lambda row: float(row.get("risk_score") or 0), reverse=True)[:limit]

    items = [
        {
            "asset_id": int(row.get("id") or 0),
            "asset_name": row.get("name") or row.get("asset_name"),
            "asset_type": row.get("asset_type") or row.get("type") or "Unknown",
            "risk_score": float(row.get("risk_score") or 0.0),
            "last_scan_date": row.get("last_scan"),
            "url": row.get("url"),
        }
        for row in rows
    ]

    return success_response(
        {
            "items": items,
            "total": len(items),
            "kpis": {
                "high_risk_count": len(items),
                "limit": limit,
            },
        },
        filters={"limit": limit},
    )


@api_dashboards_bp.route("/api/assets/recent-discoveries", methods=["GET"])
@login_required
@api_guard
def api_assets_recent_discoveries():
    days = max(1, min(request.args.get("days", default=7, type=int), 90))
    discoveries = asset_service.get_recent_discoveries(days=days)

    items = [
        {
            "asset_name": row.get("name"),
            "asset_type": row.get("type"),
            "discovery_date": row.get("date"),
            "risk_score": row.get("risk"),
            "source": row.get("source"),
        }
        for row in discoveries
    ]

    return success_response(
        {
            "items": items,
            "total": len(items),
            "kpis": {
                "days": days,
                "count": len(items),
            },
        },
        filters={"days": days},
    )


@api_dashboards_bp.route("/api/vulnerabilities/top-software", methods=["GET"])
@login_required
@api_guard
def api_vulnerabilities_top_software():
    limit = max(1, min(request.args.get("limit", default=5, type=int), 50))
    top_software = asset_service.get_top_vulnerable_software(limit=limit)
    items = [
        {
            "software_name": row.get("product"),
            "occurrence_count": int(row.get("count", 0) or 0),
        }
        for row in top_software
    ]

    return success_response(
        {
            "items": items,
            "total": len(items),
            "kpis": {
                "limit": limit,
            },
        },
        filters={"limit": limit},
    )


@api_dashboards_bp.route("/api/assets/geo-locations", methods=["GET"])
@login_required
@api_guard
def api_assets_geo_locations():
    limit = max(1, min(request.args.get("limit", default=200, type=int), 500))
    items = []
    seen_targets = set()
    for asset in asset_service.load_combined_assets():
        target = str(asset.get("name") or asset.get("asset_name") or "").strip()
        if not target or target in seen_targets:
            continue
        seen_targets.add(target)

        loc = geo_service.get_location(target)
        if str(loc.get("status") or "").lower() not in {"success", "private"}:
            continue

        items.append(
            {
                "asset_id": int(asset.get("id") or 0),
                "asset_name": target,
                "asset_type": asset.get("asset_type") or asset.get("type") or "Unknown",
                "risk_level": asset.get("risk_level") or asset.get("risk") or "Medium",
                "latitude": float(loc.get("lat") or 0.0),
                "longitude": float(loc.get("lon") or 0.0),
                "city": loc.get("city") or "Unknown",
                "country": loc.get("country") or "Unknown",
            }
        )

        if len(items) >= limit:
            break

    return success_response(
        {
            "items": items,
            "total": len(items),
            "kpis": {
                "mapped_assets": len(items),
            },
        },
        filters={"limit": limit},
    )


@api_dashboards_bp.route("/api/enterprise-metrics", methods=["GET"])
@login_required
@api_guard
def api_enterprise_metrics():
    params = parse_paging_args(default_sort="asset_cyber_score")

    cyber_data = CyberReportingService.get_cyber_rating_data(limit=2000)
    if _table_exists("findings"):
        vulnerability = RiskCalculationService.get_vulnerability_summary()
    else:
        vulnerability = {
            "total_findings": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "assets_with_critical": 0,
        }

    has_asset_metrics = _table_exists("asset_metrics")
    if has_asset_metrics:
        metrics_query = db_session.query(Asset, AssetMetric).outerjoin(
            AssetMetric,
            AssetMetric.asset_id == Asset.id,
        ).filter(Asset.is_deleted == False)
        metrics_query = apply_sort(
            metrics_query,
            params.get("sort"),
            params.get("order", "asc"),
            {
                "id": Asset.id,
                "asset_name": Asset.target,
                "pqc_score": AssetMetric.pqc_score,
                "asset_cyber_score": AssetMetric.asset_cyber_score,
                "risk_penalty": AssetMetric.risk_penalty,
                "findings": AssetMetric.total_findings_count,
            },
            Asset.id,
        )
    else:
        metrics_query = db_session.query(Asset).filter(Asset.is_deleted == False)
        metrics_query = apply_sort(
            metrics_query,
            params.get("sort"),
            params.get("order", "asc"),
            {
                "id": Asset.id,
                "asset_name": Asset.target,
            },
            Asset.id,
        )

    if params.get("search"):
        like = f"%{params['search']}%"
        metrics_query = metrics_query.filter(
            or_(
                Asset.target.ilike(like),
                Asset.owner.ilike(like),
                Asset.asset_type.ilike(like),
                AssetMetric.pqc_class_tier.ilike(like) if has_asset_metrics else Asset.target.ilike(like),
                AssetMetric.digital_label.ilike(like) if has_asset_metrics else Asset.owner.ilike(like),
            )
        )

    total = int(metrics_query.count())
    rows = metrics_query.offset((params["page"] - 1) * params["page_size"]).limit(params["page_size"]).all()

    label_map: dict[int, str] = {}
    if _table_exists("digital_labels"):
        label_rows = db_session.query(DigitalLabel).all()
        label_map = {
            int(getattr(row, "asset_id", 0) or 0): str(getattr(row, "label", "") or "")
            for row in label_rows
            if int(getattr(row, "asset_id", 0) or 0) > 0
        }

    items = []
    for row in rows:
        if has_asset_metrics:
            asset, metric = row
        else:
            asset = row
            metric = None
        asset_id = int(getattr(asset, "id", 0) or 0)
        effective_label = str(getattr(metric, "digital_label", "") or "").strip() or label_map.get(asset_id) or "Unclassified"
        items.append(
            {
                "asset_id": asset_id,
                "asset_name": str(getattr(asset, "target", "") or ""),
                "owner": str(getattr(asset, "owner", "") or ""),
                "asset_type": str(getattr(asset, "asset_type", "") or ""),
                "risk_level": str(getattr(asset, "risk_level", "") or "Unknown"),
                "pqc_score": round(float(getattr(metric, "pqc_score", 0) or 0), 2) if metric else 0.0,
                "asset_cyber_score": round(float(getattr(metric, "asset_cyber_score", 0) or 0), 2) if metric else 0.0,
                "risk_penalty": round(float(getattr(metric, "risk_penalty", 0) or 0), 2) if metric else 0.0,
                "total_findings": int(getattr(metric, "total_findings_count", 0) or 0) if metric else 0,
                "critical_findings": int(getattr(metric, "critical_findings_count", 0) or 0) if metric else 0,
                "pqc_class_tier": str(getattr(metric, "pqc_class_tier", "Unknown") or "Unknown") if metric else "Unknown",
                "digital_label": effective_label,
            }
        )

    label_distribution: dict[str, int] = {}
    for row in items:
        label_key = str(row.get("digital_label") or "Unclassified")
        label_distribution[label_key] = int(label_distribution.get(label_key, 0) or 0) + 1

    enterprise_score = float(cyber_data.get("kpis", {}).get("avg_score", 0) or 0)
    data = build_data_envelope(
        items,
        total,
        params,
        {
            "enterprise_score": round(enterprise_score, 2),
            "critical_assets": int(cyber_data.get("kpis", {}).get("critical_count", 0) or 0),
            "total_findings": int(vulnerability.get("total_findings", 0) or 0),
            "critical_findings": int(vulnerability.get("critical_count", 0) or 0),
            "high_findings": int(vulnerability.get("high_count", 0) or 0),
            "medium_findings": int(vulnerability.get("medium_count", 0) or 0),
            "low_findings": int(vulnerability.get("low_count", 0) or 0),
            "label_distribution": label_distribution,
        },
    )
    return success_response(data, filters=_filters_payload(params))


@api_dashboards_bp.route("/api/assets", methods=["GET"])
@login_required
@api_guard
def api_assets():
    from web.routes.assets import build_assets_api_response

    params = parse_paging_args(default_sort="name")
    data, filters = build_assets_api_response(
        page=params["page"],
        page_size=params["page_size"],
        sort=params["sort"] or "name",
        order=params["order"],
        search=params["search"],
    )
    payload = {
        "success": True,
        "data": data,
        "filters": filters,
    }
    if isinstance(data, dict):
        payload.update(data)
    return payload, 200


@api_dashboards_bp.route("/api/discovery", methods=["GET"])
@login_required
@api_guard
def api_discovery():
    params = parse_paging_args(default_sort="detection_date")
    tab = str(request.args.get("tab", "domains") or "domains").strip().lower()

    if tab in ("domains", "ips", "software", "subdomains"):
        items, total = _split_discovery_tab_query(tab, params)
    elif tab == "ssl":
        items, total = _ssl_discovery_query(params)
    else:
        return error_response("Invalid discovery tab. Use domains|ssl|ips|software|subdomains.", 400)

    kpis = _discovery_kpis()
    data = build_data_envelope(items, total, params, kpis)
    return success_response(data, filters=_filters_payload(params, {"tab": tab}))


@api_dashboards_bp.route("/api/cbom/metrics", methods=["GET"])
@login_required
@api_guard
def api_cbom_metrics():
    params = parse_paging_args(default_sort="asset_name")
    cbom_data = CbomService.get_cbom_dashboard_data(
        page=params["page"],
        page_size=params["page_size"],
        sort_field=params["sort"],
        sort_order=params["order"],
        search_term=params["search"],
    )
    kpis = cbom_data.get("kpis", {})
    data = build_data_envelope([], 0, params, kpis)
    return success_response(data, filters=_filters_payload(params))


@api_dashboards_bp.route("/api/cbom/entries", methods=["GET"])
@login_required
@api_guard
def api_cbom_entries():
    params = parse_paging_args(default_sort="asset_name")
    cbom_data = CbomService.get_cbom_dashboard_data(
        page=params["page"],
        page_size=params["page_size"],
        sort_field=params["sort"],
        sort_order=params["order"],
        search_term=params["search"],
    )
    page_data = cbom_data.get("page_data", {})
    items = cbom_data.get("applications", [])
    total = int(page_data.get("total_count", len(items)) or 0)
    data = build_data_envelope(items, total, params, cbom_data.get("kpis", {}))
    return success_response(data, filters=_filters_payload(params))


@api_dashboards_bp.route("/api/cbom/summary", methods=["GET"])
@login_required
@api_guard
def api_cbom_summary():
    scan_id = str(request.args.get("scan_id", "") or "").strip()
    if not scan_id:
        return error_response("scan_id is required.", 400)

    summary = None
    if scan_id.isdigit():
        summary = db_session.query(CBOMSummary).filter(CBOMSummary.scan_id == int(scan_id), CBOMSummary.is_deleted == False).first()
    if summary is None:
        scan = db_session.query(Scan).filter(Scan.scan_id == scan_id, Scan.is_deleted == False).first()
        if scan:
            summary = db_session.query(CBOMSummary).filter(CBOMSummary.scan_id == scan.id, CBOMSummary.is_deleted == False).first()

    items = []
    if summary:
        summary_scan_id = getattr(summary, "scan_id", 0)
        total_components = getattr(summary, "total_components", 0)
        weak_crypto_count = getattr(summary, "weak_crypto_count", 0)
        cert_issues_count = getattr(summary, "cert_issues_count", 0)
        items.append(
            {
                "scan_id": int(summary_scan_id or 0),
                "total_components": int(total_components or 0),
                "weak_crypto_count": int(weak_crypto_count or 0),
                "cert_issues_count": int(cert_issues_count or 0),
                "json_path": getattr(summary, "json_path", None),
            }
        )

    params = {"page": 1, "page_size": 25}
    kpis = {
        "total_components": int(items[0]["total_components"]) if items else 0,
        "weak_crypto_count": int(items[0]["weak_crypto_count"]) if items else 0,
        "cert_issues_count": int(items[0]["cert_issues_count"]) if items else 0,
    }
    data = build_data_envelope(items, len(items), params, kpis)
    return success_response(data, filters={"scan_id": scan_id})


@api_dashboards_bp.route("/api/cbom/charts", methods=["GET"])
@login_required
@api_guard
def api_cbom_charts():
    params = parse_paging_args(default_sort="asset_name")
    cbom_data = CbomService.get_cbom_dashboard_data(
        page=params["page"],
        page_size=params["page_size"],
        sort_field=params["sort"],
        sort_order=params["order"],
        search_term=params["search"],
    )
    items = [
        {
            "key_length_distribution": cbom_data.get("key_length_distribution", {}),
            "cipher_suite_usage": cbom_data.get("cipher_suite_usage", {}),
            "top_cas": cbom_data.get("ca_distribution", {}),
            "protocol_versions": cbom_data.get("protocol_distribution", {}),
            "minimum_elements": cbom_data.get("minimum_elements", {}),
            "chart_explanations": {
                "key_length_distribution": {
                    "chart_type": "bar",
                    "x_axis": "Key length bucket (bits)",
                    "y_axis": "Number of certificate/crypto observations",
                    "what_it_represents": "Each bar shows how many observed cryptographic assets are using a given key length.",
                },
                "protocol_versions": {
                    "chart_type": "donut",
                    "segments": "TLS/SSL versions",
                    "what_it_represents": "Each segment shows relative protocol usage share across scanned inventory.",
                },
                "cipher_suite_usage": {
                    "chart_type": "ranked list",
                    "what_it_represents": "Top cipher suites by observed usage frequency.",
                },
                "top_cas": {
                    "chart_type": "ranked list",
                    "what_it_represents": "Certificate Authorities ranked by issued/observed certificate count.",
                },
                "minimum_elements": {
                    "chart_type": "coverage bars",
                    "what_it_represents": "Coverage of PNB CERT-IN minimum cryptographic CBOM elements in live SQL data.",
                },
            },
        }
    ]
    data = build_data_envelope(items, 1, {"page": 1, "page_size": 1}, cbom_data.get("kpis", {}))
    return success_response(data, filters=_filters_payload(params))


@api_dashboards_bp.route("/api/cbom/minimum-elements", methods=["GET"])
@login_required
@api_guard
def api_cbom_minimum_elements():
    params = parse_paging_args(default_sort="asset_name")
    cbom_data = CbomService.get_cbom_dashboard_data(
        page=params["page"],
        page_size=params["page_size"],
        sort_field=params["sort"],
        sort_order=params["order"],
        search_term=params["search"],
    )

    minimum_elements = cbom_data.get("minimum_elements", {}) or {}
    items = minimum_elements.get("items", []) or []
    total = int(minimum_elements.get("total_entries", len(items)) or 0)
    kpis = {
        "required_fields": int((minimum_elements.get("coverage_summary") or {}).get("required_fields", 0) or 0),
        "covered_fields": int((minimum_elements.get("coverage_summary") or {}).get("covered_fields", 0) or 0),
        "coverage_pct": float((minimum_elements.get("coverage_summary") or {}).get("coverage_pct", 0) or 0),
    }
    data = build_data_envelope(items, total, params, kpis)
    data["minimum_elements"] = {
        "asset_type_distribution": minimum_elements.get("asset_type_distribution", {}),
        "field_coverage": minimum_elements.get("field_coverage", {}),
        "field_definitions": minimum_elements.get("field_definitions", {}),
        "coverage_summary": minimum_elements.get("coverage_summary", {}),
    }
    return success_response(data, filters=_filters_payload(params))


@api_dashboards_bp.route("/api/cbom", methods=["GET"])
@login_required
@api_guard
def api_cbom_alias():
    return api_cbom_entries()


@api_dashboards_bp.route("/api/cbom/export", methods=["GET"])
@login_required
@api_guard
def api_cbom_export():
    params = parse_paging_args(default_sort="asset_name")
    export_page_size = max(params["page_size"], 250)
    export_mode = str(request.args.get("mode", "x509") or "x509").strip().lower()

    selected_keys = set()
    raw_selected_keys = request.args.getlist("selected_keys")
    if not raw_selected_keys:
        single_key = str(request.args.get("row_key", "") or "").strip()
        if single_key:
            raw_selected_keys = [single_key]
    for chunk in raw_selected_keys:
        for key in str(chunk or "").split(","):
            key_text = key.strip()
            if key_text:
                selected_keys.add(key_text)

    first_page_data = CbomService.get_cbom_dashboard_data(
        page=1,
        page_size=export_page_size,
        sort_field=params["sort"],
        sort_order=params["order"],
        search_term=params["search"],
    )
    export_items = list(first_page_data.get("applications", []) or [])
    page_info = first_page_data.get("page_data", {}) or {}
    total_pages = int(page_info.get("total_pages", 1) or 1)

    if total_pages > 1:
        for page_no in range(2, total_pages + 1):
            next_page_data = CbomService.get_cbom_dashboard_data(
                page=page_no,
                page_size=export_page_size,
                sort_field=params["sort"],
                sort_order=params["order"],
                search_term=params["search"],
            )
            export_items.extend(next_page_data.get("applications", []) or [])

    if selected_keys:
        export_items = [
            item
            for item in export_items
            if str((item or {}).get("row_key", "") or "").strip() in selected_keys
        ]

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "export_format": "cbom-x509-json" if export_mode == "x509" else "cbom-json",
        "mode": export_mode,
        "selected_count": len(selected_keys),
        "kpis": first_page_data.get("kpis", {}),
        "entries": export_items,
        "charts": {
            "key_length_distribution": first_page_data.get("key_length_distribution", {}),
            "cipher_usage": first_page_data.get("cipher_usage", {}) or first_page_data.get("cipher_suite_usage", {}),
            "protocols": first_page_data.get("protocols", {}) or first_page_data.get("protocol_distribution", {}),
            "top_cas": first_page_data.get("top_cas", {}) or first_page_data.get("ca_distribution", {}),
        },
        "minimum_elements": first_page_data.get("minimum_elements", {}),
    }
    response = Response(json.dumps(payload, default=str), mimetype="application/json")
    file_suffix = "x509" if export_mode == "x509" else "cbom"
    response.headers["Content-Disposition"] = f"attachment; filename=cbom_{file_suffix}_export.json"
    return response


@api_dashboards_bp.route("/api/pqc-posture/metrics", methods=["GET"])
@login_required
@api_guard
def api_pqc_metrics():
    params = parse_paging_args(default_sort="asset_name")
    status_filter = str(request.args.get("status", "") or "").strip().lower()
    data_vm = PQCService.get_pqc_dashboard_data(
        page=params["page"],
        page_size=params["page_size"],
        sort_field=params["sort"],
        sort_order=params["order"],
        search_term=params["search"],
        status_filter=status_filter,
        pqc_ready_only=status_filter in {"pqc_ready", "elite_only"},
    )
    grade_counts = data_vm.get("grade_counts", {})
    total = max(1, sum(int(v or 0) for v in grade_counts.values()))
    elite_count = int(grade_counts.get("Elite", 0) or 0)
    standard_count = int(grade_counts.get("Standard", 0) or 0)
    legacy_count = int(grade_counts.get("Legacy", 0) or 0)
    critical_count = int(grade_counts.get("Critical", 0) or 0)
    kpis = {
        "elite": _safe_ratio(float(elite_count), float(total)),
        "standard": _safe_ratio(float(standard_count), float(total)),
        "legacy": _safe_ratio(float(legacy_count), float(total)),
        "critical": _safe_ratio(float(critical_count), float(total)),
        "critical_count": critical_count,
        "avg_score": float(data_vm.get("kpis", {}).get("avg_score", 0) or 0),
    }

    raw_status_rows = (
        db_session.query(func.lower(PQCClassification.quantum_safe_status), func.count(PQCClassification.id))
        .filter(PQCClassification.is_deleted == False)
        .group_by(func.lower(PQCClassification.quantum_safe_status))
        .all()
    )
    normalized_status_counts = {
        "safe": 0,
        "unsafe": 0,
        "migration_advised": 0,
        "unknown": 0,
    }
    for status, count in raw_status_rows:
        status_key = str(status or "unknown").strip().lower()
        if status_key in {"safe", "quantum_safe", "quantum-safe"}:
            normalized_status_counts["safe"] += int(count or 0)
        elif status_key in {"unsafe", "quantum_vulnerable", "quantum-vulnerable", "vulnerable"}:
            normalized_status_counts["unsafe"] += int(count or 0)
        elif status_key in {"migration_advised", "migration-advised", "migration advised"}:
            normalized_status_counts["migration_advised"] += int(count or 0)
        else:
            normalized_status_counts["unknown"] += int(count or 0)

    status_total = max(1, sum(normalized_status_counts.values()))
    status_bars = [
        {
            "status": key,
            "count": int(value),
            "pct": _safe_ratio(float(value), float(status_total)),
            "description": PQC_STATUS_EXPLANATIONS.get(key, ""),
        }
        for key, value in normalized_status_counts.items()
    ]

    readiness_tiers = [
        {
            "tier": "elite",
            "label": "Elite",
            "count": elite_count,
            "pct": _safe_ratio(float(elite_count), float(total)),
            "description": PQC_TIER_EXPLANATIONS["elite"],
        },
        {
            "tier": "standard",
            "label": "Standard",
            "count": standard_count,
            "pct": _safe_ratio(float(standard_count), float(total)),
            "description": PQC_TIER_EXPLANATIONS["standard"],
        },
        {
            "tier": "legacy",
            "label": "Legacy",
            "count": legacy_count,
            "pct": _safe_ratio(float(legacy_count), float(total)),
            "description": PQC_TIER_EXPLANATIONS["legacy"],
        },
        {
            "tier": "critical",
            "label": "Critical",
            "count": critical_count,
            "pct": _safe_ratio(float(critical_count), float(total)),
            "description": PQC_TIER_EXPLANATIONS["critical"],
        },
    ]

    data = build_data_envelope(
        [
            {
                "status_bar_chart": status_bars,
                "readiness_tier_bars": readiness_tiers,
                "readiness_pie_chart": readiness_tiers,
                "chart_explanation": {
                    "chart_type": "bar",
                    "x_axis": "PQC status bucket",
                    "y_axis": "Percentage of classified observations",
                    "what_it_represents": "Each bar shows the share of PQC classifications in safe/unsafe/migration_advised/unknown status.",
                },
                "tier_chart_explanation": {
                    "chart_type": "donut",
                    "segments": "Elite, Standard, Legacy, Critical",
                    "what_it_represents": "Asset-level PQC readiness posture used by dashboard KPIs and migration prioritization.",
                },
            }
        ],
        1,
        {"page": 1, "page_size": 1},
        kpis,
    )
    return success_response(data, filters=_filters_payload(params))


@api_dashboards_bp.route("/api/pqc-posture/assets", methods=["GET"])
@login_required
@api_guard
def api_pqc_assets():
    params = parse_paging_args(default_sort="asset_name")
    status_filter = str(request.args.get("status", "") or "").strip().lower()
    data_vm = PQCService.get_pqc_dashboard_data(
        page=params["page"],
        page_size=params["page_size"],
        sort_field=params["sort"],
        sort_order=params["order"],
        search_term=params["search"],
        status_filter=status_filter,
        pqc_ready_only=status_filter in {"pqc_ready", "elite_only"},
    )
    page_data = data_vm.get("page_data", {})
    items = data_vm.get("applications", [])
    total = int(page_data.get("total_count", len(items)) or 0)

    out_items = [
        {
            "asset_name": row.get("asset_name"),
            "domain": row.get("domain") or row.get("target"),
            "ip": row.get("ip") or row.get("ipv4") or row.get("ipv6"),
            "pqc_support": "✓" if str(row.get("status", "")).lower() in ("elite", "standard") else "✗",
            "supports_pqc": bool(row.get("supports_pqc")),
            "score": row.get("score"),
            "status": row.get("status"),
            "last_scan": row.get("last_scan"),
            "tls_version": row.get("tls_version"),
            "key_length": row.get("key_length"),
            "key_algorithm": row.get("key_algorithm"),
            "signature_algorithm": row.get("signature_algorithm"),
            "crypto_profile": row.get("crypto_profile"),
            "quantum_safe_algorithms": row.get("quantum_safe_algorithms", 0),
            "quantum_vulnerable_algorithms": row.get("quantum_vulnerable_algorithms", 0),
            "pqc_algorithms": row.get("pqc_algorithms", []),
            "vulnerable_algorithms": row.get("vulnerable_algorithms", []),
            "pqc_algorithms_display": row.get("pqc_algorithms_display", "None detected"),
            "classical_algorithms_display": row.get("classical_algorithms_display", "None detected"),
            "plaintext_or_no_crypto": bool(row.get("plaintext_or_no_crypto")),
            "recommendation": (
                "Maintain controls and keep monitoring cryptographic inventory."
                if str(row.get("status", "")).lower() == "elite"
                else "Complete remaining migration and remove weak/deprecated suites."
                if str(row.get("status", "")).lower() == "standard"
                else "Prioritize migration to PQC-safe algorithms and TLS 1.3 baselines."
                if str(row.get("status", "")).lower() == "legacy"
                else "Immediate remediation required: isolate exposure and replace weak crypto."
            ),
        }
        for row in items
    ]

    data = build_data_envelope(out_items, total, params, data_vm.get("kpis", {}))
    return success_response(data, filters=_filters_payload(params))


@api_dashboards_bp.route("/api/pqc-posture", methods=["GET"])
@login_required
@api_guard
def api_pqc_alias():
    return api_pqc_assets()


@api_dashboards_bp.route("/api/cyber-rating", methods=["GET"])
@login_required
@api_guard
def api_cyber_rating():
    def _to_1000(score_100: float) -> float:
        return max(0.0, min(1000.0, float(score_100 or 0.0) * 10.0))

    def _tier_1000(score_1000: float) -> str:
        value = float(score_1000 or 0.0)
        if value >= 700:
            return "Elite"
        if value >= 400:
            return "Standard"
        if value >= 200:
            return "Legacy"
        return "Critical"

    params = parse_paging_args(default_sort="generated_at")
    tier_filter = str(request.args.get("tier", "") or "").strip().lower()
    cyber = CyberReportingService.get_cyber_rating_data(limit=1000)
    rows = [
        {
            "id": int(row.get("asset_id") or 0),
            "url": row.get("target"),
            "enterprise_score": _to_1000(float(row.get("score") or 0)),
            "tier": _tier_1000(_to_1000(float(row.get("score") or 0))),
            "generated_at": to_iso(row.get("last_seen")),
        }
        for row in cyber.get("applications", [])
    ]
    q = str(params.get("search", "") or "").strip().lower()
    if q:
        rows = [
            row
            for row in rows
            if q in str(row.get("url") or "").lower()
            or q in str(row.get("tier") or "").lower()
        ]
    if tier_filter:
        rows = [
            row
            for row in rows
            if str(row.get("tier") or "").strip().lower() == tier_filter
        ]
    sort_field = str(params.get("sort") or "generated_at").lower()
    sort_map = {
        "id": lambda row: int(row.get("id") or 0),
        "target": lambda row: str(row.get("url") or "").lower(),
        "score": lambda row: float(row.get("enterprise_score") or 0),
        "tier": lambda row: str(row.get("tier") or "").lower(),
        "generated_at": lambda row: str(row.get("generated_at") or ""),
    }
    rows = sorted(rows, key=sort_map.get(sort_field, sort_map["generated_at"]), reverse=params["order"] == "desc")
    total = len(rows)
    start = (params["page"] - 1) * params["page_size"]
    end = start + params["page_size"]
    items = rows[start:end]

    avg_score_100 = float(cyber.get("kpis", {}).get("avg_score", 0) or 0)
    avg_score = _to_1000(avg_score_100)
    tier = _tier_1000(avg_score)

    tier_counts = {
        "critical": int(sum(1 for row in rows if str(row.get("tier") or "") == "Critical")),
        "legacy": int(sum(1 for row in rows if str(row.get("tier") or "") == "Legacy")),
        "standard": int(sum(1 for row in rows if str(row.get("tier") or "") == "Standard")),
        "elite": int(sum(1 for row in rows if str(row.get("tier") or "") == "Elite")),
    }
    total_urls = max(1, int(cyber.get("meta", {}).get("total_assets", total) or total or 1))

    kpis = {
        "enterprise_score": round(avg_score, 1),
        "tier": tier,
        "total_urls": int(total_urls),
        "elite_pct": round((tier_counts["elite"] / total_urls) * 100.0, 1),
        "standard_pct": round((tier_counts["standard"] / total_urls) * 100.0, 1),
        "legacy_pct": round((tier_counts["legacy"] / total_urls) * 100.0, 1),
        "critical_pct": round((tier_counts["critical"] / total_urls) * 100.0, 1),
        "critical_count": tier_counts["critical"],
        "tier_counts": {
            "critical": tier_counts["critical"],
            "legacy": tier_counts["legacy"],
            "standard": tier_counts["standard"],
            "elite": tier_counts["elite"],
        },
    }
    data = build_data_envelope(items, total, params, kpis)
    return success_response(data, filters=_filters_payload(params, {"tier": tier_filter}))


def _list_ondemand_reports() -> list[dict[str, Any]]:
    rows = db.list_scans(limit=500) or []
    out: list[dict[str, Any]] = []
    for idx, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            continue
        out.append(
            {
                "id": idx,
                "report_type": "on-demand",
                "target": row.get("target"),
                "scan_id": row.get("scan_id"),
                "status": row.get("status"),
                "generated_at": row.get("generated_at"),
            }
        )
    return out


@api_dashboards_bp.route("/api/reports/scheduled", methods=["GET"])
@login_required
@api_guard
def api_reports_scheduled():
    params = parse_paging_args(default_sort="created_at")
    rows = db.list_report_schedules(limit=1000, include_password=False)

    q = params["search"].lower()
    if q:
        rows = [
            r
            for r in rows
            if q in str(r.get("report_type", "")).lower()
            or q in str(r.get("frequency", "")).lower()
            or q in str(r.get("status", "")).lower()
            or q in str(r.get("created_by_name", "")).lower()
        ]

    sort_key = params["sort"] if params["sort"] in {"id", "report_type", "frequency", "status", "created_at", "created_by_name"} else "created_at"
    rows = sorted(rows, key=lambda r: str(r.get(sort_key, "")), reverse=params["order"] == "desc")

    total = len(rows)
    start = (params["page"] - 1) * params["page_size"]
    end = start + params["page_size"]
    items = rows[start:end]
    enabled = sum(1 for r in rows if bool(r.get("enabled", True)))

    kpis = {
        "total_scheduled": int(total),
        "enabled": int(enabled),
        "disabled": int(total - enabled),
    }
    data = build_data_envelope(items, total, params, kpis)
    return success_response(data, filters=_filters_payload(params))


@api_dashboards_bp.route("/api/reports/ondemand", methods=["GET"])
@login_required
@api_guard
def api_reports_ondemand():
    params = parse_paging_args(default_sort="generated_at")
    rows = _list_ondemand_reports()

    q = params["search"].lower()
    if q:
        rows = [
            r
            for r in rows
            if q in str(r.get("target", "")).lower()
            or q in str(r.get("scan_id", "")).lower()
            or q in str(r.get("status", "")).lower()
        ]

    sort_key = params["sort"] if params["sort"] in {"id", "target", "scan_id", "status", "generated_at"} else "generated_at"
    rows = sorted(rows, key=lambda r: str(r.get(sort_key, "")), reverse=params["order"] == "desc")

    total = len(rows)
    start = (params["page"] - 1) * params["page_size"]
    end = start + params["page_size"]
    items = rows[start:end]

    kpis = {
        "total_ondemand": int(total),
        "completed": int(sum(1 for r in rows if str(r.get("status", "")).lower() == "complete")),
        "failed": int(sum(1 for r in rows if str(r.get("status", "")).lower() == "failed")),
    }
    data = build_data_envelope(items, total, params, kpis)
    return success_response(data, filters=_filters_payload(params))


@api_dashboards_bp.route("/api/reports/ondemand/<scan_id>", methods=["GET"])
@login_required
@api_guard
def api_reports_ondemand_detail(scan_id: str):
    report = db.get_scan(str(scan_id or "").strip())
    if not isinstance(report, dict):
        return error_response("Report not found.", 404)

    findings = [
        {
            "severity": str(item.get("severity") or "").upper(),
            "title": item.get("title") or "",
            "description": item.get("description") or "",
            "category": item.get("category") or "",
        }
        for item in (report.get("findings") or [])
        if isinstance(item, dict)
    ][:20]

    recommendations_detailed = [
        {
            "priority": rec.get("priority"),
            "title": rec.get("title") or "",
            "description": rec.get("description") or "",
            "timeline": rec.get("timeline") or "",
            "impact": rec.get("impact") or "",
        }
        for rec in (report.get("recommendations_detailed") or [])
        if isinstance(rec, dict)
    ][:10]
    recommendations_simple = [str(item) for item in (report.get("top_recommendations") or [])][:10]

    data = build_data_envelope(
        [
            {
                "scan_id": report.get("scan_id") or scan_id,
                "target": report.get("target") or "",
                "generated_at": report.get("generated_at") or "",
                "status": report.get("status") or "",
                "asset_class": report.get("asset_class") or "",
                "overview": report.get("overview") or {},
                "severity_breakdown": report.get("severity_breakdown") or {},
                "findings": findings,
                "recommendations": recommendations_detailed or recommendations_simple,
            }
        ],
        total=1,
        params={"page": 1, "page_size": 1},
        kpis={
            "finding_count": len(findings),
            "recommendation_count": len(recommendations_detailed or recommendations_simple),
        },
    )
    return success_response(data, filters={"scan_id": scan_id})


@api_dashboards_bp.route("/api/reports", methods=["GET"])
@login_required
@api_guard
def api_reports_alias():
    return api_reports_scheduled()


@api_dashboards_bp.route("/api/reports/cleanup-stale", methods=["POST"])
@login_required
@api_guard
def api_reports_cleanup_stale():
    from flask_login import current_user

    user_role = str(getattr(current_user, "role", "") or "").strip().title()
    if user_role not in {"Admin", "Manager"}:
        return error_response("Only Admin/Manager can clear stale entries.", 403)

    now_utc = datetime.now(timezone.utc)
    cleaned = 0
    by_table: dict[str, int] = {}

    stale_configs = [
        (DiscoveryDomain, "domain", ["", "--"]),
        (DiscoverySSL, "endpoint", ["", "--"]),
        (DiscoveryIP, "ip_address", ["", "--"]),
        (DiscoverySoftware, "product", ["", "--"]),
    ]

    try:
        for model, key_field, empty_values in stale_configs:
            field_col = getattr(model, key_field)
            query = (
                db_session.query(model)
                .outerjoin(Asset, model.asset_id == Asset.id)
                .outerjoin(Scan, model.scan_id == Scan.id)
                .filter(model.is_deleted == False)
                .filter(
                    or_(
                        model.asset_id.is_(None),
                        Asset.id.is_(None),
                        Asset.is_deleted == True,
                        model.scan_id.is_(None),
                        Scan.id.is_(None),
                        Scan.is_deleted == True,
                    )
                )
                .filter(
                    or_(
                        field_col.is_(None),
                        func.trim(field_col) == "",
                        field_col.in_(empty_values),
                    )
                )
            )

            rows = query.all()
            table_count = 0
            for row in rows:
                row.is_deleted = True
                row.deleted_at = now_utc
                table_count += 1
            if table_count:
                by_table[getattr(model, "__tablename__", str(model))] = table_count
                cleaned += table_count

        db_session.commit()
    except Exception as exc:
        db_session.rollback()
        return error_response(f"Failed to clear stale entries: {exc}", 500)

    data = build_data_envelope(
        items=[{"cleaned": int(cleaned), "tables": by_table, "scope": "discovery"}],
        total=1,
        params={"page": 1, "page_size": 1},
        kpis={"cleaned": int(cleaned)},
    )
    return success_response(data, filters={"scope": "discovery"})


@api_dashboards_bp.route("/api/admin/api-keys", methods=["POST"])
@login_required
@api_guard
def api_admin_api_keys():
    from flask_login import current_user

    if str(getattr(current_user, "role", "") or "") != "Admin":
        return error_response("Admin role required.", 403)

    payload = request.get_json(silent=True) or {}
    target_user_id = str(payload.get("user_id") or "").strip()
    if not target_user_id:
        return error_response("user_id is required.", 400)

    db.revoke_api_key(target_user_id)
    new_key = db.generate_api_key(target_user_id)
    if not new_key:
        return error_response("Failed to generate API key.", 500)

    data = build_data_envelope(
        [{"user_id": target_user_id, "api_key": new_key}],
        total=1,
        params={"page": 1, "page_size": 1},
        kpis={},
    )
    return success_response(data, filters={})


@api_dashboards_bp.route("/api/admin/metrics", methods=["GET"])
@login_required
@api_guard
def api_admin_metrics():
    from flask_login import current_user

    if str(getattr(current_user, "role", "") or "") != "Admin":
        return error_response("Admin role required.", 403)

    users = db.list_users()
    total_users = len(users)
    active_users = sum(1 for u in users if bool(u.get("is_active", True)))
    key_issued = sum(1 for u in users if bool(u.get("api_key_hash")))

    data = build_data_envelope(
        items=[],
        total=0,
        params={"page": 1, "page_size": 25},
        kpis={
            "total_users": int(total_users),
            "active_users": int(active_users),
            "api_keys_issued": int(key_issued),
            "total_scans": int(db_session.query(func.count(Scan.id)).filter(Scan.is_deleted == False).scalar() or 0),
        },
    )
    return success_response(data, filters={})


@api_dashboards_bp.route("/api/admin/flush-cache", methods=["POST"])
@login_required
@api_guard
def api_admin_flush_cache():
    from flask_login import current_user

    if str(getattr(current_user, "role", "") or "") != "Admin":
        return error_response("Admin role required.", 403)

    try:
        from web.app import invalidate_dashboard_cache

        invalidate_dashboard_cache()
    except Exception:
        pass

    data = build_data_envelope(
        [{"flushed": True, "at": to_iso(datetime.now(timezone.utc))}],
        total=1,
        params={"page": 1, "page_size": 1},
        kpis={},
    )
    return success_response(data, filters={})


@api_dashboards_bp.route("/api/config/theme", methods=["GET"])
@login_required
@api_guard
def api_config_theme_get():
    from web.app import load_theme

    theme = load_theme()
    data = build_data_envelope(
        items=[theme],
        total=1,
        params={"page": 1, "page_size": 1},
        kpis={"mode": theme.get("mode", "system")},
    )
    return success_response(data, filters={})


@api_dashboards_bp.route("/api/config/theme", methods=["POST"])
@login_required
@api_guard
def api_config_theme_post():
    from web.app import THEME_FILE, _sanitize_theme, load_theme
    import json

    payload = request.get_json(silent=True) or {}
    current = load_theme()
    requested = {
        "mode": payload.get("mode", current.get("mode", "system")),
        "dark": payload.get("dark", current.get("dark", {})),
        "light": payload.get("light", current.get("light", {})),
    }
    theme = _sanitize_theme(requested)
    with open(THEME_FILE, "w", encoding="utf-8") as fh:
        json.dump(theme, fh, indent=2)

    data = build_data_envelope(
        items=[theme],
        total=1,
        params={"page": 1, "page_size": 1},
        kpis={"mode": theme.get("mode", "system")},
    )
    return success_response(data, filters={})


@api_dashboards_bp.route("/api/docs", methods=["GET"])
@login_required
@api_guard
def api_docs():
    endpoints = [
        "GET /api/home/metrics",
        "GET /api/assets",
        "GET /api/discovery?tab=domains|ssl|ips|software",
        "GET /api/distributions/asset-types",
        "GET /api/distributions/risk-levels",
        "GET /api/distributions/ip-versions",
        "GET /api/distributions/cert-expiry",
        "GET /api/enterprise-metrics",
        "GET /api/cbom/metrics",
        "GET /api/cbom/entries",
        "GET /api/cbom/summary?scan_id=...",
        "GET /api/cbom/charts",
        "GET /api/cbom/minimum-elements",
        "GET /api/pqc-posture/metrics",
        "GET /api/pqc-posture/assets",
        "GET /api/cyber-rating",
        "GET /api/reports/scheduled",
        "GET /api/reports/ondemand",
        "POST /api/admin/api-keys",
        "GET /api/admin/metrics",
        "POST /api/admin/flush-cache",
        "GET /api/config/theme",
        "POST /api/config/theme",
    ]
    data = build_data_envelope(
        items=[{"endpoints": endpoints}],
        total=1,
        params={"page": 1, "page_size": 1},
        kpis={"endpoint_count": len(endpoints)},
    )
    return success_response(data, filters={})
