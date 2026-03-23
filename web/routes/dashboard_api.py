from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from flask import Blueprint, request
from flask_login import login_required
from sqlalchemy import func, inspect, or_, text

from middleware.api_auth import api_guard
from src import database as db
from src.db import db_session
from src.models import (
    Asset,
    CBOMEntry,
    CBOMSummary,
    Certificate,
    ComplianceScore,
    PQCClassification,
    Scan,
)
from src.services.cbom_service import CbomService
from src.services.cyber_reporting_service import CyberReportingService
from src.services.pqc_service import PQCService
from utils.api_helper import (
    apply_sort,
    build_data_envelope,
    error_response,
    parse_paging_args,
    success_response,
    to_iso,
)

api_dashboards_bp = Blueprint("api_dashboards", __name__)


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

    if tab in ("domains", "ips", "software"):
        items, total = _split_discovery_tab_query(tab, params)
    elif tab == "ssl":
        items, total = _ssl_discovery_query(params)
    else:
        return error_response("Invalid discovery tab. Use domains|ssl|ips|software.", 400)

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
        }
    ]
    data = build_data_envelope(items, 1, {"page": 1, "page_size": 1}, cbom_data.get("kpis", {}))
    return success_response(data, filters=_filters_payload(params))


@api_dashboards_bp.route("/api/cbom", methods=["GET"])
@login_required
@api_guard
def api_cbom_alias():
    return api_cbom_entries()


@api_dashboards_bp.route("/api/pqc-posture/metrics", methods=["GET"])
@login_required
@api_guard
def api_pqc_metrics():
    params = parse_paging_args(default_sort="asset_name")
    data_vm = PQCService.get_pqc_dashboard_data(
        page=params["page"],
        page_size=params["page_size"],
        sort_field=params["sort"],
        sort_order=params["order"],
        search_term=params["search"],
    )
    grade_counts = data_vm.get("grade_counts", {})
    total = max(1, sum(int(v or 0) for v in grade_counts.values()))
    kpis = {
        "elite": _safe_ratio(float(grade_counts.get("Elite", 0)), float(total)),
        "standard": _safe_ratio(float(grade_counts.get("Standard", 0)), float(total)),
        "legacy": _safe_ratio(float(grade_counts.get("Legacy", 0)), float(total)),
        "critical": _safe_ratio(float(grade_counts.get("Critical", 0)), float(total)),
        "avg_score": float(data_vm.get("kpis", {}).get("avg_score", 0) or 0),
    }
    data = build_data_envelope([], 0, params, kpis)
    return success_response(data, filters=_filters_payload(params))


@api_dashboards_bp.route("/api/pqc-posture/assets", methods=["GET"])
@login_required
@api_guard
def api_pqc_assets():
    params = parse_paging_args(default_sort="asset_name")
    data_vm = PQCService.get_pqc_dashboard_data(
        page=params["page"],
        page_size=params["page_size"],
        sort_field=params["sort"],
        sort_order=params["order"],
        search_term=params["search"],
    )
    page_data = data_vm.get("page_data", {})
    items = data_vm.get("applications", [])
    total = int(page_data.get("total_count", len(items)) or 0)

    out_items = [
        {
            "asset_name": row.get("asset_name"),
            "ip": row.get("ip") or row.get("ipv4") or row.get("ipv6"),
            "pqc_support": "✓" if str(row.get("status", "")).lower() in ("elite", "standard") else "✗",
            "score": row.get("score"),
            "status": row.get("status"),
            "last_scan": row.get("last_scan"),
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
    params = parse_paging_args(default_sort="generated_at")
    cyber = CyberReportingService.get_cyber_rating_data(limit=1000)
    rows = [
        {
            "id": int(row.get("asset_id") or 0),
            "url": row.get("target"),
            "enterprise_score": float(row.get("score") or 0),
            "tier": row.get("tier"),
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

    avg_score = float(cyber.get("kpis", {}).get("avg_score", 0) or 0)
    if avg_score >= 80:
        tier = "Elite-PQC"
    elif avg_score >= 60:
        tier = "Advanced"
    elif avg_score >= 40:
        tier = "Standard"
    else:
        tier = "Legacy"

    kpis = {
        "enterprise_score": round(avg_score, 1),
        "tier": tier,
        "total_urls": int(cyber.get("meta", {}).get("total_assets", total) or total),
        "elite_pct": float(cyber.get("kpis", {}).get("elite_pct", 0) or 0),
        "standard_pct": float(cyber.get("kpis", {}).get("standard_pct", 0) or 0),
        "legacy_pct": float(cyber.get("kpis", {}).get("legacy_pct", 0) or 0),
        "critical_count": int(cyber.get("kpis", {}).get("critical_count", 0) or 0),
    }
    data = build_data_envelope(items, total, params, kpis)
    return success_response(data, filters=_filters_payload(params))


def _list_ondemand_reports() -> list[dict[str, Any]]:
    rows = db.list_scans(limit=500)
    out: list[dict[str, Any]] = []
    for idx, row in enumerate(rows, start=1):
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


@api_dashboards_bp.route("/api/reports", methods=["GET"])
@login_required
@api_guard
def api_reports_alias():
    return api_reports_scheduled()


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
        "GET /api/cbom/metrics",
        "GET /api/cbom/entries",
        "GET /api/cbom/summary?scan_id=...",
        "GET /api/cbom/charts",
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
