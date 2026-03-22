from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from flask import Blueprint, request
from flask_login import login_required
from sqlalchemy import func, or_

from middleware.api_auth import api_guard
from src import database as db
from src.db import db_session
from src.models import (
    Asset,
    CBOMEntry,
    CBOMSummary,
    Certificate,
    ComplianceScore,
    CyberRating,
    DiscoveryItem,
    PQCClassification,
    Scan,
)
from src.services.cbom_service import CbomService
from src.services.pqc_service import PQCService
from utils.api_helper import (
    apply_sort,
    apply_text_search,
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
    params = parse_paging_args(default_sort="risk_level")

    base = db_session.query(Asset).filter(Asset.is_deleted == False)
    base = apply_text_search(base, params["search"], [Asset.target, Asset.url, Asset.asset_type, Asset.owner, Asset.risk_level])

    sort_map = {
        "id": Asset.id,
        "asset_name": Asset.target,
        "name": Asset.target,
        "url": Asset.url,
        "type": Asset.asset_type,
        "owner": Asset.owner,
        "risk_level": Asset.risk_level,
        "last_scan": Asset.last_scan_id,
    }
    base = apply_sort(base, params["sort"], params["order"], sort_map, Asset.id)

    total = int(base.count())
    rows = base.offset((params["page"] - 1) * params["page_size"]).limit(params["page_size"]).all()

    items: list[dict[str, Any]] = []
    for row in rows:
        row_id = getattr(row, "id", None)
        last_scan_id = getattr(row, "last_scan_id", None)
        cert = (
            db_session.query(Certificate)
            .filter(Certificate.asset_id == row_id, Certificate.is_deleted == False)
            .order_by(Certificate.valid_until.is_(None).asc(), Certificate.valid_until.desc(), Certificate.id.desc())
            .first()
        )
        cert_status = "Not Scanned"
        cert_valid_until = getattr(cert, "valid_until", None) if cert else None
        cert_key_length = getattr(cert, "key_length", None) if cert else None
        if cert_valid_until is not None:
            cert_status = "Expired" if cert_valid_until < datetime.now() else "Valid"

        scan_date = None
        if last_scan_id:
            scan = db_session.query(Scan).filter(Scan.id == last_scan_id).first()
            if scan:
                scan_date = scan.completed_at or scan.scanned_at or scan.started_at

        items.append(
            {
                "id": int(row_id or 0),
                "asset_name": getattr(row, "target", None),
                "url": getattr(row, "url", None),
                "type": getattr(row, "asset_type", None),
                "owner": getattr(row, "owner", None),
                "risk_level": getattr(row, "risk_level", None),
                "cert_status": cert_status,
                "key_length": int(cert_key_length) if cert_key_length else None,
                "last_scan": to_iso(scan_date),
            }
        )

    now = datetime.now()
    expiring_cutoff = now + timedelta(days=30)
    kpis = {
        "total_assets": int(db_session.query(func.count(Asset.id)).filter(Asset.is_deleted == False).scalar() or 0),
        "web_apps": int(db_session.query(func.count(Asset.id)).filter(Asset.is_deleted == False, func.lower(Asset.asset_type) == "web app").scalar() or 0),
        "apis": int(db_session.query(func.count(Asset.id)).filter(Asset.is_deleted == False, func.lower(Asset.asset_type) == "api").scalar() or 0),
        "servers": int(db_session.query(func.count(Asset.id)).filter(Asset.is_deleted == False, func.lower(Asset.asset_type) == "server").scalar() or 0),
        "expiring_certificates": int(
            db_session.query(func.count(Certificate.id))
            .join(Asset, Certificate.asset_id == Asset.id)
            .filter(
                Certificate.is_deleted == False,
                Asset.is_deleted == False,
                Certificate.valid_until != None,
                Certificate.valid_until >= now,
                Certificate.valid_until <= expiring_cutoff,
            )
            .scalar()
            or 0
        ),
        "high_risk_assets": int(
            db_session.query(func.count(Asset.id))
            .filter(Asset.is_deleted == False, func.lower(Asset.risk_level).in_(("high", "critical")))
            .scalar()
            or 0
        ),
    }

    data = build_data_envelope(items, total, params, kpis)
    return success_response(data, filters=_filters_payload(params))


@api_dashboards_bp.route("/api/discovery", methods=["GET"])
@login_required
@api_guard
def api_discovery():
    params = parse_paging_args(default_sort="detection_date")
    tab = str(request.args.get("tab", "domains") or "domains").strip().lower()

    if tab in ("domains", "ips", "software"):
        type_map = {"domains": "domain", "ips": "ip", "software": "software"}
        dtype = type_map[tab]
        base = (
            db_session.query(DiscoveryItem, Asset)
            .outerjoin(Asset, DiscoveryItem.asset_id == Asset.id)
            .filter(DiscoveryItem.is_deleted == False, DiscoveryItem.type == dtype)
        )

        if params["search"]:
            q = params["search"]
            base = base.filter(
                or_(
                    DiscoveryItem.status.ilike(f"%{q}%"),
                    Asset.target.ilike(f"%{q}%"),
                    Asset.owner.ilike(f"%{q}%"),
                )
            )

        sort_map = {
            "id": DiscoveryItem.id,
            "name": Asset.target,
            "detection_date": DiscoveryItem.detection_date,
            "status": DiscoveryItem.status,
        }
        base = apply_sort(base, params["sort"], params["order"], sort_map, DiscoveryItem.id)
        total = int(base.count())
        rows = base.offset((params["page"] - 1) * params["page_size"]).limit(params["page_size"]).all()
        items = [
            {
                "id": int(item.id),
                "tab": tab,
                "detection_date": to_iso(item.detection_date),
                "name": asset.target if asset else None,
                "status": item.status,
                "asset_id": int(asset.id) if asset else None,
                "owner": asset.owner if asset else None,
            }
            for item, asset in rows
        ]
    elif tab == "ssl":
        base = (
            db_session.query(Certificate, Asset)
            .join(Asset, Certificate.asset_id == Asset.id)
            .filter(Certificate.is_deleted == False, Asset.is_deleted == False)
        )
        if params["search"]:
            q = params["search"]
            base = base.filter(
                or_(
                    Asset.target.ilike(f"%{q}%"),
                    Certificate.issuer.ilike(f"%{q}%"),
                    Certificate.cipher_suite.ilike(f"%{q}%"),
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
        items = [
            {
                "id": int(cert.id),
                "tab": "ssl",
                "name": asset.target,
                "issuer": cert.issuer,
                "subject_cn": cert.subject_cn,
                "valid_until": to_iso(cert.valid_until),
                "key_length": cert.key_length,
                "tls_version": cert.tls_version,
                "cipher_suite": cert.cipher_suite,
            }
            for cert, asset in rows
        ]
    else:
        return error_response("Invalid discovery tab. Use domains|ssl|ips|software.", 400)

    by_type = (
        db_session.query(DiscoveryItem.type, func.count(DiscoveryItem.id))
        .filter(DiscoveryItem.is_deleted == False)
        .group_by(DiscoveryItem.type)
        .all()
    )
    type_counts = {str(k or "unknown"): int(v or 0) for k, v in by_type}

    kpis = {
        "total_discovery_records": int(sum(type_counts.values())),
        "domains": int(type_counts.get("domain", 0)),
        "ssl": int(
            db_session.query(func.count(Certificate.id))
            .join(Asset, Certificate.asset_id == Asset.id)
            .filter(Certificate.is_deleted == False, Asset.is_deleted == False)
            .scalar()
            or 0
        ),
        "ips": int(type_counts.get("ip", 0)),
        "software": int(type_counts.get("software", 0)),
    }

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
    data = build_data_envelope(items, len(items), params, {})
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

    base = (
        db_session.query(CyberRating, Scan)
        .join(Scan, CyberRating.scan_id == Scan.id)
        .filter(CyberRating.is_deleted == False, Scan.is_deleted == False)
    )
    if params["search"]:
        q = params["search"]
        base = base.filter(or_(Scan.target.ilike(f"%{q}%"), CyberRating.rating_tier.ilike(f"%{q}%")))

    sort_map = {
        "target": Scan.target,
        "score": CyberRating.enterprise_score,
        "tier": CyberRating.rating_tier,
        "generated_at": CyberRating.generated_at,
        "id": CyberRating.id,
    }
    base = apply_sort(base, params["sort"], params["order"], sort_map, CyberRating.id)

    total = int(base.count())
    rows = base.offset((params["page"] - 1) * params["page_size"]).limit(params["page_size"]).all()

    items = [
        {
            "id": int(getattr(r, "id", 0) or 0),
            "url": getattr(s, "target", None),
            "enterprise_score": float(getattr(r, "enterprise_score", 0) or 0),
            "tier": getattr(r, "rating_tier", None),
            "scan_id": getattr(s, "scan_id", None),
            "generated_at": to_iso(getattr(r, "generated_at", None)),
        }
        for r, s in rows
    ]

    avg_score = (
        db_session.query(func.avg(CyberRating.enterprise_score))
        .filter(CyberRating.is_deleted == False)
        .scalar()
        or 0
    )
    if avg_score >= 800:
        tier = "Elite-PQC"
    elif avg_score >= 650:
        tier = "Advanced"
    elif avg_score >= 500:
        tier = "Standard"
    else:
        tier = "Legacy"

    kpis = {
        "enterprise_score": round(float(avg_score), 1),
        "tier": tier,
        "total_urls": int(total),
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
