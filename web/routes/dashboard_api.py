from __future__ import annotations

import math
from datetime import datetime
from typing import Any

from flask import Blueprint, jsonify, request
from flask_login import login_required
from sqlalchemy import func, or_

from src import database as db
from src.db import db_session
from src.models import (
    Asset,
    CBOMEntry,
    CBOMSummary,
    ComplianceScore,
    CyberRating,
    DiscoveryItem,
    PQCClassification,
    Scan,
)

api_dashboards_bp = Blueprint("api_dashboards", __name__)


def _to_iso(value: Any) -> str | None:
    if isinstance(value, datetime):
        return value.isoformat()
    if value is None:
        return None
    try:
        return str(value)
    except Exception:
        return None


def _parse_common_params() -> dict[str, Any]:
    page = max(1, request.args.get("page", 1, type=int) or 1)
    page_size = min(max(1, request.args.get("page_size", 25, type=int) or 25), 250)
    sort = str(request.args.get("sort", "id") or "id").strip()
    order = str(request.args.get("order", "asc") or "asc").strip().lower()
    q = str(request.args.get("q", "") or "").strip()
    return {
        "page": page,
        "page_size": page_size,
        "sort": sort,
        "order": "desc" if order == "desc" else "asc",
        "q": q,
    }


def _envelope(items: list[dict[str, Any]], total: int, params: dict[str, Any], kpis: dict[str, Any]):
    page = int(params["page"])
    page_size = int(params["page_size"])
    total_pages = max(1, math.ceil(total / page_size)) if page_size > 0 else 1
    return {
        "items": items,
        "total": int(total),
        "page": page,
        "page_size": page_size,
        "total_pages": int(total_pages),
        "kpis": kpis,
    }


def _apply_text_search(query, search_term: str, columns: list[Any]):
    if not search_term:
        return query
    return query.filter(or_(*[col.ilike(f"%{search_term}%") for col in columns]))


def _apply_sort(query, sort: str, order: str, sort_map: dict[str, Any], fallback: Any):
    sort_col = sort_map.get(sort, fallback)
    return query.order_by(sort_col.desc() if order == "desc" else sort_col.asc())


@api_dashboards_bp.app_errorhandler(404)
def api_not_found(_err):
    if request.path.startswith("/api/"):
        return jsonify({
            "status": "error",
            "message": "API endpoint not found.",
            "hint": "Check path and query parameters.",
        }), 404
    return _err


@api_dashboards_bp.app_errorhandler(500)
def api_internal_error(_err):
    if request.path.startswith("/api/"):
        return jsonify({
            "status": "error",
            "message": "Something went wrong while loading dashboard data.",
            "hint": "Please retry. If the issue persists, contact your administrator.",
        }), 500
    return _err


@api_dashboards_bp.route("/api/assets", methods=["GET"])
@login_required
def api_assets():
    params = _parse_common_params()

    base = db_session.query(Asset).filter(Asset.is_deleted == False)
    base = _apply_text_search(base, params["q"], [Asset.target, Asset.url, Asset.owner, Asset.asset_type, Asset.risk_level])

    sort_map = {
        "id": Asset.id,
        "name": Asset.target,
        "target": Asset.target,
        "url": Asset.url,
        "owner": Asset.owner,
        "risk": Asset.risk_level,
        "asset_type": Asset.asset_type,
        "updated_at": Asset.updated_at,
    }
    base = _apply_sort(base, params["sort"], params["order"], sort_map, Asset.id)

    total = int(base.count())
    rows = base.offset((params["page"] - 1) * params["page_size"]).limit(params["page_size"]).all()

    items = [
        {
            "id": int(getattr(row, "id", 0) or 0),
            "name": row.target,
            "url": row.url,
            "asset_type": row.asset_type,
            "owner": row.owner,
            "risk_level": row.risk_level,
            "last_scan_id": row.last_scan_id,
            "updated_at": _to_iso(row.updated_at),
        }
        for row in rows
    ]

    total_assets = total
    quantum_safe_pct = (
        db_session.query(func.avg(ComplianceScore.score_value))
        .filter(ComplianceScore.is_deleted == False, ComplianceScore.type.ilike("pqc"))
        .scalar()
        or 0
    )
    kpis = {
        "total_assets": int(total_assets),
        "quantum_safe_pct": round(float(quantum_safe_pct), 2),
    }

    return jsonify(_envelope(items, total, params, kpis)), 200


@api_dashboards_bp.route("/api/discovery", methods=["GET"])
@login_required
def api_discovery():
    params = _parse_common_params()
    tab = str(request.args.get("tab", "domains") or "domains").strip().lower()
    tab_map = {
        "domains": "domain",
        "ssl": "ssl",
        "ip_subnets": "ip",
        "software": "software",
    }
    discovery_type = tab_map.get(tab, "domain")

    base = (
        db_session.query(DiscoveryItem, Asset)
        .outerjoin(Asset, DiscoveryItem.asset_id == Asset.id)
        .filter(DiscoveryItem.is_deleted == False, DiscoveryItem.type == discovery_type)
    )

    if params["q"]:
        q = params["q"]
        base = base.filter(
            or_(
                DiscoveryItem.status.ilike(f"%{q}%"),
                Asset.target.ilike(f"%{q}%"),
                Asset.owner.ilike(f"%{q}%"),
            )
        )

    sort_map = {
        "id": DiscoveryItem.id,
        "status": DiscoveryItem.status,
        "type": DiscoveryItem.type,
        "detection_date": DiscoveryItem.detection_date,
        "name": Asset.target,
    }
    base = _apply_sort(base, params["sort"], params["order"], sort_map, DiscoveryItem.id)

    total = int(base.count())
    rows = base.offset((params["page"] - 1) * params["page_size"]).limit(params["page_size"]).all()

    items = [
        {
            "id": int(getattr(item, "id", 0) or 0),
            "type": item.type,
            "status": item.status,
            "detection_date": _to_iso(item.detection_date),
            "asset_id": int(getattr(asset, "id", 0) or 0) if asset else None,
            "asset_name": asset.target if asset else None,
            "asset_owner": asset.owner if asset else None,
        }
        for item, asset in rows
    ]

    total_discovery = (
        db_session.query(func.count(DiscoveryItem.id))
        .filter(DiscoveryItem.is_deleted == False)
        .scalar()
        or 0
    )
    kpis = {
        "total_assets": int(total_discovery),
        "quantum_safe_pct": 0.0,
    }

    return jsonify(_envelope(items, total, params, kpis)), 200


@api_dashboards_bp.route("/api/cbom", methods=["GET"])
@login_required
def api_cbom():
    params = _parse_common_params()

    base = (
        db_session.query(CBOMEntry, Asset)
        .outerjoin(Asset, CBOMEntry.asset_id == Asset.id)
        .filter(CBOMEntry.is_deleted == False)
    )

    if params["q"]:
        q = params["q"]
        base = base.filter(
            or_(
                CBOMEntry.algorithm_name.ilike(f"%{q}%"),
                CBOMEntry.category.ilike(f"%{q}%"),
                CBOMEntry.nist_status.ilike(f"%{q}%"),
                Asset.target.ilike(f"%{q}%"),
            )
        )

    sort_map = {
        "id": CBOMEntry.id,
        "asset_name": Asset.target,
        "algorithm": CBOMEntry.algorithm_name,
        "category": CBOMEntry.category,
        "key_length": CBOMEntry.key_length,
        "nist_status": CBOMEntry.nist_status,
    }
    base = _apply_sort(base, params["sort"], params["order"], sort_map, CBOMEntry.id)

    total = int(base.count())
    rows = base.offset((params["page"] - 1) * params["page_size"]).limit(params["page_size"]).all()

    items = [
        {
            "id": int(getattr(entry, "id", 0) or 0),
            "asset_id": int(getattr(asset, "id", entry.asset_id or 0) or 0),
            "asset_name": asset.target if asset else None,
            "algorithm_name": entry.algorithm_name,
            "category": entry.category,
            "key_length": entry.key_length,
            "nist_status": entry.nist_status,
            "quantum_safe_flag": bool(entry.quantum_safe_flag),
        }
        for entry, asset in rows
    ]

    total_components = (
        db_session.query(func.count(CBOMEntry.id))
        .filter(CBOMEntry.is_deleted == False)
        .scalar()
        or 0
    )
    weak_crypto = (
        db_session.query(func.count(CBOMEntry.id))
        .filter(CBOMEntry.is_deleted == False, CBOMEntry.quantum_safe_flag == False)
        .scalar()
        or 0
    )
    cert_issues = db_session.query(func.sum(CBOMSummary.cert_issues_count)).filter(CBOMSummary.is_deleted == False).scalar() or 0
    kpis = {
        "total_assets": int(total_components),
        "quantum_safe_pct": round((max(0, total_components - weak_crypto) / max(1, total_components)) * 100, 2),
        "weak_cryptography": int(weak_crypto),
        "certificate_issues": int(cert_issues or 0),
    }

    return jsonify(_envelope(items, total, params, kpis)), 200


@api_dashboards_bp.route("/api/pqc-posture", methods=["GET"])
@login_required
def api_pqc_posture():
    params = _parse_common_params()
    try:
        base = (
            db_session.query(PQCClassification, Asset)
            .join(Asset, PQCClassification.asset_id == Asset.id)
            .filter(PQCClassification.is_deleted == False, Asset.is_deleted == False)
        )

        if params["q"]:
            q = params["q"]
            base = base.filter(
                or_(
                    Asset.target.ilike(f"%{q}%"),
                    PQCClassification.algorithm_name.ilike(f"%{q}%"),
                    PQCClassification.quantum_safe_status.ilike(f"%{q}%"),
                )
            )

        sort_map = {
            "id": PQCClassification.id,
            "asset_name": Asset.target,
            "algorithm_name": PQCClassification.algorithm_name,
            "status": PQCClassification.quantum_safe_status,
            "score": PQCClassification.pqc_score,
            "nist_category": PQCClassification.nist_category,
        }
        base = _apply_sort(base, params["sort"], params["order"], sort_map, PQCClassification.id)

        total = int(base.count())
        rows = base.offset((params["page"] - 1) * params["page_size"]).limit(params["page_size"]).all()

        items = [
            {
                "id": int(getattr(pqc, "id", 0) or 0),
                "asset_id": int(getattr(asset, "id", 0) or 0),
                "asset_name": asset.target,
                "algorithm_name": pqc.algorithm_name,
                "algorithm_type": pqc.algorithm_type,
                "quantum_safe_status": pqc.quantum_safe_status,
                "nist_category": pqc.nist_category,
                "pqc_score": float(pqc.pqc_score or 0),
            }
            for pqc, asset in rows
        ]

        total_assets = (
            db_session.query(func.count(func.distinct(PQCClassification.asset_id)))
            .filter(PQCClassification.is_deleted == False)
            .scalar()
            or 0
        )
        safe_count = (
            db_session.query(func.count(PQCClassification.id))
            .filter(
                PQCClassification.is_deleted == False,
                func.lower(PQCClassification.quantum_safe_status).in_(["safe", "quantum_safe", "quantum-safe"]),
            )
            .scalar()
            or 0
        )
        total_classifications = (
            db_session.query(func.count(PQCClassification.id))
            .filter(PQCClassification.is_deleted == False)
            .scalar()
            or 0
        )
        kpis = {
            "total_assets": int(total_assets),
            "quantum_safe_pct": round((safe_count / max(1, total_classifications)) * 100, 2),
        }

        return jsonify(_envelope(items, total, params, kpis)), 200
    except Exception:
        kpis = {"total_assets": 0, "quantum_safe_pct": 0.0}
        return jsonify(_envelope([], 0, params, kpis)), 200


@api_dashboards_bp.route("/api/cyber-rating", methods=["GET"])
@login_required
def api_cyber_rating():
    params = _parse_common_params()
    try:
        base = (
            db_session.query(CyberRating, Scan)
            .join(Scan, CyberRating.scan_id == Scan.id)
            .filter(CyberRating.is_deleted == False, Scan.is_deleted == False)
        )

        if params["q"]:
            q = params["q"]
            base = base.filter(
                or_(
                    Scan.target.ilike(f"%{q}%"),
                    CyberRating.organization_id.ilike(f"%{q}%"),
                    CyberRating.rating_tier.ilike(f"%{q}%"),
                )
            )

        sort_map = {
            "id": CyberRating.id,
            "target": Scan.target,
            "score": CyberRating.enterprise_score,
            "tier": CyberRating.rating_tier,
            "generated_at": CyberRating.generated_at,
        }
        base = _apply_sort(base, params["sort"], params["order"], sort_map, CyberRating.id)

        total = int(base.count())
        rows = base.offset((params["page"] - 1) * params["page_size"]).limit(params["page_size"]).all()

        items = [
            {
                "id": int(getattr(rating, "id", 0) or 0),
                "organization_id": rating.organization_id,
                "target": scan.target,
                "scan_id": scan.scan_id,
                "enterprise_score": float(rating.enterprise_score or 0),
                "rating_tier": rating.rating_tier,
                "generated_at": _to_iso(rating.generated_at),
            }
            for rating, scan in rows
        ]

        avg_score = (
            db_session.query(func.avg(CyberRating.enterprise_score))
            .filter(CyberRating.is_deleted == False)
            .scalar()
            or 0
        )
        total_urls = (
            db_session.query(func.count(Scan.id))
            .filter(Scan.is_deleted == False)
            .scalar()
            or 0
        )
        kpis = {
            "total_assets": int(total_urls),
            "quantum_safe_pct": round(float(avg_score), 2),
        }

        return jsonify(_envelope(items, total, params, kpis)), 200
    except Exception:
        kpis = {"total_assets": 0, "quantum_safe_pct": 0.0}
        return jsonify(_envelope([], 0, params, kpis)), 200


@api_dashboards_bp.route("/api/reports", methods=["GET"])
@login_required
def api_reports():
    params = _parse_common_params()

    schedules = db.list_report_schedules(limit=500, include_password=False)

    q = params["q"].lower()
    if q:
        schedules = [
            row
            for row in schedules
            if q in str(row.get("report_type", "")).lower()
            or q in str(row.get("frequency", "")).lower()
            or q in str(row.get("status", "")).lower()
            or q in str(row.get("created_by_name", "")).lower()
        ]

    sort_key = params["sort"]
    reverse = params["order"] == "desc"
    allowed = {"id", "report_type", "frequency", "status", "created_at", "created_by_name"}
    if sort_key not in allowed:
        sort_key = "created_at"
    schedules = sorted(schedules, key=lambda row: str(row.get(sort_key, "")), reverse=reverse)

    total = len(schedules)
    start = (params["page"] - 1) * params["page_size"]
    end = start + params["page_size"]
    items = schedules[start:end]

    total_schedules = total
    enabled_count = sum(1 for row in schedules if bool(row.get("enabled", True)))
    kpis = {
        "total_assets": int(total_schedules),
        "quantum_safe_pct": round((enabled_count / max(1, total_schedules)) * 100, 2),
    }

    return jsonify(_envelope(items, total, params, kpis)), 200
