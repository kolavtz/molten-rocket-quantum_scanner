"""
API CBOM Blueprint  —  /api/cbom/*
Sprint 3: Hardened CBOM API endpoints with consistent response envelope.

Envelope shape (all endpoints):
{
  "success": true,
  "correlationId": "...",
  "data": {...},
  "meta": {
    "generatedAt": "ISO8601",
    "freshness": "fresh|stale|degraded",
    "partial": false,
    "assetId": 1,
    "hostname": "..."
  },
  "errors": []
}

Bug fixes applied in this file:
- Bug 3: /api/cbom/charts was never a standalone route — now it is.
- Bug 11: /api/cbom/export page_size logic was max() instead of min().
- All search params now use 'search' consistently (not 'q').
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from flask import Blueprint, jsonify, request, Response
from flask_login import login_required

from src.db import db_session as SessionLocal
from src.models import (
    Asset, Certificate, CBOMEntry, CBOMSummary, Scan,
    DomainCurrentState, AssetSSLProfile, DomainEvent,
)
from src.services.cbom_service import CbomService
from src.services.current_state_service import CurrentStateService
from sqlalchemy import func, distinct, desc

api_cbom = Blueprint("api_cbom", __name__, url_prefix="/api/cbom")


# ─── Envelope helpers ────────────────────────────────────────────────────────

def _envelope(
    success: bool = True,
    data: Any = None,
    errors: Optional[list] = None,
    correlation_id: Optional[str] = None,
    asset_id: Optional[int] = None,
    hostname: Optional[str] = None,
    freshness: str = "fresh",
    partial: bool = False,
    status: int = 200,
) -> tuple:
    body = {
        "success": success,
        "correlationId": correlation_id or str(uuid.uuid4()),
        "data": data if data is not None else {},
        "meta": {
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "freshness": freshness,
            "partial": partial,
            "assetId": asset_id,
            "hostname": hostname,
        },
        "errors": errors or [],
    }
    return jsonify(body), status


def _parse_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# ─── /api/cbom/metrics ───────────────────────────────────────────────────────

@api_cbom.route("/metrics", methods=["GET"])
@login_required
def get_cbom_metrics():
    """
    GET /api/cbom/metrics
    Returns org-wide CBOM KPIs derived from real DB data.
    No hardcoded values; empty states return 0.
    """
    cid = str(uuid.uuid4())
    try:
        db = SessionLocal()

        total_apps = db.query(func.count(distinct(CBOMEntry.asset_id))).filter(
            CBOMEntry.is_deleted == False
        ).scalar() or 0

        sites_surveyed = db.query(func.count(distinct(Certificate.asset_id))).filter(
            Certificate.is_deleted == False
        ).scalar() or 0

        active_certs = db.query(func.count(Certificate.id)).filter(
            Certificate.is_deleted == False,
            Certificate.valid_until != None,
            Certificate.valid_until >= datetime.now(),
        ).scalar() or 0

        # Weak crypto: key < 2048 OR weak TLS version
        weak_crypto_count = db.query(func.count(Certificate.id)).filter(
            Certificate.is_deleted == False,
            Certificate.key_length != None,
            Certificate.key_length < 2048,
        ).scalar() or 0

        cert_issues = db.query(func.count(Certificate.id)).filter(
            Certificate.is_deleted == False,
            (Certificate.is_expired == True) | (Certificate.is_self_signed == True),
        ).scalar() or 0

        db.close()

        return _envelope(
            success=True,
            data={
                "kpis": {
                    "total_applications": int(total_apps),
                    "sites_surveyed": int(sites_surveyed),
                    "active_certificates": int(active_certs),
                    "weak_crypto_count": int(weak_crypto_count),
                    "cert_issues": int(cert_issues),
                }
            },
            correlation_id=cid,
        )
    except Exception as exc:
        return _envelope(success=False, errors=[str(exc)], correlation_id=cid, status=500)


# ─── /api/cbom/entries ───────────────────────────────────────────────────────

@api_cbom.route("/entries", methods=["GET"])
@login_required
def get_cbom_entries():
    """
    GET /api/cbom/entries?page=1&page_size=25&search=term&sort=key_length&order=desc
    Returns paginated CBOM inventory entries backed by real DB data.
    Bug fix: uses 'search' param (not 'q').
    """
    cid = str(uuid.uuid4())
    try:
        page = max(1, _parse_int(request.args.get("page"), 1))
        page_size = min(max(1, _parse_int(request.args.get("page_size"), 25)), 250)
        search = (request.args.get("search") or request.args.get("q") or "").strip()
        sort_field = (request.args.get("sort") or "key_length").strip().lower()
        sort_order = (request.args.get("order") or "asc").strip().lower()
        asset_id = request.args.get("asset_id", type=int)
        start_date = request.args.get("start_date")
        end_date = request.args.get("end_date")

        cbom_data = CbomService.get_cbom_dashboard_data(
            asset_id=asset_id,
            start_date=start_date,
            end_date=end_date,
            page=page,
            page_size=page_size,
            sort_field=sort_field,
            sort_order=sort_order,
            search_term=search,
        )

        kpis = cbom_data.get("kpis", {})
        apps = cbom_data.get("applications", [])
        page_data = cbom_data.get("page_data", {})

        items = []
        for row in apps:
            last_scan = row.get("last_scan")
            if hasattr(last_scan, "isoformat"):
                last_scan = last_scan.isoformat()
            items.append({
                "asset_id": row.get("asset_id"),
                "asset_name": row.get("asset_name"),
                "cert_status": row.get("cert_status"),
                "is_current": row.get("is_current", False),
                "key_length": row.get("key_length"),
                "public_key_type": row.get("public_key_type"),
                "cipher_suite": row.get("cipher_suite"),
                "ca": row.get("ca"),
                "tls_version": row.get("tls_version"),
                "subject_cn": row.get("subject_cn"),
                "issuer_cn": row.get("issuer_cn"),
                "valid_from": row.get("valid_from"),
                "valid_until": row.get("valid_until"),
                "first_seen_at": row.get("first_seen_at"),
                "last_seen_at": row.get("last_seen_at"),
                "fingerprint_sha256": row.get("fingerprint_sha256"),
                "certificate_details": row.get("certificate_details"),
                "last_scan": last_scan,
            })

        return _envelope(
            success=True,
            data={
                "items": items,
                "total": page_data.get("total_count", len(items)),
                "page": page,
                "page_size": page_size,
                "has_next": page_data.get("has_next", False),
                "has_prev": page_data.get("has_prev", False),
                "kpis": kpis,
            },
            correlation_id=cid,
        )
    except Exception as exc:
        return _envelope(success=False, errors=[str(exc)], correlation_id=cid, status=500)


# ─── /api/cbom/charts ────────────────────────────────────────────────────────

@api_cbom.route("/charts", methods=["GET"])
@login_required
def get_cbom_charts():
    """
    GET /api/cbom/charts?asset_id=1&start_date=YYYY-MM-DD&end_date=YYYY-MM-DD
    Bug fix: This endpoint was missing entirely — frontend was hitting a 404.
    Supports optional asset_id, start_date, end_date filters.
    """
    cid = str(uuid.uuid4())
    try:
        asset_id = request.args.get("asset_id", type=int)
        start_date = request.args.get("start_date")
        end_date = request.args.get("end_date")

        cbom_data = CbomService.get_cbom_dashboard_data(
            asset_id=asset_id,
            start_date=start_date,
            end_date=end_date,
            page=1,
            page_size=1,  # We only need distribution data; skip application rows
        )

        return _envelope(
            success=True,
            data={
                "key_length_distribution": cbom_data.get("key_length_distribution", {}),
                "protocol_versions": cbom_data.get("protocol_distribution", {}),
                "cipher_suite_usage": cbom_data.get("cipher_usage", {}),
                "top_cas": cbom_data.get("ca_distribution", {}),
                "chart_explanations": {
                    "key_length_distribution": {
                        "chart_type": "bar",
                        "x_axis": "Key Length (bits)",
                        "y_axis": "Certificate Count",
                        "what_it_represents": "Distribution of RSA/ECDSA key sizes across all monitored certificates.",
                    },
                    "protocol_versions": {
                        "chart_type": "donut",
                        "what_it_represents": "Proportion of TLS versions in use (TLS 1.3 preferred, TLS 1.0/1.1 critical).",
                    },
                    "cipher_suite_usage": {
                        "chart_type": "ranked_list",
                        "what_it_represents": "Most common cipher suites across all assets.",
                    },
                    "top_cas": {
                        "chart_type": "ranked_list",
                        "what_it_represents": "Certificate Authorities issuing the most certs in inventory.",
                    },
                },
            },
            correlation_id=cid,
            asset_id=asset_id,
        )
    except Exception as exc:
        return _envelope(success=False, errors=[str(exc)], correlation_id=cid, status=500)


# ─── /api/cbom/minimum-elements ──────────────────────────────────────────────

@api_cbom.route("/minimum-elements", methods=["GET"])
@login_required
def get_minimum_elements():
    """
    GET /api/cbom/minimum-elements?page=1&page_size=25
    Returns CERT-IN Table 9 minimum element coverage data.
    """
    cid = str(uuid.uuid4())
    try:
        page = max(1, _parse_int(request.args.get("page"), 1))
        page_size = min(max(1, _parse_int(request.args.get("page_size"), 25)), 250)
        asset_id = request.args.get("asset_id", type=int)
        search = (request.args.get("search") or "").strip()

        cbom_data = CbomService.get_cbom_dashboard_data(
            asset_id=asset_id, page=page, page_size=page_size, search_term=search
        )
        minimum_elements = cbom_data.get("minimum_elements", {})

        return _envelope(
            success=True,
            data={
                "items": minimum_elements.get("items", []),
                "total": minimum_elements.get("total_entries", 0),
                "page": page,
                "page_size": page_size,
                "minimum_elements": {
                    "asset_type_distribution": minimum_elements.get("asset_type_distribution", {}),
                    "field_coverage": minimum_elements.get("field_coverage", {}),
                    "field_definitions": minimum_elements.get("field_definitions", {}),
                    "coverage_summary": minimum_elements.get("coverage_summary", {}),
                },
            },
            correlation_id=cid,
        )
    except Exception as exc:
        return _envelope(success=False, errors=[str(exc)], correlation_id=cid, status=500)


# ─── /api/cbom/export ────────────────────────────────────────────────────────

@api_cbom.route("/export", methods=["GET"])
@login_required
def export_cbom():
    """
    GET /api/cbom/export
    Downloads full CBOM JSON payload as attachment.
    Bug fix: page_size was max(page_size, 250) which allowed > 250; now capped at min(..., 250).
    """
    cid = str(uuid.uuid4())
    try:
        raw_page_size = _parse_int(request.args.get("page_size"), 100)
        # Bug fix: was max(raw_page_size, 250) — allows unbounded. Now capped at 250.
        page_size = min(max(raw_page_size, 10), 250)
        search = (request.args.get("search") or request.args.get("q") or "").strip()
        asset_id = request.args.get("asset_id", type=int)

        cbom_data = CbomService.get_cbom_dashboard_data(
            asset_id=asset_id, page=1, page_size=page_size, search_term=search
        )

        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "correlation_id": cid,
            "kpis": cbom_data.get("kpis", {}),
            "entries": cbom_data.get("applications", []),
            "charts": {
                "key_length_distribution": cbom_data.get("key_length_distribution", {}),
                "cipher_suite_usage": cbom_data.get("cipher_usage", {}),
                "protocol_versions": cbom_data.get("protocol_distribution", {}),
                "top_cas": cbom_data.get("ca_distribution", {}),
            },
            "minimum_elements": cbom_data.get("minimum_elements", {}),
        }

        resp = Response(
            json.dumps(payload, default=str, indent=2),
            mimetype="application/json",
        )
        resp.headers["Content-Disposition"] = (
            f'attachment; filename="cbom_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json"'
        )
        return resp, 200

    except Exception as exc:
        return _envelope(success=False, errors=[str(exc)], correlation_id=cid, status=500)


# ─── /api/cbom/summary ───────────────────────────────────────────────────────

@api_cbom.route("/summary", methods=["GET"])
@login_required
def get_cbom_summary():
    """GET /api/cbom/summary?scan_id=123  —  Single-scan CBOM summary."""
    cid = str(uuid.uuid4())
    try:
        scan_id = request.args.get("scan_id", type=int)
        if not scan_id:
            return _envelope(
                success=False, errors=["scan_id parameter required"],
                correlation_id=cid, status=400
            )

        db = SessionLocal()
        entries = db.query(CBOMEntry).filter(
            CBOMEntry.scan_id == scan_id, CBOMEntry.is_deleted == False
        ).all()

        summary = {
            "scan_id": scan_id,
            "total_entries": len(entries),
            "weak_crypto_count": sum(1 for e in entries if e.key_length and e.key_length < 2048),
            "unique_algorithms": len(set(e.algorithm_name for e in entries if e.algorithm_name)),
        }
        db.close()

        return _envelope(success=True, data=summary, correlation_id=cid)
    except Exception as exc:
        return _envelope(success=False, errors=[str(exc)], correlation_id=cid, status=500)


# ─── /api/cbom/asset/<id>/current ────────────────────────────────────────────

@api_cbom.route("/asset/<int:asset_id>/current", methods=["GET"])
@login_required
def get_asset_current_state(asset_id: int):
    """
    GET /api/cbom/asset/{asset_id}/current
    Returns the canonical current SSL/TLS state for one asset.
    Uses DomainCurrentState as the source of truth.
    """
    cid = str(uuid.uuid4())
    try:
        db = SessionLocal()
        state = CurrentStateService.get_current_state(asset_id=asset_id, db_session=db)
        db.close()

        return _envelope(
            success=True,
            data=state,
            correlation_id=cid,
            asset_id=asset_id,
            hostname=state.get("hostname"),
            freshness=state.get("freshness_status", "unknown"),
            partial=not state.get("has_data", True),
        )
    except Exception as exc:
        return _envelope(
            success=False, errors=[str(exc)], correlation_id=cid,
            asset_id=asset_id, status=500
        )


# ─── /api/cbom/asset/<id>/ssl/history ────────────────────────────────────────

@api_cbom.route("/asset/<int:asset_id>/ssl/history", methods=["GET"])
@login_required
def get_asset_ssl_history(asset_id: int):
    """
    GET /api/cbom/asset/{asset_id}/ssl/history
    Returns paginated certificate history for one asset, newest first.
    """
    cid = str(uuid.uuid4())
    try:
        page = max(1, _parse_int(request.args.get("page"), 1))
        page_size = min(max(1, _parse_int(request.args.get("page_size"), 25)), 100)
        include_all = request.args.get("include_all", "false").lower() == "true"

        db = SessionLocal()

        q = db.query(Certificate).filter(
            Certificate.asset_id == asset_id,
            Certificate.is_deleted == False,
        ).order_by(Certificate.first_seen_at.desc().nullslast())

        if not include_all:
            q = q.filter(Certificate.is_current == True)

        total = q.count()
        certs = q.offset((page - 1) * page_size).limit(page_size).all()

        items = []
        for cert in certs:
            san_list = []
            if cert.san_domains:
                try:
                    san_list = json.loads(cert.san_domains)
                except Exception:
                    san_list = [cert.san_domains]

            items.append({
                "id": cert.id,
                "cert_status": CbomService._compute_cert_status(cert),
                "is_current": cert.is_current,
                "subject_cn": cert.subject_cn,
                "issuer_cn": cert.issuer_cn,
                "serial": cert.serial,
                "fingerprint_sha256": cert.fingerprint_sha256,
                "valid_from": cert.valid_from.isoformat() if cert.valid_from else None,
                "valid_until": cert.valid_until.isoformat() if cert.valid_until else None,
                "expiry_days": cert.expiry_days,
                "tls_version": cert.tls_version,
                "key_length": cert.key_length,
                "cipher_suite": cert.cipher_suite,
                "ca": cert.ca,
                "san_domains": san_list,
                "first_seen_at": cert.first_seen_at.isoformat() if cert.first_seen_at else None,
                "last_seen_at": cert.last_seen_at.isoformat() if cert.last_seen_at else None,
            })

        db.close()

        return _envelope(
            success=True,
            data={"items": items, "total": total, "page": page, "page_size": page_size,
                  "has_next": (page * page_size) < total, "has_prev": page > 1},
            correlation_id=cid,
            asset_id=asset_id,
        )
    except Exception as exc:
        return _envelope(success=False, errors=[str(exc)], correlation_id=cid,
                         asset_id=asset_id, status=500)


# ─── /api/cbom/asset/<id>/tls/history ────────────────────────────────────────

@api_cbom.route("/asset/<int:asset_id>/tls/history", methods=["GET"])
@login_required
def get_asset_tls_history(asset_id: int):
    """
    GET /api/cbom/asset/{asset_id}/tls/history
    Returns AssetSSLProfile history (TLS version changes over time).
    """
    cid = str(uuid.uuid4())
    try:
        page = max(1, _parse_int(request.args.get("page"), 1))
        page_size = min(max(1, _parse_int(request.args.get("page_size"), 25)), 100)

        db = SessionLocal()

        q = db.query(AssetSSLProfile).filter(
            AssetSSLProfile.asset_id == asset_id,
            AssetSSLProfile.is_deleted == False,
        ).order_by(AssetSSLProfile.created_at.desc())

        total = q.count()
        profiles = q.offset((page - 1) * page_size).limit(page_size).all()

        items = [{
            "id": p.id,
            "is_current": p.is_current,
            "supports_tls_1_0": p.supports_tls_1_0,
            "supports_tls_1_1": p.supports_tls_1_1,
            "supports_tls_1_2": p.supports_tls_1_2,
            "supports_tls_1_3": p.supports_tls_1_3,
            "preferred_cipher": p.preferred_cipher,
            "weak_cipher_count": p.weak_cipher_count,
            "hsts_enabled": p.hsts_enabled,
            "hsts_max_age": p.hsts_max_age,
            "created_at": p.created_at.isoformat() if p.created_at else None,
        } for p in profiles]

        db.close()

        return _envelope(
            success=True,
            data={"items": items, "total": total, "page": page, "page_size": page_size,
                  "has_next": (page * page_size) < total, "has_prev": page > 1},
            correlation_id=cid,
            asset_id=asset_id,
        )
    except Exception as exc:
        return _envelope(success=False, errors=[str(exc)], correlation_id=cid,
                         asset_id=asset_id, status=500)


# ─── /api/cbom/asset/<id>/events ─────────────────────────────────────────────

@api_cbom.route("/asset/<int:asset_id>/events", methods=["GET"])
@login_required
def get_asset_events(asset_id: int):
    """
    GET /api/cbom/asset/{asset_id}/events?page=1&page_size=25
    Returns DomainEvent timeline for one asset, newest first.
    """
    cid = str(uuid.uuid4())
    try:
        page = max(1, _parse_int(request.args.get("page"), 1))
        page_size = min(max(1, _parse_int(request.args.get("page_size"), 25)), 100)
        severity = request.args.get("severity")

        db = SessionLocal()
        q = db.query(DomainEvent).filter(
            DomainEvent.asset_id == asset_id
        ).order_by(DomainEvent.created_at.desc())

        if severity:
            q = q.filter(DomainEvent.severity == severity)

        total = q.count()
        events = q.offset((page - 1) * page_size).limit(page_size).all()

        items = [{
            "id": e.id,
            "event_type": e.event_type,
            "event_title": e.event_title,
            "event_description": e.event_description,
            "severity": e.severity,
            "correlation_id": e.correlation_id,
            "created_at": e.created_at.isoformat() if e.created_at else None,
        } for e in events]

        db.close()

        return _envelope(
            success=True,
            data={"items": items, "total": total, "page": page, "page_size": page_size,
                  "has_next": (page * page_size) < total, "has_prev": page > 1},
            correlation_id=cid,
            asset_id=asset_id,
        )
    except Exception as exc:
        return _envelope(success=False, errors=[str(exc)], correlation_id=cid,
                         asset_id=asset_id, status=500)


# ─── /api/cbom/asset/<id>/diagnostics ────────────────────────────────────────

@api_cbom.route("/asset/<int:asset_id>/diagnostics", methods=["GET"])
@login_required
def get_asset_diagnostics(asset_id: int):
    """
    GET /api/cbom/asset/{asset_id}/diagnostics
    Returns ingestion health, recent scan outcomes, and error summaries.
    """
    cid = str(uuid.uuid4())
    try:
        db = SessionLocal()

        asset = db.query(Asset).filter_by(id=asset_id, is_deleted=False).first()
        if not asset:
            db.close()
            return _envelope(success=False, errors=["Asset not found"],
                             correlation_id=cid, status=404)

        dcs = db.query(DomainCurrentState).filter_by(asset_id=asset_id).first()

        # Recent scans (last 10)
        recent_scans = (
            db.query(Scan)
            .filter(
                Scan.target == asset.target,
                Scan.is_deleted == False,
            )
            .order_by(Scan.completed_at.desc())
            .limit(10)
            .all()
        )

        scan_history = [{
            "scan_id": s.scan_id,
            "status": s.status,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "error_message": s.error_message,
            "correlation_id": getattr(s, "correlation_id", None),
        } for s in recent_scans]

        # Cert count summary
        total_certs = db.query(func.count(Certificate.id)).filter(
            Certificate.asset_id == asset_id, Certificate.is_deleted == False
        ).scalar() or 0
        current_certs = db.query(func.count(Certificate.id)).filter(
            Certificate.asset_id == asset_id,
            Certificate.is_deleted == False,
            Certificate.is_current == True,
        ).scalar() or 0

        db.close()

        return _envelope(
            success=True,
            data={
                "asset": {"id": asset.id, "hostname": asset.target},
                "current_state": {
                    "freshness_status": dcs.freshness_status if dcs else "unknown",
                    "last_successful_scan_at": (
                        dcs.last_successful_scan_at.isoformat()
                        if dcs and dcs.last_successful_scan_at else None
                    ),
                    "last_failed_scan_at": (
                        dcs.last_failed_scan_at.isoformat()
                        if dcs and dcs.last_failed_scan_at else None
                    ),
                    "render_status": dcs.render_status if dcs else None,
                    "render_error_message": dcs.render_error_message if dcs else None,
                },
                "certificate_summary": {
                    "total_historical": total_certs,
                    "current_count": current_certs,
                },
                "scan_history": scan_history,
            },
            correlation_id=cid,
            asset_id=asset_id,
            hostname=asset.target,
        )
    except Exception as exc:
        return _envelope(success=False, errors=[str(exc)], correlation_id=cid,
                         asset_id=asset_id, status=500)


# ─── /api/cbom/dashboard/summary ─────────────────────────────────────────────

@api_cbom.route("/dashboard/summary", methods=["GET"])
@login_required
def get_dashboard_summary():
    """
    GET /api/cbom/dashboard/summary?page=1&page_size=25
    Org-wide paginated summary of all asset current states.
    Used by the CBOM overview tab.
    """
    cid = str(uuid.uuid4())
    try:
        page = max(1, _parse_int(request.args.get("page"), 1))
        page_size = min(max(1, _parse_int(request.args.get("page_size"), 25)), 100)

        db = SessionLocal()
        result = CurrentStateService.get_all_assets_summary(
            db_session=db, page=page, page_size=page_size
        )
        db.close()

        return _envelope(success=True, data=result, correlation_id=cid)
    except Exception as exc:
        return _envelope(success=False, errors=[str(exc)], correlation_id=cid, status=500)


# ─── Legacy alias ─────────────────────────────────────────────────────────────

@api_cbom.route("", methods=["GET"])
@login_required
def cbom_root_alias():
    """Alias: GET /api/cbom → redirects to /api/cbom/entries."""
    return get_cbom_entries()
