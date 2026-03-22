# pyre-ignore-all-errors
"""Asset inventory routes and shared page helpers."""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from datetime import datetime, timezone
from types import SimpleNamespace
from urllib.parse import urlparse

from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from flask_wtf.csrf import generate_csrf
from markupsafe import escape
from sqlalchemy import func, text

from src.db import db_session
from src.models import Asset, CBOMEntry, CBOMSummary, CyberRating, Certificate, ComplianceScore, DiscoveryItem, PQCClassification, Scan
from src.services.asset_service import AssetService
from src.services.inventory_scan_service import InventoryScanService
from utils.table_helper import paginate_query

logger = logging.getLogger(__name__)

assets_bp = Blueprint("assets", __name__)

ALLOWED_DELETE_ROLES = {"Admin", "Manager"}
ALLOWED_RISK_LEVELS = {"Low", "Medium", "High", "Critical"}
_deleted_by_user_id_accepts_text: bool | None = None


def _invalidate_caches() -> None:
    """Clear dashboard caches so KPI cards refresh immediately after writes."""

    try:
        from web.blueprints.dashboard import _dashboard_data_cache

        _dashboard_data_cache["data"] = None
        _dashboard_data_cache["updated_at"] = 0
    except Exception:
        pass


def _normalize_target(raw_target: str) -> str:
    target = str(raw_target or "").strip()
    if not target:
        return ""

    if "://" in target:
        parsed = urlparse(target)
        target = parsed.hostname or parsed.netloc or parsed.path or target

    target = target.strip().lower()
    if not target:
        return ""

    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    if ":" in target and target.count(":") == 1:
        host, maybe_port = target.rsplit(":", 1)
        if maybe_port.isdigit():
            target = host

    return target


def _asset_match_keys(asset: Asset) -> set[str]:
    """Build canonical matching keys so duplicate/legacy asset rows can be deleted together."""
    keys: set[str] = set()
    for candidate in (
        getattr(asset, "target", None),
        getattr(asset, "name", None),
        getattr(asset, "url", None),
    ):
        normalized = _normalize_target(str(candidate or ""))
        if normalized:
            keys.add(normalized)
    return keys


def _validate_target(target: str) -> bool:
    if not target or len(target) > 255:
        return False
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    hostname_pattern = re.compile(r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$|^[a-z0-9]$", re.IGNORECASE)
    return bool(hostname_pattern.match(target))


def _score_to_risk(score: float) -> str:
    if score >= 80:
        return "Low"
    if score >= 60:
        return "Medium"
    if score >= 40:
        return "High"
    return "Critical"


def _get_inventory_kpis() -> dict:
    total_assets = (
        db_session.query(func.count(Asset.id))
        .filter(Asset.is_deleted == False, Asset.deleted_at.is_(None))
        .scalar()
        or 0
    )
    total_scans = (
        db_session.query(func.count(Scan.id))
        .filter(Scan.is_deleted == False, Scan.deleted_at.is_(None))
        .scalar()
        or 0
    )
    vulnerable_assets = (
        db_session.query(func.count(Asset.id))
        .filter(
            Asset.is_deleted == False,
            Asset.deleted_at.is_(None),
            func.lower(Asset.risk_level).in_(("critical", "high")),
        )
        .scalar()
        or 0
    )

    quantum_safe_percent = (
        db_session.query(func.avg(ComplianceScore.score_value))
        .filter(
            ComplianceScore.is_deleted == False,
            ComplianceScore.deleted_at.is_(None),
            ComplianceScore.type.ilike("pqc"),
        )
        .scalar()
        or 0
    )

    avg_pqc_score = (
        db_session.query(func.avg(PQCClassification.pqc_score))
        .filter(
            PQCClassification.is_deleted == False,
            PQCClassification.deleted_at.is_(None),
            func.lower(PQCClassification.quantum_safe_status).in_(("safe", "quantum_safe", "quantum-safe")),
        )
        .scalar()
        or 0
    )

    return {
        "total_assets": int(total_assets),
        "total_scans": int(total_scans),
        "quantum_safe_percent": round(float(quantum_safe_percent or 0), 2),
        "vulnerable_assets": int(vulnerable_assets),
        "high_risk_assets": int(vulnerable_assets),
        "avg_pqc_score": round(float(avg_pqc_score or 0), 2),
    }


def _make_action_html(asset: dict, csrf_token: str) -> str:
    asset_id = int(asset.get("id") or 0)
    edit_data = {
        "asset_id": asset_id,
        "name": asset.get("name") or "",
        "url": asset.get("url") or "",
        "owner": asset.get("owner") or "",
        "risk_level": asset.get("risk_level") or "Medium",
        "last_scan": asset.get("last_scan") or "",
    }
    data_attrs = " ".join(
        f'data-{key.replace("_", "-")}="{escape(str(value))}"'
        for key, value in edit_data.items()
    )
    scan_target = escape(str(asset.get("name") or ""))

    return f"""
    <div class="row-actions">
      <button
        type="button"
        class="btn-mini btn-edit"
        {data_attrs}
        data-open-asset-edit
      >Edit</button>
      <form action="{url_for('assets.asset_scan')}" method="post" class="inline-form">
        <input type="hidden" name="csrf_token" value="{csrf_token}">
        <input type="hidden" name="asset_id" value="{asset_id}">
        <button type="submit" class="btn-mini btn-scan">Scan</button>
      </form>
      <form
        action="{url_for('assets.asset_delete', asset_id=asset_id)}"
        method="post"
        class="inline-form"
        data-asset-delete-form
        data-api-endpoint="{url_for('assets.asset_delete_api', asset_id=asset_id)}"
        data-asset-name="{scan_target}"
        onsubmit="return confirm('Move {scan_target} to Recycle Bin?');"
      >
        <input type="hidden" name="csrf_token" value="{csrf_token}">
        <button type="submit" class="btn-mini btn-delete">Move to Recycle Bin</button>
      </form>
    </div>
    """


def _decorate_asset_rows(rows: list[dict], csrf_token: str) -> list[dict]:
    decorated: list[dict] = []
    for row in rows:
        risk = str(row.get("risk_level") or row.get("risk") or "Medium")
        cert_status = str(row.get("cert_status") or "Not Scanned")
        decorated.append(
            {
                **row,
                "select_html": f'<input type="checkbox" class="asset-select-checkbox" name="asset_ids" value="{escape(str(row.get("id") or ""))}" form="bulkAssetsForm" data-row-checkbox>',
                "risk_html": f'<span class="risk-pill risk-{escape(risk.lower())}">{escape(risk)}</span>',
                "cert_status_html": f'<span class="cert-pill cert-{escape(cert_status.lower().replace(" ", "-"))}">{escape(cert_status)}</span>',
                "actions_html": _make_action_html(row, csrf_token),
                "last_scan": row.get("last_scan") or "Never",
                "key_length": row.get("key_length") or "-",
            }
        )
    return decorated


def _build_headers() -> list[dict]:
    return [
        {
            "label": '<input type="checkbox" id="selectAllAssets" data-select-all aria-label="Select all assets">',
            "field": "select_html",
            "sortable": False,
            "safe": True,
            "safe_label": True,
            "class_name": "select-column sticky-column",
        },
        {"label": "Asset Name", "field": "name", "sortable": True, "class_name": "asset-name-column"},
        {"label": "URL", "field": "url", "sortable": True, "class_name": "url-column"},
        {"label": "Type", "field": "asset_type", "sortable": True},
        {"label": "Owner", "field": "owner", "sortable": True},
        {"label": "Risk", "field": "risk_html", "sortable": True, "safe": True, "class_name": "risk-column"},
        {"label": "Cert Status", "field": "cert_status_html", "sortable": True, "safe": True, "class_name": "cert-column"},
        {"label": "Key Length", "field": "key_length", "sortable": True, "class_name": "key-column"},
        {"label": "Last Scan", "field": "last_scan", "sortable": True, "class_name": "scan-column"},
        {
            "label": "Actions",
            "field": "actions_html",
            "sortable": False,
            "safe": True,
            "class_name": "actions-column",
        },
    ]


def build_assets_page_context():
    """Build the assets inventory context used by both /assets and /asset-inventory."""

    service = AssetService()
    try:
        vm = service.get_inventory_view_model(testing_mode=current_app.config.get("TESTING", False))
    except Exception as exc:
        logger.exception("Asset inventory view model build failed")
        vm = {
            "empty": True,
            "kpis": {},
            "asset_type_distribution": {},
            "asset_risk_distribution": {},
            "risk_heatmap": [],
            "certificate_expiry_timeline": {},
            "ip_version_breakdown": {},
            "assets": [],
            "nameserver_records": [],
            "crypto_overview": [],
            "asset_locations": [],
            "certificate_inventory": [],
        }

    vm["kpis"] = {**vm.get("kpis", {}), **_get_inventory_kpis()}

    assets = list(vm.get("assets", []))
    assets = [asset for asset in assets if not asset.get("is_deleted")]
    vm["assets"] = assets
    page = request.args.get("page", 1, type=int)
    page_size = request.args.get("page_size", 25, type=int)
    sort = request.args.get("sort", "name")
    order = request.args.get("order", "asc")
    search = request.args.get("q", "")

    page_data = paginate_query(
        assets,
        page=page,
        page_size=page_size,
        sort=sort,
        order=order,
        search=search,
        searchable_columns=["name", "url", "owner", "asset_type", "risk_level", "cert_status", "last_scan"],
    )

    asset_csrf_token = generate_csrf()
    page_data["items"] = _decorate_asset_rows(list(page_data["items"]), asset_csrf_token)

    return {
        "vm": vm,
        "page_data": SimpleNamespace(**page_data),
        "headers": _build_headers(),
        "asset_csrf_token": asset_csrf_token,
    }


def render_assets_inventory_page():
    """Render the shared asset inventory page."""

    context = build_assets_page_context()
    return render_template("asset_inventory.html", **context)


@assets_bp.route("/assets", methods=["GET"])
@login_required
def assets_index():
    return render_assets_inventory_page()


@assets_bp.route("/assets/scan", methods=["POST"])
@login_required
def asset_scan():
    """Create or locate an asset, run a scan, and persist the result."""

    wants_json = request.accept_mimetypes.best == "application/json" or request.is_json
    target_raw = (request.form.get("target") or request.form.get("asset_target") or "").strip()
    asset_id = request.form.get("asset_id", type=int)
    asset_type = (request.form.get("asset_type") or "Web App").strip() or "Web App"
    owner = (request.form.get("owner") or getattr(current_user, "username", "Unassigned") or "Unassigned").strip() or "Unassigned"
    risk_level = (request.form.get("risk_level") or "Medium").strip() or "Medium"

    try:
        asset = None
        target = ""
        if asset_id:
            asset = db_session.query(Asset).filter(Asset.id == asset_id, Asset.is_deleted == False).first()
            if asset:
                target = _normalize_target(asset.target or asset.name or asset.url or "")

        if not asset:
            target = _normalize_target(target_raw)
            if not _validate_target(target):
                message = "Provide a valid target URL, hostname, or IP address."
                if wants_json:
                    return jsonify({"status": "error", "message": message}), 400
                flash(message, "error")
                return redirect(url_for("assets.assets_index"))

            asset = db_session.query(Asset).filter(func.lower(Asset.target) == target).first()
            if asset and getattr(asset, "is_deleted", False):
                asset.is_deleted = False
                asset.deleted_at = None
                asset.deleted_by_user_id = None

            if not asset:
                asset = Asset(
                    target=target,
                    url=f"https://{target}",
                    asset_type=asset_type,
                    owner=owner,
                    risk_level=risk_level,
                    notes="Auto-created from inventory scan",
                    is_deleted=False,
                )
                db_session.add(asset)
                db_session.flush()

        if not str(getattr(asset, "url", "") or ""):
            asset.url = f"https://{target}"
        if not str(getattr(asset, "owner", "") or "").strip():
            asset.owner = owner
        if not str(getattr(asset, "asset_type", "") or "").strip():
            asset.asset_type = asset_type
        if not str(getattr(asset, "risk_level", "") or "").strip():
            asset.risk_level = risk_level

        db_session.commit()

        scan_service = InventoryScanService(scan_runner=current_app.config.get("RUN_SCAN_PIPELINE_FUNC"))
        result = scan_service.scan_asset(asset, scan_kind="asset_inventory")
        if result.get("status") == "complete":
            db_session.commit()
            _invalidate_caches()
            message = f"Scan completed for {target}."
            if wants_json:
                return jsonify({"status": "complete", "message": message, "data": result}), 200
            flash(message, "success")
        else:
            db_session.commit()
            _invalidate_caches()
            message = "Scan completed with warnings."
            if wants_json:
                return jsonify({"status": "warning", "message": message, "data": result}), 200
            flash(message, "warning")
    except Exception as exc:
        db_session.rollback()
        logger.exception("Asset scan failed")
        if wants_json:
            return jsonify({"status": "error", "message": str(exc)}), 500
        flash(f"Scan failed: {exc}", "error")

    return redirect(request.referrer or url_for("assets.assets_index"))


def _apply_asset_updates(asset: Asset, owner: str | None, risk_level: str | None) -> None:
    if owner is not None:
        asset.owner = owner.strip() or asset.owner or "Unassigned"
    if risk_level is not None:
        if risk_level.strip() in ALLOWED_RISK_LEVELS:
            asset.risk_level = risk_level.strip()


def _request_wants_json() -> bool:
    if request.is_json:
        return True
    best = request.accept_mimetypes.best or ""
    return best == "application/json"


def _request_payload() -> dict:
    if request.is_json:
        return request.get_json(silent=True) or {}
    return request.form.to_dict(flat=False)


def _payload_value(payload: dict, key: str, default: str | None = None) -> str | None:
    raw = payload.get(key, default)
    if isinstance(raw, list):
        raw = raw[0] if raw else default
    if raw is None:
        return default
    return str(raw)


def _schema_allows_text_deleted_by_user_id() -> bool:
    """Detect whether DB column supports UUID/text values for deleted_by_user_id."""

    global _deleted_by_user_id_accepts_text
    if _deleted_by_user_id_accepts_text is not None:
        return _deleted_by_user_id_accepts_text

    try:
        bind = db_session.get_bind()
        dialect_name = str(getattr(getattr(bind, "dialect", None), "name", "")).lower()
        if dialect_name == "sqlite":
            _deleted_by_user_id_accepts_text = True
            return True

        if dialect_name == "mysql":
            row = db_session.execute(
                text("SHOW COLUMNS FROM assets LIKE 'deleted_by_user_id'")
            ).mappings().first()
            column_type = str((row or {}).get("Type") or "").lower()
            _deleted_by_user_id_accepts_text = any(
                token in column_type for token in ("char", "text", "uuid")
            )
            return bool(_deleted_by_user_id_accepts_text)
    except Exception:
        pass

    # Prefer permissive fallback for unknown backends/test doubles.
    _deleted_by_user_id_accepts_text = True
    return True


def _resolve_deleted_by_user_id() -> str | None:
    """Return a DB-safe audit user id for soft-delete fields.

    Some deployed schemas still use numeric deleted_by_user_id columns while
    auth user IDs are UUIDs. Persist UUIDs only when the underlying schema
    supports text; otherwise store NULL to avoid DataError/500 failures.
    """

    raw_user_id = getattr(current_user, "id", None)
    text_user_id = str(raw_user_id or "").strip()
    if not text_user_id:
        return None
    if text_user_id.isdigit():
        return text_user_id
    if _schema_allows_text_deleted_by_user_id():
        return text_user_id
    return None


def _extract_asset_ids(payload: dict) -> list[int]:
    ids: list[str] = []
    raw_asset_ids = payload.get("asset_ids")
    if isinstance(raw_asset_ids, list):
        ids.extend(str(value) for value in raw_asset_ids if str(value).strip())
    elif raw_asset_ids is not None:
        ids.extend(part.strip() for part in str(raw_asset_ids).split(",") if part.strip())

    raw_selected = payload.get("selected_asset_ids")
    if isinstance(raw_selected, list):
        for value in raw_selected:
            ids.extend(part.strip() for part in str(value).split(",") if part.strip())
    elif raw_selected is not None:
        ids.extend(part.strip() for part in str(raw_selected).split(",") if part.strip())

    return [int(value) for value in ids if value.isdigit()]


def _json_response(message: str, code: int, **data):
    return jsonify({"status": "success" if code < 400 else "error", "message": message, **data}), code


def _soft_delete_assets_by_ids(asset_ids: list[int]) -> tuple[list[Asset], str | None]:
    selected_assets = db_session.query(Asset).filter(Asset.id.in_(asset_ids), Asset.is_deleted == False).all()
    if not selected_assets:
        return [], "Asset not found."

    target_keys: set[str] = set()
    for asset in selected_assets:
        target_keys.update(_asset_match_keys(asset))

    assets_to_delete_map: dict[int, Asset] = {int(asset.id): asset for asset in selected_assets}
    if target_keys:
        active_assets = db_session.query(Asset).filter(Asset.is_deleted == False).all()
        for candidate in active_assets:
            if _asset_match_keys(candidate).intersection(target_keys):
                assets_to_delete_map[int(candidate.id)] = candidate

    return list(assets_to_delete_map.values()), None


def _soft_delete_asset(asset: Asset) -> None:
    now = datetime.now(timezone.utc)
    user_id = _resolve_deleted_by_user_id()
    asset.is_deleted = True
    asset.deleted_at = now
    asset.deleted_by_user_id = user_id

    for child in asset.discovery_items:
        child.is_deleted = True
        child.deleted_at = now
        child.deleted_by_user_id = user_id
    for child in asset.certificates:
        child.is_deleted = True
        child.deleted_at = now
        child.deleted_by_user_id = user_id
    for child in asset.pqc_classifications:
        child.is_deleted = True
        child.deleted_at = now
        child.deleted_by_user_id = user_id
    for child in asset.cbom_entries:
        child.is_deleted = True
        child.deleted_at = now
        child.deleted_by_user_id = user_id
    for child in asset.compliance_scores:
        child.is_deleted = True
        child.deleted_at = now
        child.deleted_by_user_id = user_id

    canonical_target = _normalize_target(asset.target or asset.name or "")
    if canonical_target:
        scans = db_session.query(Scan).filter(func.lower(Scan.target) == canonical_target, Scan.is_deleted == False).all()
        for scan in scans:
            scan.is_deleted = True
            scan.deleted_at = now
            scan.deleted_by_user_id = user_id
            for model in (DiscoveryItem, Certificate, PQCClassification, CBOMEntry, ComplianceScore, CBOMSummary, CyberRating):
                rows = db_session.query(model).filter(model.scan_id == scan.id, model.is_deleted == False).all()
                for row in rows:
                    row.is_deleted = True
                    row.deleted_at = now
                    row.deleted_by_user_id = user_id


@assets_bp.route("/assets/bulk-delete", methods=["POST"])
@login_required
def asset_bulk_delete():
    wants_json = _request_wants_json()
    user_role = str(getattr(current_user, "role", "") or "").strip().title()
    if user_role not in ALLOWED_DELETE_ROLES:
        message = "Only Admin or Manager users can delete assets."
        if wants_json:
            return _json_response(message, 403)
        flash(message, "error")
        return redirect(request.referrer or url_for("assets.assets_index"))

    payload = _request_payload()
    asset_ids = _extract_asset_ids(payload)
    if not asset_ids:
        message = "Select one or more assets first."
        if wants_json:
            return _json_response(message, 400)
        flash(message, "warning")
        return redirect(request.referrer or url_for("assets.assets_index"))

    try:
        assets_to_delete, error_message = _soft_delete_assets_by_ids(asset_ids)
        if error_message:
            if wants_json:
                return _json_response(error_message, 404)
            flash(error_message, "error")
            return redirect(request.referrer or url_for("assets.assets_index"))

        for asset in assets_to_delete:
            _soft_delete_asset(asset)
        db_session.commit()
        _invalidate_caches()
        message = f"Moved {len(assets_to_delete)} asset(s) to Recycle Bin."
        if wants_json:
            return _json_response(
                message,
                200,
                deleted_count=len(assets_to_delete),
                deleted_ids=[int(asset.id) for asset in assets_to_delete],
            )
        flash(message, "success")
    except Exception as exc:
        db_session.rollback()
        logger.exception("Bulk delete failed")
        message = f"Bulk delete failed: {exc}"
        if wants_json:
            return _json_response(message, 500)
        flash(message, "error")

    return redirect(request.referrer or url_for("assets.assets_index"))


@assets_bp.route("/assets/bulk-edit", methods=["POST"])
@login_required
def asset_bulk_edit():
    wants_json = _request_wants_json()
    payload = _request_payload()
    asset_ids = _extract_asset_ids(payload)
    owner = _payload_value(payload, "owner")
    risk_level = _payload_value(payload, "risk_level")

    if not asset_ids:
        message = "Select one or more assets first."
        if wants_json:
            return _json_response(message, 400)
        flash(message, "warning")
        return redirect(request.referrer or url_for("assets.assets_index"))

    try:
        assets = db_session.query(Asset).filter(Asset.id.in_(asset_ids), Asset.is_deleted == False).all()
        for asset in assets:
            _apply_asset_updates(asset, owner, risk_level)
        db_session.commit()
        _invalidate_caches()
        message = f"Updated {len(assets)} asset(s)."
        if wants_json:
            return _json_response(message, 200, updated_count=len(assets))
        flash(message, "success")
    except Exception as exc:
        db_session.rollback()
        logger.exception("Bulk edit failed")
        message = f"Bulk edit failed: {exc}"
        if wants_json:
            return _json_response(message, 500)
        flash(message, "error")

    return redirect(request.referrer or url_for("assets.assets_index"))


@assets_bp.route("/api/assets/bulk-delete", methods=["POST"])
@login_required
def asset_bulk_delete_api():
    return asset_bulk_delete()


@assets_bp.route("/api/assets/bulk-edit", methods=["POST"])
@login_required
def asset_bulk_edit_api():
    return asset_bulk_edit()


@assets_bp.route("/assets/<int:asset_id>/edit", methods=["POST"])
@login_required
def asset_edit(asset_id: int):
    wants_json = _request_wants_json()
    payload = _request_payload()
    owner = _payload_value(payload, "owner")
    risk_level = _payload_value(payload, "risk_level")

    try:
        asset = db_session.query(Asset).filter(Asset.id == asset_id, Asset.is_deleted == False).first()
        if not asset:
            message = "Asset not found."
            if wants_json:
                return _json_response(message, 404)
            flash(message, "error")
            return redirect(request.referrer or url_for("assets.assets_index"))

        _apply_asset_updates(asset, owner, risk_level)
        db_session.commit()
        _invalidate_caches()
        message = f"Updated asset '{asset.name}'."
        if wants_json:
            return _json_response(message, 200, asset_id=int(asset.id))
        flash(message, "success")
    except Exception as exc:
        db_session.rollback()
        logger.exception("Asset edit failed")
        message = f"Update failed: {exc}"
        if wants_json:
            return _json_response(message, 500)
        flash(message, "error")

    return redirect(request.referrer or url_for("assets.assets_index"))


@assets_bp.route("/assets/<int:asset_id>/delete", methods=["POST"])
@login_required
def asset_delete(asset_id: int):
    wants_json = _request_wants_json()
    user_role = str(getattr(current_user, "role", "") or "").strip().title()
    if user_role not in ALLOWED_DELETE_ROLES:
        message = "Only Admin or Manager users can delete assets."
        if wants_json:
            return _json_response(message, 403)
        flash(message, "error")
        return redirect(request.referrer or url_for("assets.assets_index"))

    try:
        assets_to_delete, error_message = _soft_delete_assets_by_ids([asset_id])
        if error_message:
            if wants_json:
                return _json_response(error_message, 404)
            flash(error_message, "error")
            return redirect(request.referrer or url_for("assets.assets_index"))

        asset_name = str(assets_to_delete[0].name or "")
        for candidate in assets_to_delete:
            _soft_delete_asset(candidate)

        db_session.commit()
        _invalidate_caches()
        message = f"Moved {len(assets_to_delete)} matching asset record(s) for '{asset_name}' to Recycle Bin."
        if wants_json:
            return _json_response(
                message,
                200,
                deleted_count=len(assets_to_delete),
                deleted_ids=[int(asset.id) for asset in assets_to_delete],
            )
        flash(message, "success")
    except Exception as exc:
        db_session.rollback()
        logger.exception("Asset delete failed")
        message = f"Delete failed: {exc}"
        if wants_json:
            return _json_response(message, 500)
        flash(message, "error")

    return redirect(request.referrer or url_for("assets.assets_index"))


@assets_bp.route("/api/assets/<int:asset_id>/edit", methods=["POST"])
@login_required
def asset_edit_api(asset_id: int):
    return asset_edit(asset_id)


@assets_bp.route("/api/assets/<int:asset_id>/delete", methods=["POST"])
@login_required
def asset_delete_api(asset_id: int):
    return asset_delete(asset_id)
