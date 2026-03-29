from __future__ import annotations

import json
import math
import threading
import uuid
from datetime import datetime, timezone
import re
from typing import Any

from flask import Blueprint, abort, current_app, jsonify, render_template, request
from flask_login import current_user, login_required
from sqlalchemy import or_

from src import database as db
from src.db import db_session
from src.models import Asset, Certificate, Scan

scans_bp = Blueprint("scans", __name__)

SCAN_ROLES = {"Admin", "Manager", "SingleScan", "Viewer"}
BULK_SCAN_ROLES = {"Admin", "Manager"}

_scan_jobs_lock = threading.Lock()
_scan_jobs: dict[str, dict[str, Any]] = {}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso_datetime(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _days_remaining(valid_until: datetime | None) -> int | None:
    if valid_until is None:
        return None
    now_naive = datetime.now(timezone.utc).replace(tzinfo=None)
    return int((valid_until - now_naive).days)


def _certificate_status(valid_until: datetime | None, is_expired: bool | None) -> str:
    expired = bool(is_expired)
    remaining = _days_remaining(valid_until)
    if expired or (remaining is not None and remaining < 0):
        return "Expired"
    if remaining is None:
        return "Unknown"
    if remaining == 0:
        return "Expires Today"
    if remaining <= 30:
        return "Expiring"
    return "Valid"


def _safe_json_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item or "").strip()]
    text = str(value or "").strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return [str(item) for item in parsed if str(item or "").strip()]
    except Exception:
        pass
    return []


def _can_scan() -> bool:
    role = str(getattr(current_user, "role", "") or "").strip().title()
    return getattr(current_user, "is_authenticated", False) and role in {r.title() for r in SCAN_ROLES}


def _can_bulk_scan() -> bool:
    role = str(getattr(current_user, "role", "") or "").strip().title()
    return getattr(current_user, "is_authenticated", False) and role in {r.title() for r in BULK_SCAN_ROLES}


def _parse_ports(value: Any) -> list[int] | None:
    if value is None:
        return None
    if isinstance(value, list):
        parsed = []
        for item in value:
            try:
                p = int(item)
            except (TypeError, ValueError):
                continue
            if 1 <= p <= 65535:
                parsed.append(p)
        return parsed or None
    if isinstance(value, str):
        parsed = []
        for token in value.replace(" ", ",").split(","):
            token = token.strip()
            if not token:
                continue
            try:
                p = int(token)
            except (TypeError, ValueError):
                continue
            if 1 <= p <= 65535:
                parsed.append(p)
        return parsed or None
    return None


def _normalize_status(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"complete", "completed", "done", "success"}:
        return "completed"
    if text in {"running", "in_progress", "queued", "pending"}:
        return "running"
    if text in {"failed", "error"}:
        return "failed"
    return text or "unknown"


def _normalize_scan_type(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return "single"
    if text in {"bulk", "api_bulk", "manual_bulk"}:
        return text
    if text in {"single", "api_single", "manual_single", "api_scan_run", "manual"}:
        return text
    if "bulk" in text:
        return "bulk"
    return "single"


def _build_scan_item_from_report(report: dict[str, Any]) -> dict[str, Any]:
    overview = report.get("overview") if isinstance(report.get("overview"), dict) else {}
    pqc_score = overview.get("average_compliance_score")
    if pqc_score is None:
        pqc_score = report.get("overall_pqc_score")

    assets_found = report.get("total_assets")
    if assets_found is None:
        assets_found = len(report.get("discovered_services") or [])

    scan_id = str(report.get("scan_id") or "")
    
    # Extract timestamps
    started_at = str(report.get("started_at") or report.get("timestamp") or "")
    completed_at = str(report.get("completed_at") or report.get("generated_at") or "")
    
    return {
        "scan_id": scan_id,
        "target": str(report.get("target") or ""),
        "scan_type": _normalize_scan_type(report.get("scan_kind") or report.get("scan_type")),
        "status": _normalize_status(report.get("status") or "completed"),
        "assets_found": int(assets_found or 0),
        "pqc_score": round(float(pqc_score or 0), 2),
        "started_at": started_at,
        "completed_at": completed_at,
        "date": started_at or completed_at or "",
        "add_to_inventory": bool(report.get("add_to_inventory", False)),
        "actions": f"/results/{scan_id}" if scan_id else "",
    }


def _collect_scan_items() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    seen: set[str] = set()

    # persisted scans
    for report in db.list_scans(limit=2000):
        if not isinstance(report, dict):
            continue
        item = _build_scan_item_from_report(report)
        sid = item.get("scan_id")
        if sid:
            seen.add(sid)
        items.append(item)

    # in-memory scans fallback / latest
    try:
        import web.app as web_app_module

        for report in web_app_module.scan_store.values():
            if not isinstance(report, dict):
                continue
            item = _build_scan_item_from_report(report)
            sid = item.get("scan_id")
            if sid and sid in seen:
                continue
            if sid:
                seen.add(sid)
            items.append(item)
    except Exception:
        pass

    # running jobs (in-memory tracking IDs)
    with _scan_jobs_lock:
        for tracking_id, job in _scan_jobs.items():
            scan_ids = job.get("scan_ids") or []
            statuses = job.get("statuses") or {}
            for sid in scan_ids:
                if sid in seen:
                    continue
                st = statuses.get(sid) if isinstance(statuses, dict) else {}
                items.append(
                    {
                        "scan_id": sid,
                        "target": str(st.get("target") or ""),
                        "scan_type": _normalize_scan_type(st.get("scan_type") or (st.get("options") or {}).get("scan_type") or "single"),
                        "status": _normalize_status(st.get("status") or job.get("status")),
                        "assets_found": int(st.get("assets_found") or 0),
                        "pqc_score": round(float(st.get("pqc_score") or 0), 2),
                        "started_at": str(st.get("started_at") or job.get("started_at") or ""),
                        "completed_at": str(st.get("completed_at") or job.get("completed_at") or ""),
                        "date": str(st.get("updated_at") or job.get("updated_at") or ""),
                        "actions": f"/api/scans/{sid}/status",
                    }
                )
                seen.add(sid)

    return items


def _resolve_result_scan_id(scan_id: str) -> str:
    snapshot = _status_snapshot(scan_id)
    if isinstance(snapshot, dict):
        resolved = str(snapshot.get("result_scan_id") or "").strip()
        if resolved:
            return resolved
    return str(scan_id or "").strip()


def _normalize_tls_row_from_report(raw_row: dict[str, Any], scan_id: str) -> dict[str, Any]:
    host = str(raw_row.get("host") or "").strip()
    port = int(raw_row.get("port") or 0) if str(raw_row.get("port") or "").strip() else None
    endpoint = str(raw_row.get("endpoint") or "").strip()
    if not endpoint and host:
        endpoint = f"{host}:{port}" if port else host

    cert_days = raw_row.get("cert_days_remaining")
    try:
        cert_days_int = int(cert_days) if cert_days is not None else None
    except (TypeError, ValueError):
        cert_days_int = None

    cert_expired = bool(raw_row.get("cert_expired"))
    cert_status = str(raw_row.get("cert_status") or "").strip()
    if not cert_status:
        if cert_expired or (cert_days_int is not None and cert_days_int < 0):
            cert_status = "Expired"
        elif cert_days_int is not None and cert_days_int <= 30:
            cert_status = "Expiring"
        elif cert_days_int is not None:
            cert_status = "Valid"
        else:
            cert_status = "Unknown"

    certificate_details = raw_row.get("certificate_details") if isinstance(raw_row.get("certificate_details"), dict) else {}

    if not certificate_details:
        certificate_details = {
            "certificate_version": "",
            "serial_number": str(raw_row.get("serial_number") or ""),
            "certificate_signature_algorithm": str(raw_row.get("signature_algorithm") or ""),
            "certificate_signature": "",
            "issuer": str(raw_row.get("issuer") or raw_row.get("issuer_cn") or raw_row.get("issuer_o") or ""),
            "validity": {
                "not_before": str(raw_row.get("valid_from") or ""),
                "not_after": str(raw_row.get("valid_to") or ""),
            },
            "subject": str(raw_row.get("subject") or raw_row.get("subject_cn") or ""),
            "subject_public_key_info": {
                "subject_public_key_algorithm": str(raw_row.get("key_type") or ""),
                "subject_public_key_bits": int(raw_row.get("key_length") or raw_row.get("key_size") or 0),
                "subject_public_key": str(raw_row.get("public_key_pem") or ""),
            },
            "extensions": [],
            "certificate_key_usage": [],
            "extended_key_usage": [],
            "certificate_basic_constraints": {},
            "certificate_subject_key_id": "",
            "certificate_authority_key_id": "",
            "authority_information_access": [],
            "certificate_subject_alternative_name": [str(item) for item in (raw_row.get("san_domains") or []) if str(item or "").strip()],
            "certificate_policies": [],
            "crl_distribution_points": [],
            "signed_certificate_timestamp_list": [],
        }

    return {
        "certificate_id": None,
        "scan_id": scan_id,
        "asset_id": None,
        "asset_name": None,
        "endpoint": endpoint,
        "host": host or None,
        "port": port,
        "issuer": str(raw_row.get("issuer_cn") or raw_row.get("issuer_o") or ""),
        "subject": str(raw_row.get("subject") or ""),
        "subject_cn": str(raw_row.get("subject_cn") or ""),
        "subject_o": str(raw_row.get("subject_o") or ""),
        "subject_ou": str(raw_row.get("subject_ou") or ""),
        "issuer_cn": str(raw_row.get("issuer_cn") or ""),
        "issuer_o": str(raw_row.get("issuer_o") or ""),
        "issuer_ou": str(raw_row.get("issuer_ou") or ""),
        "serial": str(raw_row.get("serial_number") or ""),
        "tls_version": str(raw_row.get("tls_version") or raw_row.get("protocol_version") or "Unknown"),
        "cipher_suite": str(raw_row.get("cipher_suite") or "Unknown"),
        "key_length": int(raw_row.get("key_length") or raw_row.get("key_size") or 0),
        "key_algorithm": str(raw_row.get("key_type") or ""),
        "signature_algorithm": str(raw_row.get("signature_algorithm") or ""),
        "fingerprint_sha256": str(raw_row.get("cert_sha256") or ""),
        "san_domains": [str(item) for item in (raw_row.get("san_domains") or []) if str(item or "").strip()],
        "certificate_details": certificate_details,
        "cert_chain_length": int(raw_row.get("certificate_chain_length") or 0),
        "valid_from": str(raw_row.get("valid_from") or "") or None,
        "valid_until": str(raw_row.get("valid_to") or "") or None,
        "days_remaining": cert_days_int,
        "is_expired": cert_expired,
        "is_self_signed": False,
        "status": cert_status,
    }


def _certificate_items_from_report(report: dict[str, Any], scan_id: str) -> list[dict[str, Any]]:
    tls_rows = report.get("tls_results")
    if not isinstance(tls_rows, list):
        return []
    return [
        _normalize_tls_row_from_report(dict(row), scan_id)
        for row in tls_rows
        if isinstance(row, dict)
    ]


def _status_snapshot(scan_id: str) -> dict[str, Any] | None:
    with _scan_jobs_lock:
        for job in _scan_jobs.values():
            statuses = job.get("statuses") or {}
            if scan_id in statuses:
                row = dict(statuses[scan_id])
                row["job_id"] = job.get("job_id")
                row["job_status"] = job.get("status")
                row["completed"] = int(job.get("completed") or 0)
                row["total"] = int(job.get("total") or 0)
                return row
    return None


def _load_scan_report(scan_id: str) -> dict[str, Any] | None:
    try:
        import web.app as web_app_module

        report = web_app_module.scan_store.get(scan_id)
        if isinstance(report, dict):
            return report
    except Exception:
        pass

    report = db.get_scan(scan_id)
    if isinstance(report, dict):
        return report

    return None


def _certificate_summary(items: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(items)
    expired = 0
    expiring_30 = 0
    self_signed = 0
    weak_tls = 0
    weak_keys = 0
    statuses: dict[str, int] = {}

    for row in items:
        status = str(row.get("status") or "Unknown")
        statuses[status] = int(statuses.get(status, 0) or 0) + 1

        if bool(row.get("is_expired")) or status.lower() == "expired":
            expired += 1

        remaining = row.get("days_remaining")
        try:
            remaining_int = int(remaining) if remaining is not None else None
        except (TypeError, ValueError):
            remaining_int = None
        if remaining_int is not None and 0 <= remaining_int <= 30:
            expiring_30 += 1

        if bool(row.get("is_self_signed")):
            self_signed += 1

        tls_version = str(row.get("tls_version") or "").upper().replace(" ", "")
        if tls_version in {"TLS1.0", "TLS1.1", "SSLV3", "SSLV2"}:
            weak_tls += 1

        key_length = row.get("key_length")
        try:
            key_int = int(key_length) if key_length is not None else 0
        except (TypeError, ValueError):
            key_int = 0
        if 0 < key_int < 2048:
            weak_keys += 1

    return {
        "total_certificates": int(total),
        "expired": int(expired),
        "expiring_30_days": int(expiring_30),
        "self_signed": int(self_signed),
        "weak_tls": int(weak_tls),
        "weak_keys": int(weak_keys),
        "status_distribution": statuses,
    }


def _apply_certificate_sort(items: list[dict[str, Any]], sort: str, order: str) -> list[dict[str, Any]]:
    sort_field = str(sort or "valid_until").strip().lower()
    reverse = str(order or "asc").strip().lower() == "desc"

    def _key(row: dict[str, Any]):
        if sort_field in {"key_length", "days_remaining", "port"}:
            try:
                return int(row.get(sort_field) or 0)
            except (TypeError, ValueError):
                return 0
        return str(row.get(sort_field) or "").lower()

    return sorted(items, key=_key, reverse=reverse)


def _apply_certificate_search(items: list[dict[str, Any]], query: str) -> list[dict[str, Any]]:
    q = str(query or "").strip().lower()
    if not q:
        return items
    out: list[dict[str, Any]] = []
    for row in items:
        haystack = " ".join(
            [
                str(row.get("endpoint") or ""),
                str(row.get("issuer") or ""),
                str(row.get("subject_cn") or ""),
                str(row.get("subject") or ""),
                str(row.get("serial") or ""),
                str(row.get("tls_version") or ""),
                str(row.get("cipher_suite") or ""),
                str(row.get("fingerprint_sha256") or ""),
            ]
        ).lower()
        if q in haystack:
            out.append(row)
    return out


def _upsert_inventory_asset_from_scan(
    *,
    target: str,
    add_to_inventory: bool,
    owner: str | None,
    risk_level: str | None,
    notes: str | None,
    asset_type: str | None,
) -> None:
    if not add_to_inventory:
        return

    try:
        from sqlalchemy import func
        from src.db import db_session
        from src.models import Asset

        canonical = str(target or "").strip().lower()
        if not canonical:
            return

        asset = db_session.query(Asset).filter(func.lower(Asset.name) == canonical).first()
        if not asset:
            asset = Asset(
                name=canonical,
                url=f"https://{canonical}" if not canonical.startswith(("http://", "https://")) else canonical,
                asset_type=str(asset_type or "Web App").strip() or "Web App",
                owner=(str(owner).strip() if owner else None),
                risk_level=str(risk_level or "Medium").strip() or "Medium",
                notes=(str(notes).strip() if notes else None),
                is_deleted=False,
            )
            db_session.add(asset)
        else:
            if getattr(asset, "is_deleted", False):
                asset.is_deleted = False
            if owner:
                asset.owner = str(owner).strip()
            if risk_level:
                asset.risk_level = str(risk_level).strip() or asset.risk_level
            if notes:
                existing = str(getattr(asset, "notes", "") or "").strip()
                incoming = str(notes).strip()
                asset.notes = incoming if not existing else f"{existing} | {incoming}"
            if asset_type:
                asset.asset_type = str(asset_type).strip() or asset.asset_type

        db_session.commit()
    except Exception:
        try:
            from src.db import db_session

            db_session.rollback()
        except Exception:
            pass


def _process_job(
    job_id: str,
    requested_by: str | None,
    ports: list[int] | None,
    testing_mode: bool,
    options: dict[str, Any] | None,
) -> None:
    job_options = dict(options or {})
    with _scan_jobs_lock:
        job = _scan_jobs.get(job_id)
        if not job:
            return
        job["status"] = "running"
        job["started_at"] = _now_iso()
        scan_ids = list(job.get("scan_ids") or [])
        targets = list(job.get("targets") or [])

    try:
        import web.app as web_app_module

        for idx, target in enumerate(targets):
            tracking_scan_id = scan_ids[idx]
            with _scan_jobs_lock:
                running_job = _scan_jobs.get(job_id)
                if not running_job:
                    return
                statuses = running_job.get("statuses") or {}
                statuses[tracking_scan_id]["status"] = "running"
                statuses[tracking_scan_id]["updated_at"] = _now_iso()
                running_job["statuses"] = statuses

            try:
                clean_target, _ = web_app_module.sanitize_target(target)
                effective_ports = ports
                if not effective_ports and bool(job_options.get("autodiscovery")):
                    try:
                        from config import AUTODISCOVERY_PORTS

                        effective_ports = list(AUTODISCOVERY_PORTS)
                    except Exception:
                        effective_ports = None

                report = web_app_module.run_scan_pipeline(
                    clean_target,
                    ports=effective_ports,
                    asset_class_hint=(str(job_options.get("asset_class_hint") or "").strip() or None),
                    scan_kind=str(job_options.get("scan_type") or ("api_bulk" if len(targets) > 1 else "api_single")),
                    scanned_by=requested_by,
                    add_to_inventory=bool(job_options.get("add_to_inventory")),
                )

                if not testing_mode and not bool(report.get("orm_persisted")):
                    db.save_scan(report)

                web_app_module.scan_store[report.get("scan_id")] = report

                _upsert_inventory_asset_from_scan(
                    target=clean_target,
                    add_to_inventory=bool(job_options.get("add_to_inventory")),
                    owner=(str(job_options.get("owner") or "").strip() or None),
                    risk_level=(str(job_options.get("risk_level") or "").strip() or None),
                    notes=(str(job_options.get("notes") or "").strip() or None),
                    asset_type=(str(job_options.get("asset_type") or "").strip() or None),
                )

                with _scan_jobs_lock:
                    running_job = _scan_jobs.get(job_id)
                    if not running_job:
                        return
                    statuses = running_job.get("statuses") or {}
                    statuses[tracking_scan_id] = {
                        "scan_id": tracking_scan_id,
                        "target": clean_target,
                        "scan_type": _normalize_scan_type(job_options.get("scan_type") or ("api_bulk" if len(targets) > 1 else "api_single")),
                        "status": "completed",
                        "assets_found": int(report.get("total_assets") or len(report.get("discovered_services") or [])),
                        "pqc_score": float((report.get("overview") or {}).get("average_compliance_score") or report.get("overall_pqc_score") or 0),
                        "result_scan_id": report.get("scan_id"),
                        "started_at": str(running_job.get("started_at") or ""),
                        "completed_at": _now_iso(),
                        "updated_at": _now_iso(),
                    }
                    running_job["statuses"] = statuses
                    running_job["completed"] = int(running_job.get("completed") or 0) + 1
                    running_job["updated_at"] = _now_iso()
            except Exception as exc:
                with _scan_jobs_lock:
                    running_job = _scan_jobs.get(job_id)
                    if not running_job:
                        return
                    statuses = running_job.get("statuses") or {}
                    statuses[tracking_scan_id] = {
                        "scan_id": tracking_scan_id,
                        "target": target,
                        "scan_type": _normalize_scan_type(job_options.get("scan_type") or ("api_bulk" if len(targets) > 1 else "api_single")),
                        "status": "failed",
                        "error": str(exc),
                        "started_at": str(running_job.get("started_at") or ""),
                        "completed_at": _now_iso(),
                        "updated_at": _now_iso(),
                    }
                    running_job["statuses"] = statuses
                    running_job["failed"] = int(running_job.get("failed") or 0) + 1
                    running_job["updated_at"] = _now_iso()

        with _scan_jobs_lock:
            finished_job = _scan_jobs.get(job_id)
            if not finished_job:
                return
            finished_job["status"] = "completed" if int(finished_job.get("failed") or 0) == 0 else "completed_with_errors"
            finished_job["completed_at"] = _now_iso()
            finished_job["updated_at"] = _now_iso()
    except Exception as exc:
        with _scan_jobs_lock:
            failed_job = _scan_jobs.get(job_id)
            if failed_job:
                failed_job["status"] = "failed"
                failed_job["error"] = str(exc)
                failed_job["updated_at"] = _now_iso()


def _start_job(targets: list[str], ports: list[int] | None, options: dict[str, Any] | None = None) -> dict[str, Any]:
    job_id = uuid.uuid4().hex[:12]
    tracking_scan_ids = [uuid.uuid4().hex[:10] for _ in targets]
    statuses = {
        sid: {
            "scan_id": sid,
            "target": targets[idx],
            "status": "queued",
            "updated_at": _now_iso(),
            "options": dict(options or {}),
        }
        for idx, sid in enumerate(tracking_scan_ids)
    }
    with _scan_jobs_lock:
        _scan_jobs[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "targets": list(targets),
            "scan_ids": list(tracking_scan_ids),
            "statuses": statuses,
            "scan_type": _normalize_scan_type((options or {}).get("scan_type") or ("bulk" if len(targets) > 1 else "single")),
            "total": len(targets),
            "completed": 0,
            "failed": 0,
            "created_at": _now_iso(),
            "updated_at": _now_iso(),
        }

    requested_by = getattr(current_user, "username", None) if getattr(current_user, "is_authenticated", False) else None
    testing_mode = bool(current_app.config.get("TESTING", False))
    thread = threading.Thread(
        target=_process_job,
        args=(job_id, requested_by, ports, testing_mode, dict(options or {})),
        daemon=True,
    )
    thread.start()

    return {
        "job_id": job_id,
        "scan_ids": tracking_scan_ids,
        "queued_count": len(tracking_scan_ids),
    }


@scans_bp.route("/scans", methods=["GET"])
@login_required
def scans_page():
    if not _can_scan():
        abort(403)
    return render_template(
        "scans.html",
        can_single_scan=_can_scan(),
        can_bulk_scan=_can_bulk_scan(),
    )


@scans_bp.route("/api/scans", methods=["GET"])
@login_required
def api_scans_list():
    page = max(1, request.args.get("page", 1, type=int) or 1)
    page_size = min(max(1, request.args.get("page_size", 25, type=int) or 25), 250)
    q = str(request.args.get("q", "") or "").strip().lower()
    status_filter = _normalize_status(request.args.get("status", ""))
    scan_type_filter = _normalize_scan_type(request.args.get("scan_type", "")) if str(request.args.get("scan_type", "")).strip() else ""
    date_from_raw = str(request.args.get("date_from", "") or "").strip()
    date_to_raw = str(request.args.get("date_to", "") or "").strip()
    sort = str(request.args.get("sort", "date") or "date").strip().lower()
    order = str(request.args.get("order", "desc") or "desc").strip().lower()

    date_from = None
    date_to = None
    if date_from_raw:
        try:
            date_from = datetime.fromisoformat(date_from_raw)
        except ValueError:
            date_from = None
    if date_to_raw:
        try:
            date_to = datetime.fromisoformat(f"{date_to_raw}T23:59:59")
        except ValueError:
            date_to = None

    items = _collect_scan_items()

    if q:
        items = [
            row
            for row in items
            if q in str(row.get("scan_id", "")).lower()
            or q in str(row.get("target", "")).lower()
            or q in str(row.get("status", "")).lower()
        ]

    if status_filter:
        items = [row for row in items if _normalize_status(row.get("status")) == status_filter]

    if scan_type_filter:
        items = [row for row in items if _normalize_scan_type(row.get("scan_type")) == scan_type_filter]

    if date_from or date_to:
        filtered_items: list[dict[str, Any]] = []
        for row in items:
            row_dt = _parse_iso_datetime(row.get("started_at") or row.get("date") or row.get("completed_at"))
            if row_dt is None:
                continue
            row_naive = row_dt.replace(tzinfo=None)
            if date_from and row_naive < date_from:
                continue
            if date_to and row_naive > date_to:
                continue
            filtered_items.append(row)
        items = filtered_items

    sort_key_map = {
        "scan_id": lambda r: str(r.get("scan_id") or ""),
        "scan_type": lambda r: str(r.get("scan_type") or ""),
        "target": lambda r: str(r.get("target") or ""),
        "status": lambda r: str(r.get("status") or ""),
        "assets_found": lambda r: int(r.get("assets_found") or 0),
        "pqc_score": lambda r: float(r.get("pqc_score") or 0),
        "started_at": lambda r: str(r.get("started_at") or ""),
        "completed_at": lambda r: str(r.get("completed_at") or ""),
        "date": lambda r: str(r.get("date") or ""),
    }
    key_fn = sort_key_map.get(sort, sort_key_map["date"])
    items = sorted(items, key=key_fn, reverse=(order == "desc"))

    # Legacy compatibility: no pagination params => return list.
    legacy_mode = all(param not in request.args for param in ("page", "page_size", "sort", "order", "q", "status", "scan_type", "date_from", "date_to"))
    if legacy_mode:
        return jsonify(items), 200

    total = len(items)
    total_pages = max(1, math.ceil(total / page_size))
    if page > total_pages:
        page = total_pages
    start = (page - 1) * page_size
    end = start + page_size

    payload = {
        "items": items[start:end],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "kpis": {
            "total_scans": total,
            "completed": len([r for r in items if _normalize_status(r.get("status")) == "completed"]),
            "running": len([r for r in items if _normalize_status(r.get("status")) == "running"]),
        },
    }
    return jsonify(payload), 200


@scans_bp.route("/api/scans", methods=["POST"])
@login_required
def api_scan_single():
    if not _can_scan():
        return jsonify({"status": "error", "message": "Insufficient role for scan execution."}), 403

    payload = request.get_json(silent=True) or {}
    target = str(payload.get("target") or "").strip()
    ports = _parse_ports(payload.get("ports"))
    autodiscovery = bool(payload.get("autodiscovery", False))
    
    # Inventory metadata
    add_to_inventory = bool(payload.get("add_to_inventory", False))
    inv_owner = str(payload.get("owner") or "").strip() or None
    inv_risk = str(payload.get("risk_level") or "Medium").strip()
    inv_notes = str(payload.get("notes") or "").strip() or None
    asset_type = str(payload.get("asset_type") or "Web App").strip()
    asset_class_mode = str(payload.get("asset_class_mode") or "auto").strip().lower()
    asset_class_value = str(payload.get("asset_class_value") or "").strip()
    asset_class_hint = asset_class_value if asset_class_mode == "manual" and asset_class_value else None
    
    if not target:
        return jsonify({"status": "error", "message": "Missing 'target'."}), 400

    job = _start_job(
        [target],
        ports,
        options={
            "scan_type": "single",
            "autodiscovery": autodiscovery,
            "add_to_inventory": add_to_inventory,
            "owner": inv_owner,
            "risk_level": inv_risk,
            "notes": inv_notes,
            "asset_type": asset_type,
            "asset_class_hint": asset_class_hint,
        },
    )
    scan_id = job["scan_ids"][0]

    return jsonify({"status": "accepted", "scan_id": scan_id, "job_id": job["job_id"]}), 202


@scans_bp.route("/api/scans/bulk", methods=["POST"])
@login_required
def api_scan_bulk():
    if not _can_bulk_scan():
        return jsonify({"status": "error", "message": "Insufficient role for bulk scan execution."}), 403

    payload = request.get_json(silent=True) or {}
    raw_targets = payload.get("targets")
    ports = _parse_ports(payload.get("ports"))
    autodiscovery = bool(payload.get("autodiscovery", False))
    add_to_inventory = bool(payload.get("add_to_inventory", False))
    inv_owner = str(payload.get("owner") or "").strip() or None
    inv_risk = str(payload.get("risk_level") or "Medium").strip() or "Medium"
    inv_notes = str(payload.get("notes") or "").strip() or None
    asset_type = str(payload.get("asset_type") or "Web App").strip() or "Web App"
    asset_class_mode = str(payload.get("asset_class_mode") or "auto").strip().lower()
    asset_class_value = str(payload.get("asset_class_value") or "").strip()
    asset_class_hint = asset_class_value if asset_class_mode == "manual" and asset_class_value else None

    if not isinstance(raw_targets, list):
        return jsonify({"status": "error", "message": "'targets' must be an array."}), 400

    targets = [str(t).strip() for t in raw_targets if str(t).strip()]
    if not targets:
        return jsonify({"status": "error", "message": "At least one valid target is required."}), 400

    job = _start_job(
        targets,
        ports,
        options={
            "scan_type": "bulk",
            "autodiscovery": autodiscovery,
            "add_to_inventory": add_to_inventory,
            "owner": inv_owner,
            "risk_level": inv_risk,
            "notes": inv_notes,
            "asset_type": asset_type,
            "asset_class_hint": asset_class_hint,
        },
    )
    return jsonify({"status": "accepted", "job_id": job["job_id"], "scan_ids": job["scan_ids"], "queued_count": job["queued_count"]}), 202


@scans_bp.route("/api/scans/<scan_id>/status", methods=["GET"])
@login_required
def api_scan_status(scan_id: str):
    # Prefer in-flight tracking status.
    snapshot = _status_snapshot(scan_id)
    if snapshot is not None:
        return jsonify({"status": "success", "data": snapshot}), 200

    # Fallback: check persisted/in-memory reports by real scan_id.
    report = _load_scan_report(scan_id)

    if isinstance(report, dict):
        item = _build_scan_item_from_report(report)
        return jsonify(
            {
                "status": "success",
                "data": {
                    "scan_id": scan_id,
                    "target": item.get("target"),
                    "status": _normalize_status(item.get("status") or "completed"),
                    "assets_found": item.get("assets_found"),
                    "pqc_score": item.get("pqc_score"),
                    "updated_at": item.get("date") or _now_iso(),
                    "result_scan_id": scan_id,
                },
            }
        ), 200

    return jsonify({"status": "error", "message": "Scan status not found."}), 404


@scans_bp.route("/api/scans/<scan_id>/result", methods=["GET"])
@login_required
def api_scan_result(scan_id: str):
    report = _load_scan_report(scan_id)
    if isinstance(report, dict):
        return jsonify({"status": "success", "data": report}), 200

    snapshot = _status_snapshot(scan_id)
    if snapshot is not None:
        return jsonify({"status": "success", "data": snapshot}), 200

    return jsonify({"status": "error", "message": "Scan result not found."}), 404


@scans_bp.route("/api/scans/<scan_id>/promote", methods=["POST"])
@login_required
def api_scan_promote(scan_id: str):
    if not _can_scan():
        return jsonify({"status": "error", "message": "Insufficient role for scan promotion."}), 403

    payload = request.get_json(silent=True) or {}
    destination = str(payload.get("destination") or "inventory").strip().lower()
    if destination not in {"inventory", "cbom"}:
        return jsonify({"status": "error", "message": "Invalid destination. Use 'inventory' or 'cbom'."}), 400

    resolved_scan_id = _resolve_result_scan_id(scan_id)
    report = _load_scan_report(resolved_scan_id)
    target = str((report or {}).get("target") or "").strip()

    scan_row = db_session.query(Scan).filter(
        Scan.is_deleted == False,
        or_(Scan.scan_id == resolved_scan_id, Scan.scan_id == scan_id),
    ).order_by(Scan.id.desc()).first()

    if destination == "cbom":
        if scan_row is None or not bool(getattr(scan_row, "add_to_inventory", False)):
            return jsonify({
                "status": "error",
                "message": "Scan must be added to inventory before enabling CBOM visibility.",
            }), 400
        return jsonify({
            "status": "success",
            "message": "CBOM visibility is active for this inventory-promoted scan.",
            "scan_id": resolved_scan_id,
            "destination": "cbom",
        }), 200

    if not target:
        return jsonify({"status": "error", "message": "Unable to resolve scan target for promotion."}), 404

    _upsert_inventory_asset_from_scan(
        target=target,
        add_to_inventory=True,
        owner=None,
        risk_level=None,
        notes="Promoted from Scan Center",
        asset_type="Web App",
    )

    if scan_row is not None:
        try:
            scan_row.add_to_inventory = True
            db_session.commit()
        except Exception:
            db_session.rollback()

    return jsonify({
        "status": "success",
        "message": "Scan promoted to inventory successfully.",
        "scan_id": resolved_scan_id,
        "destination": "inventory",
    }), 200


@scans_bp.route("/api/scans/metrics", methods=["GET"])
@login_required
def api_scan_metrics():
    items = _collect_scan_items()
    now = datetime.now(timezone.utc)
    since = now.timestamp() - (24 * 60 * 60)

    total_scans = len(items)
    completed = 0
    failed = 0
    running = 0
    total_assets_found = 0
    pqc_scores: list[float] = []
    scans_last_24h = 0

    for row in items:
        status_text = str(row.get("status") or "").strip().lower()
        if status_text in {"completed", "complete", "success", "done"}:
            completed += 1
        elif status_text in {"failed", "error"}:
            failed += 1
        elif status_text in {"queued", "pending", "running", "in_progress"}:
            running += 1

        try:
            total_assets_found += int(row.get("assets_found") or 0)
        except (TypeError, ValueError):
            pass

        try:
            score = float(row.get("pqc_score") or 0)
            if score > 0:
                pqc_scores.append(score)
        except (TypeError, ValueError):
            pass

        dt = _parse_iso_datetime(row.get("date") or row.get("started_at") or row.get("completed_at"))
        if dt is not None and dt.timestamp() >= since:
            scans_last_24h += 1

    active_jobs = 0
    with _scan_jobs_lock:
        for job in _scan_jobs.values():
            state = str(job.get("status") or "").strip().lower()
            if state in {"queued", "running"}:
                active_jobs += 1

    settled = completed + failed
    success_rate = round((completed / settled) * 100.0, 2) if settled > 0 else 0.0
    avg_pqc_score = round(sum(pqc_scores) / len(pqc_scores), 2) if pqc_scores else 0.0

    payload = {
        "success": True,
        "data": {
            "items": [
                {
                    "as_of": _now_iso(),
                    "total_scans": int(total_scans),
                    "completed": int(completed),
                    "failed": int(failed),
                    "running": int(running),
                    "active_jobs": int(active_jobs),
                    "scans_last_24h": int(scans_last_24h),
                    "total_assets_found": int(total_assets_found),
                    "avg_pqc_score": float(avg_pqc_score),
                    "success_rate": float(success_rate),
                }
            ],
            "total": 1,
            "page": 1,
            "page_size": 1,
            "total_pages": 1,
            "kpis": {
                "total_scans": int(total_scans),
                "completed": int(completed),
                "failed": int(failed),
                "running": int(running),
                "active_jobs": int(active_jobs),
                "scans_last_24h": int(scans_last_24h),
                "total_assets_found": int(total_assets_found),
                "avg_pqc_score": float(avg_pqc_score),
                "success_rate": float(success_rate),
            },
        },
        "filters": {},
    }
    return jsonify(payload), 200


@scans_bp.route("/api/scans/<scan_id>/certificates", methods=["GET"])
@login_required
def api_scan_certificates(scan_id: str):
    page = max(1, request.args.get("page", 1, type=int) or 1)
    page_size = min(max(1, request.args.get("page_size", 25, type=int) or 25), 200)
    q = str(request.args.get("q", request.args.get("search", "")) or "").strip()
    sort = str(request.args.get("sort", "valid_until") or "valid_until").strip()
    order = str(request.args.get("order", "asc") or "asc").strip().lower()

    resolved_scan_id = _resolve_result_scan_id(scan_id)

    scan_row = db_session.query(Scan).filter(
        Scan.is_deleted == False,
        or_(Scan.scan_id == resolved_scan_id, Scan.scan_id == scan_id),
    ).order_by(Scan.id.desc()).first()

    all_items: list[dict[str, Any]] = []

    if scan_row is not None:
        cert_query = (
            db_session.query(Certificate, Asset)
            .join(Asset, Certificate.asset_id == Asset.id)
            .filter(
                Certificate.is_deleted == False,
                Asset.is_deleted == False,
                Certificate.scan_id == scan_row.id,
            )
        )

        if q:
            like = f"%{q}%"
            cert_query = cert_query.filter(
                or_(
                    Certificate.endpoint.ilike(like),
                    Certificate.issuer.ilike(like),
                    Certificate.subject.ilike(like),
                    Certificate.subject_cn.ilike(like),
                    Certificate.serial.ilike(like),
                    Certificate.tls_version.ilike(like),
                    Certificate.cipher_suite.ilike(like),
                    Certificate.fingerprint_sha256.ilike(like),
                    Asset.target.ilike(like),
                )
            )

        sort_map = {
            "certificate_id": Certificate.id,
            "endpoint": Certificate.endpoint,
            "issuer": Certificate.issuer,
            "subject_cn": Certificate.subject_cn,
            "valid_from": Certificate.valid_from,
            "valid_until": Certificate.valid_until,
            "tls_version": Certificate.tls_version,
            "key_length": Certificate.key_length,
            "status": Certificate.is_expired,
        }
        sort_col = sort_map.get(sort, Certificate.valid_until)
        cert_query = cert_query.order_by(sort_col.desc() if order == "desc" else sort_col.asc(), Certificate.id.desc())

        rows = cert_query.all()
        for cert, asset in rows:
            status = _certificate_status(cert.valid_until, cert.is_expired)
            all_items.append(
                {
                    "certificate_id": int(cert.id),
                    "scan_id": str(scan_row.scan_id),
                    "asset_id": int(asset.id) if asset is not None else None,
                    "asset_name": str(asset.target or "") if asset is not None else None,
                    "endpoint": str(cert.endpoint or ""),
                    "host": str(asset.target or "") if asset is not None else None,
                    "port": int(cert.port) if cert.port is not None else None,
                    "issuer": str(cert.issuer or cert.ca or ""),
                    "subject": str(cert.subject or ""),
                    "subject_cn": str(cert.subject_cn or ""),
                    "subject_o": str(cert.subject_o or cert.company_name or ""),
                    "subject_ou": str(cert.subject_ou or ""),
                    "issuer_cn": str(cert.issuer_cn or cert.ca or ""),
                    "issuer_o": str(cert.issuer_o or cert.ca_name or ""),
                    "issuer_ou": str(cert.issuer_ou or ""),
                    "serial": str(cert.serial or ""),
                    "tls_version": str(cert.tls_version or ""),
                    "cipher_suite": str(cert.cipher_suite or ""),
                    "key_length": int(cert.key_length or 0),
                    "key_algorithm": str(cert.key_algorithm or cert.public_key_type or ""),
                    "signature_algorithm": str(cert.signature_algorithm or ""),
                    "fingerprint_sha256": str(cert.fingerprint_sha256 or ""),
                    "san_domains": _safe_json_list(cert.san_domains),
                    "certificate_details": {
                        "certificate_version": "",
                        "serial_number": str(cert.serial or ""),
                        "certificate_signature_algorithm": str(cert.signature_algorithm or ""),
                        "certificate_signature": "",
                        "issuer": str(cert.issuer or cert.ca or ""),
                        "validity": {
                            "not_before": cert.valid_from.isoformat() if cert.valid_from else "",
                            "not_after": cert.valid_until.isoformat() if cert.valid_until else "",
                        },
                        "subject": str(cert.subject or cert.subject_cn or ""),
                        "subject_public_key_info": {
                            "subject_public_key_algorithm": str(cert.public_key_type or cert.key_algorithm or ""),
                            "subject_public_key_bits": int(cert.key_length or 0),
                            "subject_public_key": str(cert.public_key_pem or ""),
                        },
                        "extensions": [],
                        "certificate_key_usage": [],
                        "extended_key_usage": [],
                        "certificate_basic_constraints": {},
                        "certificate_subject_key_id": "",
                        "certificate_authority_key_id": "",
                        "authority_information_access": [],
                        "certificate_subject_alternative_name": _safe_json_list(cert.san_domains),
                        "certificate_policies": [],
                        "crl_distribution_points": [],
                        "signed_certificate_timestamp_list": [],
                    },
                    "cert_chain_length": int(cert.cert_chain_length or 0),
                    "valid_from": cert.valid_from.isoformat() if cert.valid_from else None,
                    "valid_until": cert.valid_until.isoformat() if cert.valid_until else None,
                    "days_remaining": _days_remaining(cert.valid_until),
                    "is_expired": bool(cert.is_expired),
                    "is_self_signed": bool(cert.is_self_signed),
                    "status": status,
                }
            )

    if not all_items:
        report = _load_scan_report(resolved_scan_id)
        if isinstance(report, dict):
            all_items = _certificate_items_from_report(report, resolved_scan_id)

    all_items = _apply_certificate_search(all_items, q)
    all_items = _apply_certificate_sort(all_items, sort, order)

    total = len(all_items)
    total_pages = max(1, math.ceil(total / page_size)) if page_size else 1
    if page > total_pages:
        page = total_pages

    offset = (page - 1) * page_size
    items = all_items[offset: offset + page_size]
    summary = _certificate_summary(all_items)

    payload = {
        "success": True,
        "data": {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "kpis": summary,
        },
        "filters": {
            "scan_id": scan_id,
            "resolved_scan_id": resolved_scan_id,
            "q": q,
            "sort": sort,
            "order": order,
        },
    }
    return jsonify(payload), 200


# ── Scan Scheduling Endpoints ──

_scan_schedules_in_memory: dict[str, dict[str, Any]] = {}


def _normalize_schedule_frequency(value: Any) -> str:
    freq = str(value or "").strip().lower()
    return freq if freq in {"daily", "weekly", "monthly"} else ""


def _normalize_schedule_time(value: Any) -> str:
    time_text = str(value or "").strip()
    if not time_text:
        return ""
    if not re.fullmatch(r"^([01]\d|2[0-3]):([0-5]\d)$", time_text):
        return ""
    return time_text


def _validate_schedule_payload(payload: dict[str, Any], *, partial: bool) -> tuple[dict[str, Any], str | None]:
    updates: dict[str, Any] = {}

    if not partial or "target" in payload:
        target = str(payload.get("target") or "").strip()
        if not target:
            return {}, "Missing 'target'."
        updates["target"] = target

    if not partial or "frequency" in payload:
        frequency = _normalize_schedule_frequency(payload.get("frequency"))
        if not frequency:
            return {}, "Invalid 'frequency'. Use daily, weekly, or monthly."
        updates["frequency"] = frequency

    if not partial or "scheduled_time" in payload:
        scheduled_time = _normalize_schedule_time(payload.get("scheduled_time"))
        if not scheduled_time:
            return {}, "Invalid 'scheduled_time'. Use HH:MM (24-hour)."
        updates["scheduled_time"] = scheduled_time

    if not partial or "timezone" in payload:
        timezone_val = str(payload.get("timezone") or "").strip()
        if not timezone_val:
            return {}, "Missing 'timezone'."
        updates["timezone"] = timezone_val

    if "auto_add_to_inventory" in payload:
        updates["auto_add_to_inventory"] = bool(payload.get("auto_add_to_inventory"))
    elif not partial:
        updates["auto_add_to_inventory"] = False

    if partial and not updates:
        return {}, "No updatable fields provided."

    return updates, None


@scans_bp.route("/api/scan-schedules", methods=["GET"])
@login_required
def list_scan_schedules():
    """List all active scan schedules."""
    if not _can_bulk_scan():
        return jsonify({"status": "error", "message": "Insufficient role for schedule access."}), 403
    schedules = list(_scan_schedules_in_memory.values())
    return jsonify({"data": schedules, "schedules": schedules, "total": len(schedules)}), 200


@scans_bp.route("/api/scan-schedules", methods=["POST"])
@login_required
def create_scan_schedule():
    """Create a new scan schedule."""
    if not _can_bulk_scan():
        return jsonify({"status": "error", "message": "Insufficient role for scan scheduling."}), 403

    payload = request.get_json(silent=True) or {}
    defaulted_payload = {
        "target": payload.get("target"),
        "frequency": payload.get("frequency") or "daily",
        "scheduled_time": payload.get("scheduled_time") or "12:00",
        "timezone": payload.get("timezone") or "UTC",
        "auto_add_to_inventory": payload.get("auto_add_to_inventory", False),
    }
    updates, err = _validate_schedule_payload(defaulted_payload, partial=False)
    if err:
        return jsonify({"status": "error", "message": err}), 400

    schedule_id = f"sched_{uuid.uuid4().hex[:8]}"
    schedule = {
        "id": schedule_id,
        "target": updates["target"],
        "frequency": updates["frequency"],
        "scheduled_time": updates["scheduled_time"],
        "timezone": updates["timezone"],
        "auto_add_to_inventory": bool(updates.get("auto_add_to_inventory", False)),
        "status": "active",
        "last_run_at": None,
        "next_run_at": None,
        "created_by": str(getattr(current_user, "username", "anonymous")),
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
        "updated_by": str(getattr(current_user, "username", "anonymous")),
    }

    _scan_schedules_in_memory[schedule_id] = schedule

    # TODO: Persist to database table scan_schedules
    return jsonify({"status": "created", "data": schedule, "message": "Schedule created successfully."}), 201


@scans_bp.route("/api/scan-schedules/<schedule_id>", methods=["GET"])
@login_required
def get_scan_schedule(schedule_id: str):
    """Get full details for a specific scan schedule."""
    if not _can_bulk_scan():
        return jsonify({"status": "error", "message": "Insufficient role for schedule access."}), 403

    schedule = _scan_schedules_in_memory.get(schedule_id)
    if not schedule:
        return jsonify({"status": "error", "message": "Schedule not found."}), 404

    return jsonify({"status": "success", "data": schedule}), 200


@scans_bp.route("/api/scan-schedules/<schedule_id>", methods=["PUT", "PATCH"])
@login_required
def update_scan_schedule(schedule_id: str):
    """Update an existing scan schedule."""
    if not _can_bulk_scan():
        return jsonify({"status": "error", "message": "Insufficient role for schedule update."}), 403

    schedule = _scan_schedules_in_memory.get(schedule_id)
    if not schedule:
        return jsonify({"status": "error", "message": "Schedule not found."}), 404

    payload = request.get_json(silent=True) or {}
    partial = request.method.upper() == "PATCH"
    updates, err = _validate_schedule_payload(payload, partial=partial)
    if err:
        return jsonify({"status": "error", "message": err}), 400

    schedule.update(updates)
    schedule["updated_at"] = _now_iso()
    schedule["updated_by"] = str(getattr(current_user, "username", "anonymous"))

    _scan_schedules_in_memory[schedule_id] = schedule
    return jsonify({"status": "updated", "data": schedule, "message": "Schedule updated successfully."}), 200


@scans_bp.route("/api/scan-schedules/<schedule_id>", methods=["DELETE"])
@login_required
def delete_scan_schedule(schedule_id: str):
    """Delete a scan schedule."""
    if not _can_bulk_scan():
        return jsonify({"status": "error", "message": "Insufficient role for schedule deletion."}), 403
    if schedule_id in _scan_schedules_in_memory:
        del _scan_schedules_in_memory[schedule_id]
        return jsonify({"status": "deleted", "message": "Schedule deleted successfully."}), 200

    return jsonify({"status": "error", "message": "Schedule not found."}), 404
