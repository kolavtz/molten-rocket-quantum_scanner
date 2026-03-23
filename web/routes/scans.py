from __future__ import annotations

import json
import math
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from flask import Blueprint, current_app, jsonify, render_template, request
from flask_login import current_user, login_required

from src import database as db

scans_bp = Blueprint("scans", __name__)

SCAN_ROLES = {"Admin", "Manager", "SingleScan"}

_scan_jobs_lock = threading.Lock()
_scan_jobs: dict[str, dict[str, Any]] = {}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _can_scan() -> bool:
    role = str(getattr(current_user, "role", "") or "").strip().title()
    return getattr(current_user, "is_authenticated", False) and role in {r.title() for r in SCAN_ROLES}


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
        "status": _normalize_status(report.get("status") or "completed"),
        "assets_found": int(assets_found or 0),
        "pqc_score": round(float(pqc_score or 0), 2),
        "started_at": started_at,
        "completed_at": completed_at,
        "date": started_at or completed_at or "",
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
                        "status": _normalize_status(st.get("status") or job.get("status")),
                        "assets_found": int(st.get("assets_found") or 0),
                        "pqc_score": round(float(st.get("pqc_score") or 0), 2),
                        "date": str(st.get("updated_at") or job.get("updated_at") or ""),
                        "actions": f"/api/scans/{sid}/status",
                    }
                )
                seen.add(sid)

    return items


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


def _process_job(job_id: str, requested_by: str | None, ports: list[int] | None, testing_mode: bool) -> None:
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
                report = web_app_module.run_scan_pipeline(
                    clean_target,
                    ports=ports,
                    scan_kind="api_bulk" if len(targets) > 1 else "api_single",
                    scanned_by=requested_by,
                )

                if not testing_mode and not bool(report.get("orm_persisted")):
                    db.save_scan(report)

                web_app_module.scan_store[report.get("scan_id")] = report

                with _scan_jobs_lock:
                    running_job = _scan_jobs.get(job_id)
                    if not running_job:
                        return
                    statuses = running_job.get("statuses") or {}
                    statuses[tracking_scan_id] = {
                        "scan_id": tracking_scan_id,
                        "target": clean_target,
                        "status": "completed",
                        "assets_found": int(report.get("total_assets") or len(report.get("discovered_services") or [])),
                        "pqc_score": float((report.get("overview") or {}).get("average_compliance_score") or report.get("overall_pqc_score") or 0),
                        "result_scan_id": report.get("scan_id"),
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
                        "status": "failed",
                        "error": str(exc),
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


def _start_job(targets: list[str], ports: list[int] | None) -> dict[str, Any]:
    job_id = uuid.uuid4().hex[:12]
    tracking_scan_ids = [uuid.uuid4().hex[:10] for _ in targets]
    statuses = {
        sid: {
            "scan_id": sid,
            "target": targets[idx],
            "status": "queued",
            "updated_at": _now_iso(),
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
            "total": len(targets),
            "completed": 0,
            "failed": 0,
            "created_at": _now_iso(),
            "updated_at": _now_iso(),
        }

    requested_by = getattr(current_user, "username", None) if getattr(current_user, "is_authenticated", False) else None
    testing_mode = bool(current_app.config.get("TESTING", False))
    thread = threading.Thread(target=_process_job, args=(job_id, requested_by, ports, testing_mode), daemon=True)
    thread.start()

    return {
        "job_id": job_id,
        "scan_ids": tracking_scan_ids,
        "queued_count": len(tracking_scan_ids),
    }


@scans_bp.route("/scans", methods=["GET"])
@login_required
def scans_page():
    return render_template("scans.html")


@scans_bp.route("/api/scans", methods=["GET"])
@login_required
def api_scans_list():
    page = max(1, request.args.get("page", 1, type=int) or 1)
    page_size = min(max(1, request.args.get("page_size", 25, type=int) or 25), 250)
    q = str(request.args.get("q", "") or "").strip().lower()
    status_filter = _normalize_status(request.args.get("status", ""))
    sort = str(request.args.get("sort", "date") or "date").strip().lower()
    order = str(request.args.get("order", "desc") or "desc").strip().lower()

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

    sort_key_map = {
        "scan_id": lambda r: str(r.get("scan_id") or ""),
        "target": lambda r: str(r.get("target") or ""),
        "status": lambda r: str(r.get("status") or ""),
        "assets_found": lambda r: int(r.get("assets_found") or 0),
        "pqc_score": lambda r: float(r.get("pqc_score") or 0),
        "date": lambda r: str(r.get("date") or ""),
    }
    key_fn = sort_key_map.get(sort, sort_key_map["date"])
    items = sorted(items, key=key_fn, reverse=(order == "desc"))

    # Legacy compatibility: no pagination params => return list.
    legacy_mode = all(param not in request.args for param in ("page", "page_size", "sort", "order", "q", "status"))
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
    
    # Inventory metadata
    add_to_inventory = payload.get("add_to_inventory", False)
    inv_owner = str(payload.get("owner") or "").strip() or None
    inv_risk = str(payload.get("risk_level") or "Medium").strip()
    inv_notes = str(payload.get("notes") or "").strip() or None
    asset_type = str(payload.get("asset_type") or "Web App").strip()
    
    if not target:
        return jsonify({"status": "error", "message": "Missing 'target'."}), 400

    job = _start_job([target], ports)
    scan_id = job["scan_ids"][0]
    
    # Store inventory metadata for post-scan processing
    if add_to_inventory:
        try:
            _scan_jobs_lock.acquire()
            if scan_id in _scan_jobs:
                _scan_jobs[scan_id]["inventory_meta"] = {
                    "add_to_inventory": True,
                    "owner": inv_owner,
                    "risk_level": inv_risk,
                    "notes": inv_notes,
                    "asset_type": asset_type
                }
        finally:
            _scan_jobs_lock.release()
    
    return jsonify({"status": "accepted", "scan_id": scan_id, "job_id": job["job_id"]}), 202


@scans_bp.route("/api/scans/bulk", methods=["POST"])
@login_required
def api_scan_bulk():
    if not _can_scan():
        return jsonify({"status": "error", "message": "Insufficient role for bulk scan execution."}), 403

    payload = request.get_json(silent=True) or {}
    raw_targets = payload.get("targets")
    ports = _parse_ports(payload.get("ports"))

    if not isinstance(raw_targets, list):
        return jsonify({"status": "error", "message": "'targets' must be an array."}), 400

    targets = [str(t).strip() for t in raw_targets if str(t).strip()]
    if not targets:
        return jsonify({"status": "error", "message": "At least one valid target is required."}), 400

    job = _start_job(targets, ports)
    return jsonify({"status": "accepted", "job_id": job["job_id"], "scan_ids": job["scan_ids"], "queued_count": job["queued_count"]}), 202


@scans_bp.route("/api/scans/<scan_id>/status", methods=["GET"])
@login_required
def api_scan_status(scan_id: str):
    # Prefer in-flight tracking status.
    snapshot = _status_snapshot(scan_id)
    if snapshot is not None:
        return jsonify({"status": "success", "data": snapshot}), 200

    # Fallback: check persisted/in-memory reports by real scan_id.
    report = None
    try:
        import web.app as web_app_module

        report = web_app_module.scan_store.get(scan_id)
    except Exception:
        report = None

    if not isinstance(report, dict):
        report = db.get_scan(scan_id)

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


# ── Scan Scheduling Endpoints ──

_scan_schedules_in_memory: dict[str, dict[str, Any]] = {}


@scans_bp.route("/api/scan-schedules", methods=["GET"])
@login_required
def list_scan_schedules():
    """List all active scan schedules."""
    schedules = list(_scan_schedules_in_memory.values())
    return jsonify({"data": schedules, "schedules": schedules, "total": len(schedules)}), 200


@scans_bp.route("/api/scan-schedules", methods=["POST"])
@login_required
def create_scan_schedule():
    """Create a new scan schedule."""
    if not _can_scan():
        return jsonify({"status": "error", "message": "Insufficient role for scan scheduling."}), 403

    payload = request.get_json(silent=True) or {}
    target = str(payload.get("target") or "").strip()
    frequency = str(payload.get("frequency") or "daily").strip().lower()
    scheduled_time = str(payload.get("scheduled_time") or "12:00").strip()
    timezone_val = str(payload.get("timezone") or "UTC").strip()
    auto_add = payload.get("auto_add_to_inventory", False)

    if not target or frequency not in {"daily", "weekly", "monthly"}:
        return jsonify({"status": "error", "message": "Missing or invalid target/frequency."}), 400

    schedule_id = f"sched_{uuid.uuid4().hex[:8]}"
    schedule = {
        "id": schedule_id,
        "target": target,
        "frequency": frequency,
        "scheduled_time": scheduled_time,
        "timezone": timezone_val,
        "auto_add_to_inventory": auto_add,
        "created_by": str(getattr(current_user, "username", "anonymous")),
        "created_at": _now_iso(),
    }

    _scan_schedules_in_memory[schedule_id] = schedule

    # TODO: Persist to database table scan_schedules
    return jsonify({"status": "created", "data": schedule, "message": "Schedule created successfully."}), 201


@scans_bp.route("/api/scan-schedules/<schedule_id>", methods=["DELETE"])
@login_required
def delete_scan_schedule(schedule_id: str):
    """Delete a scan schedule."""
    if schedule_id in _scan_schedules_in_memory:
        del _scan_schedules_in_memory[schedule_id]
        return jsonify({"status": "deleted", "message": "Schedule deleted successfully."}), 200

    return jsonify({"status": "error", "message": "Schedule not found."}), 404
