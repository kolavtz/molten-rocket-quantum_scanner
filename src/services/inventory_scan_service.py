"""
Inventory Bulk Scan Service

Provides inventory-wide and per-asset scanning by delegating to the
primary scan pipeline used by the web app, then synchronizing key fields
back to inventory assets.
"""

from __future__ import annotations

import datetime
import json
import ipaddress
import logging
import os
import threading
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any, Dict, List
from urllib.parse import urlparse

from sqlalchemy import func

from src.db import db_session
from src.models import Asset, Certificate, PQCClassification, Scan
from src.scanner.network_discovery import sanitize_target

from config import RESULTS_DIR

logger = logging.getLogger(__name__)

_SCAN_EXECUTOR = ThreadPoolExecutor(max_workers=max(1, int(os.getenv("QSS_SCAN_MAX_WORKERS", "4") or "4")))


def _persist_raw_scan_artifact(report: Dict[str, Any]) -> str:
    """Persist a raw scan artifact with the milestone naming contract.

    Required naming shape: ``scan_<timestamp>_<uuid>.json``.
    """
    os.makedirs(RESULTS_DIR, exist_ok=True)
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    artifact_name = f"scan_{ts}_{uuid.uuid4().hex}.json"
    artifact_path = os.path.join(RESULTS_DIR, artifact_name)
    with open(artifact_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)
    return artifact_path


def run_scan_pipeline(
    target: str,
    ports: list[int] | None = None,
    options: dict[str, Any] | None = None,
    scan_runner=None,
) -> Dict[str, Any]:
    """Validate + execute one scan pipeline run and persist a raw artifact.

    This helper keeps controller routes thin and centralizes milestone behavior:
    canonical target handling, safe option forwarding, and raw JSON persistence.
    """
    clean_target, _ = sanitize_target(str(target or "").strip())
    opts = dict(options or {})

    runner = scan_runner
    if not callable(runner):
        from web.app import run_scan_pipeline as app_run_scan_pipeline

        runner = app_run_scan_pipeline

    kwargs = {
        "ports": ports,
        "asset_class_hint": opts.get("asset_class_hint"),
        "scan_kind": str(opts.get("scan_type") or opts.get("scan_kind") or "manual"),
        "scanned_by": opts.get("scanned_by"),
        "add_to_inventory": bool(opts.get("add_to_inventory", False)),
    }

    report = runner(clean_target, **kwargs)
    if not isinstance(report, dict):
        raise ValueError("scan_runner must return a dictionary report")

    report.setdefault("target", clean_target)
    report.setdefault("requested_target", str(target or "").strip())

    raw_path = _persist_raw_scan_artifact(report)
    report["raw_result_path"] = raw_path
    return report


def submit_scan_pipeline(
    target: str,
    ports: list[int] | None = None,
    options: dict[str, Any] | None = None,
    scan_runner=None,
) -> Future:
    """Submit one scan run to the shared local executor."""
    return _SCAN_EXECUTOR.submit(run_scan_pipeline, target, ports, options, scan_runner)


class InventoryScanService:
    """Inventory scanning orchestration with process-level status tracking."""

    _state_lock = threading.Lock()
    _scan_in_progress = False
    _last_scan_time: datetime.datetime | None = None
    _last_scan_summary: Dict = {}
    _last_scan_results: Dict = {}
    _progress: Dict = {
        "current": 0,
        "total": 0,
        "current_target": "",
        "successful": 0,
        "failed": 0,
        "started_at": None,
    }

    def __init__(self, scan_runner=None) -> None:
        """Create service instance.

        scan_runner should be a callable compatible with run_scan_pipeline(target).
        """
        self.scan_runner = scan_runner

    def get_all_assets(self) -> List[Asset]:
        """Retrieve all non-deleted assets from inventory."""
        return (
            db_session.query(Asset)
            .filter(Asset.is_deleted == False)
            .order_by(Asset.name.asc())
            .all()
        )

    def _canonical_target(self, asset: Asset) -> str:
        """Normalize asset target to avoid duplicate scans and duplicates in DB writes."""
        raw = str(getattr(asset, "name", "") or "").strip()
        asset_url = str(getattr(asset, "url", "") or "").strip()
        if not raw and asset_url:
            parsed = urlparse(asset_url)
            raw = parsed.hostname or asset_url

        if raw.startswith(("http://", "https://", "ftp://")):
            parsed = urlparse(raw)
            raw = parsed.hostname or raw

        raw = raw.strip().lower()
        if ":" in raw and not raw.count(":") > 1:
            host, port = raw.rsplit(":", 1)
            if port.isdigit():
                raw = host
        return raw

    def _score_to_risk(self, score: float) -> str:
        if score >= 80:
            return "Low"
        if score >= 60:
            return "Medium"
        if score >= 40:
            return "High"
        return "Critical"

    def _sync_asset_from_report(self, asset: Asset, report: Dict) -> None:
        """Update inventory asset metadata from completed report."""
        target = self._canonical_target(asset)

        # Keep canonical URL/host shape for consistency and duplicate prevention.
        asset.name = target or str(getattr(asset, "name", "") or "")
        if target and not str(getattr(asset, "url", "") or ""):
            asset.url = f"https://{target}"

        discovered = report.get("discovered_services") or []
        for svc in discovered:
            host = str(svc.get("host") or "").strip()
            if not host:
                continue
            try:
                ip_obj = ipaddress.ip_address(host)
                if ip_obj.version == 4 and not str(getattr(asset, "ipv4", "") or ""):
                    asset.ipv4 = host
                elif ip_obj.version == 6 and not str(getattr(asset, "ipv6", "") or ""):
                    asset.ipv6 = host
            except ValueError:
                continue

        overview = report.get("overview") or {}
        score = float(overview.get("average_compliance_score") or 0)
        if score > 0:
            asset.risk_level = self._score_to_risk(score)

        latest_scan = (
            db_session.query(Scan)
            .filter(func.lower(Scan.target) == target)
            .order_by(Scan.id.desc())
            .first()
        )
        if latest_scan:
            asset.last_scan_id = latest_scan.id

            try:
                from src.services.pqc_calculation_service import PQCCalculationService
                from src.services.risk_calculation_service import RiskCalculationService

                # Math Engine Hook: Generates org_pqc_metrics and asset_metrics dynamically
                metric_savepoint = db_session.begin_nested()
                try:
                    PQCCalculationService.calculate_and_store_pqc_metrics(asset.id, latest_scan.id, auto_commit=False)
                    RiskCalculationService.calculate_and_store_risk_metrics(asset.id, latest_scan.id, auto_commit=False)
                    metric_savepoint.commit()
                except Exception:
                    metric_savepoint.rollback()
                    raise
            except Exception as e:
                logger.error(f"Failed to calculate dashboard metrics for {target}: {e}")

    def scan_asset(self, asset: Asset, scan_kind: str = "inventory_asset") -> Dict:
        """Scan a single asset and sync key fields into inventory."""
        asset_id = int(getattr(asset, "id", 0) or 0)
        asset_name = str(getattr(asset, "name", "") or "")
        target = self._canonical_target(asset)
        if not target:
            return {
                "asset_id": asset_id,
                "asset_name": asset_name,
                "target": "",
                "status": "failed",
                "errors": ["empty_target"],
            }

        try:
            if not callable(self.scan_runner):
                raise RuntimeError("scan_runner_not_configured")

            scanned_by = str(getattr(asset, "owner", "") or "system")
            try:
                report = self.scan_runner(
                    target,
                    scan_kind=scan_kind,
                    scanned_by=scanned_by,
                    add_to_inventory=True,
                )
            except TypeError:
                # Backward compatibility for older scan runners that accept target only.
                try:
                    report = self.scan_runner(target, scan_kind=scan_kind, scanned_by=scanned_by)
                except TypeError:
                    report = self.scan_runner(target)
            status = "complete" if report.get("status") == "complete" else "failed"
            if status == "complete":
                self._sync_asset_from_report(asset, report)
                return {
                    "asset_id": asset_id,
                    "asset_name": asset_name,
                    "target": target,
                    "scan_id": report.get("scan_id"),
                    "status": "complete",
                    "errors": [],
                }
            return {
                "asset_id": asset_id,
                "asset_name": asset_name,
                "target": target,
                "scan_id": report.get("scan_id"),
                "status": "failed",
                "errors": [str(report.get("message") or "scan_failed")],
            }
        except Exception as exc:
            db_session.rollback()
            logger.exception("Inventory asset scan failed for %s", target)
            return {
                "asset_id": asset_id,
                "asset_name": asset_name,
                "target": target,
                "status": "failed",
                "errors": [str(exc)],
            }

    def scan_all_assets(self, background: bool = False) -> Dict:
        """Scan all inventory assets, optionally in a background thread."""
        with self._state_lock:
            if self._scan_in_progress:
                return {
                    "status": "in_progress",
                    "message": "A scan is already in progress",
                    "error": "scan_already_in_progress",
                }
            self.__class__._scan_in_progress = True

        if background:
            worker = threading.Thread(target=self._scan_all_assets_internal, daemon=True)
            worker.start()
            return {"status": "started", "message": "Background scan started"}

        return self._scan_all_assets_internal()

    def _scan_all_assets_internal(self) -> Dict:
        started_at = datetime.datetime.now(datetime.timezone.utc)
        self.__class__._last_scan_time = started_at

        summary = {
            "total_assets": 0,
            "unique_targets": 0,
            "skipped_duplicates": 0,
            "successful": 0,
            "failed": 0,
            "started_at": started_at.isoformat(),
            "results": {},
        }

        detailed_results: Dict[int, Dict] = {}
        try:
            assets = self.get_all_assets()
            summary["total_assets"] = len(assets)

            seen_targets: set[str] = set()
            unique_assets: List[Asset] = []
            for asset in assets:
                target = self._canonical_target(asset)
                if not target:
                    continue
                if target in seen_targets:
                    summary["skipped_duplicates"] += 1
                    continue
                seen_targets.add(target)
                unique_assets.append(asset)

            summary["unique_targets"] = len(unique_assets)

            self.__class__._progress = {
                "current": 0,
                "total": len(unique_assets),
                "current_target": "",
                "successful": 0,
                "failed": 0,
                "started_at": started_at.isoformat(),
            }

            for idx, asset in enumerate(unique_assets, start=1):
                target = self._canonical_target(asset)
                logger.info("[INVENTORY SCAN] %s/%s %s", idx, len(unique_assets), target)
                self.__class__._progress["current_target"] = target
                result = self.scan_asset(asset, scan_kind="inventory_bulk")
                asset_id = int(getattr(asset, "id", 0) or 0)
                detailed_results[asset_id] = result
                summary["results"][target] = {
                    "status": result.get("status"),
                    "scan_id": result.get("scan_id"),
                    "errors": result.get("errors", []),
                }

                if result.get("status") == "complete":
                    summary["successful"] += 1
                    self.__class__._progress["successful"] = int(self.__class__._progress.get("successful", 0)) + 1
                else:
                    summary["failed"] += 1
                    self.__class__._progress["failed"] = int(self.__class__._progress.get("failed", 0)) + 1

                self.__class__._progress["current"] = idx

            db_session.commit()
            summary["completed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self.__class__._last_scan_summary = summary
            self.__class__._last_scan_results = detailed_results
            return {"status": "complete", "summary": summary, "detailed_results": detailed_results}
        except Exception as exc:
            db_session.rollback()
            logger.exception("Inventory bulk scan failed")
            return {
                "status": "failed",
                "error": str(exc),
                "summary": summary,
                "detailed_results": detailed_results,
            }
        finally:
            with self._state_lock:
                self.__class__._scan_in_progress = False
            self.__class__._progress["current_target"] = ""

    def get_scan_status(self) -> Dict:
        """Get current inventory scan status."""
        progress_total = int(self._progress.get("total") or 0)
        progress_current = int(self._progress.get("current") or 0)
        percent_complete = 0
        if progress_total > 0:
            percent_complete = int((progress_current * 100) / progress_total)

        return {
            "in_progress": self._scan_in_progress,
            "last_scan_time": self._last_scan_time.isoformat() if self._last_scan_time else None,
            "last_summary": self._last_scan_summary,
            "last_results_count": len(self._last_scan_results),
            "progress": {
                **self._progress,
                "percent_complete": percent_complete,
            },
        }

    def get_asset_scan_history(self, asset_id: int) -> List[Dict]:
        """Return latest scan/certificate/PQC snapshots for an asset."""
        asset = db_session.query(Asset).filter_by(id=asset_id, is_deleted=False).first()
        if not asset:
            return []

        history: List[Dict] = []

        canonical_target = self._canonical_target(asset)
        latest_scan = (
            db_session.query(Scan)
            .filter(func.lower(Scan.target) == canonical_target)
            .order_by(Scan.id.desc())
            .first()
        )
        if latest_scan:
            completed_at = getattr(latest_scan, "completed_at", None)
            history.append(
                {
                    "type": "scan",
                    "timestamp": completed_at.isoformat() if completed_at else None,
                    "data": {
                        "scan_id": latest_scan.id,
                        "target": latest_scan.target,
                        "status": latest_scan.status,
                        "overall_pqc_score": latest_scan.overall_pqc_score,
                    },
                }
            )

        latest_cert = (
            db_session.query(Certificate)
            .filter_by(asset_id=asset_id)
            .order_by(Certificate.id.desc())
            .first()
        )
        if latest_cert:
            history.append(
                {
                    "type": "certificate",
                    "timestamp": latest_cert.updated_at.isoformat() if latest_cert.updated_at else None,
                    "data": {
                        "subject": latest_cert.subject,
                        "issuer": latest_cert.issuer,
                        "key_length": latest_cert.key_length,
                        "tls_version": latest_cert.tls_version,
                    },
                }
            )

        latest_pqc = (
            db_session.query(PQCClassification)
            .filter_by(asset_id=asset_id)
            .order_by(PQCClassification.id.desc())
            .first()
        )
        if latest_pqc:
            history.append(
                {
                    "type": "pqc_assessment",
                    "timestamp": latest_pqc.updated_at.isoformat() if latest_pqc.updated_at else None,
                    "data": {
                        "status": latest_pqc.quantum_safe_status,
                        "score": latest_pqc.pqc_score,
                        "algorithm_name": latest_pqc.algorithm_name,
                    },
                }
            )

        return history
