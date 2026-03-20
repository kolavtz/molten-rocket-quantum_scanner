"""
Inventory Bulk Scan Service

Provides inventory-wide and per-asset scanning by delegating to the
primary scan pipeline used by the web app, then synchronizing key fields
back to inventory assets.
"""

from __future__ import annotations

import datetime
import ipaddress
import logging
import threading
from typing import Dict, List
from urllib.parse import urlparse

from sqlalchemy import func

from src.db import db_session
from src.models import Asset, Certificate, PQCClassification, Scan

logger = logging.getLogger(__name__)


class InventoryScanService:
    """Inventory scanning orchestration with process-level status tracking."""

    _state_lock = threading.Lock()
    _scan_in_progress = False
    _last_scan_time: datetime.datetime | None = None
    _last_scan_summary: Dict = {}
    _last_scan_results: Dict = {}

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

    def scan_asset(self, asset: Asset) -> Dict:
        """Scan a single asset and sync key fields into inventory."""
        # Lazy import prevents import-cycle issues during app startup.
        from web.app import run_scan_pipeline

        target = self._canonical_target(asset)
        if not target:
            return {
                "asset_id": asset.id,
                "asset_name": asset.name,
                "target": "",
                "status": "failed",
                "errors": ["empty_target"],
            }

        try:
            report = run_scan_pipeline(target)
            status = "complete" if report.get("status") == "complete" else "failed"
            if status == "complete":
                self._sync_asset_from_report(asset, report)
                return {
                    "asset_id": asset.id,
                    "asset_name": asset.name,
                    "target": target,
                    "scan_id": report.get("scan_id"),
                    "status": "complete",
                    "errors": [],
                }
            return {
                "asset_id": asset.id,
                "asset_name": asset.name,
                "target": target,
                "scan_id": report.get("scan_id"),
                "status": "failed",
                "errors": [str(report.get("message") or "scan_failed")],
            }
        except Exception as exc:
            logger.exception("Inventory asset scan failed for %s", target)
            return {
                "asset_id": asset.id,
                "asset_name": asset.name,
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

            for idx, asset in enumerate(unique_assets, start=1):
                target = self._canonical_target(asset)
                logger.info("[INVENTORY SCAN] %s/%s %s", idx, len(unique_assets), target)
                result = self.scan_asset(asset)
                asset_id = int(getattr(asset, "id", 0) or 0)
                detailed_results[asset_id] = result
                summary["results"][target] = {
                    "status": result.get("status"),
                    "scan_id": result.get("scan_id"),
                    "errors": result.get("errors", []),
                }

                if result.get("status") == "complete":
                    summary["successful"] += 1
                else:
                    summary["failed"] += 1

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

    def get_scan_status(self) -> Dict:
        """Get current inventory scan status."""
        return {
            "in_progress": self._scan_in_progress,
            "last_scan_time": self._last_scan_time.isoformat() if self._last_scan_time else None,
            "last_summary": self._last_scan_summary,
            "last_results_count": len(self._last_scan_results),
        }

    def get_asset_scan_history(self, asset_id: int) -> List[Dict]:
        """Return latest scan/certificate/PQC snapshots for an asset."""
        asset = db_session.query(Asset).filter_by(id=asset_id, is_deleted=False).first()
        if not asset:
            return []

        history: List[Dict] = []

        latest_scan = (
            db_session.query(Scan)
            .filter(func.lower(Scan.target) == (asset.name or "").lower())
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
