"""
CurrentStateService
====================
Sprint 2: Manages DomainCurrentState reads and refreshes.

Responsibilities:
- Refresh current-state after scan completion.
- Provide typed get_current_state() for dashboard API layer.
- Handle graceful fallbacks when no scans exist for an asset.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

# Threshold in hours: if last_successful_scan_at is older than this, mark 'stale'
STALE_THRESHOLD_HOURS = 24


class CurrentStateService:
    """
    Manages canonical current-state reads and refreshes.

    Usage::

        from src.services.current_state_service import CurrentStateService

        # After a scan completes:
        CurrentStateService.refresh_after_scan(asset_id=1, scan_id=42, db_session=db)

        # To read for dashboard:
        state = CurrentStateService.get_current_state(asset_id=1, db_session=db)
    """

    @classmethod
    def refresh_after_scan(
        cls,
        asset_id: int,
        scan_id: int,
        db_session: Any,
    ) -> bool:
        """
        Recompute and persist DomainCurrentState for a given asset after scan completion.

        Finds the latest complete scan for the asset, locates its Certificate with
        is_current=True, and updates (or creates) the DomainCurrentState row.

        Returns True if refresh succeeded.
        """
        from src.models import Asset, Scan, Certificate, DomainCurrentState

        try:
            # Find asset
            asset = db_session.query(Asset).filter_by(id=asset_id, is_deleted=False).first()
            if not asset:
                log.warning("CurrentStateService.refresh_after_scan: asset %d not found", asset_id)
                return False

            # Find the triggering scan
            scan = db_session.query(Scan).filter_by(id=scan_id, is_deleted=False).first()
            if not scan:
                log.warning("CurrentStateService.refresh_after_scan: scan %d not found", scan_id)
                return False

            # Find current certificate for this asset
            current_cert = (
                db_session.query(Certificate)
                .filter(
                    Certificate.asset_id == asset_id,
                    Certificate.is_current == True,
                    Certificate.is_deleted == False,
                )
                .first()
            )

            now = datetime.now(timezone.utc)

            dcs = db_session.query(DomainCurrentState).filter_by(asset_id=asset_id).first()
            if dcs is None:
                dcs = DomainCurrentState(asset_id=asset_id)
                db_session.add(dcs)

            dcs.latest_scan_id = scan.id
            dcs.current_ssl_certificate_id = current_cert.id if current_cert else None
            dcs.freshness_status = "fresh"
            dcs.last_successful_scan_at = now
            dcs.render_status = "ok"
            dcs.render_error_message = None

            db_session.commit()
            log.info("CurrentStateService: refreshed DomainCurrentState for asset=%d", asset_id)
            return True

        except Exception as exc:
            db_session.rollback()
            log.exception("CurrentStateService.refresh_after_scan failed for asset=%d: %s", asset_id, exc)
            return False

    @classmethod
    def get_current_state(
        cls,
        asset_id: int,
        db_session: Any,
    ) -> Dict[str, Any]:
        """
        Return a typed dict representing the current SSL/TLS state for one asset.

        Always returns a dict (never raises). If no data exists, returns an
        explicit empty state with has_data=False.
        """
        from src.models import DomainCurrentState, Certificate, Scan, Asset, AssetSSLProfile

        try:
            asset = db_session.query(Asset).filter_by(id=asset_id, is_deleted=False).first()
            if not asset:
                return cls._empty_state(asset_id, reason="Asset not found")

            dcs = db_session.query(DomainCurrentState).filter_by(asset_id=asset_id).first()

            # Compute freshness
            freshness_status = cls._compute_freshness(dcs)

            # Get current certificate
            cert_data: Optional[Dict[str, Any]] = None
            if dcs and dcs.current_ssl_certificate_id:
                cert = db_session.query(Certificate).filter_by(
                    id=dcs.current_ssl_certificate_id
                ).first()
                if cert:
                    cert_data = cls._cert_to_dict(cert)

            # Get current SSL profile
            profile_data: Optional[Dict[str, Any]] = None
            profile = (
                db_session.query(AssetSSLProfile)
                .filter_by(asset_id=asset_id, is_current=True, is_deleted=False)
                .first()
            )
            if profile:
                profile_data = cls._profile_to_dict(profile)

            # Get latest scan
            latest_scan_data: Optional[Dict[str, Any]] = None
            if dcs and dcs.latest_scan_id:
                scan = db_session.query(Scan).filter_by(id=dcs.latest_scan_id).first()
                if scan:
                    latest_scan_data = {
                        "scan_id": scan.scan_id,
                        "status": scan.status,
                        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                    }

            return {
                "has_data": cert_data is not None or profile_data is not None,
                "asset_id": asset_id,
                "hostname": asset.target,
                "freshness_status": freshness_status,
                "render_status": dcs.render_status if dcs else "ok",
                "render_error_message": dcs.render_error_message if dcs else None,
                "last_successful_scan_at": (
                    dcs.last_successful_scan_at.isoformat() if dcs and dcs.last_successful_scan_at else None
                ),
                "last_failed_scan_at": (
                    dcs.last_failed_scan_at.isoformat() if dcs and dcs.last_failed_scan_at else None
                ),
                "current_certificate": cert_data,
                "ssl_profile": profile_data,
                "latest_scan": latest_scan_data,
            }

        except Exception as exc:
            log.exception("CurrentStateService.get_current_state failed for asset=%d: %s", asset_id, exc)
            return cls._empty_state(asset_id, reason=str(exc))

    @classmethod
    def get_all_assets_summary(
        cls,
        db_session: Any,
        page: int = 1,
        page_size: int = 25,
    ) -> Dict[str, Any]:
        """
        Return a paginated summary of all assets' current states.
        Used by the CBOM overview dashboard tab.
        """
        from src.models import DomainCurrentState, Asset, Certificate

        try:
            total = db_session.query(Asset).filter_by(is_deleted=False).count()

            assets = (
                db_session.query(Asset)
                .filter_by(is_deleted=False)
                .order_by(Asset.target.asc())
                .offset((page - 1) * page_size)
                .limit(page_size)
                .all()
            )

            items = []
            for asset in assets:
                dcs = db_session.query(DomainCurrentState).filter_by(asset_id=asset.id).first()
                cert_details: Dict[str, Any] = {}
                if dcs and dcs.current_ssl_certificate_id:
                    cert = db_session.query(Certificate).filter_by(
                        id=dcs.current_ssl_certificate_id
                    ).first()
                    if cert:
                        cert_details = {
                            "cert_status": cls._compute_cert_status(cert),
                            "issuer_cn": cert.issuer_cn,
                            "valid_until": cert.valid_until.isoformat() if cert.valid_until else None,
                            "expiry_days": cert.expiry_days,
                            "tls_version": cert.tls_version,
                            "key_length": cert.key_length,
                            "cipher_suite": cert.cipher_suite,
                        }

                items.append({
                    "asset_id": asset.id,
                    "hostname": asset.target,
                    "freshness_status": cls._compute_freshness(dcs),
                    "has_scan": dcs is not None,
                    **cert_details,
                })

            return {
                "items": items,
                "total": total,
                "page": page,
                "page_size": page_size,
                "has_next": (page * page_size) < total,
                "has_prev": page > 1,
            }

        except Exception as exc:
            log.exception("CurrentStateService.get_all_assets_summary failed: %s", exc)
            return {"items": [], "total": 0, "page": page, "page_size": page_size, "has_next": False, "has_prev": False}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_freshness(dcs: Optional[Any]) -> str:
        """Return 'fresh' | 'stale' | 'degraded' | 'unknown'."""
        if dcs is None:
            return "unknown"
        if dcs.freshness_status == "degraded":
            return "degraded"
        if dcs.last_successful_scan_at:
            age = datetime.now(timezone.utc) - dcs.last_successful_scan_at.replace(tzinfo=timezone.utc)
            if age > timedelta(hours=STALE_THRESHOLD_HOURS):
                return "stale"
        return dcs.freshness_status or "unknown"

    @staticmethod
    def _compute_cert_status(cert: Any) -> str:
        """Return human-readable cert status from Certificate model row."""
        if cert.is_expired or (cert.expiry_days is not None and cert.expiry_days < 0):
            return "Expired"
        if cert.expiry_days is not None and cert.expiry_days <= 30:
            return "Expiring Soon"
        if cert.is_self_signed:
            return "Self-Signed"
        return "Valid"

    @staticmethod
    def _cert_to_dict(cert: Any) -> Dict[str, Any]:
        """Convert Certificate model row to a typed dict for API consumption."""
        from src.services.current_state_service import CurrentStateService as _cls
        import json

        cert_details: Dict[str, Any] = {}
        if cert.certificate_details:
            try:
                cert_details = json.loads(cert.certificate_details)
            except Exception:
                pass

        san_domains: List[str] = []
        if cert.san_domains:
            try:
                san_domains = json.loads(cert.san_domains)
            except Exception:
                san_domains = [cert.san_domains]

        return {
            "id": cert.id,
            "cert_status": _cls._compute_cert_status(cert),
            "subject_cn": cert.subject_cn,
            "subject_o": cert.subject_o,
            "issuer_cn": cert.issuer_cn,
            "issuer_o": cert.issuer_o,
            "serial": cert.serial,
            "fingerprint_sha256": cert.fingerprint_sha256,
            "valid_from": cert.valid_from.isoformat() if cert.valid_from else None,
            "valid_until": cert.valid_until.isoformat() if cert.valid_until else None,
            "expiry_days": cert.expiry_days,
            "is_expired": cert.is_expired,
            "is_self_signed": cert.is_self_signed,
            "is_current": cert.is_current,
            "tls_version": cert.tls_version,
            "key_length": cert.key_length,
            "key_algorithm": cert.key_algorithm,
            "public_key_type": cert.public_key_type,
            "cipher_suite": cert.cipher_suite,
            "signature_algorithm": cert.signature_algorithm,
            "ca": cert.ca,
            "san_domains": san_domains,
            "cert_chain_length": cert.cert_chain_length,
            "first_seen_at": cert.first_seen_at.isoformat() if cert.first_seen_at else None,
            "last_seen_at": cert.last_seen_at.isoformat() if cert.last_seen_at else None,
            "certificate_details": cert_details,
        }

    @staticmethod
    def _profile_to_dict(profile: Any) -> Dict[str, Any]:
        """Convert AssetSSLProfile model row to a typed dict."""
        import json

        cipher_list: List[str] = []
        if profile.cipher_list_json:
            try:
                cipher_list = json.loads(profile.cipher_list_json)
            except Exception:
                pass

        return {
            "id": profile.id,
            "supports_tls_1_0": profile.supports_tls_1_0,
            "supports_tls_1_1": profile.supports_tls_1_1,
            "supports_tls_1_2": profile.supports_tls_1_2,
            "supports_tls_1_3": profile.supports_tls_1_3,
            "preferred_cipher": profile.preferred_cipher,
            "cipher_list": cipher_list,
            "weak_cipher_count": profile.weak_cipher_count,
            "insecure_protocol_count": profile.insecure_protocol_count,
            "hsts_enabled": profile.hsts_enabled,
            "hsts_max_age": profile.hsts_max_age,
        }

    @staticmethod
    def _empty_state(asset_id: int, reason: str = "") -> Dict[str, Any]:
        """Return an explicit empty state dict."""
        return {
            "has_data": False,
            "asset_id": asset_id,
            "hostname": None,
            "freshness_status": "unknown",
            "render_status": "error",
            "render_error_message": reason or "No data available",
            "last_successful_scan_at": None,
            "last_failed_scan_at": None,
            "current_certificate": None,
            "ssl_profile": None,
            "latest_scan": None,
        }
