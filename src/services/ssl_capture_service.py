"""
SSLCaptureService
==================
Sprint 2: Hardened SSL/TLS ingestion pipeline.

Responsibilities:
1. Normalize hostname (strip protocol prefix, default port 443).
2. Perform TLS handshake with SNI via TLSAnalyzer (retry-safe).
3. Dedup certificates by dedup_hash (SHA-256 of asset_id + fingerprint_sha256).
4. Insert new Certificate row OR update last_seen_at on existing.
5. Build / update AssetSSLProfile snapshot for this scan.
6. Update DomainCurrentState atomically (transaction).
7. Emit DomainEvent entries for state changes (cert renewed, TLS version changed, etc.).
8. Never clear current_ssl_certificate_id on failure — last-good-data principle.

All DB writes are wrapped in a single transaction and rolled back on any failure.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)


# ─── Result type ─────────────────────────────────────────────────────────────

@dataclass
class CaptureResult:
    success: bool = False
    asset_id: Optional[int] = None
    scan_id: Optional[int] = None
    cert_id: Optional[int] = None
    profile_id: Optional[int] = None
    is_new_cert: bool = False
    changes: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "asset_id": self.asset_id,
            "scan_id": self.scan_id,
            "cert_id": self.cert_id,
            "profile_id": self.profile_id,
            "is_new_cert": self.is_new_cert,
            "changes": self.changes,
            "errors": self.errors,
            "correlation_id": self.correlation_id,
        }


# ─── Service ─────────────────────────────────────────────────────────────────

class SSLCaptureService:
    """
    Hardened SSL/TLS ingestion pipeline.

    Usage::

        from src.services.ssl_capture_service import SSLCaptureService
        result = SSLCaptureService.capture_and_persist(asset, scan, db_session)
        if result.success:
            print(f"Cert ID: {result.cert_id}, new={result.is_new_cert}")
        else:
            print(f"Errors: {result.errors}")
    """

    @classmethod
    def capture_and_persist(
        cls,
        asset: Any,       # src.models.Asset instance
        scan: Any,        # src.models.Scan instance
        db_session: Any,  # SQLAlchemy session
        correlation_id: Optional[str] = None,
    ) -> CaptureResult:
        """
        Full capture pipeline: TLS handshake → dedup → persist → update state.

        Never raises. All exceptions are caught and reported via result.errors.
        """
        result = CaptureResult(
            asset_id=asset.id,
            scan_id=scan.id,
            correlation_id=correlation_id or str(uuid.uuid4()),
        )

        try:
            # Step 1 — normalize hostname
            hostname, port = cls._normalize_target(asset.target)
            log.info("[%s] SSL capture start: %s:%d (asset=%d, scan=%d)",
                     result.correlation_id, hostname, port, asset.id, scan.id)

            # Step 2 — TLS handshake
            from src.scanner.tls_analyzer import TLSAnalyzer
            analyzer = TLSAnalyzer()
            tls_result = analyzer.analyze_endpoint(hostname, port)

            if not tls_result.is_successful:
                cls._handle_failure(asset, scan, tls_result, result, db_session)
                return result

            # Step 3 — build dedup key (choose canonical fingerprint)
            # Use shared helper so both ORM and raw-sql worker compute identical values
            cert_obj = tls_result.certificate
            from src.scanner.dedup_utils import compute_dedup_values

            dedup_algorithm, dedup_value, dedup_hash = compute_dedup_values(asset.id, cert_obj)
            # Keep legacy variable name for compatibility within this method
            fingerprint = dedup_value or ""

            # Step 4 — find or create Certificate row
            cert_row, is_new = cls._upsert_certificate(
                asset, scan, tls_result, fingerprint, dedup_hash, dedup_algorithm, dedup_value, db_session
            )

            # Step 5 — build / update AssetSSLProfile (inside transaction)
            profile_row = cls._upsert_ssl_profile(
                asset, scan, tls_result, db_session
            )

            # Step 6 — flush to get cert_row.id / profile_row.id
            db_session.flush()
            result.cert_id = cert_row.id
            result.profile_id = profile_row.id
            result.is_new_cert = is_new

            if is_new:
                result.changes.append("new_certificate_observed")
            else:
                result.changes.append("existing_certificate_last_seen_updated")

            # Step 7 — update DomainCurrentState atomically
            changes_from_state = cls._update_current_state(
                asset, scan, cert_row, profile_row, db_session
            )
            result.changes.extend(changes_from_state)

            # Step 8 — emit DomainEvents for detected changes
            cls._emit_domain_events(
                asset, scan, cert_row, profile_row,
                changes_from_state, result.correlation_id, db_session
            )

            db_session.commit()
            result.success = True
            log.info("[%s] SSL capture complete: cert=%d is_new=%s changes=%s",
                     result.correlation_id, cert_row.id, is_new, result.changes)

        except Exception as exc:
            db_session.rollback()
            msg = f"SSLCaptureService error: {exc}"
            log.exception("[%s] %s", result.correlation_id, msg)
            result.errors.append(msg)

        return result

    # ------------------------------------------------------------------
    # Step 1 — Normalize target
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_target(target: str) -> Tuple[str, int]:
        """
        Extract hostname and port from a raw target string.

        Examples::
            "https://pnb.bank.in"  → ("pnb.bank.in", 443)
            "pnb.bank.in:8443"     → ("pnb.bank.in", 8443)
            "pnb.bank.in"          → ("pnb.bank.in", 443)
        """
        # Strip scheme
        cleaned = re.sub(r"^https?://", "", target.strip()).rstrip("/")
        # Split host:port
        if ":" in cleaned:
            parts = cleaned.rsplit(":", 1)
            try:
                return parts[0], int(parts[1])
            except ValueError:
                pass
        return cleaned, 443

    # ------------------------------------------------------------------
    # Step 2b — Handle scan failure (degrade, don't clear)
    # ------------------------------------------------------------------

    @staticmethod
    def _handle_failure(
        asset: Any,
        scan: Any,
        tls_result: Any,
        result: CaptureResult,
        db_session: Any,
    ) -> None:
        """Mark the domain-current-state as degraded without clearing SSL data."""
        from src.models import DomainCurrentState
        error_msg = tls_result.error or "Unknown TLS error"
        error_code = tls_result.error_code or "UNKNOWN"
        result.errors.append(f"TLS handshake failed [{error_code}]: {error_msg}")
        log.warning("[%s] TLS failure for asset=%d: [%s] %s",
                    result.correlation_id, asset.id, error_code, error_msg)

        try:
            dcs = db_session.query(DomainCurrentState).filter_by(asset_id=asset.id).first()
            if dcs:
                dcs.freshness_status = "degraded"
                dcs.last_failed_scan_at = datetime.now(timezone.utc)
                dcs.render_status = "error"
                dcs.render_error_message = f"[{error_code}] {error_msg}"
                # Deliberately NOT clearing current_ssl_certificate_id — last-good-data principle
            db_session.commit()
        except Exception as ex:
            db_session.rollback()
            log.error("[%s] Failed to update DomainCurrentState on failure: %s",
                      result.correlation_id, ex)

    # ------------------------------------------------------------------
    # Step 3 — Dedup hash
    # ------------------------------------------------------------------

    @staticmethod
    def _make_dedup_hash(asset_id: int, fingerprint: str) -> str:
        """SHA-256 of asset_id + fingerprint for idempotent insert detection."""
        raw = f"{asset_id}:{fingerprint}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------
    # Step 4 — Upsert Certificate
    # ------------------------------------------------------------------

    @staticmethod
    def _upsert_certificate(
        asset: Any,
        scan: Any,
        tls_result: Any,
        fingerprint: str,
        dedup_hash: str,
        dedup_algorithm: Optional[str],
        dedup_value: Optional[str],
        db_session: Any,
    ) -> Tuple[Any, bool]:
        """
        Find or create a Certificate row.

        If a row with the same dedup_hash already exists for this asset,
        update its last_seen_at and mark it is_current.
        Otherwise, create a new row, clear is_current on previous rows,
        and set is_current=True on the new one.

        Returns (cert_row, is_new).
        """
        from src.models import Certificate

        now = datetime.now(timezone.utc)

        # Check for existing cert by dedup_hash
        existing = (
            db_session.query(Certificate)
            .filter(Certificate.dedup_hash == dedup_hash, Certificate.is_deleted == False)
            .first()
        )

        if existing:
            # Same cert seen again — update tracking fields
            existing.last_seen_at = now
            existing.scan_id = scan.id  # update to latest scan reference
            # Refresh expiry_days
            if existing.valid_until:
                delta = existing.valid_until - now.replace(tzinfo=None)
                existing.expiry_days = delta.days
                existing.is_expired = delta.days < 0

            # Update any additional fingerprint / version fields if available
            try:
                cert_obj = getattr(tls_result, "certificate", None)
                if cert_obj and getattr(cert_obj, "certificate_details", None) and isinstance(cert_obj.certificate_details, dict):
                    pk_info = cert_obj.certificate_details.get("subject_public_key_info", {})
                    pubkey_fp = pk_info.get("public_key_fingerprint_sha256") or None
                    if pubkey_fp:
                        existing.public_key_fingerprint_sha256 = str(pubkey_fp)
                    cert_ver = cert_obj.certificate_details.get("certificate_version")
                    if cert_ver:
                        existing.certificate_version = str(cert_ver)
                    cert_fmt = cert_obj.certificate_details.get("certificate_format")
                    if cert_fmt:
                        existing.certificate_format = str(cert_fmt)
                    fp1 = cert_obj.certificate_details.get("fingerprint_sha1")
                    if fp1:
                        existing.fingerprint_sha1 = str(fp1)
                    fpm = cert_obj.certificate_details.get("fingerprint_md5")
                    if fpm:
                        existing.fingerprint_md5 = str(fpm)
            except Exception:
                pass

            # Ensure it's marked current (clear other is_current rows first)
            db_session.query(Certificate).filter(
                Certificate.asset_id == asset.id,
                Certificate.id != existing.id,
                Certificate.is_current == True,
            ).update({"is_current": False}, synchronize_session="fetch")
            existing.is_current = True

            return existing, False

        cert = tls_result.certificate
        # Build cert fields from TLS result
        valid_from = None
        valid_until = None
        if cert:
            valid_from = cls_parse_dt(cert.not_before)
            valid_until = cls_parse_dt(cert.not_after)

        expiry_days: Optional[int] = None
        is_expired = False
        if valid_until:
            delta = valid_until - now.replace(tzinfo=None)
            expiry_days = delta.days
            is_expired = delta.days < 0

        cert_details_json: Optional[str] = None
        if cert and cert.certificate_details:
            try:
                cert_details_json = json.dumps(cert.certificate_details)
            except Exception:
                pass

        # Detect self-signed
        is_self_signed = (
            cert is not None
            and cert.issuer_cn == cert.subject_cn
            and bool(cert.subject_cn)
        )

        # Clear is_current on previous certs for this asset
        db_session.query(Certificate).filter(
            Certificate.asset_id == asset.id,
            Certificate.is_current == True,
        ).update({"is_current": False}, synchronize_session="fetch")

        new_cert = Certificate(
            asset_id=asset.id,
            scan_id=scan.id,
            endpoint=f"{tls_result.host}:{tls_result.port}",
            port=tls_result.port,
            issuer=cert.issuer_cn if cert else None,
            subject=cert.subject_cn if cert else None,
            subject_cn=cert.subject_cn if cert else None,
            subject_o=cert.subject_o if cert else None,
            subject_ou=cert.subject_ou if cert else None,
            issuer_cn=cert.issuer_cn if cert else None,
            issuer_o=cert.issuer_o if cert else None,
            issuer_ou=cert.issuer_ou if cert else None,
            serial=cert.serial_number if cert else None,
            company_name=cert.subject_o if cert else None,
            valid_from=valid_from,
            valid_until=valid_until,
            expiry_days=expiry_days,
            fingerprint_sha256=(fingerprint if (dedup_algorithm == 'sha256' or not dedup_algorithm) else None) or getattr(cert, 'fingerprint_sha256', None) or (cert.certificate_details.get('fingerprint_sha256') if getattr(cert, 'certificate_details', None) and isinstance(cert.certificate_details, dict) else None),
            fingerprint_sha1=(cert.certificate_details.get('fingerprint_sha1') if cert and getattr(cert, 'certificate_details', None) and isinstance(cert.certificate_details, dict) else None),
            fingerprint_md5=(cert.certificate_details.get('fingerprint_md5') if cert and getattr(cert, 'certificate_details', None) and isinstance(cert.certificate_details, dict) else None),
            public_key_fingerprint_sha256=(
                (cert.certificate_details.get("subject_public_key_info", {}) or {}).get("public_key_fingerprint_sha256")
                if cert and getattr(cert, "certificate_details", None) and isinstance(cert.certificate_details, dict) else None
            ),
            certificate_version=(cert.certificate_details.get("certificate_version") if cert and getattr(cert, "certificate_details", None) and isinstance(cert.certificate_details, dict) else None),
            certificate_format=(cert.certificate_details.get("certificate_format") if cert and getattr(cert, "certificate_details", None) and isinstance(cert.certificate_details, dict) else None),
            dedup_algorithm=dedup_algorithm,
            dedup_value=dedup_value,
            dedup_hash=dedup_hash,
            tls_version=tls_result.protocol_version,
            key_length=cert.public_key_bits if cert else None,
            key_algorithm=cert.public_key_type if cert else None,
            public_key_type=cert.public_key_type if cert else None,
            public_key_pem=cert.public_key_pem if cert else None,
            cipher_suite=tls_result.cipher_suite,
            signature_algorithm=cert.signature_algorithm if cert else None,
            ca=cert.issuer_cn if cert else None,
            san_domains=json.dumps(cert.san_domains) if (cert and cert.san_domains) else None,
            cert_chain_length=tls_result.certificate_chain_length,
            is_self_signed=is_self_signed,
            is_expired=is_expired,
            is_current=True,
            first_seen_at=now,
            last_seen_at=now,
            certificate_details=cert_details_json,
        )

        db_session.add(new_cert)
        return new_cert, True

    # ------------------------------------------------------------------
    # Step 5 — Upsert SSL Profile
    # ------------------------------------------------------------------

    @staticmethod
    def _upsert_ssl_profile(
        asset: Any,
        scan: Any,
        tls_result: Any,
        db_session: Any,
    ) -> Any:
        """Create (or update) the AssetSSLProfile for this scan."""
        from src.models import AssetSSLProfile

        now = datetime.now(timezone.utc)
        protos = set(tls_result.supported_protocols or [])

        # Count weak ciphers in the cipher suite list
        weak_ciphers = [
            c for c in (tls_result.all_cipher_suites or [])
            if any(w in c.upper() for w in ("RC4", "DES", "NULL", "EXPORT", "ANON", "MD5"))
        ]

        # Clear is_current on previous profiles
        db_session.query(AssetSSLProfile).filter(
            AssetSSLProfile.asset_id == asset.id,
            AssetSSLProfile.is_current == True,
        ).update({"is_current": False}, synchronize_session="fetch")

        profile = AssetSSLProfile(
            asset_id=asset.id,
            scan_id=scan.id,
            supports_tls_1_0="TLSv1.0" in protos,
            supports_tls_1_1="TLSv1.1" in protos,
            supports_tls_1_2="TLSv1.2" in protos,
            supports_tls_1_3="TLSv1.3" in protos,
            preferred_cipher=tls_result.cipher_suite,
            cipher_list_json=json.dumps(tls_result.all_cipher_suites) if tls_result.all_cipher_suites else None,
            weak_cipher_count=len(weak_ciphers),
            insecure_protocol_count=sum(1 for p in ["TLSv1.0", "TLSv1.1"] if p in protos),
            hsts_enabled=tls_result.hsts_enabled,
            hsts_max_age=tls_result.hsts_max_age,
            is_current=True,
            first_seen_at=now,
            last_seen_at=now,
        )
        db_session.add(profile)
        return profile

    # ------------------------------------------------------------------
    # Step 6 — Update DomainCurrentState
    # ------------------------------------------------------------------

    @staticmethod
    def _update_current_state(
        asset: Any,
        scan: Any,
        cert_row: Any,
        profile_row: Any,
        db_session: Any,
    ) -> List[str]:
        """Atomically update DomainCurrentState. Returns list of change keys."""
        from src.models import DomainCurrentState

        changes: List[str] = []
        now = datetime.now(timezone.utc)

        dcs = db_session.query(DomainCurrentState).filter_by(asset_id=asset.id).first()

        if dcs is None:
            dcs = DomainCurrentState(
                asset_id=asset.id,
                latest_scan_id=scan.id,
                current_ssl_certificate_id=cert_row.id,
                freshness_status="fresh",
                last_successful_scan_at=now,
                render_status="ok",
            )
            db_session.add(dcs)
            changes.append("domain_current_state_created")
        else:
            if dcs.current_ssl_certificate_id != cert_row.id:
                changes.append("current_certificate_rotated")
            dcs.latest_scan_id = scan.id
            dcs.current_ssl_certificate_id = cert_row.id
            dcs.freshness_status = "fresh"
            dcs.last_successful_scan_at = now
            dcs.render_status = "ok"
            dcs.render_error_message = None

        return changes

    # ------------------------------------------------------------------
    # Step 7 — Emit DomainEvents
    # ------------------------------------------------------------------

    @staticmethod
    def _emit_domain_events(
        asset: Any,
        scan: Any,
        cert_row: Any,
        profile_row: Any,
        changes: List[str],
        correlation_id: str,
        db_session: Any,
    ) -> None:
        """Append DomainEvent rows for each detected state change."""
        from src.models import DomainEvent

        now = datetime.now(timezone.utc)

        event_map = {
            "new_certificate_observed": ("cert_renewed", "New Certificate Detected", "info"),
            "current_certificate_rotated": ("cert_renewed", "Certificate Was Rotated", "warning"),
            "domain_current_state_created": ("scan_succeeded", "First Successful Scan", "info"),
            "existing_certificate_last_seen_updated": ("scan_succeeded", "Certificate Re-confirmed", "info"),
        }

        for change_key in changes:
            if change_key not in event_map:
                continue
            event_type, title, severity = event_map[change_key]
            event = DomainEvent(
                asset_id=asset.id,
                scan_id=scan.id,
                event_type=event_type,
                event_title=title,
                event_description=f"Change detected during scan {scan.scan_id}",
                severity=severity,
                correlation_id=correlation_id,
                created_at=now,
            )
            db_session.add(event)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def cls_parse_dt(value: str) -> Optional[datetime]:
    """Parse common certificate datetime string formats to datetime object."""
    if not value:
        return None
    formats = [
        "%b %d %H:%M:%S %Y %Z",  # ssl.getpeercert() format
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(value.strip(), fmt)
        except ValueError:
            continue
    return None
