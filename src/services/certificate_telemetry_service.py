"""
SSL/TLS Certificate Telemetry Service

Complete database-backed certificate metrics for all dashboards.
Maps UI widgets → SQL queries → Database fields.

All certificate data comes from:
- `certificates` table (populated during scan ingestion)
- `assets` table (asset metadata)
- `scans` table (scan context)

No mock or hardcoded data — all metrics computed from DB.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple
from sqlalchemy import func, and_, or_
from collections import Counter
import json

from src.models import Certificate, Asset, Scan


class CertificateTelemetryService:
    """Unified service for all SSL/TLS certificate metrics across dashboards."""
    
    def __init__(self):
        pass

    @staticmethod
    def _load_json_list(value) -> List[str]:
        if isinstance(value, list):
            return [str(item) for item in value if str(item or "").strip()]
        raw = str(value or "").strip()
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [str(item) for item in parsed if str(item or "").strip()]
        except Exception:
            pass
        return []
    
    def _get_db_session(self):
        """Get SQLAlchemy session from app context."""
        from src.db import db_session
        return db_session

    def _certificate_details_from_row(self, cert: Certificate) -> Dict:
        base = {
            "certificate_version": "",
            "serial_number": str(cert.serial or ""),
            "certificate_signature_algorithm": str(cert.signature_algorithm or ""),
            "certificate_signature": "",
            "issuer": str(cert.issuer or cert.ca or ""),
            "validity": {
                "not_before": cert.valid_from.isoformat() if cert.valid_from is not None else "",
                "not_after": cert.valid_until.isoformat() if cert.valid_until is not None else "",
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
            "certificate_subject_alternative_name": self._load_json_list(cert.san_domains),
            "certificate_policies": [],
            "crl_distribution_points": [],
            "signed_certificate_timestamp_list": [],
        }

        try:
            report_raw = getattr(getattr(cert, "scan", None), "report_json", None)
            report = {}
            if isinstance(report_raw, dict):
                report = report_raw
            elif isinstance(report_raw, str) and report_raw.strip():
                report = json.loads(report_raw)

            tls_rows = report.get("tls_results") if isinstance(report.get("tls_results"), list) else []
            cert_serial = str(cert.serial or "").strip().upper()
            cert_subject_cn = str(cert.subject_cn or "").strip().lower()
            cert_endpoint = str(cert.endpoint or "").strip().lower()

            for row in tls_rows:
                if not isinstance(row, dict):
                    continue
                row_serial = str(row.get("serial_number") or "").strip().upper()
                row_subject_cn = str(row.get("subject_cn") or "").strip().lower()
                row_host = str(row.get("host") or "").strip().lower()
                row_port = int(row.get("port") or 0) if str(row.get("port") or "").strip() else 0
                row_endpoint = f"{row_host}:{row_port}" if row_host and row_port else row_host

                if cert_serial and row_serial and cert_serial == row_serial:
                    details = row.get("certificate_details")
                    if isinstance(details, dict):
                        return {**base, **details}
                if cert_subject_cn and row_subject_cn and cert_subject_cn == row_subject_cn:
                    details = row.get("certificate_details")
                    if isinstance(details, dict):
                        return {**base, **details}
                if cert_endpoint and row_endpoint and cert_endpoint == row_endpoint:
                    details = row.get("certificate_details")
                    if isinstance(details, dict):
                        return {**base, **details}
        except Exception:
            pass

        return base
    
    # ════════════════════════════════════════════════════════════════════
    # 1. EXPIRING CERTIFICATES — Core Metric
    # ════════════════════════════════════════════════════════════════════
    
    def get_expiring_certificates_count(self, days_threshold: int = 30) -> int:
        """
        SQL Query:
            SELECT COUNT(*) FROM certificates c
            WHERE c.is_deleted = 0
            AND NOW() < valid_until < DATE_ADD(NOW(), INTERVAL ? DAYS)
        
        Maps to: vm.kpis.expiring_certificates (UI card)
        """
        db = self._get_db_session()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        threshold_date = now + timedelta(days=days_threshold)
        
        count = db.query(func.count(Certificate.id)).filter(
            Certificate.is_deleted == False,
            Certificate.valid_until > now,
            Certificate.valid_until <= threshold_date
        ).scalar() or 0
        
        return int(count)
    
    def get_expired_certificates_count(self) -> int:
        """
        SQL Query:
            SELECT COUNT(*) FROM certificates c
            WHERE c.is_deleted = 0 AND valid_until < NOW()
        
        Maps to: Certificate health indicator
        """
        db = self._get_db_session()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        
        count = db.query(func.count(Certificate.id)).filter(
            Certificate.is_deleted == False,
            Certificate.valid_until < now
        ).scalar() or 0
        
        return int(count)
    
    # ════════════════════════════════════════════════════════════════════
    # 2. CERTIFICATE EXPIRY TIMELINE — Expiry Buckets
    # ════════════════════════════════════════════════════════════════════
    
    def get_certificate_expiry_timeline(self) -> Dict[str, int]:
        """
        SQL Query (4 aggregations):
            SELECT COUNT(*) FROM certificates c WHERE c.is_deleted = 0
            AND DATEDIFF(c.valid_until, NOW()) BETWEEN 0 AND 30   → "0-30"
            AND DATEDIFF(c.valid_until, NOW()) BETWEEN 31 AND 60  → "30-60"
            AND DATEDIFF(c.valid_until, NOW()) BETWEEN 61 AND 90  → "60-90"
            AND DATEDIFF(c.valid_until, NOW()) > 90               → ">90"
        
        Maps to: vm.certificate_expiry_timeline (Jinja template loop)
        
        Returns:
            {"0-30": 5, "30-60": 3, "60-90": 2, ">90": 15}
        """
        db = self._get_db_session()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        
        # Get all valid certificates (not expired, not deleted)
        certs = db.query(Certificate).filter(
            Certificate.is_deleted == False,
            Certificate.valid_until > now
        ).all()
        
        buckets = {"0-30": 0, "30-60": 0, "60-90": 0, ">90": 0}
        
        for cert in certs:
            if cert.valid_until is None:
                continue
            
            days_left = (cert.valid_until - now).days
            
            if days_left <= 30:
                buckets["0-30"] += 1
            elif days_left <= 60:
                buckets["30-60"] += 1
            elif days_left <= 90:
                buckets["60-90"] += 1
            else:
                buckets[">90"] += 1
        
        return buckets
    
    # ════════════════════════════════════════════════════════════════════
    # 3. CERTIFICATE INVENTORY TABLE — All Certs with Details
    # ════════════════════════════════════════════════════════════════════
    
    def get_certificate_inventory(self, limit: int = 100) -> List[Dict]:
        """
        SQL Query:
            SELECT c.*, a.target as asset_name, s.target as scan_target
            FROM certificates c
            LEFT JOIN assets a ON c.asset_id = a.id
            LEFT JOIN scans s ON c.scan_id = s.id
            WHERE c.is_deleted = 0
            ORDER BY c.valid_until ASC  (soonest expiry first)
            LIMIT ?
        
        Maps to:
            - vm.certificate_inventory (Jinja template table rows)
            - HTML Table columns: Asset, Issuer, Key, TLS, Days Left, Status
        
        Returns list of certificate rows with computed fields.
        """
        db = self._get_db_session()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        
        certs = db.query(Certificate).filter(
            Certificate.is_deleted == False
        ).order_by(Certificate.valid_until.asc()).limit(limit).all()
        
        inventory = []
        
        for cert in certs:
            asset_name = "Unknown"
            if cert.asset_id is not None and cert.asset is not None:
                asset_name = str(cert.asset.target or "Unknown")
            
            # Compute days remaining
            days_remaining = None
            status = "Unknown"
            
            valid_until = cert.valid_until
            if valid_until is not None:
                days_remaining = (valid_until - now).days
                
                if days_remaining < 0:
                    status = "Expired"
                elif days_remaining == 0:
                    status = "Expires Today"
                elif days_remaining <= 7:
                    status = "Critical"
                elif days_remaining <= 30:
                    status = "Expiring"
                else:
                    status = "Valid"

            key_length_val = cert.key_length
            key_length = int(key_length_val) if key_length_val is not None else 0
            cipher_suite = cert.cipher_suite or "Unknown"
            tls_version = cert.tls_version or "Unknown"
            issuer = cert.issuer or cert.ca or "Unknown"
            ca = cert.ca or cert.issuer or "Unknown"
            fingerprint_str = str(cert.fingerprint_sha256 or "")
            fingerprint = fingerprint_str[:16] + "..." if fingerprint_str else "N/A"
            
            inventory.append({
                "certificate_id": cert.id,
                "asset": asset_name,
                "endpoint": str(cert.endpoint or ""),
                "issuer": str(issuer),
                "subject": str(cert.subject or ""),
                "subject_cn": str(cert.subject_cn or ""),
                "subject_o": str(cert.subject_o or cert.company_name or ""),
                "subject_ou": str(cert.subject_ou or ""),
                "issuer_cn": str(cert.issuer_cn or cert.ca or ""),
                "issuer_o": str(cert.issuer_o or cert.ca_name or ""),
                "issuer_ou": str(cert.issuer_ou or ""),
                "key_length": key_length,
                "public_key_type": str(cert.public_key_type or cert.key_algorithm or ""),
                "public_key_pem": str(cert.public_key_pem or ""),
                "cipher_suite": str(cipher_suite),
                "tls_version": str(tls_version),
                "ca": str(ca),
                "serial": str(cert.serial or ""),
                "valid_from": cert.valid_from.isoformat() if cert.valid_from is not None else None,
                "valid_until": valid_until.isoformat() if valid_until is not None else None,
                "days_remaining": days_remaining,
                "status": status,
                "fingerprint": fingerprint,
                "fingerprint_sha256": str(cert.fingerprint_sha256 or ""),
                "san_domains": self._load_json_list(cert.san_domains),
                "cert_chain_length": int(cert.cert_chain_length or 0),
                "certificate_details": self._certificate_details_from_row(cert),
            })
        
        return inventory
    
    # ════════════════════════════════════════════════════════════════════
    # 4. CRYPTO OVERVIEW — Key Length & Cipher Suite Distribution
    # ════════════════════════════════════════════════════════════════════
    
    def get_key_length_distribution(self) -> Dict[str, int]:
        """
        SQL Query:
            SELECT key_length, COUNT(*) FROM certificates
            WHERE is_deleted = 0 GROUP BY key_length
        
        Maps to: Crypto metrics widget / charts
        
        Returns:
            {"2048": 45, "4096": 23, "256": 5, "Other": 2}
        """
        db = self._get_db_session()
        
        certs = db.query(Certificate).filter(
            Certificate.is_deleted == False
        ).all()
        
        distribution = Counter()
        
        for cert in certs:
            key_len_raw = cert.key_length
            key_len = int(key_len_raw) if key_len_raw is not None else 0
            
            if key_len >= 4096:
                distribution["4096+"] += 1
            elif key_len >= 2048:
                distribution["2048"] += 1
            elif key_len >= 256:
                distribution["256-2047"] += 1
            elif key_len > 0:
                distribution["<256"] += 1
            else:
                distribution["Unknown"] += 1
        
        return dict(distribution)
    
    def get_cipher_suite_distribution(self, limit: int = 10) -> List[Dict]:
        """
        SQL Query:
            SELECT cipher_suite, COUNT(*) as count
            FROM certificates WHERE is_deleted = 0
            GROUP BY cipher_suite
            ORDER BY count DESC LIMIT ?
        
        Maps to: Cipher suite widget
        
        Returns top ciphers with counts.
        """
        db = self._get_db_session()
        
        certs = db.query(Certificate).filter(
            Certificate.is_deleted == False
        ).all()
        
        cipher_counts = Counter(
            cert.cipher_suite for cert in certs
            if cert.cipher_suite is not None
        )
        
        return [
            {"cipher_suite": cipher, "count": count}
            for cipher, count in cipher_counts.most_common(limit)
        ]
    
    # ════════════════════════════════════════════════════════════════════
    # 5. TLS VERSION DISTRIBUTION
    # ════════════════════════════════════════════════════════════════════
    
    def get_tls_version_distribution(self) -> Dict[str, int]:
        """
        SQL Query:
            SELECT tls_version, COUNT(*) FROM certificates
            WHERE is_deleted = 0 GROUP BY tls_version
        
        Maps to: TLS version coverage widget
        
        Returns:
            {"TLS 1.3": 60, "TLS 1.2": 35, "TLS 1.0": 5}
        """
        db = self._get_db_session()
        
        certs = db.query(Certificate).filter(
            Certificate.is_deleted == False
        ).all()
        
        distribution = Counter(
            cert.tls_version for cert in certs
            if cert.tls_version is not None
        )
        
        # Group legacy versions for clarity
        result = dict(distribution)
        
        # Ensure common versions are present
        for version in ["TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0"]:
            if version not in result:
                result[version] = 0
        
        return result
    
    # ════════════════════════════════════════════════════════════════════
    # 6. CERTIFICATE AUTHORITY DISTRIBUTION
    # ════════════════════════════════════════════════════════════════════
    
    def get_certificate_authority_distribution(self, limit: int = 10) -> List[Dict]:
        """
        SQL Query:
            SELECT ca, COUNT(*) as count FROM certificates
            WHERE is_deleted = 0 GROUP BY ca
            ORDER BY count DESC LIMIT ?
        
        Maps to: CA distribution widget / pie chart
        
        Returns top CAs with certificate counts.
        """
        db = self._get_db_session()
        
        certs = db.query(Certificate).filter(
            Certificate.is_deleted == False
        ).all()
        
        # Fallback to issuer if ca is not set
        ca_counts = Counter()
        for cert in certs:
            ca = str(cert.ca or cert.issuer or "Unknown")
            ca_counts[ca] += 1
        
        return [
            {"ca": ca, "count": count}
            for ca, count in ca_counts.most_common(limit)
        ]
    
    # ════════════════════════════════════════════════════════════════════
    # 7. WEAK CRYPTOGRAPHY DETECTION
    # ════════════════════════════════════════════════════════════════════
    
    def get_weak_cryptography_metrics(self) -> Dict[str, int]:
        """
        SQL Queries (multiple conditions):
            SELECT COUNT(*) FROM certificates WHERE is_deleted = 0
            AND key_length < 2048                           → weak_keys
            AND tls_version IN ('TLS 1.0', 'TLS 1.1', ...)  → weak_tls
            AND cipher_suite LIKE '%NULL%'                  → null_ciphers
        
        Maps to:
            - Dashboard kpis weak crypto indicators
            - CBOM weak component count
        """
        db = self._get_db_session()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        
        # Weak keys (< 2048-bit)
        weak_keys_count = db.query(func.count(Certificate.id)).filter(
            Certificate.is_deleted == False,
            Certificate.key_length < 2048,
            Certificate.key_length > 0
        ).scalar() or 0
        
        # Weak TLS versions
        weak_tls_versions = ["TLS 1.0", "TLS 1.1", "SSLv3", "SSLv2"]
        weak_tls_count = db.query(func.count(Certificate.id)).filter(
            Certificate.is_deleted == False,
            Certificate.tls_version.in_(weak_tls_versions)
        ).scalar() or 0
        
        # Expired certificates
        expired_count = db.query(func.count(Certificate.id)).filter(
            Certificate.is_deleted == False,
            Certificate.valid_until < now
        ).scalar() or 0
        
        # Self-signed (issuer == subject)
        all_certs = db.query(Certificate).filter(
            Certificate.is_deleted == False
        ).all()
        
        self_signed_count = sum(
            1 for cert in all_certs
            if cert.issuer and cert.subject and cert.issuer == cert.subject
        )
        
        return {
            "weak_keys": int(weak_keys_count),
            "weak_tls": int(weak_tls_count),
            "expired": int(expired_count),
            "self_signed": self_signed_count,
        }
    
    # ════════════════════════════════════════════════════════════════════
    # 8. CERTIFICATE ISSUES COUNT (for CBOM)
    # ════════════════════════════════════════════════════════════════════
    
    def get_certificate_issues_count(self) -> int:
        """
        Combined count of certificate-related issues:
        - Expired certificates
        - Expiring soon (< 30 days)
        - Weak cryptography
        
        SQL Query (aggregation):
            COUNT(expired) + COUNT(expiring) + COUNT(weak_keys) + COUNT(weak_tls)
        
        Maps to: vm.cbom_summary.cert_issues_count
        """
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        threshold_date = now + timedelta(days=30)
        
        db = self._get_db_session()
        
        # Expired or expiring
        urgent_count = db.query(func.count(Certificate.id)).filter(
            Certificate.is_deleted == False,
            Certificate.valid_until <= threshold_date
        ).scalar() or 0
        
        # Weak crypto
        weak_metrics = self.get_weak_cryptography_metrics()
        weak_count = weak_metrics["weak_keys"] + weak_metrics["weak_tls"]
        
        return int(urgent_count) + weak_count
    
    # ════════════════════════════════════════════════════════════════════
    # 9. CERTIFICATE CHAIN ANALYSIS
    # ════════════════════════════════════════════════════════════════════
    
    def get_certificate_chain_depth_by_asset(self, asset_id: int) -> Optional[int]:
        """
        SQL Query:
            SELECT MAX(cert_chain_position) FROM certificates
            WHERE asset_id = ? AND is_deleted = 0
        
        Note: This requires storing cert_chain_position in schema
        For now, this is a placeholder for future implementation.
        """
        return None
    
    # ════════════════════════════════════════════════════════════════════
    # 10. CERTIFICATE BY ASSET (One-to-Latest-Cert Relationship)
    # ════════════════════════════════════════════════════════════════════
    
    def get_latest_certificate_for_asset(self, asset_id: int) -> Optional[Dict]:
        """
        SQL Query:
            SELECT * FROM certificates
            WHERE asset_id = ? AND is_deleted = 0
            ORDER BY valid_until DESC LIMIT 1
        
        Maps to: Asset detail view certificate info
        
        Returns latest certificate record for the asset.
        """
        db = self._get_db_session()
        
        cert = db.query(Certificate).filter(
            Certificate.asset_id == asset_id,
            Certificate.is_deleted == False
        ).order_by(Certificate.valid_until.desc()).first()
        
        if not cert:
            return None
        
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        days_remaining = None
        status = "Unknown"
        
        if cert.valid_until:
            days_remaining = (cert.valid_until - now).days
            if days_remaining < 0:
                status = "Expired"
            elif days_remaining <= 30:
                status = "Expiring"
            else:
                status = "Valid"
        
        return {
            "certificate_id": cert.id,
            "endpoint": str(cert.endpoint or ""),
            "issuer": str(cert.issuer or cert.ca or "Unknown"),
            "subject": str(cert.subject or ""),
            "subject_cn": str(cert.subject_cn or ""),
            "subject_o": str(cert.subject_o or cert.company_name or ""),
            "subject_ou": str(cert.subject_ou or ""),
            "issuer_cn": str(cert.issuer_cn or cert.ca or ""),
            "issuer_o": str(cert.issuer_o or cert.ca_name or ""),
            "issuer_ou": str(cert.issuer_ou or ""),
            "serial": str(cert.serial or ""),
            "key_length": int(cert.key_length or 0),
            "public_key_type": str(cert.public_key_type or cert.key_algorithm or ""),
            "public_key_pem": str(cert.public_key_pem or ""),
            "tls_version": str(cert.tls_version or "Unknown"),
            "cipher_suite": str(cert.cipher_suite or "Unknown"),
            "ca": str(cert.ca or "Unknown"),
            "valid_from": cert.valid_from.isoformat() if cert.valid_from else None,
            "valid_until": cert.valid_until.isoformat() if cert.valid_until else None,
            "days_remaining": days_remaining,
            "status": status,
            "fingerprint": str(cert.fingerprint_sha256 or "")[:16] + "..." if cert.fingerprint_sha256 else "N/A",
            "fingerprint_sha256": str(cert.fingerprint_sha256 or ""),
            "san_domains": self._load_json_list(cert.san_domains),
            "cert_chain_length": int(cert.cert_chain_length or 0),
            "certificate_details": self._certificate_details_from_row(cert),
        }
    
    # ════════════════════════════════════════════════════════════════════
    # 11. COMPLETE TELEMETRY PAYLOAD (All Dashboard Metrics at Once)
    # ════════════════════════════════════════════════════════════════════
    
    def get_complete_certificate_telemetry(self) -> Dict:
        """
        Build comprehensive certificate telemetry payload for dashboards.
        Single method call fetches all certificate-related metrics.
        
        Reduces multiple database round-trips to unified payload.
        """
        return {
            # KPI metrics
            "kpis": {
                "total_certificates": self._get_total_certificates_count(),
                "expiring_certificates": self.get_expiring_certificates_count(),
                "expired_certificates": self.get_expired_certificates_count(),
            },
            
            # Timelines and distributions
            "expiry_timeline": self.get_certificate_expiry_timeline(),
            "tls_version_distribution": self.get_tls_version_distribution(),
            "key_length_distribution": self.get_key_length_distribution(),
            
            # Detailed inventory
            "certificate_inventory": self.get_certificate_inventory(),
            "certificate_authority_distribution": self.get_certificate_authority_distribution(),
            "cipher_suite_distribution": self.get_cipher_suite_distribution(),
            
            # Weak crypto indicators
            "weak_cryptography": self.get_weak_cryptography_metrics(),
            
            # CBOM-specific
            "cert_issues_count": self.get_certificate_issues_count(),
        }
    
    # ════════════════════════════════════════════════════════════════════
    # HELPER METHODS
    # ════════════════════════════════════════════════════════════════════
    
    def _get_total_certificates_count(self) -> int:
        """Total active certificates in inventory."""
        db = self._get_db_session()
        count = db.query(func.count(Certificate.id)).filter(
            Certificate.is_deleted == False
        ).scalar() or 0
        return int(count)
    
    def _mark_certificate_fingerprint(self, certificate_id: int, fingerprint: str) -> bool:
        """
        Store certificate fingerprint (SHA-256) for deduplication/tracking.
        
        SQL Update:
            UPDATE certificates SET fingerprint_sha256 = ? WHERE id = ?
        """
        db = self._get_db_session()
        
        try:
            cert = db.query(Certificate).filter_by(id=certificate_id).first()
            if cert:
                cert.fingerprint_sha256 = fingerprint
                db.commit()
                return True
        except Exception:
            db.rollback()
        
        return False
