"""
CBOM Service layer for Cryptographic Bill of Materials dashboard and API.

Encapsulates query logic in one service for reusability and easier unit tests.
"""

from datetime import datetime
from typing import Dict, List, Any, Optional
import json
import hashlib

from src import db
from src.models import Asset, Scan, Certificate, CBOMEntry, CBOMSummary, DiscoverySSL
from sqlalchemy import func, distinct, desc, asc, inspect, or_

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
except Exception:  # pragma: no cover - runtime optional import safety
    serialization = None
    load_pem_public_key = None


class _DBSessionProxy:
    def __getattr__(self, name):
        return getattr(db.db_session, name)


db_session = _DBSessionProxy()


class CbomService:
    WEAK_TLS_VERSIONS = ["SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1"]
    MINIMUM_ELEMENT_FIELDS = [
        "asset_type",
        "element_name",
        "primitive",
        "mode",
        "crypto_functions",
        "classical_security_level",
        "oid",
        "key_id",
        "key_state",
        "key_size",
        "key_creation_date",
        "key_activation_date",
        "protocol_name",
        "protocol_version_name",
        "cipher_suites",
        "subject_name",
        "issuer_name",
        "not_valid_before",
        "not_valid_after",
        "signature_algorithm_reference",
        "subject_public_key_reference",
        "certificate_format",
        "certificate_extension",
    ]

    PNB_MINIMUM_ELEMENT_DEFINITIONS = {
        "asset_type": "Type of cryptographic asset (algorithm, key, protocol, certificate).",
        "element_name": "Name of the cryptographic element or algorithm (for example AES-128-GCM).",
        "primitive": "Cryptographic primitive represented by the element (for example signature, cipher, hash).",
        "mode": "Operational mode used by the algorithm (for example GCM).",
        "crypto_functions": "Supported cryptographic functions (for example key generation, encryption, decryption).",
        "classical_security_level": "Classical security strength in bits against non-quantum attacks.",
        "oid": "Object Identifier used to uniquely identify protocol/algorithm/certificate references.",
        "key_id": "Unique key identifier/reference in lifecycle management.",
        "key_state": "Current key state such as active, revoked, or expired.",
        "key_size": "Size of the key in bits.",
        "key_creation_date": "Date-time when the key was created.",
        "key_activation_date": "Date-time when the key became operational.",
        "protocol_name": "Name of protocol such as TLS, SSH, IPsec.",
        "protocol_version_name": "Protocol version such as TLS 1.2/TLS 1.3.",
        "cipher_suites": "Cipher suites supported/used by the protocol context.",
        "subject_name": "Certificate subject distinguished name.",
        "issuer_name": "Certificate issuer distinguished name (CA).",
        "not_valid_before": "Certificate validity start timestamp.",
        "not_valid_after": "Certificate validity end/expiry timestamp.",
        "signature_algorithm_reference": "Certificate signature algorithm reference (with OID where available).",
        "subject_public_key_reference": "Reference to subject public key details/algorithm.",
        "certificate_format": "Certificate format (for example X.509).",
        "certificate_extension": "Certificate file extension (for example .crt).",
    }

    @staticmethod
    def _dn_component(dn_value: str, key: str) -> str:
        raw_dn = str(dn_value or "").strip()
        if not raw_dn:
            return ""
        for part in raw_dn.split(","):
            token = part.strip()
            if token.upper().startswith(f"{key.upper()}="):
                return token.split("=", 1)[1].strip()
        return ""

    @staticmethod
    def _public_key_fingerprint_sha256_from_pem(public_key_pem: str) -> str:
        key_pem = str(public_key_pem or "").strip()
        if not key_pem or load_pem_public_key is None or serialization is None:
            return ""
        try:
            pub_key = load_pem_public_key(key_pem.encode("utf-8"))
            pub_der = pub_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return hashlib.sha256(pub_der).hexdigest().upper()
        except Exception:
            return ""

    @classmethod
    def _build_x509_minimum_payload(
        cls,
        certificate_details: Dict[str, Any],
        subject_cn: str,
        subject_o: str,
        subject_ou: str,
        issuer_cn: str,
        issuer_o: str,
        issuer_ou: str,
        valid_from: str,
        valid_until: str,
        cert_fingerprint_sha256: str,
        public_key_fingerprint_sha256: str,
    ) -> Dict[str, Any]:
        details = certificate_details if isinstance(certificate_details, dict) else {}
        validity = details.get("validity") if isinstance(details.get("validity"), dict) else {}
        spki = details.get("subject_public_key_info") if isinstance(details.get("subject_public_key_info"), dict) else {}

        subject_dn = str(details.get("subject") or "")
        issuer_dn = str(details.get("issuer") or "")

        resolved_subject_cn = str(subject_cn or cls._dn_component(subject_dn, "CN") or "").strip()
        resolved_subject_o = str(subject_o or cls._dn_component(subject_dn, "O") or "").strip()
        resolved_subject_ou = str(subject_ou or cls._dn_component(subject_dn, "OU") or "").strip()

        resolved_issuer_cn = str(issuer_cn or cls._dn_component(issuer_dn, "CN") or "").strip()
        resolved_issuer_o = str(issuer_o or cls._dn_component(issuer_dn, "O") or "").strip()
        resolved_issuer_ou = str(issuer_ou or cls._dn_component(issuer_dn, "OU") or "").strip()

        resolved_valid_from = str(valid_from or validity.get("not_before") or "").strip()
        resolved_valid_until = str(valid_until or validity.get("not_after") or "").strip()

        resolved_cert_fingerprint = str(
            cert_fingerprint_sha256
            or details.get("fingerprint_sha256")
            or details.get("fingerprint")
            or ""
        ).strip()
        resolved_public_key_fingerprint = str(
            public_key_fingerprint_sha256
            or spki.get("public_key_fingerprint_sha256")
            or ""
        ).strip()

        if not resolved_public_key_fingerprint:
            resolved_public_key_fingerprint = cls._public_key_fingerprint_sha256_from_pem(
                str(spki.get("subject_public_key") or "")
            )

        na_value = "<Not Part Of Certificate>"
        return {
            "issued_to": {
                "common_name": resolved_subject_cn or na_value,
                "organization": resolved_subject_o or na_value,
                "organizational_unit": resolved_subject_ou or na_value,
            },
            "issued_by": {
                "common_name": resolved_issuer_cn or na_value,
                "organization": resolved_issuer_o or na_value,
                "organizational_unit": resolved_issuer_ou or na_value,
            },
            "validity_period": {
                "issued_on": resolved_valid_from or "-",
                "expires_on": resolved_valid_until or "-",
            },
            "sha256_fingerprints": {
                "certificate": resolved_cert_fingerprint or "-",
                "public_key": resolved_public_key_fingerprint or "-",
            },
        }

    @staticmethod
    def _table_exists(table_name: str) -> bool:
        try:
            bind = db_session.get_bind()
            if bind is None:
                return False
            has_table_result = inspect(bind).has_table(table_name)
            return has_table_result is True
        except Exception:
            return False

    @staticmethod
    def _safe_json_dict(value: Any) -> Dict[str, Any]:
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                return {}
            try:
                parsed = json.loads(raw)
                return parsed if isinstance(parsed, dict) else {}
            except Exception:
                return {}
        return {}

    @staticmethod
    def _certificate_details_from_cert_row(cert: Certificate) -> Dict[str, Any]:
        return {
            "certificate_version": "",
            "serial_number": str(getattr(cert, "serial", "") or ""),
            "certificate_signature_algorithm": str(getattr(cert, "signature_algorithm", "") or ""),
            "certificate_signature": "",
            "issuer": str(getattr(cert, "issuer", "") or getattr(cert, "ca", "") or ""),
            "validity": {
                "not_before": getattr(cert, "valid_from", None).isoformat() if getattr(cert, "valid_from", None) else "",
                "not_after": getattr(cert, "valid_until", None).isoformat() if getattr(cert, "valid_until", None) else "",
            },
            "subject": str(getattr(cert, "subject", "") or getattr(cert, "subject_cn", "") or ""),
            "subject_public_key_info": {
                "subject_public_key_algorithm": str(getattr(cert, "public_key_type", "") or getattr(cert, "key_algorithm", "") or ""),
                "subject_public_key_bits": int(getattr(cert, "key_length", 0) or 0),
                "subject_public_key": str(getattr(cert, "public_key_pem", "") or ""),
            },
            "fingerprint_sha256": str(getattr(cert, "fingerprint_sha256", "") or ""),
            "certificate_format": "X.509",
            "extensions": [],
            "certificate_key_usage": [],
            "extended_key_usage": [],
            "certificate_basic_constraints": {},
            "certificate_subject_key_id": "",
            "certificate_authority_key_id": "",
            "authority_information_access": [],
            "certificate_subject_alternative_name": [],
            "certificate_policies": [],
            "crl_distribution_points": [],
            "signed_certificate_timestamp_list": [],
        }

    @staticmethod
    def _find_report_certificate_row(scan: Scan, cert: Certificate) -> Dict[str, Any]:
        return CbomService._find_report_tls_row(
            scan=scan,
            serial=str(getattr(cert, "serial", "") or ""),
            subject_cn=str(getattr(cert, "subject_cn", "") or ""),
            endpoint=str(getattr(cert, "endpoint", "") or ""),
            issuer=str(getattr(cert, "issuer", "") or getattr(cert, "ca", "") or ""),
        )

    @staticmethod
    def _find_report_tls_row(
        scan: Scan,
        serial: str = "",
        subject_cn: str = "",
        endpoint: str = "",
        issuer: str = "",
    ) -> Dict[str, Any]:
        report = CbomService._safe_json_dict(getattr(scan, "report_json", None))
        raw_tls_rows = report.get("tls_results")
        tls_rows = raw_tls_rows if isinstance(raw_tls_rows, list) else []

        serial = str(serial or "").strip().upper()
        subject_cn = str(subject_cn or "").strip().lower()
        endpoint = str(endpoint or "").strip().lower()
        issuer = str(issuer or "").strip().lower()

        for row in tls_rows:
            if not isinstance(row, dict):
                continue
            row_serial = str(row.get("serial_number") or "").strip().upper()
            row_subject_cn = str(row.get("subject_cn") or "").strip().lower()
            row_issuer = str(row.get("issuer") or "").strip().lower()
            row_host = str(row.get("host") or "").strip().lower()
            row_port = int(row.get("port") or 0) if str(row.get("port") or "").strip() else 0
            row_endpoint = f"{row_host}:{row_port}" if row_host and row_port else row_host

            if serial and row_serial and serial == row_serial:
                return dict(row)
            if subject_cn and issuer and row_subject_cn and row_issuer and subject_cn == row_subject_cn and issuer == row_issuer:
                return dict(row)
            if subject_cn and row_subject_cn and subject_cn == row_subject_cn:
                return dict(row)
            if endpoint and row_endpoint and endpoint == row_endpoint:
                return dict(row)
            if endpoint and row_host and endpoint == row_host:
                return dict(row)
            if endpoint and row_endpoint and endpoint.startswith(row_endpoint):
                return dict(row)

        return {}

    @staticmethod
    def _build_scan_filters(start_date: Optional[str] = None, end_date: Optional[str] = None) -> List[Any]:
        filters = [
            Asset.is_deleted == False,
            Scan.is_deleted == False,
            Scan.status == "complete",
        ]
        scan_time_expr = func.coalesce(Scan.scanned_at, Scan.completed_at, Scan.started_at)
        if start_date:
            try:
                filters.append(scan_time_expr >= datetime.fromisoformat(start_date))
            except ValueError:
                pass
        if end_date:
            try:
                filters.append(scan_time_expr <= datetime.fromisoformat(end_date))
            except ValueError:
                pass
        return filters

    @staticmethod
    def _build_cert_filters(
        asset_id: Optional[int] = None,
        current_only: bool = False,
    ) -> List[Any]:
        """Build base filters for certificate queries.

        Args:
            asset_id: Filter to a single asset if provided.
            current_only: If True, only include certificates with is_current=True.
                          Use this for the CBOM "current state" view. Leave False
                          for historical / all-scans views.
        """
        filters = [
            Asset.is_deleted == False,
            Scan.is_deleted == False,
            Scan.status == "complete",
            Certificate.is_deleted == False,
        ]
        # Bug fix: removed Scan.add_to_inventory == True filter.
        # Many scans never have this flag set, causing zero records in dashboard.
        # We rely on status == 'complete' as the promotion gate instead.
        if asset_id is not None:
            filters.append(Certificate.asset_id == asset_id)
        if current_only:
            filters.append(Certificate.is_current == True)
        return filters

    @staticmethod
    def _compute_cert_status(cert_row: Any) -> str:
        """Compute human-readable cert status from a Certificate ORM row."""
        now = datetime.now()
        valid_until = getattr(cert_row, "valid_until", None)
        is_expired = getattr(cert_row, "is_expired", False)
        expiry_days = getattr(cert_row, "expiry_days", None)
        is_self_signed = getattr(cert_row, "is_self_signed", False)

        # Use explicit flag first; then fall back to date comparison
        if is_expired:
            return "Expired"
        # If expiry_days is available, use it (avoids timezone drift from now())
        if expiry_days is not None:
            if expiry_days < 0:
                return "Expired"
            if expiry_days <= 30:
                return "Expiring Soon"
        elif valid_until and valid_until < now:
            return "Expired"
        if is_self_signed:
            return "Self-Signed"
        return "Valid"

    @staticmethod
    def _build_applications_query(
        asset_id: Optional[int],
        start_date: Optional[str],
        end_date: Optional[str],
        search_term: str,
    ):
        scan_filters = CbomService._build_scan_filters(start_date, end_date)
        q = (
            db_session.query(Certificate, Asset, Scan)
            .join(Asset, Certificate.asset_id == Asset.id)
            .join(Scan, Certificate.scan_id == Scan.id)
            .filter(*scan_filters)
        )
        if asset_id is not None:
            q = q.filter(Asset.id == asset_id)
        search_term = (search_term or "").strip()
        if search_term:
            like = f"%{search_term}%"
            q = q.filter(
                Asset.target.ilike(like)
                | Certificate.ca.ilike(like)
                | Certificate.cipher_suite.ilike(like)
                | Certificate.tls_version.ilike(like)
            )
        return q

    @staticmethod
    def _build_cbom_entries_query(
        asset_id: Optional[int],
        start_date: Optional[str],
        end_date: Optional[str],
        search_term: str,
    ):
        q = (
            db_session.query(CBOMEntry, Asset, Scan)
            .join(Scan, CBOMEntry.scan_id == Scan.id)
            .outerjoin(Asset, CBOMEntry.asset_id == Asset.id)
            .filter(
                CBOMEntry.is_deleted == False,
                Scan.is_deleted == False,
                Scan.status == "complete",
                # Exclude CBOM entries linked to soft-deleted inventory assets.
                # Keep entries with no asset association (outerjoin) but drop ones
                # where Asset.is_deleted == True.
                or_(Asset.id == None, Asset.is_deleted == False),
            )
        )
        if asset_id is not None:
            q = q.filter(CBOMEntry.asset_id == asset_id)
        if start_date or end_date:
            scan_time_expr = func.coalesce(Scan.scanned_at, Scan.completed_at, Scan.started_at)
            if start_date:
                try:
                    q = q.filter(scan_time_expr >= datetime.fromisoformat(start_date))
                except ValueError:
                    pass
            if end_date:
                try:
                    q = q.filter(scan_time_expr <= datetime.fromisoformat(end_date))
                except ValueError:
                    pass
        search_term = (search_term or "").strip()
        if search_term:
            like = f"%{search_term}%"
            q = q.filter(
                CBOMEntry.algorithm_name.ilike(like)
                | CBOMEntry.asset_type.ilike(like)
                | CBOMEntry.element_name.ilike(like)
                | CBOMEntry.oid.ilike(like)
                | CBOMEntry.protocol_name.ilike(like)
                | CBOMEntry.subject_name.ilike(like)
                | CBOMEntry.issuer_name.ilike(like)
            )
        return q

    @classmethod
    def _build_minimum_elements_payload(
        cls,
        asset_id: Optional[int],
        start_date: Optional[str],
        end_date: Optional[str],
        search_term: str,
    ) -> Dict[str, Any]:
        entries_query = cls._build_cbom_entries_query(asset_id, start_date, end_date, search_term)
        total_entries_raw = entries_query.count()
        try:
            total_entries = int(total_entries_raw or 0)
        except (TypeError, ValueError):
            total_entries = 0

        rows_result = entries_query.order_by(CBOMEntry.id.desc()).limit(200).all()
        if isinstance(rows_result, list):
            rows = rows_result
        else:
            try:
                rows = list(rows_result)
            except TypeError:
                rows = []
        items = []
        for entry, asset, scan in rows:
            items.append(
                {
                    "id": int(getattr(entry, "id", 0) or 0),
                    "asset_id": int(getattr(entry, "asset_id", 0) or 0) if getattr(entry, "asset_id", None) else None,
                    "asset_name": str(getattr(asset, "target", "") or ""),
                    "scan_id": int(getattr(scan, "id", 0) or 0),
                    "asset_type": str(getattr(entry, "asset_type", "") or ""),
                    "element_name": str(getattr(entry, "element_name", "") or getattr(entry, "algorithm_name", "") or ""),
                    "oid": str(getattr(entry, "oid", "") or ""),
                    "primitive": str(getattr(entry, "primitive", "") or ""),
                    "mode": str(getattr(entry, "mode", "") or ""),
                    "protocol_version_name": str(getattr(entry, "protocol_version_name", "") or getattr(entry, "protocol_version", "") or ""),
                    "key_size": getattr(entry, "key_size", None) or getattr(entry, "key_length", None),
                    "subject_name": str(getattr(entry, "subject_name", "") or ""),
                    "issuer_name": str(getattr(entry, "issuer_name", "") or ""),
                    "not_valid_after": (
                        getattr(entry, "not_valid_after", None).isoformat()
                        if getattr(getattr(entry, "not_valid_after", None), "isoformat", None)
                        else None
                    ),
                }
            )

        distribution_rows = (
            db_session.query(CBOMEntry.asset_type, func.count(CBOMEntry.id))
            .join(Scan, CBOMEntry.scan_id == Scan.id)
            .outerjoin(Asset, CBOMEntry.asset_id == Asset.id)
            .filter(
                CBOMEntry.is_deleted == False,
                Scan.is_deleted == False,
                Scan.status == "complete",
                # Exclude entries linked to deleted inventory assets while keeping
                # entries that have no asset association (null asset_id).
                or_(Asset.id == None, Asset.is_deleted == False),
            )
        )
        if asset_id is not None:
            distribution_rows = distribution_rows.filter(CBOMEntry.asset_id == asset_id)
        if start_date or end_date:
            scan_time_expr = func.coalesce(Scan.scanned_at, Scan.completed_at, Scan.started_at)
            if start_date:
                try:
                    distribution_rows = distribution_rows.filter(scan_time_expr >= datetime.fromisoformat(start_date))
                except ValueError:
                    pass
            if end_date:
                try:
                    distribution_rows = distribution_rows.filter(scan_time_expr <= datetime.fromisoformat(end_date))
                except ValueError:
                    pass
        distribution_rows = distribution_rows.group_by(CBOMEntry.asset_type).all()
        asset_type_distribution = {
            str((k or "unknown")): int(v or 0)
            for k, v in distribution_rows
        }

        # ── Optimized field coverage ─────────────────────────────────────────────
        # Bug fix: replaced 24 separate per-field queries with a single aggregation
        # using CASE statements, reducing DB round-trips from 24 to 1.
        # Also removed Scan.add_to_inventory == True filter (see _build_cert_filters).
        field_coverage = {}
        if total_entries > 0:
            from sqlalchemy import case, literal
            coverage_query = (
                db_session.query(
                    *[
                        func.sum(
                            case(
                                (getattr(CBOMEntry, field_name).isnot(None), 1),
                                else_=0,
                            )
                        ).label(field_name)
                        for field_name in cls.MINIMUM_ELEMENT_FIELDS
                    ]
                )
                .join(Scan, CBOMEntry.scan_id == Scan.id)
                .outerjoin(Asset, CBOMEntry.asset_id == Asset.id)
                .filter(
                    CBOMEntry.is_deleted == False,
                    Scan.is_deleted == False,
                    Scan.status == "complete",
                    or_(Asset.id == None, Asset.is_deleted == False),
                )
            )
            if asset_id is not None:
                coverage_query = coverage_query.filter(CBOMEntry.asset_id == asset_id)
            if start_date or end_date:
                scan_time_expr = func.coalesce(Scan.scanned_at, Scan.completed_at, Scan.started_at)
                if start_date:
                    try:
                        coverage_query = coverage_query.filter(scan_time_expr >= datetime.fromisoformat(start_date))
                    except ValueError:
                        pass
                if end_date:
                    try:
                        coverage_query = coverage_query.filter(scan_time_expr <= datetime.fromisoformat(end_date))
                    except ValueError:
                        pass

            coverage_row = coverage_query.first()
            for field_name in cls.MINIMUM_ELEMENT_FIELDS:
                count_val = int(getattr(coverage_row, field_name, 0) or 0)
                pct = round((count_val / total_entries) * 100, 1)
                field_coverage[field_name] = {"count": count_val, "coverage_pct": pct}
        else:
            for field_name in cls.MINIMUM_ELEMENT_FIELDS:
                field_coverage[field_name] = {"count": 0, "coverage_pct": 0.0}

        covered_fields = sum(
            1
            for field_name in cls.MINIMUM_ELEMENT_FIELDS
            if int((field_coverage.get(field_name) or {}).get("count", 0) or 0) > 0
        )

        return {
            "total_entries": int(total_entries),
            "asset_type_distribution": asset_type_distribution,
            "field_coverage": field_coverage,
            "field_definitions": {
                field_name: {
                    "description": cls.PNB_MINIMUM_ELEMENT_DEFINITIONS.get(field_name, ""),
                    "required": True,
                }
                for field_name in cls.MINIMUM_ELEMENT_FIELDS
            },
            "coverage_summary": {
                "required_fields": len(cls.MINIMUM_ELEMENT_FIELDS),
                "covered_fields": int(covered_fields),
                "coverage_pct": round((covered_fields / len(cls.MINIMUM_ELEMENT_FIELDS)) * 100, 1)
                if cls.MINIMUM_ELEMENT_FIELDS
                else 0.0,
            },
            "items": items,
        }

    @classmethod
    def get_cbom_dashboard_data(
        cls,
        asset_id: Optional[int] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        limit: int = 200,
        page: int = 1,
        page_size: int = 100,
        sort_field: str = "asset_name",
        sort_order: str = "asc",
        search_term: str = "",
    ) -> Dict[str, Any]:
        scan_filters = cls._build_scan_filters(start_date, end_date)
        cert_filters = cls._build_cert_filters(asset_id)

        scan_query = (
            db_session.query(Scan, Asset)
            .join(Asset, func.lower(Asset.target) == func.lower(Scan.target))
            .filter(*scan_filters)
        )
        cert_query = (
            db_session.query(Certificate)
            .join(Asset, Certificate.asset_id == Asset.id)
            .join(Scan, Certificate.scan_id == Scan.id)
            .filter(*cert_filters)
        )

        discovery_ssl_query = None
        if cls._table_exists("discovery_ssl"):
            discovery_ssl_query = (
                db_session.query(DiscoverySSL, Asset, Scan)
                .join(Scan, DiscoverySSL.scan_id == Scan.id)
                .outerjoin(Asset, DiscoverySSL.asset_id == Asset.id)
                .filter(
                    DiscoverySSL.is_deleted == False,
                    Scan.is_deleted == False,
                    Scan.status == "complete",
                    # Exclude discovery rows attached to deleted assets.
                    or_(Asset.id == None, Asset.is_deleted == False),
                )
            )
            if asset_id is not None:
                discovery_ssl_query = discovery_ssl_query.filter(DiscoverySSL.asset_id == asset_id)
            if start_date or end_date:
                scan_time_expr = func.coalesce(Scan.scanned_at, Scan.completed_at, Scan.started_at)
                if start_date:
                    try:
                        discovery_ssl_query = discovery_ssl_query.filter(scan_time_expr >= datetime.fromisoformat(start_date))
                    except ValueError:
                        pass
                if end_date:
                    try:
                        discovery_ssl_query = discovery_ssl_query.filter(scan_time_expr <= datetime.fromisoformat(end_date))
                    except ValueError:
                        pass
            search_term_normalized = (search_term or "").strip()
            if search_term_normalized:
                like = f"%{search_term_normalized}%"
                discovery_ssl_query = discovery_ssl_query.filter(
                    func.coalesce(DiscoverySSL.endpoint, "").ilike(like)
                    | func.coalesce(DiscoverySSL.issuer, "").ilike(like)
                    | func.coalesce(DiscoverySSL.cipher_suite, "").ilike(like)
                    | func.coalesce(DiscoverySSL.subject_cn, "").ilike(like)
                    | func.coalesce(Asset.target, "").ilike(like)
                )

        now = datetime.now()

        scan_count = scan_query.count()
        total_applications = cert_query.with_entities(func.count(distinct(Certificate.asset_id))).scalar() or 0

        cert_count = cert_query.count()

        discovery_ssl_rows = []
        discovery_ssl_count = 0
        if discovery_ssl_query is not None:
            discovery_ssl_rows = discovery_ssl_query.all()
            discovery_ssl_count = len(discovery_ssl_rows)

        active_certificates = cert_query.filter(Certificate.valid_until != None, Certificate.valid_until >= now).count()
        weak_tls_count = cert_query.filter(Certificate.tls_version.in_(cls.WEAK_TLS_VERSIONS)).count()
        weak_key_count = cert_query.filter(Certificate.key_length != None, Certificate.key_length < 2048).count()
        expired_count = cert_query.filter(Certificate.valid_until != None, Certificate.valid_until < now).count()
        self_signed_count = cert_query.filter(Certificate.issuer != None, Certificate.subject != None, Certificate.issuer == Certificate.subject).count()

        if discovery_ssl_rows:
            for dssl, _asset, _scan in discovery_ssl_rows:
                valid_until = getattr(dssl, "valid_until", None)
                if valid_until is not None and valid_until >= now:
                    active_certificates += 1
                tls_version = str(getattr(dssl, "tls_version", "") or "")
                if tls_version in cls.WEAK_TLS_VERSIONS:
                    weak_tls_count += 1
                key_length = getattr(dssl, "key_length", None)
                if key_length is not None:
                    try:
                        if int(key_length) < 2048:
                            weak_key_count += 1
                    except (TypeError, ValueError):
                        pass
                if valid_until is not None and valid_until < now:
                    expired_count += 1
                issuer = str(getattr(dssl, "issuer", "") or "").strip().lower()
                subject_cn = str(getattr(dssl, "subject_cn", "") or "").strip().lower()
                if issuer and subject_cn and issuer == subject_cn:
                    self_signed_count += 1

        cbom_entry_issue_count = (
            db_session.query(func.count(CBOMEntry.id))
            .join(Scan, CBOMEntry.scan_id == Scan.id)
            .join(Asset, func.lower(Asset.target) == func.lower(Scan.target))
            .filter(Asset.is_deleted == False, Scan.is_deleted == False, Scan.status == "complete", CBOMEntry.quantum_safe_flag == False)
        )
        if asset_id is not None:
            cbom_entry_issue_count = cbom_entry_issue_count.filter(Asset.id == asset_id)
        if start_date or end_date:
            for f in cls._build_scan_filters(start_date, end_date):
                cbom_entry_issue_count = cbom_entry_issue_count.filter(f)
        cbom_entry_issue_count = cbom_entry_issue_count.scalar() or 0

        cbom_summary_issue_sum = (
            db_session.query(func.sum(CBOMSummary.cert_issues_count))
            .join(Scan, CBOMSummary.scan_id == Scan.id)
            .join(Asset, func.lower(Asset.target) == func.lower(Scan.target))
            .filter(Asset.is_deleted == False, Scan.is_deleted == False, Scan.status == "complete")
        )
        if asset_id is not None:
            cbom_summary_issue_sum = cbom_summary_issue_sum.filter(Asset.id == asset_id)
        if start_date or end_date:
            for f in cls._build_scan_filters(start_date, end_date):
                cbom_summary_issue_sum = cbom_summary_issue_sum.filter(f)
        cbom_summary_issue_sum = int(cbom_summary_issue_sum.scalar() or 0)

        weak_cryptography_total = weak_tls_count + weak_key_count + expired_count + self_signed_count
        cbom_issue_total = cbom_entry_issue_count + cbom_summary_issue_sum
        certificate_issues = max(weak_cryptography_total, cbom_issue_total)

        site_count = cert_query.with_entities(func.count(distinct(Certificate.asset_id))).scalar() or 0

        # Distributions
        # Bug fix: Added .order_by(Certificate.key_length.asc()) so chart displays
        # in ascending numeric order (512, 1024, 2048, 4096) instead of arbitrary DB order.
        key_length_dist = {
            str(int(k)) if k is not None else "Unknown": v
            for k, v in db_session.query(Certificate.key_length, func.count(Certificate.id))
            .join(Asset, Certificate.asset_id == Asset.id)
            .join(Scan, Certificate.scan_id == Scan.id)
            .filter(*cert_filters)
            .group_by(Certificate.key_length)
            .order_by(Certificate.key_length.asc())  # Bug fix: was unordered
            .all()
        }
        if not key_length_dist:
            key_length_dist = {"No Data": 0}

        cipher_dist = {
            str(k or "Unknown")[:40]: v
            for k, v in db_session.query(Certificate.cipher_suite, func.count(Certificate.id))
            .join(Asset, Certificate.asset_id == Asset.id)
            .join(Scan, Certificate.scan_id == Scan.id)
            .filter(*cert_filters)
            .group_by(Certificate.cipher_suite)
            .order_by(func.count(Certificate.id).desc())
            .limit(10)
            .all()
        }
        if not cipher_dist:
            cipher_dist = {"No Data": 0}

        ca_dist = {
            str(k or "Unknown")[:40]: v
            for k, v in db_session.query(Certificate.ca, func.count(Certificate.id))
            .join(Asset, Certificate.asset_id == Asset.id)
            .join(Scan, Certificate.scan_id == Scan.id)
            .filter(*cert_filters)
            .group_by(Certificate.ca)
            .order_by(func.count(Certificate.id).desc())
            .limit(10)
            .all()
        }
        if not ca_dist:
            ca_dist = {"No Data": 0}

        tls_dist = {
            str(k or "Unknown"): v
            for k, v in db_session.query(Certificate.tls_version, func.count(Certificate.id))
            .join(Asset, Certificate.asset_id == Asset.id)
            .join(Scan, Certificate.scan_id == Scan.id)
            .filter(*cert_filters)
            .group_by(Certificate.tls_version)
            .order_by(func.count(Certificate.id).desc())
            .limit(10)
            .all()
        }
        if not tls_dist:
            tls_dist = {"No Data": 0}

        if discovery_ssl_rows:
            discovery_asset_ids = {
                int(getattr(dssl, "asset_id", 0) or 0)
                for dssl, _asset, _scan in discovery_ssl_rows
                if getattr(dssl, "asset_id", None) is not None
            }
            if discovery_asset_ids:
                site_count = max(int(site_count or 0), len(discovery_asset_ids))

            for dssl, _asset, _scan in discovery_ssl_rows:
                key_len_val = getattr(dssl, "key_length", None)
                key_bucket = "Unknown"
                try:
                    if key_len_val is not None:
                        key_bucket = str(int(key_len_val))
                except (TypeError, ValueError):
                    key_bucket = "Unknown"
                key_length_dist[key_bucket] = int(key_length_dist.get(key_bucket, 0) or 0) + 1

                cipher_key = str(getattr(dssl, "cipher_suite", "") or "Unknown")[:40]
                cipher_dist[cipher_key] = int(cipher_dist.get(cipher_key, 0) or 0) + 1

                issuer_key = str(getattr(dssl, "issuer", "") or "Unknown")[:40]
                ca_dist[issuer_key] = int(ca_dist.get(issuer_key, 0) or 0) + 1

                tls_key = str(getattr(dssl, "tls_version", "") or "Unknown")
                tls_dist[tls_key] = int(tls_dist.get(tls_key, 0) or 0) + 1

            # Keep top lists bounded and ordered for chart payloads
            cipher_dist = dict(sorted(cipher_dist.items(), key=lambda kv: int(kv[1] or 0), reverse=True)[:10])
            ca_dist = dict(sorted(ca_dist.items(), key=lambda kv: int(kv[1] or 0), reverse=True)[:10])

        app_query = cls._build_applications_query(
            asset_id=asset_id,
            start_date=start_date,
            end_date=end_date,
            search_term=search_term,
        )

        sort_field = (sort_field or "asset_name").strip().lower()
        sort_order = (sort_order or "asc").strip().lower()
        sort_map = {
            "asset_name": Asset.target,
            "asset_id": Asset.target,
            "key_length": Certificate.key_length,
            "cipher_suite": Certificate.cipher_suite,
            "ca": Certificate.ca,
            "tls_version": Certificate.tls_version,
            "valid_until": Certificate.valid_until,
            "last_scan": func.coalesce(Scan.scanned_at, Scan.completed_at, Scan.started_at),
        }
        sort_col = sort_map.get(sort_field, Asset.target)
        app_query = app_query.order_by(desc(sort_col) if sort_order == "desc" else asc(sort_col))

        page = max(1, int(page or 1))
        page_size = max(1, min(int(page_size or 100), 250))
        total_count = app_query.count()
        total_pages = max(1, (total_count + page_size - 1) // page_size)
        if page > total_pages:
            page = total_pages
        offset = (page - 1) * page_size

        rows_result = app_query.offset(offset).limit(page_size).all()
        if isinstance(rows_result, list):
            rows = rows_result
        else:
            try:
                rows = list(rows_result)
            except TypeError:
                rows = []
        applications = []
        for cert, asset, scan in rows:
            valid_from = getattr(cert, "valid_from", None)
            valid_until = getattr(cert, "valid_until", None)
            cert_record_id = int(getattr(cert, "id", 0) or 0)
            cert_source = "certificate"
            certificate_details = cls._certificate_details_from_cert_row(cert)
            report_row = cls._find_report_certificate_row(scan, cert)
            report_certificate_details = report_row.get("certificate_details") if isinstance(report_row.get("certificate_details"), dict) else {}
            if report_certificate_details:
                certificate_details = {
                    **certificate_details,
                    **report_certificate_details,
                }
            validity = certificate_details.get("validity") if isinstance(certificate_details.get("validity"), dict) else {}
            cert_valid_until = valid_until.isoformat() if hasattr(valid_until, "isoformat") and valid_until else None
            if not cert_valid_until:
                cert_valid_until = str(report_row.get("valid_to") or "").strip() or str(validity.get("not_after") or "").strip() or None

            cert_fingerprint = str(getattr(cert, "fingerprint_sha256", "") or "").strip()
            if not cert_fingerprint:
                cert_fingerprint = str(report_row.get("cert_sha256") or "").strip() or str(certificate_details.get("fingerprint_sha256") or "").strip()

            cert_spki = certificate_details.get("subject_public_key_info") if isinstance(certificate_details.get("subject_public_key_info"), dict) else {}
            public_key_fingerprint = str(cert_spki.get("public_key_fingerprint_sha256") or "").strip()
            if not public_key_fingerprint:
                public_key_fingerprint = cls._public_key_fingerprint_sha256_from_pem(str(getattr(cert, "public_key_pem", "") or ""))
            if not public_key_fingerprint:
                public_key_fingerprint = cls._public_key_fingerprint_sha256_from_pem(str(cert_spki.get("subject_public_key") or ""))

            certificate_details = {
                **certificate_details,
                "fingerprint_sha256": cert_fingerprint,
                "certificate_format": str(certificate_details.get("certificate_format") or "X.509"),
                "subject_public_key_info": {
                    **cert_spki,
                    "public_key_fingerprint_sha256": public_key_fingerprint,
                },
            }

            x509_minimum = cls._build_x509_minimum_payload(
                certificate_details=certificate_details,
                subject_cn=str(getattr(cert, "subject_cn", "") or ""),
                subject_o=str(getattr(cert, "subject_o", "") or ""),
                subject_ou=str(getattr(cert, "subject_ou", "") or ""),
                issuer_cn=str(getattr(cert, "issuer_cn", "") or ""),
                issuer_o=str(getattr(cert, "issuer_o", "") or ""),
                issuer_ou=str(getattr(cert, "issuer_ou", "") or ""),
                valid_from=valid_from.isoformat() if hasattr(valid_from, "isoformat") and valid_from else "",
                valid_until=cert_valid_until or "",
                cert_fingerprint_sha256=cert_fingerprint,
                public_key_fingerprint_sha256=public_key_fingerprint,
            )
            row_key = f"{cert_source}:{cert_record_id}" if cert_record_id > 0 else "|".join([
                cert_source,
                str(int(getattr(asset, "id", 0) or 0)),
                str(getattr(cert, "endpoint", "") or "").strip().lower(),
                str(getattr(cert, "serial", "") or "").strip().lower(),
            ])

            applications.append(
                {
                    "source": cert_source,
                    "record_id": cert_record_id,
                    "row_key": row_key,
                    "asset_id": int(getattr(asset, "id", 0) or 0),
                    "asset_name": str(getattr(asset, "target", "") or "Unknown Asset"),
                    "endpoint": str(getattr(cert, "endpoint", "") or ""),
                    "serial": str(getattr(cert, "serial", "") or ""),
                    "key_length": int(getattr(cert, "key_length", 0) or 0),
                    "public_key_type": str(getattr(cert, "public_key_type", "") or getattr(cert, "key_algorithm", "") or "Unknown"),
                    "public_key_pem": str(getattr(cert, "public_key_pem", "") or ""),
                    "cipher_suite": str(getattr(cert, "cipher_suite", "") or "Unknown"),
                    "ca": str(getattr(cert, "ca", "") or getattr(cert, "issuer", "") or "Unknown"),
                    "tls_version": str(getattr(cert, "tls_version", "") or "Unknown"),
                    "subject_cn": str(getattr(cert, "subject_cn", "") or ""),
                    "subject_o": str(getattr(cert, "subject_o", "") or ""),
                    "subject_ou": str(getattr(cert, "subject_ou", "") or ""),
                    "issuer_cn": str(getattr(cert, "issuer_cn", "") or ""),
                    "issuer_o": str(getattr(cert, "issuer_o", "") or ""),
                    "issuer_ou": str(getattr(cert, "issuer_ou", "") or ""),
                    "valid_from": valid_from.isoformat() if hasattr(valid_from, "isoformat") and valid_from else None,
                    "valid_until": cert_valid_until,
                    "fingerprint_sha256": cert_fingerprint,
                    # Bug fix: was hardcoded to "Valid"; now computed from actual DB state
                    "cert_status": cls._compute_cert_status(cert),
                    "is_current": bool(getattr(cert, "is_current", False)),
                    "first_seen_at": (
                        getattr(cert, "first_seen_at", None).isoformat()
                        if getattr(cert, "first_seen_at", None) else None
                    ),
                    "last_seen_at": (
                        getattr(cert, "last_seen_at", None).isoformat()
                        if getattr(cert, "last_seen_at", None) else None
                    ),
                    "certificate_details": certificate_details,
                    "x509_minimum": x509_minimum,
                    "last_scan": (
                        getattr(scan, "scanned_at", None)
                        or getattr(scan, "completed_at", None)
                        or getattr(scan, "started_at", None)
                    ),
                }
            )

        existing_row_keys = {
            (
                int(app.get("asset_id") or 0),
                str(app.get("endpoint") or "").strip().lower(),
                str(app.get("tls_version") or "").strip().lower(),
                str(app.get("cipher_suite") or "").strip().lower(),
                str(app.get("subject_cn") or "").strip().lower(),
                str(app.get("issuer") or app.get("ca") or "").strip().lower(),
                int(app.get("key_length") or 0),
            )
            for app in applications
        }

        if discovery_ssl_rows:
            for dssl, asset, scan in discovery_ssl_rows:
                asset_id_value = int(getattr(dssl, "asset_id", 0) or 0)
                endpoint_value = str(getattr(dssl, "endpoint", "") or "").strip()
                tls_value = str(getattr(dssl, "tls_version", "") or "Unknown")
                cipher_value = str(getattr(dssl, "cipher_suite", "") or "Unknown")
                subject_cn_value = str(getattr(dssl, "subject_cn", "") or "")
                issuer_value = str(getattr(dssl, "issuer", "") or "")
                key_len_value = int(getattr(dssl, "key_length", 0) or 0)
                report_row = cls._find_report_tls_row(
                    scan=scan,
                    subject_cn=subject_cn_value,
                    endpoint=endpoint_value,
                    issuer=issuer_value,
                )
                report_certificate_details = report_row.get("certificate_details") if isinstance(report_row.get("certificate_details"), dict) else {}

                dedupe_key = (
                    asset_id_value,
                    endpoint_value.lower(),
                    tls_value.lower(),
                    cipher_value.lower(),
                    subject_cn_value.lower(),
                    issuer_value.lower(),
                    key_len_value,
                )
                if dedupe_key in existing_row_keys:
                    continue
                existing_row_keys.add(dedupe_key)

                derived_asset_name = str(getattr(asset, "target", "") or "").strip()
                if not derived_asset_name:
                    derived_asset_name = endpoint_value or "Unknown Asset"

                valid_until = getattr(dssl, "valid_until", None)
                valid_from = None
                resolved_valid_until = valid_until.isoformat() if hasattr(valid_until, "isoformat") and valid_until else None
                if not resolved_valid_until:
                    resolved_valid_until = (
                        str(report_row.get("valid_to") or "").strip()
                        or str((report_certificate_details.get("validity") or {}).get("not_after") or "").strip()
                        or None
                    )
                resolved_fingerprint = (
                    str(report_row.get("cert_sha256") or "").strip()
                    or str(report_certificate_details.get("fingerprint_sha256") or "").strip()
                    or str(report_certificate_details.get("fingerprint") or "").strip()
                )
                resolved_cert_status = str(report_row.get("cert_status") or "").strip() or "Valid"
                discovery_record_id = int(getattr(dssl, "id", 0) or 0)
                discovery_source = "discovery_ssl"
                row_key = f"{discovery_source}:{discovery_record_id}" if discovery_record_id > 0 else "|".join([
                    discovery_source,
                    str(asset_id_value),
                    endpoint_value.lower(),
                    subject_cn_value.lower(),
                    str(resolved_fingerprint or "").lower(),
                ])

                default_certificate_details = {
                    "certificate_version": "",
                    "serial_number": str(report_row.get("serial_number") or ""),
                    "certificate_signature_algorithm": str(report_row.get("signature_algorithm") or ""),
                    "certificate_signature": "",
                    "issuer": issuer_value,
                    "validity": {
                        "not_before": str(report_row.get("valid_from") or ""),
                        "not_after": resolved_valid_until or "",
                    },
                    "subject": subject_cn_value,
                    "subject_public_key_info": {
                        "subject_public_key_algorithm": str(report_row.get("public_key_type") or ""),
                        "subject_public_key_bits": key_len_value,
                        "subject_public_key": "",
                    },
                    "extensions": [],
                    "certificate_key_usage": [],
                    "extended_key_usage": [],
                    "certificate_basic_constraints": {},
                    "certificate_subject_key_id": "",
                    "certificate_authority_key_id": "",
                    "authority_information_access": [],
                    "certificate_subject_alternative_name": [],
                    "certificate_policies": [],
                    "crl_distribution_points": [],
                    "signed_certificate_timestamp_list": [],
                    "fingerprint_sha256": resolved_fingerprint,
                    "certificate_format": str(report_certificate_details.get("certificate_format") or "X.509"),
                }
                merged_certificate_details = {
                    **default_certificate_details,
                    **report_certificate_details,
                }
                merged_spki = merged_certificate_details.get("subject_public_key_info") if isinstance(merged_certificate_details.get("subject_public_key_info"), dict) else {}
                resolved_public_key_fingerprint = str(merged_spki.get("public_key_fingerprint_sha256") or "").strip()
                if not resolved_public_key_fingerprint:
                    resolved_public_key_fingerprint = cls._public_key_fingerprint_sha256_from_pem(str(merged_spki.get("subject_public_key") or ""))

                merged_certificate_details = {
                    **merged_certificate_details,
                    "fingerprint_sha256": resolved_fingerprint,
                    "certificate_format": str(merged_certificate_details.get("certificate_format") or "X.509"),
                    "subject_public_key_info": {
                        **merged_spki,
                        "public_key_fingerprint_sha256": resolved_public_key_fingerprint,
                    },
                }

                x509_minimum = cls._build_x509_minimum_payload(
                    certificate_details=merged_certificate_details,
                    subject_cn=subject_cn_value,
                    subject_o="",
                    subject_ou="",
                    issuer_cn="",
                    issuer_o=issuer_value,
                    issuer_ou="",
                    valid_from="",
                    valid_until=resolved_valid_until or "",
                    cert_fingerprint_sha256=resolved_fingerprint,
                    public_key_fingerprint_sha256=resolved_public_key_fingerprint,
                )

                applications.append(
                    {
                        "source": discovery_source,
                        "record_id": discovery_record_id,
                        "row_key": row_key,
                        "asset_id": asset_id_value,
                        "asset_name": derived_asset_name,
                        "endpoint": endpoint_value,
                        "serial": "",
                        "key_length": key_len_value,
                        "public_key_type": "Unknown",
                        "public_key_pem": "",
                        "cipher_suite": cipher_value,
                        "ca": issuer_value or "Unknown",
                        "tls_version": tls_value,
                        "subject_cn": subject_cn_value,
                        "subject_o": "",
                        "subject_ou": "",
                        "issuer_cn": "",
                        "issuer_o": "",
                        "issuer_ou": "",
                        "valid_from": valid_from.isoformat() if hasattr(valid_from, "isoformat") and valid_from else None,
                        "valid_until": resolved_valid_until,
                        "fingerprint_sha256": resolved_fingerprint,
                        "cert_status": resolved_cert_status,
                        "certificate_details": merged_certificate_details,
                        "x509_minimum": x509_minimum,
                        "last_scan": (
                            getattr(scan, "scanned_at", None)
                            or getattr(scan, "completed_at", None)
                            or getattr(scan, "started_at", None)
                        ),
                    }
                )

        total_applications = len({int(app.get("asset_id") or 0) for app in applications if int(app.get("asset_id") or 0) > 0})
        if total_applications <= 0:
            total_applications = int(cert_query.with_entities(func.count(distinct(Certificate.asset_id))).scalar() or 0)

        if limit:
            applications = applications[: max(1, int(limit))]

        weakness_heatmap = [
            {"x": "Transport", "y": "Weak TLS", "value": weak_tls_count},
            {"x": "Transport", "y": "Weak Keys", "value": weak_key_count},
            {"x": "Lifecycle", "y": "Expired", "value": expired_count},
            {"x": "Identity", "y": "Self-Signed", "value": self_signed_count},
            {"x": "CBOM", "y": "Entry Issues", "value": cbom_entry_issue_count},
            {"x": "CBOM", "y": "Summary Issues", "value": cbom_summary_issue_sum},
        ]

        return {
            "kpis": {
                "total_applications": total_applications,
                "sites_surveyed": site_count,
                "active_certificates": active_certificates,
                "weak_cryptography": weak_cryptography_total,
                "certificate_issues": certificate_issues,
            },
            "key_length_distribution": key_length_dist,
            "cipher_usage": cipher_dist,
            "cipher_suite_usage": cipher_dist,
            "top_cas": ca_dist,
            "ca_distribution": ca_dist,
            "protocols": tls_dist,
            "protocol_distribution": tls_dist,
            "weakness_heatmap": weakness_heatmap,
            "applications": applications,
            "page_data": {
                "items": applications,
                "total_count": total_count,
                "page": page,
                "page_size": page_size,
                "total_pages": total_pages,
                "has_next": page < total_pages,
                "has_prev": page > 1,
            },
            "minimum_elements": cls._build_minimum_elements_payload(
                asset_id=asset_id,
                start_date=start_date,
                end_date=end_date,
                search_term=search_term,
            ),
            "meta": {
                "scan_count": scan_count,
                "certificate_count": cert_count + discovery_ssl_count,
                "certificate_inventory_count": cert_count,
                "discovery_ssl_count": discovery_ssl_count,
            },
        }
