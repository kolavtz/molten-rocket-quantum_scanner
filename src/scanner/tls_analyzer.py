"""
TLS Analyzer Module

Performs deep TLS handshake analysis against a target endpoint, extracting
cipher suites, protocol versions, key exchange mechanisms, certificate
details, and the full certificate chain.

Classes:
    TLSAnalyzer — extracts comprehensive TLS configuration from an endpoint.
"""

from __future__ import annotations

import socket
import ssl
import datetime
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

try:
    from sslyze import Scanner, ServerNetworkLocation
    HAS_SSLYZE = True
except ImportError:
    HAS_SSLYZE = False

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from config import HANDSHAKE_TIMEOUT_SECONDS, CIPHER_KEX_PATTERNS


# ── Data classes ──────────────────────────────────────────────────────

@dataclass
class CertificateInfo:
    """Parsed X.509 certificate fields."""

    subject: Dict[str, str] = field(default_factory=dict)
    issuer: Dict[str, str] = field(default_factory=dict)

    # Explicit expansions for easier template rendering
    subject_cn: str = ""
    subject_o: str = ""
    subject_ou: str = ""
    issuer_cn: str = ""
    issuer_o: str = ""
    issuer_ou: str = ""

    serial_number: str = ""
    not_before: str = ""
    not_after: str = ""
    signature_algorithm: str = ""
    public_key_type: str = ""
    public_key_bits: int = 0
    public_key_pem: str = ""
    san_domains: List[str] = field(default_factory=list)
    is_expired: bool = False
    days_until_expiry: int = 0
    fingerprint_sha256: str = ""
    certificate_details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "subject_cn": self.subject_cn,
            "subject_o": self.subject_o,
            "subject_ou": self.subject_ou,
            "issuer_cn": self.issuer_cn,
            "issuer_o": self.issuer_o,
            "issuer_ou": self.issuer_ou,
            "serial_number": self.serial_number,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "signature_algorithm": self.signature_algorithm,
            "public_key_type": self.public_key_type,
            "public_key_bits": self.public_key_bits,
            "public_key_pem": self.public_key_pem,
            "san_domains": self.san_domains,
            "is_expired": self.is_expired,
            "days_until_expiry": self.days_until_expiry,
            "fingerprint_sha256": self.fingerprint_sha256,
            "certificate_details": self.certificate_details,
        }


@dataclass
class TLSEndpointResult:
    """Full TLS analysis result for a single endpoint."""

    host: str
    port: int
    protocol_version: str = ""
    cipher_suite: str = ""
    cipher_bits: int = 0
    key_exchange: str = ""
    certificate: Optional[CertificateInfo] = None
    certificate_chain_length: int = 0
    supported_protocols: List[str] = field(default_factory=list)
    all_cipher_suites: List[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def is_successful(self) -> bool:
        return self.error is None and self.cipher_suite != ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "protocol_version": self.protocol_version,
            "cipher_suite": self.cipher_suite,
            "cipher_bits": self.cipher_bits,
            "key_exchange": self.key_exchange,
            "certificate": self.certificate.to_dict() if self.certificate else None,
            "certificate_chain_length": self.certificate_chain_length,
            "supported_protocols": self.supported_protocols,
            "all_cipher_suites": self.all_cipher_suites,
            "error": self.error,
        }


class TLSAnalyzer:
    """Extracts comprehensive TLS configuration from an endpoint.

    Usage::

        analyzer = TLSAnalyzer()
        result = analyzer.analyze_endpoint("google.com", 443)
        print(result.cipher_suite, result.key_exchange)
    """

    def __init__(self, timeout: float = HANDSHAKE_TIMEOUT_SECONDS) -> None:
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_endpoint(
        self, host: str, port: int = 443
    ) -> TLSEndpointResult:
        """Perform full TLS analysis on *host*:*port*.

        Returns
        -------
        TLSEndpointResult
            Contains cipher suite, protocol, key exchange, certificate
            info, and full chain length.
        """
        result = TLSEndpointResult(host=host, port=port)

        try:
            self._analyze_with_stdlib(result, host, port)
        except Exception as exc:
            result.error = f"stdlib analysis failed: {exc}"

        # Augment with SSLyze if available
        if HAS_SSLYZE and result.error is None:
            try:
                self._augment_with_sslyze(result, host, port)
            except Exception as exc:
                # Keep stdlib analysis as source of truth; SSLyze is best-effort enrichment.
                result.error = result.error or f"sslyze enrichment failed: {exc}"

        # Derive key exchange from cipher suite name
        if result.cipher_suite and not result.key_exchange:
            result.key_exchange = self._extract_key_exchange(
                result.cipher_suite
            )

        return result

    def get_supported_protocols(self, host: str, port: int = 443) -> List[str]:
        """Probe which TLS protocol versions the server supports."""
        supported: List[str] = []
        protocols_to_test = [
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
        ]
        for name, version in protocols_to_test:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = version
                ctx.maximum_version = version
                sock = socket.create_connection(
                    (host, port), timeout=self.timeout
                )
                tls_sock = ctx.wrap_socket(sock, server_hostname=host)
                tls_sock.close()
                supported.append(name)
            except Exception:
                pass
        return supported

    # ------------------------------------------------------------------
    # Private — stdlib ssl
    # ------------------------------------------------------------------

    def _analyze_with_stdlib(
        self, result: TLSEndpointResult, host: str, port: int
    ) -> None:
        """Populate *result* using Python's built-in ``ssl`` module."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        sock = socket.create_connection((host, port), timeout=self.timeout)
        tls_sock = ctx.wrap_socket(sock, server_hostname=host)

        # Cipher info
        cipher_info = tls_sock.cipher()  # (name, version, bits)
        if cipher_info:
            result.cipher_suite = cipher_info[0]
            result.protocol_version = cipher_info[1] or ""
            result.cipher_bits = cipher_info[2] or 0

        # Protocol
        version_str = tls_sock.version()
        if version_str:
            result.protocol_version = version_str

        # Certificate
        peer_cert = tls_sock.getpeercert(binary_form=False)
        peer_cert_der = tls_sock.getpeercert(binary_form=True)
        if peer_cert or peer_cert_der:
            result.certificate = self._parse_stdlib_cert(
                peer_cert or {}, peer_cert_der
            )

        # Supported protocols
        result.supported_protocols = self.get_supported_protocols(host, port)

        tls_sock.close()

    def _parse_stdlib_cert(
        self,
        cert_dict: Dict[str, Any],
        cert_der: Optional[bytes] = None,
    ) -> CertificateInfo:
        """Parse a certificate dict returned by ``ssl.getpeercert()``."""
        info = CertificateInfo()

        # Subject
        subject_tuples = cert_dict.get("subject", ())
        for rdn in subject_tuples:
            for attr_name, attr_value in rdn:
                info.subject[attr_name] = attr_value

        # Issuer
        issuer_tuples = cert_dict.get("issuer", ())
        for rdn in issuer_tuples:
            for attr_name, attr_value in rdn:
                info.issuer[attr_name] = attr_value

        # Explicit component mapping
        info.subject_cn = info.subject.get("commonName", "")
        info.subject_o = info.subject.get("organizationName", "")
        info.subject_ou = info.subject.get("organizationalUnitName", "")

        info.issuer_cn = info.issuer.get("commonName", "")
        info.issuer_o = info.issuer.get("organizationName", "")
        info.issuer_ou = info.issuer.get("organizationalUnitName", "")

        # Serial
        info.serial_number = cert_dict.get("serialNumber", "")

        # Validity
        info.not_before = cert_dict.get("notBefore", "")
        info.not_after = cert_dict.get("notAfter", "")

        # Expiry check
        if info.not_after:
            try:
                # Format: 'Mar  5 00:00:00 2025 GMT'
                exp_dt = datetime.datetime.strptime(
                    info.not_after, "%b %d %H:%M:%S %Y %Z"
                )
                now = datetime.datetime.utcnow()
                delta = exp_dt - now
                info.days_until_expiry = delta.days
                info.is_expired = delta.days < 0
            except ValueError:
                pass

        # SAN
        san_entries = cert_dict.get("subjectAltName", ())
        info.san_domains = [v for _type, v in san_entries if _type == "DNS"]

        # Extract public key info from DER if available
        if cert_der:
            try:
                from cryptography import x509
                from cryptography.x509.oid import (
                    AuthorityInformationAccessOID,
                    ExtensionOID,
                    NameOID,
                )
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric import (
                    rsa, ec, dsa, ed25519, ed448,
                )
                cert_obj = x509.load_der_x509_certificate(cert_der)
                pub = cert_obj.public_key()

                if isinstance(pub, rsa.RSAPublicKey):
                    info.public_key_type = "RSA"
                    info.public_key_bits = pub.key_size
                elif isinstance(pub, ec.EllipticCurvePublicKey):
                    info.public_key_type = f"ECDSA ({pub.curve.name})"
                    info.public_key_bits = pub.key_size
                elif isinstance(pub, dsa.DSAPublicKey):
                    info.public_key_type = "DSA"
                    info.public_key_bits = pub.key_size
                elif isinstance(pub, ed25519.Ed25519PublicKey):
                    info.public_key_type = "Ed25519"
                    info.public_key_bits = 256
                elif isinstance(pub, ed448.Ed448PublicKey):
                    info.public_key_type = "Ed448"
                    info.public_key_bits = 448
                else:
                    info.public_key_type = type(pub).__name__

                # Signature algorithm
                info.signature_algorithm = cert_obj.signature_algorithm_oid._name

                # SHA-256 fingerprint
                import hashlib
                info.fingerprint_sha256 = hashlib.sha256(
                    cert_der
                ).hexdigest().upper()
                public_key_der = pub.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                public_key_fingerprint_sha256 = hashlib.sha256(
                    public_key_der
                ).hexdigest().upper()
                info.public_key_pem = pub.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("utf-8", errors="ignore")

                def _name_value(name_obj: Any, oid: Any) -> str:
                    try:
                        attrs = name_obj.get_attributes_for_oid(oid)
                        if attrs:
                            return str(attrs[0].value)
                    except Exception:
                        return ""
                    return ""

                def _extension_name(ext: Any) -> str:
                    try:
                        return str(ext.oid._name or ext.oid.dotted_string)
                    except Exception:
                        return str(getattr(ext, "oid", ""))

                def _ku_bool(ku_obj: Any, field: str) -> bool:
                    try:
                        return bool(getattr(ku_obj, field, False))
                    except Exception:
                        return False

                key_usage_values: list[str] = []
                extended_key_usage_values: list[str] = []
                basic_constraints: dict[str, Any] = {}
                subject_key_id = ""
                authority_key_id = ""
                authority_information_access: list[str] = []
                certificate_policies: list[str] = []
                crl_distribution_points: list[str] = []
                signed_certificate_timestamps: list[str] = []
                extension_names: list[str] = []

                for ext in cert_obj.extensions:
                    extension_names.append(_extension_name(ext))

                    if ext.oid == ExtensionOID.KEY_USAGE:
                        ku = ext.value
                        if _ku_bool(ku, "digital_signature"):
                            key_usage_values.append("digital_signature")
                        if _ku_bool(ku, "content_commitment"):
                            key_usage_values.append("content_commitment")
                        if _ku_bool(ku, "key_encipherment"):
                            key_usage_values.append("key_encipherment")
                        if _ku_bool(ku, "data_encipherment"):
                            key_usage_values.append("data_encipherment")
                        if _ku_bool(ku, "key_agreement"):
                            key_usage_values.append("key_agreement")
                        if _ku_bool(ku, "key_cert_sign"):
                            key_usage_values.append("key_cert_sign")
                        if _ku_bool(ku, "crl_sign"):
                            key_usage_values.append("crl_sign")
                        if _ku_bool(ku, "encipher_only"):
                            key_usage_values.append("encipher_only")
                        if _ku_bool(ku, "decipher_only"):
                            key_usage_values.append("decipher_only")

                    elif ext.oid == ExtensionOID.EXTENDED_KEY_USAGE:
                        eku = ext.value
                        for usage_oid in eku:
                            extended_key_usage_values.append(str(getattr(usage_oid, "_name", "") or usage_oid.dotted_string))

                    elif ext.oid == ExtensionOID.BASIC_CONSTRAINTS:
                        bc = ext.value
                        basic_constraints = {
                            "ca": bool(getattr(bc, "ca", False)),
                            "path_length": getattr(bc, "path_length", None),
                        }

                    elif ext.oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER:
                        ski = ext.value
                        digest = getattr(ski, "digest", None)
                        subject_key_id = digest.hex().upper() if digest else ""

                    elif ext.oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
                        aki = ext.value
                        key_identifier = getattr(aki, "key_identifier", None)
                        authority_key_id = key_identifier.hex().upper() if key_identifier else ""

                    elif ext.oid == ExtensionOID.AUTHORITY_INFORMATION_ACCESS:
                        aia = ext.value
                        for desc in aia:
                            method_oid = getattr(desc, "access_method", None)
                            method_name = ""
                            if method_oid == AuthorityInformationAccessOID.CA_ISSUERS:
                                method_name = "caIssuers"
                            elif method_oid == AuthorityInformationAccessOID.OCSP:
                                method_name = "ocsp"
                            else:
                                method_name = str(getattr(method_oid, "_name", "") or getattr(method_oid, "dotted_string", ""))
                            location = getattr(getattr(desc, "access_location", None), "value", "")
                            authority_information_access.append(f"{method_name}:{location}")

                    elif ext.oid == ExtensionOID.CERTIFICATE_POLICIES:
                        policies = ext.value
                        for policy in policies:
                            oid_obj = getattr(policy, "policy_identifier", None)
                            if oid_obj is not None:
                                certificate_policies.append(str(getattr(oid_obj, "dotted_string", "")))

                    elif ext.oid == ExtensionOID.CRL_DISTRIBUTION_POINTS:
                        points = ext.value
                        for point in points:
                            full_name = getattr(point, "full_name", None) or []
                            for name in full_name:
                                crl_distribution_points.append(str(getattr(name, "value", "")))

                    elif ext.oid.dotted_string == "1.3.6.1.4.1.11129.2.4.2":
                        try:
                            sct_list = ext.value
                            for sct in sct_list:
                                log_id = getattr(sct, "log_id", b"")
                                log_id_text = log_id.hex().upper() if hasattr(log_id, "hex") else str(log_id)
                                timestamp = getattr(sct, "timestamp", None)
                                signed_certificate_timestamps.append(f"log_id={log_id_text}; timestamp={timestamp}")
                        except Exception:
                            signed_certificate_timestamps.append("present")

                subject_public_key_algorithm = info.public_key_type or type(pub).__name__

                subject_cn = _name_value(cert_obj.subject, NameOID.COMMON_NAME)
                subject_o = _name_value(cert_obj.subject, NameOID.ORGANIZATION_NAME)
                issuer_cn = _name_value(cert_obj.issuer, NameOID.COMMON_NAME)
                issuer_o = _name_value(cert_obj.issuer, NameOID.ORGANIZATION_NAME)

                if not info.subject_cn:
                    info.subject_cn = subject_cn
                if not info.subject_o:
                    info.subject_o = subject_o
                if not info.issuer_cn:
                    info.issuer_cn = issuer_cn
                if not info.issuer_o:
                    info.issuer_o = issuer_o

                info.certificate_details = {
                    "certificate_version": str(getattr(cert_obj, "version", "")),
                    "serial_number": str(info.serial_number or format(getattr(cert_obj, "serial_number", 0), "X")),
                    "certificate_signature_algorithm": str(info.signature_algorithm or ""),
                    "certificate_signature": getattr(cert_obj, "signature", b"").hex().upper(),
                    "issuer": cert_obj.issuer.rfc4514_string(),
                    "validity": {
                        "not_before": info.not_before,
                        "not_after": info.not_after,
                    },
                    "subject": cert_obj.subject.rfc4514_string(),
                    "subject_public_key_info": {
                        "subject_public_key_algorithm": subject_public_key_algorithm,
                        "subject_public_key_bits": info.public_key_bits,
                        "subject_public_key": info.public_key_pem,
                        "public_key_fingerprint_sha256": public_key_fingerprint_sha256,
                    },
                    "fingerprint_sha256": info.fingerprint_sha256,
                    "certificate_format": "X.509",
                    "extensions": extension_names,
                    "certificate_key_usage": key_usage_values,
                    "extended_key_usage": extended_key_usage_values,
                    "certificate_basic_constraints": basic_constraints,
                    "certificate_subject_key_id": subject_key_id,
                    "certificate_authority_key_id": authority_key_id,
                    "authority_information_access": authority_information_access,
                    "certificate_subject_alternative_name": info.san_domains,
                    "certificate_policies": certificate_policies,
                    "crl_distribution_points": crl_distribution_points,
                    "signed_certificate_timestamp_list": signed_certificate_timestamps,
                }

            except Exception:
                pass

        if not info.certificate_details:
            info.certificate_details = {
                "certificate_version": "",
                "serial_number": info.serial_number,
                "certificate_signature_algorithm": info.signature_algorithm,
                "certificate_signature": "",
                "issuer": "",
                "validity": {
                    "not_before": info.not_before,
                    "not_after": info.not_after,
                },
                "subject": "",
                "subject_public_key_info": {
                    "subject_public_key_algorithm": info.public_key_type,
                    "subject_public_key_bits": info.public_key_bits,
                    "subject_public_key": info.public_key_pem,
                    "public_key_fingerprint_sha256": "",
                },
                "fingerprint_sha256": info.fingerprint_sha256,
                "certificate_format": "X.509",
                "extensions": [],
                "certificate_key_usage": [],
                "extended_key_usage": [],
                "certificate_basic_constraints": {},
                "certificate_subject_key_id": "",
                "certificate_authority_key_id": "",
                "authority_information_access": [],
                "certificate_subject_alternative_name": info.san_domains,
                "certificate_policies": [],
                "crl_distribution_points": [],
                "signed_certificate_timestamp_list": [],
            }

        return info

    # ------------------------------------------------------------------
    # Private — SSLyze augmentation
    # ------------------------------------------------------------------

    def _augment_with_sslyze(
        self, result: TLSEndpointResult, host: str, port: int
    ) -> None:
        """Use SSLyze for deeper inspection (chain length and scanner metadata)."""
        scanner = Scanner()
        server_location = ServerNetworkLocation(host, int(port))

        raw_scan_results = scanner.scan(server_location)
        if not isinstance(raw_scan_results, Iterable):
            return

        for scan_result in raw_scan_results:
            self._extract_sslyze_chain_length(result, scan_result)

    def _extract_sslyze_chain_length(self, result: TLSEndpointResult, scan_result: Any) -> None:
        """Best-effort extraction of cert chain length across SSLyze result shapes."""
        # Common modern layout: scan_result.scan_result.certificate_info
        candidates: list[Any] = [scan_result]
        scan_result_attr = getattr(scan_result, "scan_result", None)
        if scan_result_attr is not None:
            candidates.append(scan_result_attr)

        for candidate in candidates:
            cert_info = getattr(candidate, "certificate_info", None)
            if cert_info is None:
                continue

            # Most SSLyze certificate plugin outputs expose deployed_certificate_chain.
            deployed_chain = getattr(cert_info, "deployed_certificate_chain", None)
            if deployed_chain is None:
                continue

            certs = getattr(deployed_chain, "certificates", None)
            if isinstance(certs, list) and certs:
                result.certificate_chain_length = len(certs)
                return

            if isinstance(deployed_chain, list) and deployed_chain:
                result.certificate_chain_length = len(deployed_chain)
                return

    # ------------------------------------------------------------------
    # Private — Key Exchange extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_key_exchange(cipher_suite: str) -> str:
        """Derive key exchange mechanism from cipher suite name.

        Examples::

            'ECDHE-RSA-AES256-GCM-SHA384'  → 'ECDHE'
            'TLS_AES_256_GCM_SHA384'       → 'TLS1.3-ECDHE'
            'TLS_CHACHA20_POLY1305_SHA256'  → 'TLS1.3-ECDHE'
        """
        upper = cipher_suite.upper()

        # TLS 1.3 cipher suites don't embed kex in name;
        # key exchange is always ephemeral (usually X25519/ECDHE)
        if upper.startswith("TLS_AES") or upper.startswith("TLS_CHACHA"):
            return "TLS1.3-ECDHE"

        for pattern, kex in CIPHER_KEX_PATTERNS.items():
            if pattern.upper() in upper:
                return kex

        return "UNKNOWN"
