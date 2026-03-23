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
from typing import Any, Dict, List, Optional

try:
    from OpenSSL import SSL, crypto
    HAS_PYOPENSSL = True
except ImportError:
    HAS_PYOPENSSL = False

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

        # Augment with pyOpenSSL if available
        if HAS_PYOPENSSL and result.error is None:
            try:
                self._augment_with_pyopenssl(result, host, port)
            except Exception:
                pass  # pyopenssl augmentation is best-effort

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
        if peer_cert:
            result.certificate = self._parse_stdlib_cert(
                peer_cert, peer_cert_der
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
                info.public_key_pem = pub.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("utf-8", errors="ignore")

            except Exception:
                pass

        return info

    # ------------------------------------------------------------------
    # Private — pyOpenSSL augmentation
    # ------------------------------------------------------------------

    def _augment_with_pyopenssl(
        self, result: TLSEndpointResult, host: str, port: int
    ) -> None:
        """Use pyOpenSSL for deeper inspection (chain length, all ciphers)."""
        ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
        ctx.set_verify(SSL.VERIFY_NONE, lambda *a: True)

        sock = socket.create_connection((host, port), timeout=self.timeout)
        conn = SSL.Connection(ctx, sock)
        conn.set_tlsext_host_name(host.encode())
        conn.set_connect_state()
        conn.do_handshake()

        # Certificate chain length
        chain = conn.get_peer_cert_chain()
        if chain:
            result.certificate_chain_length = len(chain)

        conn.shutdown()
        conn.close()

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
