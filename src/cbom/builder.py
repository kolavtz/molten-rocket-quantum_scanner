"""
CBOM Builder Module — CERT-IN Compliant

Assembles scanned cryptographic asset records into a structured
Cryptographic Bill of Materials (CBOM) data structure ready for
CycloneDX export.

Generates separate entries per CERT-IN asset type:
  - Algorithms (cipher, key exchange, signature, hash)
  - Keys (public keys extracted from certificates)
  - Protocols (TLS version and cipher suite negotiation)
  - Certificates (X.509 certificate metadata)

Classes:
    CryptoAsset  — a single cryptographic asset record (legacy compat).
    CBOMBuilder  — builds a CERT-IN compliant CBOM from scan results.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from config import (
    APP_NAME, APP_VERSION,
    ALGORITHM_OID_MAP, ALGORITHM_METADATA, PROTOCOL_OID_MAP,
    ALL_PQC_ALGORITHMS,
)


@dataclass
class CryptoAsset:
    """Represents a single cryptographic asset discovered during scanning."""

    asset_id: str = ""
    host: str = ""
    port: int = 0
    service: str = ""

    # TLS details
    protocol_version: str = ""
    cipher_suite: str = ""
    cipher_bits: int = 0
    key_exchange: str = ""

    # Certificate details
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_serial: str = ""
    cert_not_before: str = ""
    cert_not_after: str = ""
    cert_signature_algorithm: str = ""
    cert_public_key_type: str = ""
    cert_public_key_bits: int = 0
    cert_fingerprint: str = ""
    cert_is_expired: bool = False
    cert_days_until_expiry: int = 0

    # PQC classification
    is_quantum_safe: bool = False
    pqc_status: str = "quantum_vulnerable"
    risk_level: str = "HIGH"

    def __post_init__(self) -> None:
        if not self.asset_id:
            self.asset_id = str(uuid.uuid4())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "host": self.host,
            "port": self.port,
            "service": self.service,
            "protocol_version": self.protocol_version,
            "cipher_suite": self.cipher_suite,
            "cipher_bits": self.cipher_bits,
            "key_exchange": self.key_exchange,
            "cert_subject": self.cert_subject,
            "cert_issuer": self.cert_issuer,
            "cert_serial": self.cert_serial,
            "cert_not_before": self.cert_not_before,
            "cert_not_after": self.cert_not_after,
            "cert_signature_algorithm": self.cert_signature_algorithm,
            "cert_public_key_type": self.cert_public_key_type,
            "cert_public_key_bits": self.cert_public_key_bits,
            "cert_fingerprint": self.cert_fingerprint,
            "cert_is_expired": self.cert_is_expired,
            "cert_days_until_expiry": self.cert_days_until_expiry,
            "is_quantum_safe": self.is_quantum_safe,
            "pqc_status": self.pqc_status,
            "risk_level": self.risk_level,
        }


@dataclass
class CBOM:
    """Cryptographic Bill of Materials container."""

    serial_number: str = ""
    version: int = 1
    timestamp: str = ""
    tool_name: str = APP_NAME
    tool_version: str = APP_VERSION
    assets: List[CryptoAsset] = field(default_factory=list)

    # CERT-IN typed inventories
    algorithms: List[Dict[str, Any]] = field(default_factory=list)
    keys: List[Dict[str, Any]] = field(default_factory=list)
    protocols: List[Dict[str, Any]] = field(default_factory=list)
    certificates: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.serial_number:
            self.serial_number = f"urn:uuid:{uuid.uuid4()}"
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    # ── Convenience properties ──

    @property
    def total_assets(self) -> int:
        return len(self.assets)

    @property
    def quantum_safe_count(self) -> int:
        return sum(1 for a in self.assets if a.is_quantum_safe)

    @property
    def quantum_vulnerable_count(self) -> int:
        return sum(1 for a in self.assets if not a.is_quantum_safe)

    @property
    def expired_cert_count(self) -> int:
        return sum(1 for a in self.assets if a.cert_is_expired)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "serial_number": self.serial_number,
            "version": self.version,
            "timestamp": self.timestamp,
            "tool": {"name": self.tool_name, "version": self.tool_version},
            "summary": {
                "total_assets": self.total_assets,
                "quantum_safe": self.quantum_safe_count,
                "quantum_vulnerable": self.quantum_vulnerable_count,
                "expired_certificates": self.expired_cert_count,
            },
            "assets": [a.to_dict() for a in self.assets],
            # CERT-IN typed inventories
            "cert_in_inventory": {
                "algorithms": self.algorithms,
                "keys": self.keys,
                "protocols": self.protocols,
                "certificates": self.certificates,
            },
        }


class CBOMBuilder:
    """Builds a CBOM from scan + PQC assessment results.

    Usage::

        builder = CBOMBuilder()
        cbom = builder.build(tls_results, pqc_assessments)
    """

    def build(
        self,
        tls_results: List[Dict[str, Any]],
        pqc_assessments: List[Dict[str, Any]],
    ) -> CBOM:
        """Assemble a CBOM from paired TLS + PQC data.

        Parameters
        ----------
        tls_results : list[dict]
            Each element is ``TLSEndpointResult.to_dict()`` output.
        pqc_assessments : list[dict]
            Each element is ``PQCAssessment.to_dict()`` output. Entries
            are matched to *tls_results* by endpoint identity
            (host + port). If endpoint metadata is missing, the method
            falls back to index alignment for backward compatibility.

        Returns
        -------
        CBOM
        """
        cbom = CBOM()

        pqc_by_endpoint: Dict[tuple[str, int], List[Dict[str, Any]]] = {}
        for pqc in pqc_assessments:
            key = self._endpoint_key(pqc.get("host", ""), pqc.get("port", 0))
            pqc_by_endpoint.setdefault(key, []).append(pqc)

        for i, tls_data in enumerate(tls_results):
            tls_key = self._endpoint_key(tls_data.get("host", ""), tls_data.get("port", 0))
            pqc_bucket = pqc_by_endpoint.get(tls_key, [])

            if pqc_bucket:
                pqc_data = pqc_bucket.pop(0)
            elif i < len(pqc_assessments):
                # Backward-compatible fallback for malformed/missing host+port.
                pqc_data = pqc_assessments[i]
            else:
                pqc_data = {}

            asset = self._build_asset(tls_data, pqc_data)
            cbom.assets.append(asset)

            # Decompose into CERT-IN typed records
            self._extract_algorithms(tls_data, pqc_data, asset, cbom)
            self._extract_key(tls_data, asset, cbom)
            self._extract_protocol(tls_data, asset, cbom)
            self._extract_certificate(tls_data, asset, cbom)

        return cbom

    # ------------------------------------------------------------------
    # Private — Legacy asset builder
    # ------------------------------------------------------------------

    def _build_asset(
        self, tls: Dict[str, Any], pqc: Dict[str, Any]
    ) -> CryptoAsset:
        """Merge TLS result + PQC assessment into a CryptoAsset."""
        cert = tls.get("certificate") or {}

        subject_cn = cert.get("subject", {}).get("commonName", "")
        issuer_cn = cert.get("issuer", {}).get("commonName", "")

        return CryptoAsset(
            host=tls.get("host", ""),
            port=tls.get("port", 0),
            service=f"TLS-{tls.get('port', 0)}",
            protocol_version=tls.get("protocol_version", ""),
            cipher_suite=tls.get("cipher_suite", ""),
            cipher_bits=tls.get("cipher_bits", 0),
            key_exchange=tls.get("key_exchange", ""),
            cert_subject=subject_cn,
            cert_issuer=issuer_cn,
            cert_serial=cert.get("serial_number", ""),
            cert_not_before=cert.get("not_before", ""),
            cert_not_after=cert.get("not_after", ""),
            cert_signature_algorithm=cert.get("signature_algorithm", ""),
            cert_public_key_type=cert.get("public_key_type", ""),
            cert_public_key_bits=cert.get("public_key_bits", 0),
            cert_fingerprint=cert.get("fingerprint_sha256", ""),
            cert_is_expired=cert.get("is_expired", False),
            cert_days_until_expiry=cert.get("days_until_expiry", 0),
            is_quantum_safe=pqc.get("is_quantum_safe", False),
            pqc_status=pqc.get("overall_status", "quantum_vulnerable"),
            risk_level=pqc.get("risk_level", "HIGH"),
        )

    # ------------------------------------------------------------------
    # CERT-IN typed record extractors
    # ------------------------------------------------------------------

    def _extract_algorithms(
        self,
        tls: Dict[str, Any],
        pqc: Dict[str, Any],
        asset: CryptoAsset,
        cbom: CBOM,
    ) -> None:
        """Extract Algorithm records for CERT-IN CBOM.

        Produces entries for: cipher (symmetric), key exchange, and
        signature algorithm discovered on the endpoint.
        """
        algo_names = set()

        # 1. Symmetric cipher from cipher suite
        cipher_name = self._normalize_cipher_name(tls.get("cipher_suite", ""))
        if cipher_name:
            algo_names.add(cipher_name)

        # 2. Key exchange algorithm
        kex = tls.get("key_exchange", "")
        if kex:
            algo_names.add(kex)

        # 3. Signature algorithm from certificate
        cert = tls.get("certificate") or {}
        sig_algo = cert.get("signature_algorithm", "")
        if sig_algo:
            algo_names.add(sig_algo)

        for name in algo_names:
            meta = ALGORITHM_METADATA.get(name, {})
            is_pqc = name.upper() in {a.upper() for a in ALL_PQC_ALGORITHMS}
            cbom.algorithms.append({
                "name": name,
                "asset_type": "algorithm",
                "primitive": meta.get("primitive", "unknown"),
                "mode": meta.get("mode", "unknown"),
                "crypto_functions": meta.get("crypto_functions", []),
                "classical_security_level": meta.get("classical_security_bits", 0),
                "oid": ALGORITHM_OID_MAP.get(name, ""),
                "quantum_safe_status": "quantum-safe" if is_pqc else "quantum-vulnerable",
                "host": asset.host,
                "port": asset.port,
            })

    def _extract_key(
        self, tls: Dict[str, Any], asset: CryptoAsset, cbom: CBOM
    ) -> None:
        """Extract Key record from the certificate's public key."""
        cert = tls.get("certificate") or {}
        pk_type = cert.get("public_key_type", "")
        if not pk_type:
            return

        key_state = "expired" if cert.get("is_expired", False) else "active"
        cbom.keys.append({
            "name": f"{pk_type}-{cert.get('public_key_bits', 0)}",
            "asset_type": "key",
            "id": cert.get("serial_number", str(uuid.uuid4())),
            "state": key_state,
            "size": cert.get("public_key_bits", 0),
            "creation_date": cert.get("not_before", ""),
            "activation_date": cert.get("not_before", ""),
            "host": asset.host,
            "port": asset.port,
        })

    def _extract_protocol(
        self, tls: Dict[str, Any], asset: CryptoAsset, cbom: CBOM
    ) -> None:
        """Extract Protocol record from the TLS negotiation."""
        proto_ver = tls.get("protocol_version", "")
        if not proto_ver:
            return

        cbom.protocols.append({
            "name": "TLS",
            "asset_type": "protocol",
            "version": proto_ver,
            "cipher_suites": tls.get("cipher_suite", ""),
            "oid": PROTOCOL_OID_MAP.get(proto_ver, ""),
            "host": asset.host,
            "port": asset.port,
        })

    def _extract_certificate(
        self, tls: Dict[str, Any], asset: CryptoAsset, cbom: CBOM
    ) -> None:
        """Extract Certificate record for CERT-IN CBOM."""
        cert = tls.get("certificate") or {}
        subject_cn = cert.get("subject", {}).get("commonName", "")
        if not subject_cn:
            return

        issuer_cn = cert.get("issuer", {}).get("commonName", "")
        sig_algo = cert.get("signature_algorithm", "")

        cbom.certificates.append({
            "name": subject_cn,
            "asset_type": "certificate",
            "subject_name": subject_cn,
            "issuer_name": issuer_cn,
            "not_valid_before": cert.get("not_before", ""),
            "not_valid_after": cert.get("not_after", ""),
            "signature_algorithm_ref": sig_algo,
            "signature_algorithm_oid": ALGORITHM_OID_MAP.get(sig_algo, ""),
            "subject_public_key_ref": f"{cert.get('public_key_type', '')}-{cert.get('public_key_bits', 0)}",
            "format": "X.509",
            "extension": ".crt",
            "fingerprint_sha256": cert.get("fingerprint_sha256", ""),
            "serial_number": cert.get("serial_number", ""),
            "is_expired": cert.get("is_expired", False),
            "days_until_expiry": cert.get("days_until_expiry", 0),
            "host": asset.host,
            "port": asset.port,
        })

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_cipher_name(cipher_suite: str) -> str:
        """Extract the symmetric cipher name from a full cipher suite string.

        E.g. 'TLS_AES_256_GCM_SHA384' → 'AES-256-GCM'
             'ECDHE-RSA-AES128-GCM-SHA256' → 'AES-128-GCM'
        """
        suite_upper = cipher_suite.upper()
        if "CHACHA20" in suite_upper:
            return "CHACHA20-POLY1305"
        if "AES" in suite_upper:
            bits = "256" if "256" in suite_upper else "128"
            if "GCM" in suite_upper:
                return f"AES-{bits}-GCM"
            if "CBC" in suite_upper:
                return f"AES-{bits}-CBC"
            return f"AES-{bits}-GCM"  # default to GCM for TLS 1.3
        if "3DES" in suite_upper or "DES-CBC3" in suite_upper:
            return "3DES-CBC"
        return ""

    @staticmethod
    def _endpoint_key(host: Any, port: Any) -> tuple[str, int]:
        """Return a normalized endpoint identity key."""
        normalized_host = str(host or "").strip().lower()
        try:
            normalized_port = int(port or 0)
        except (TypeError, ValueError):
            normalized_port = 0
        return normalized_host, normalized_port
