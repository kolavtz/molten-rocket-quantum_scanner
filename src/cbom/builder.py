"""
CBOM Builder Module

Assembles scanned cryptographic asset records into a structured
Cryptographic Bill of Materials (CBOM) data structure ready for
CycloneDX export.

Classes:
    CryptoAsset  — a single cryptographic asset record.
    CBOMBuilder  — builds a CBOM from scan results.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from config import APP_NAME, APP_VERSION


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
            Each element is ``PQCAssessment.to_dict()`` output, aligned
            with *tls_results* by index.

        Returns
        -------
        CBOM
        """
        cbom = CBOM()

        for i, tls_data in enumerate(tls_results):
            pqc_data = pqc_assessments[i] if i < len(pqc_assessments) else {}
            asset = self._build_asset(tls_data, pqc_data)
            cbom.assets.append(asset)

        return cbom

    # ------------------------------------------------------------------
    # Private
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
