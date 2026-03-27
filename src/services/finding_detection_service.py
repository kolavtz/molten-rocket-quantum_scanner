"""Finding detection service for Phase 3.

Detects certificate and transport findings and persists them into `findings`.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any, Dict, List

from src.db import db_session
from src.models import Certificate, Finding
from config import (
    WEAK_TLS_VERSIONS,
    WEAK_KEY_LENGTH_BITS,
    EXPIRING_CERT_THRESHOLD_DAYS,
    FINDING_SEVERITY_MAP,
)


class FindingDetectionService:
    """Detects and stores certificate-security findings for assets/scans."""

    WEAK_CIPHER_MARKERS = ["RC4", "3DES", "DES", "NULL", "ANON", "EXPORT", "MD5"]
    WEAK_SIGNATURE_MARKERS = ["MD5", "SHA1"]

    @classmethod
    def detect_and_store_findings(cls, asset_id: int, scan_id: int) -> Dict[str, Any]:
        certs = (
            db_session.query(Certificate)
            .filter(
                Certificate.asset_id == asset_id,
                Certificate.scan_id == scan_id,
                Certificate.is_deleted == False,
            )
            .all()
        )

        created = 0
        by_type: Dict[str, int] = {}

        for cert in certs:
            for finding in cls._detect_certificate_findings(cert):
                if cls._finding_exists(
                    scan_id=scan_id,
                    asset_id=asset_id,
                    certificate_id=getattr(cert, "id", None),
                    issue_type=finding["issue_type"],
                ):
                    continue
                obj = Finding(
                    asset_id=asset_id,
                    scan_id=scan_id,
                    certificate_id=getattr(cert, "id", None),
                    issue_type=finding["issue_type"],
                    severity=finding["severity"],
                    description=finding["description"],
                    metadata_json=json.dumps(finding.get("metadata", {})),
                )
                db_session.add(obj)
                created += 1
                by_type[finding["issue_type"]] = int(by_type.get(finding["issue_type"], 0)) + 1

        return {
            "created": created,
            "by_type": by_type,
            "checked_certificates": len(certs),
        }

    @classmethod
    def _detect_certificate_findings(cls, cert: Certificate) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        now = datetime.utcnow()

        tls_version = str(getattr(cert, "tls_version", "") or "").strip()
        if tls_version in WEAK_TLS_VERSIONS:
            findings.append(
                cls._finding(
                    "weak_tls_version",
                    f"Weak TLS version detected: {tls_version}",
                    {"tls_version": tls_version},
                )
            )

        key_length = getattr(cert, "key_length", None)
        if key_length is not None and int(key_length) < int(WEAK_KEY_LENGTH_BITS):
            findings.append(
                cls._finding(
                    "weak_key_length",
                    f"Weak key length detected: {key_length} bits",
                    {"key_length": int(key_length), "minimum_recommended": int(WEAK_KEY_LENGTH_BITS)},
                )
            )

        valid_until = getattr(cert, "valid_until", None)
        if valid_until is not None:
            if valid_until < now:
                findings.append(
                    cls._finding(
                        "expired_certificate",
                        "Certificate is expired",
                        {"valid_until": valid_until.isoformat()},
                    )
                )
            elif valid_until <= now + timedelta(days=int(EXPIRING_CERT_THRESHOLD_DAYS)):
                findings.append(
                    cls._finding(
                        "expiring_certificate",
                        "Certificate is expiring soon",
                        {
                            "valid_until": valid_until.isoformat(),
                            "threshold_days": int(EXPIRING_CERT_THRESHOLD_DAYS),
                        },
                    )
                )

        if bool(getattr(cert, "is_self_signed", False)):
            findings.append(
                cls._finding(
                    "self_signed_cert",
                    "Self-signed certificate detected",
                    {
                        "subject": str(getattr(cert, "subject", "") or ""),
                        "issuer": str(getattr(cert, "issuer", "") or ""),
                    },
                )
            )

        cipher_suite = str(getattr(cert, "cipher_suite", "") or "").upper()
        if cipher_suite and any(marker in cipher_suite for marker in cls.WEAK_CIPHER_MARKERS):
            findings.append(
                cls._finding(
                    "weak_cipher",
                    f"Weak cipher suite detected: {cipher_suite}",
                    {"cipher_suite": cipher_suite},
                )
            )

        signature_algorithm = str(getattr(cert, "signature_algorithm", "") or "").upper()
        if signature_algorithm and any(marker in signature_algorithm for marker in cls.WEAK_SIGNATURE_MARKERS):
            findings.append(
                cls._finding(
                    "weak_signature_algorithm",
                    f"Weak signature algorithm detected: {signature_algorithm}",
                    {"signature_algorithm": signature_algorithm},
                )
            )

        endpoint = str(getattr(cert, "endpoint", "") or "")
        endpoint_host = endpoint.split(":", 1)[0].strip().lower() if endpoint else ""
        subject_cn = str(getattr(cert, "subject_cn", "") or "").strip().lower()
        san_domains_raw = str(getattr(cert, "san_domains", "") or "").lower()
        if endpoint_host and subject_cn and endpoint_host not in subject_cn and endpoint_host not in san_domains_raw:
            findings.append(
                cls._finding(
                    "mismatched_hostname",
                    "Certificate hostname does not match endpoint",
                    {
                        "endpoint_host": endpoint_host,
                        "subject_cn": subject_cn,
                    },
                )
            )

        return findings

    @staticmethod
    def _finding(issue_type: str, description: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        severity = str(FINDING_SEVERITY_MAP.get(issue_type, "low"))
        return {
            "issue_type": issue_type,
            "severity": severity,
            "description": description,
            "metadata": metadata,
        }

    @staticmethod
    def _finding_exists(scan_id: int, asset_id: int, certificate_id: Any, issue_type: str) -> bool:
        return (
            db_session.query(Finding.id)
            .filter(
                Finding.scan_id == scan_id,
                Finding.asset_id == asset_id,
                Finding.certificate_id == certificate_id,
                Finding.issue_type == issue_type,
                Finding.is_deleted == False,
            )
            .first()
            is not None
        )
