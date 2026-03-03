"""
Certificate / Label Issuer Module

Generates "Quantum-Safe" or "PQC Ready" digital labels for endpoints
that pass NIST PQC compliance validation.

Classes:
    QuantumSafeLabel   — data for a single label.
    CertificateIssuer  — issues labels based on validation results.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from config import APP_NAME, APP_VERSION


@dataclass
class QuantumSafeLabel:
    """Digital label certifying an endpoint's PQC readiness."""

    label_id: str = ""
    host: str = ""
    port: int = 0
    label: str = ""                     # "Fully Quantum Safe", "PQC Ready", "Partial", "Non-Compliant"
    compliance_score: int = 0
    standard: str = ""
    issued_at: str = ""
    valid_until: str = ""
    issuer: str = APP_NAME
    issuer_version: str = APP_VERSION
    details: Dict[str, Any] = field(default_factory=dict)
    badge_color: str = "#22c55e"        # green by default
    checksum: str = ""

    def __post_init__(self) -> None:
        if not self.label_id:
            self.label_id = str(uuid.uuid4())
        if not self.issued_at:
            self.issued_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label_id": self.label_id,
            "host": self.host,
            "port": self.port,
            "label": self.label,
            "compliance_score": self.compliance_score,
            "standard": self.standard,
            "issued_at": self.issued_at,
            "valid_until": self.valid_until,
            "issuer": self.issuer,
            "issuer_version": self.issuer_version,
            "details": self.details,
            "badge_color": self.badge_color,
            "checksum": self.checksum,
        }


class CertificateIssuer:
    """Issues Quantum-Safe labels based on validation results.

    Usage::

        issuer = CertificateIssuer()
        label = issuer.issue_label(validation_result_dict)
        print(label.label, label.compliance_score)
    """

    VALIDITY_DAYS = {
        "Fully Quantum Safe": 730,     # highest tier — 2 years
        "PQC Ready": 365,
        "Partial": 90,
        "Non-Compliant": 30,
    }

    BADGE_COLORS = {
        "Fully Quantum Safe": "#10b981",  # emerald
        "PQC Ready": "#22c55e",           # green
        "Partial": "#f59e0b",              # amber
        "Non-Compliant": "#ef4444",        # red
    }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def issue_label(
        self, validation_result: Dict[str, Any]
    ) -> QuantumSafeLabel:
        """Issue a label for the given validation result.

        Parameters
        ----------
        validation_result : dict
            Output of ``QuantumSafeChecker.validate().to_dict()``.

        Returns
        -------
        QuantumSafeLabel
        """
        label_text = validation_result.get("label", "Non-Compliant")
        score = validation_result.get("compliance_score", 0)
        host = validation_result.get("host", "")
        port = validation_result.get("port", 0)

        # Upgrade "PQC Ready" to "Fully Quantum Safe" if score is 100
        # and there are no critical/high findings
        if (label_text == "PQC Ready"
                and score >= 100
                and validation_result.get("critical_findings", 0) == 0
                and validation_result.get("high_findings", 0) == 0):
            label_text = "Fully Quantum Safe"

        validity = self.VALIDITY_DAYS.get(label_text, 30)
        now = datetime.now(timezone.utc)
        valid_until = (now + timedelta(days=validity)).isoformat()

        # Determine NIST standard reference
        standard = self._determine_standard(validation_result)

        label = QuantumSafeLabel(
            host=host,
            port=port,
            label=label_text,
            compliance_score=score,
            standard=standard,
            valid_until=valid_until,
            badge_color=self.BADGE_COLORS.get(label_text, "#6b7280"),
            details={
                "critical_findings": validation_result.get("critical_findings", 0),
                "high_findings": validation_result.get("high_findings", 0),
                "hndl_risk_level": validation_result.get("hndl_risk_level", ""),
                "recommendations_count": len(
                    validation_result.get("recommendations", [])
                ),
            },
        )

        # Compute integrity checksum
        label.checksum = self._compute_checksum(label)

        return label

    def issue_labels(
        self, validation_results: List[Dict[str, Any]]
    ) -> List[QuantumSafeLabel]:
        """Issue labels for multiple validation results."""
        return [self.issue_label(vr) for vr in validation_results]

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    @staticmethod
    def _determine_standard(vr: Dict[str, Any]) -> str:
        standards: List[str] = []

        for finding in vr.get("findings", []):
            ref = finding.get("nist_reference", "")
            if ref and ref not in standards:
                standards.append(ref)

        if not standards:
            standards.append("NIST FIPS 203/204/205")

        return " | ".join(standards)

    @staticmethod
    def _compute_checksum(label: QuantumSafeLabel) -> str:
        """SHA-256 checksum of label fields for tamper detection."""
        payload = (
            f"{label.label_id}|{label.host}|{label.port}|"
            f"{label.label}|{label.compliance_score}|"
            f"{label.issued_at}|{label.valid_until}"
        )
        return hashlib.sha256(payload.encode()).hexdigest()
