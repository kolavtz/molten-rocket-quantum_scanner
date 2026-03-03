"""
Quantum-Safe Checker Module

Validates whether an endpoint's cryptographic configuration meets
NIST Post-Quantum Cryptography standards and provides detailed
findings with HNDL risk scoring.

Classes:
    ValidationFinding  — a single compliance finding.
    ValidationResult   — full validation outcome for an endpoint.
    QuantumSafeChecker — validates endpoints against NIST PQC standards.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from config import (
    ALL_PQC_ALGORITHMS,
    NIST_APPROVED_KEMS,
    NIST_APPROVED_SIGNATURES,
    NIST_APPROVED_HASH_SIGNATURES,
    QUANTUM_VULNERABLE_KEY_EXCHANGES,
    QUANTUM_VULNERABLE_SIGNATURES,
    HNDL_RISK_WEIGHTS,
)


@dataclass
class ValidationFinding:
    """A single compliance finding."""

    severity: str = "INFO"          # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str = ""              # "key_exchange", "signature", "certificate", "protocol"
    title: str = ""
    description: str = ""
    current_value: str = ""
    recommended_value: str = ""
    nist_reference: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "current_value": self.current_value,
            "recommended_value": self.recommended_value,
            "nist_reference": self.nist_reference,
        }


@dataclass
class ValidationResult:
    """Full validation outcome for an endpoint."""

    host: str = ""
    port: int = 0
    is_quantum_safe: bool = False
    compliance_score: int = 0           # 0-100
    hndl_risk_level: str = "HIGH"       # HIGH, MEDIUM, LOW
    hndl_risk_score: int = 9            # 1-10
    findings: List[ValidationFinding] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    label: str = "Non-Compliant"        # "PQC Ready", "Partial", "Non-Compliant"

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "is_quantum_safe": self.is_quantum_safe,
            "compliance_score": self.compliance_score,
            "hndl_risk_level": self.hndl_risk_level,
            "hndl_risk_score": self.hndl_risk_score,
            "label": self.label,
            "critical_findings": self.critical_count,
            "high_findings": self.high_count,
            "findings": [f.to_dict() for f in self.findings],
            "recommendations": self.recommendations,
        }


class QuantumSafeChecker:
    """Validates endpoints against NIST PQC standards.

    Usage::

        checker = QuantumSafeChecker()
        result = checker.validate(tls_result_dict, pqc_assessment_dict)
        print(result.label, result.compliance_score)
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(
        self,
        tls_result: Dict[str, Any],
        pqc_assessment: Dict[str, Any],
    ) -> ValidationResult:
        """Run full NIST PQC compliance validation.

        Parameters
        ----------
        tls_result : dict
            Output of ``TLSEndpointResult.to_dict()``.
        pqc_assessment : dict
            Output of ``PQCAssessment.to_dict()``.

        Returns
        -------
        ValidationResult
        """
        result = ValidationResult(
            host=tls_result.get("host", ""),
            port=tls_result.get("port", 0),
        )

        score_components: List[int] = []

        # ── 1. Key Exchange ──
        self._check_key_exchange(tls_result, result, score_components)

        # ── 2. Protocol Version ──
        self._check_protocol_version(tls_result, result, score_components)

        # ── 3. Certificate ──
        self._check_certificate(tls_result, result, score_components)

        # ── 4. PQC Status ──
        self._check_pqc_status(pqc_assessment, result, score_components)

        # ── Compute overall score ──
        if score_components:
            result.compliance_score = round(
                sum(score_components) / len(score_components)
            )
        else:
            result.compliance_score = 0

        # ── HNDL risk ──
        result.hndl_risk_level, result.hndl_risk_score = (
            self._compute_hndl_risk(tls_result)
        )

        # ── Determine label ──
        if result.compliance_score >= 90 and result.critical_count == 0:
            result.is_quantum_safe = True
            result.label = "PQC Ready"
        elif result.compliance_score >= 50:
            result.label = "Partial"
        else:
            result.label = "Non-Compliant"

        # ── Generate recommendations ──
        result.recommendations = self._generate_recommendations(result)

        return result

    # ------------------------------------------------------------------
    # Private — Individual Checks
    # ------------------------------------------------------------------

    def _check_key_exchange(
        self,
        tls: Dict[str, Any],
        result: ValidationResult,
        scores: List[int],
    ) -> None:
        kex = tls.get("key_exchange", "")
        if not kex:
            return

        kex_upper = kex.upper()
        is_pqc = any(
            alg.upper() in kex_upper
            for alg in (NIST_APPROVED_KEMS | {"X25519MLKEM768"})
        )

        if is_pqc:
            scores.append(100)
            result.findings.append(ValidationFinding(
                severity="INFO",
                category="key_exchange",
                title="Quantum-safe key exchange detected",
                description=f"Key exchange '{kex}' uses a NIST-approved PQC algorithm.",
                current_value=kex,
                nist_reference="FIPS 203 (ML-KEM)",
            ))
        else:
            scores.append(0)
            result.findings.append(ValidationFinding(
                severity="CRITICAL",
                category="key_exchange",
                title="Quantum-vulnerable key exchange",
                description=(
                    f"Key exchange '{kex}' is vulnerable to Shor's algorithm. "
                    "A sufficiently powerful quantum computer could break this."
                ),
                current_value=kex,
                recommended_value="ML-KEM-768 or ML-KEM-1024",
                nist_reference="FIPS 203 (ML-KEM)",
            ))

    def _check_protocol_version(
        self,
        tls: Dict[str, Any],
        result: ValidationResult,
        scores: List[int],
    ) -> None:
        proto = tls.get("protocol_version", "")
        if "1.3" in proto:
            scores.append(100)
            result.findings.append(ValidationFinding(
                severity="INFO",
                category="protocol",
                title="TLS 1.3 in use",
                description="TLS 1.3 is the recommended version and required for PQC cipher suites.",
                current_value=proto,
            ))
        elif "1.2" in proto:
            scores.append(50)
            result.findings.append(ValidationFinding(
                severity="MEDIUM",
                category="protocol",
                title="TLS 1.2 detected — upgrade recommended",
                description="TLS 1.2 does not support PQC key exchange natively. Upgrade to TLS 1.3.",
                current_value=proto,
                recommended_value="TLSv1.3",
            ))
        elif proto:
            scores.append(0)
            result.findings.append(ValidationFinding(
                severity="CRITICAL",
                category="protocol",
                title="Outdated TLS version",
                description=f"Protocol '{proto}' is deprecated and insecure.",
                current_value=proto,
                recommended_value="TLSv1.3",
            ))

    def _check_certificate(
        self,
        tls: Dict[str, Any],
        result: ValidationResult,
        scores: List[int],
    ) -> None:
        cert = tls.get("certificate")
        if not cert:
            return

        # Signature algorithm
        sig_alg = cert.get("signature_algorithm", "")
        sig_upper = sig_alg.upper()

        pqc_sigs = NIST_APPROVED_SIGNATURES | NIST_APPROVED_HASH_SIGNATURES
        is_pqc_sig = any(alg.upper() in sig_upper for alg in pqc_sigs)

        if is_pqc_sig:
            scores.append(100)
        else:
            scores.append(20)
            result.findings.append(ValidationFinding(
                severity="HIGH",
                category="certificate",
                title="Certificate uses quantum-vulnerable signature",
                description=f"Signature algorithm '{sig_alg}' is not quantum-safe.",
                current_value=sig_alg,
                recommended_value="ML-DSA-65 or SLH-DSA-SHA2-256f",
                nist_reference="FIPS 204 (ML-DSA) / FIPS 205 (SLH-DSA)",
            ))

        # Expiry
        if cert.get("is_expired"):
            result.findings.append(ValidationFinding(
                severity="CRITICAL",
                category="certificate",
                title="Certificate is expired",
                description="The server certificate has expired and should be replaced immediately.",
                current_value=cert.get("not_after", ""),
            ))
        elif cert.get("days_until_expiry", 999) < 30:
            result.findings.append(ValidationFinding(
                severity="HIGH",
                category="certificate",
                title="Certificate expires soon",
                description=f"Certificate expires in {cert['days_until_expiry']} days.",
                current_value=cert.get("not_after", ""),
            ))

        # Key size
        pk_type = cert.get("public_key_type", "")
        pk_bits = cert.get("public_key_bits", 0)
        if "RSA" in pk_type.upper() and pk_bits < 3072:
            result.findings.append(ValidationFinding(
                severity="HIGH",
                category="certificate",
                title="Weak RSA key size",
                description=f"RSA key is {pk_bits}-bit. Minimum 3072-bit recommended (NIST SP 800-131A).",
                current_value=f"RSA-{pk_bits}",
                recommended_value="RSA-3072+ or PQC-based certificate",
            ))

    def _check_pqc_status(
        self,
        pqc: Dict[str, Any],
        result: ValidationResult,
        scores: List[int],
    ) -> None:
        status = pqc.get("overall_status", "quantum_vulnerable")
        if status == "quantum_safe":
            scores.append(100)
        elif status == "hybrid":
            scores.append(60)
            result.findings.append(ValidationFinding(
                severity="MEDIUM",
                category="pqc",
                title="Hybrid PQC detected",
                description="Endpoint uses a mix of quantum-safe and classical algorithms.",
                recommended_value="Transition to fully PQC-only algorithms.",
            ))
        else:
            scores.append(0)

    # ------------------------------------------------------------------
    # HNDL Risk
    # ------------------------------------------------------------------

    def _compute_hndl_risk(
        self, tls: Dict[str, Any]
    ) -> tuple[str, int]:
        """Compute HNDL risk based on host/service keywords."""
        host = tls.get("host", "").lower()

        for level, info in HNDL_RISK_WEIGHTS.items():
            for kw in info["keywords"]:
                if kw in host:
                    return level, info["score"]

        # Default: HIGH for unknown endpoints (conservative)
        return "HIGH", 9

    # ------------------------------------------------------------------
    # Recommendations
    # ------------------------------------------------------------------

    def _generate_recommendations(
        self, result: ValidationResult
    ) -> List[str]:
        recs: List[str] = []

        for f in result.findings:
            if f.severity in ("CRITICAL", "HIGH") and f.recommended_value:
                recs.append(
                    f"{f.title}: migrate from {f.current_value} to {f.recommended_value}"
                )

        if not result.is_quantum_safe:
            recs.append(
                "Enable TLS 1.3 and configure PQC key exchange (ML-KEM-768) on your server."
            )
            recs.append(
                "Obtain a PQC-signed certificate using ML-DSA or SLH-DSA from a supporting CA."
            )
            recs.append(
                "Consider hybrid key exchange (X25519+ML-KEM-768) as a transitional step."
            )

        return recs
