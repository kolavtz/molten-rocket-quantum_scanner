"""
Post-Quantum Cryptography (PQC) Detector Module

Classifies the cryptographic algorithms used by an endpoint as
quantum-safe, quantum-vulnerable, or hybrid, based on NIST PQC
standards (FIPS 203/204/205).

Classes:
    PQCDetector — analyses TLS analysis results and classifies PQC readiness.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from config import (
    ALL_PQC_ALGORITHMS,
    NIST_APPROVED_KEMS,
    NIST_APPROVED_SIGNATURES,
    NIST_APPROVED_HASH_SIGNATURES,
    DRAFT_PQC_ALGORITHMS,
    QUANTUM_VULNERABLE_KEY_EXCHANGES,
    QUANTUM_VULNERABLE_SIGNATURES,
)


# ── Data classes ──────────────────────────────────────────────────────

@dataclass
class AlgorithmClassification:
    """Classification of a single algorithm."""

    name: str
    category: str = ""          # "key_exchange", "signature", "cipher", "hash"
    status: str = "unknown"     # "quantum_safe", "quantum_vulnerable", "hybrid", "unknown"
    standard: str = ""          # e.g. "FIPS 203 (ML-KEM)", "FIPS 204 (ML-DSA)"
    is_nist_approved: bool = False
    is_draft: bool = False
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "status": self.status,
            "standard": self.standard,
            "is_nist_approved": self.is_nist_approved,
            "is_draft": self.is_draft,
            "notes": self.notes,
        }


@dataclass
class PQCAssessment:
    """Complete PQC assessment for an endpoint."""

    host: str
    port: int
    is_quantum_safe: bool = False
    is_hybrid: bool = False
    quantum_safe_algorithms: List[AlgorithmClassification] = field(
        default_factory=list
    )
    quantum_vulnerable_algorithms: List[AlgorithmClassification] = field(
        default_factory=list
    )
    overall_status: str = "quantum_vulnerable"  # "quantum_safe", "quantum_vulnerable", "hybrid"
    risk_level: str = "HIGH"                     # "HIGH", "MEDIUM", "LOW"
    details: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "is_quantum_safe": self.is_quantum_safe,
            "is_hybrid": self.is_hybrid,
            "overall_status": self.overall_status,
            "risk_level": self.risk_level,
            "quantum_safe_algorithms": [
                a.to_dict() for a in self.quantum_safe_algorithms
            ],
            "quantum_vulnerable_algorithms": [
                a.to_dict() for a in self.quantum_vulnerable_algorithms
            ],
            "details": self.details,
        }


class PQCDetector:
    """Classifies the PQC readiness of TLS endpoint analysis results.

    Usage::

        detector = PQCDetector()
        assessment = detector.assess_endpoint(tls_result)
        print(assessment.overall_status)
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def assess_endpoint(self, tls_result: Dict[str, Any]) -> PQCAssessment:
        """Assess PQC readiness from a TLS analysis result dict.

        Parameters
        ----------
        tls_result : dict
            Output of ``TLSAnalyzer.analyze_endpoint().to_dict()``.

        Returns
        -------
        PQCAssessment
        """
        host = tls_result.get("host", "unknown")
        port = tls_result.get("port", 0)
        assessment = PQCAssessment(host=host, port=port)

        # ── Classify key exchange ──
        kex = tls_result.get("key_exchange", "")
        if kex:
            kex_class = self.classify_algorithm(kex, "key_exchange")
            if kex_class.status == "quantum_safe":
                assessment.quantum_safe_algorithms.append(kex_class)
            else:
                assessment.quantum_vulnerable_algorithms.append(kex_class)

        # ── Classify cipher suite (may embed kex info) ──
        cipher = tls_result.get("cipher_suite", "")
        if cipher:
            cipher_class = self.classify_algorithm(cipher, "cipher_suite")
            if cipher_class.status == "quantum_safe":
                assessment.quantum_safe_algorithms.append(cipher_class)
            elif cipher_class.status == "quantum_vulnerable":
                assessment.quantum_vulnerable_algorithms.append(cipher_class)

        # ── Classify certificate signature algorithm ──
        cert = tls_result.get("certificate")
        if cert:
            sig_alg = cert.get("signature_algorithm", "")
            if sig_alg:
                sig_class = self.classify_algorithm(sig_alg, "signature")
                if sig_class.status == "quantum_safe":
                    assessment.quantum_safe_algorithms.append(sig_class)
                else:
                    assessment.quantum_vulnerable_algorithms.append(sig_class)

            # ── Classify public key type ──
            pk_type = cert.get("public_key_type", "")
            if pk_type:
                pk_class = self.classify_algorithm(pk_type, "public_key")
                if pk_class.status == "quantum_safe":
                    assessment.quantum_safe_algorithms.append(pk_class)
                elif pk_class.status not in ("unknown",):
                    assessment.quantum_vulnerable_algorithms.append(pk_class)

        # ── Determine overall status ──
        has_safe = len(assessment.quantum_safe_algorithms) > 0
        has_vuln = len(assessment.quantum_vulnerable_algorithms) > 0

        if has_safe and not has_vuln:
            assessment.is_quantum_safe = True
            assessment.overall_status = "quantum_safe"
            assessment.risk_level = "LOW"
            assessment.details = (
                "All detected algorithms are quantum-safe (NIST-approved)."
            )
        elif has_safe and has_vuln:
            assessment.is_hybrid = True
            assessment.overall_status = "hybrid"
            assessment.risk_level = "MEDIUM"
            assessment.details = (
                "Endpoint uses a mix of quantum-safe and quantum-vulnerable "
                "algorithms.  Migration to fully PQC-only is recommended."
            )
        else:
            assessment.overall_status = "quantum_vulnerable"
            assessment.risk_level = "HIGH"
            assessment.details = (
                "No quantum-safe algorithms detected.  This endpoint is "
                "vulnerable to future quantum attacks (Harvest Now, Decrypt "
                "Later)."
            )

        return assessment

    def classify_algorithm(
        self, name: str, category: str = ""
    ) -> AlgorithmClassification:
        """Classify a single algorithm name.

        Parameters
        ----------
        name : str
            Algorithm or cipher suite name (e.g. ``"ECDHE"``, ``"ML-KEM-768"``).
        category : str
            One of ``"key_exchange"``, ``"signature"``, ``"cipher_suite"``,
            ``"public_key"``.

        Returns
        -------
        AlgorithmClassification
        """
        upper = name.upper().strip()
        canon = self._canonicalize(upper)
        result = AlgorithmClassification(name=name, category=category)

        # ── Check NIST-approved KEM ──
        if self._matches_any(canon, NIST_APPROVED_KEMS):
            result.status = "quantum_safe"
            result.is_nist_approved = True
            result.standard = "FIPS 203 (ML-KEM)"
            return result

        # ── Check NIST-approved signatures ──
        if self._matches_any(canon, NIST_APPROVED_SIGNATURES):
            result.status = "quantum_safe"
            result.is_nist_approved = True
            result.standard = "FIPS 204 (ML-DSA)"
            return result

        # ── Check NIST-approved hash-based signatures ──
        if self._matches_any(canon, NIST_APPROVED_HASH_SIGNATURES):
            result.status = "quantum_safe"
            result.is_nist_approved = True
            result.standard = "FIPS 205 (SLH-DSA)"
            return result

        # ── Check draft PQC ──
        if self._matches_any(canon, DRAFT_PQC_ALGORITHMS):
            result.status = "quantum_safe"
            result.is_draft = True
            result.standard = "Draft NIST PQC"
            result.notes = "Algorithm is in draft stage—not yet fully standardized."
            return result

        # ── Check quantum-vulnerable key exchanges ──
        if category in ("key_exchange", "cipher_suite", ""):
            for vuln in QUANTUM_VULNERABLE_KEY_EXCHANGES:
                if vuln.upper() in upper:
                    result.status = "quantum_vulnerable"
                    result.notes = (
                        f"Uses {vuln}, which is vulnerable to Shor's algorithm."
                    )
                    return result

        # ── Check quantum-vulnerable signatures/public keys ──
        if category in ("signature", "public_key", ""):
            for vuln in QUANTUM_VULNERABLE_SIGNATURES:
                if vuln.upper() in upper:
                    result.status = "quantum_vulnerable"
                    result.notes = (
                        f"Uses {vuln}, which is vulnerable to quantum attacks."
                    )
                    return result

        # ── Symmetric ciphers / hashes (quantum-resistant inherently) ──
        symmetric_patterns = (
            "AES", "CHACHA20", "POLY1305", "SHA256", "SHA384", "SHA512",
            "GCM", "CBC", "CCM",
        )
        for pat in symmetric_patterns:
            if pat in upper:
                result.status = "quantum_resistant"
                result.notes = (
                    "Symmetric cipher / hash — resistant to quantum attacks "
                    "(Grover's provides only quadratic speedup)."
                )
                return result

        result.status = "unknown"
        result.notes = "Algorithm not recognized in PQC classification database."
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _canonicalize(name: str) -> str:
        """Normalize algorithm name for comparison."""
        # Remove common separators
        return re.sub(r"[_\-\s]+", "-", name.upper()).strip("-")

    @staticmethod
    def _matches_any(name: str, reference_set: set) -> bool:
        """Check if *name* matches any entry in *reference_set*."""
        canon_set = {
            re.sub(r"[_\-\s]+", "-", s.upper()).strip("-") for s in reference_set
        }
        return name in canon_set
