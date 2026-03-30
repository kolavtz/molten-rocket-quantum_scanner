"""
Unit tests for Quantum-Safe Checker and Certificate Issuer.
"""
import pytest

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.validator.quantum_safe_checker import QuantumSafeChecker, ValidationResult
from src.validator.certificate_issuer import CertificateIssuer, QuantumSafeLabel


# ── Test Data ──

VULNERABLE_TLS = {
    "host": "api.bank.com",
    "port": 443,
    "protocol_version": "TLSv1.2",
    "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384",
    "key_exchange": "ECDHE",
    "certificate": {
        "signature_algorithm": "sha256WithRSAEncryption",
        "public_key_type": "RSA",
        "public_key_bits": 2048,
        "is_expired": False,
        "days_until_expiry": 200,
        "not_after": "Jun 15 2026",
    },
}

VULNERABLE_PQC = {
    "overall_status": "quantum_vulnerable",
    "is_quantum_safe": False,
    "risk_level": "HIGH",
}

SAFE_TLS = {
    "host": "secure.bank.com",
    "port": 443,
    "protocol_version": "TLSv1.3",
    "cipher_suite": "TLS_AES_256_GCM_SHA384",
    "key_exchange": "ML-KEM-768",
    "certificate": {
        "signature_algorithm": "ML-DSA-65",
        "public_key_type": "ML-DSA-65",
        "public_key_bits": 0,
        "is_expired": False,
        "days_until_expiry": 300,
        "not_after": "Dec 31 2026",
    },
}

SAFE_PQC = {
    "overall_status": "quantum_safe",
    "is_quantum_safe": True,
    "risk_level": "LOW",
}


class TestQuantumSafeChecker:
    """Tests for QuantumSafeChecker.validate()."""

    def setup_method(self):
        self.checker = QuantumSafeChecker()

    def test_vulnerable_endpoint_non_compliant(self):
        result = self.checker.validate(VULNERABLE_TLS, VULNERABLE_PQC)
        assert result.label == "Non-Compliant"
        assert result.is_quantum_safe is False
        assert result.compliance_score < 50

    def test_vulnerable_has_critical_findings(self):
        result = self.checker.validate(VULNERABLE_TLS, VULNERABLE_PQC)
        assert result.critical_count > 0

    def test_safe_endpoint_pqc_ready(self):
        result = self.checker.validate(SAFE_TLS, SAFE_PQC)
        assert result.label == "PQC Ready"
        assert result.is_quantum_safe is True
        assert result.compliance_score >= 90

    def test_recommendations_generated(self):
        result = self.checker.validate(VULNERABLE_TLS, VULNERABLE_PQC)
        assert len(result.recommendations) > 0

    def test_hndl_risk_banking_keyword(self):
        result = self.checker.validate(VULNERABLE_TLS, VULNERABLE_PQC)
        # "api" keyword in host should give HIGH risk
        assert result.hndl_risk_level == "HIGH"

    def test_hndl_risk_low_for_public_pqc_tls13(self):
        tls = {
            "host": "www.public-site.example",
            "port": 443,
            "protocol_version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "key_exchange": "ML-KEM-768",
            "certificate": {
                "signature_algorithm": "ML-DSA-65",
                "public_key_type": "ML-DSA-65",
                "public_key_bits": 0,
                "is_expired": False,
                "days_until_expiry": 180,
                "not_after": "Dec 31 2026",
            },
        }
        pqc = {
            "overall_status": "quantum_safe",
            "is_quantum_safe": True,
            "risk_level": "LOW",
        }

        result = self.checker.validate(tls, pqc)
        assert result.hndl_risk_level == "LOW"

    def test_hndl_risk_medium_for_public_classical_tls12(self):
        tls = {
            "host": "www.public-site.example",
            "port": 443,
            "protocol_version": "TLSv1.2",
            "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384",
            "key_exchange": "ECDHE",
            "certificate": {
                "signature_algorithm": "sha256WithRSAEncryption",
                "public_key_type": "RSA",
                "public_key_bits": 2048,
                "is_expired": False,
                "days_until_expiry": 180,
                "not_after": "Dec 31 2026",
            },
        }
        pqc = {
            "overall_status": "quantum_vulnerable",
            "is_quantum_safe": False,
            "risk_level": "HIGH",
        }

        result = self.checker.validate(tls, pqc)
        assert result.hndl_risk_level == "MEDIUM"

    def test_to_dict_structure(self):
        result = self.checker.validate(VULNERABLE_TLS, VULNERABLE_PQC)
        d = result.to_dict()
        assert "findings" in d
        assert "recommendations" in d
        assert "compliance_score" in d

    def test_weak_rsa_finding(self):
        result = self.checker.validate(VULNERABLE_TLS, VULNERABLE_PQC)
        finding_titles = [f.title for f in result.findings]
        assert any("Weak RSA" in t for t in finding_titles)

    def test_tls12_medium_finding(self):
        result = self.checker.validate(VULNERABLE_TLS, VULNERABLE_PQC)
        finding_titles = [f.title for f in result.findings]
        assert any("TLS 1.2" in t for t in finding_titles)


class TestCertificateIssuer:
    """Tests for CertificateIssuer."""

    def setup_method(self):
        self.issuer = CertificateIssuer()

    def test_fully_quantum_safe_label(self):
        checker = QuantumSafeChecker()
        result = checker.validate(SAFE_TLS, SAFE_PQC)
        label = self.issuer.issue_label(result.to_dict())
        # 100% score with zero findings -> "Fully Quantum Safe"
        assert label.label == "Fully Quantum Safe"
        assert label.compliance_score >= 90
        assert label.badge_color == "#10b981"  # emerald

    def test_non_compliant_label(self):
        checker = QuantumSafeChecker()
        result = checker.validate(VULNERABLE_TLS, VULNERABLE_PQC)
        label = self.issuer.issue_label(result.to_dict())
        assert label.label == "Non-Compliant"
        assert label.badge_color == "#ef4444"

    def test_label_has_checksum(self):
        checker = QuantumSafeChecker()
        result = checker.validate(SAFE_TLS, SAFE_PQC)
        label = self.issuer.issue_label(result.to_dict())
        assert len(label.checksum) == 64  # SHA-256 hex

    def test_label_validity_period(self):
        checker = QuantumSafeChecker()
        result = checker.validate(SAFE_TLS, SAFE_PQC)
        label = self.issuer.issue_label(result.to_dict())
        assert label.valid_until != ""

    def test_issue_labels_batch(self):
        checker = QuantumSafeChecker()
        r1 = checker.validate(SAFE_TLS, SAFE_PQC).to_dict()
        r2 = checker.validate(VULNERABLE_TLS, VULNERABLE_PQC).to_dict()
        labels = self.issuer.issue_labels([r1, r2])
        assert len(labels) == 2
        assert labels[0].label == "Fully Quantum Safe"
        assert labels[1].label == "Non-Compliant"

    def test_to_dict(self):
        checker = QuantumSafeChecker()
        result = checker.validate(SAFE_TLS, SAFE_PQC)
        label = self.issuer.issue_label(result.to_dict())
        d = label.to_dict()
        assert "label_id" in d
        assert "checksum" in d
        assert "badge_color" in d
