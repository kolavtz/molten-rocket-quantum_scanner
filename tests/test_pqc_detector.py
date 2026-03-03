"""
Unit tests for the PQC Detector module.
"""
import pytest

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.scanner.pqc_detector import PQCDetector, PQCAssessment, AlgorithmClassification


class TestClassifyAlgorithm:
    """Tests for PQCDetector.classify_algorithm()."""

    def setup_method(self):
        self.detector = PQCDetector()

    # ── Quantum-Safe (NIST-approved) ──

    def test_ml_kem_768(self):
        c = self.detector.classify_algorithm("ML-KEM-768", "key_exchange")
        assert c.status == "quantum_safe"
        assert c.is_nist_approved is True
        assert "FIPS 203" in c.standard

    def test_kyber1024(self):
        c = self.detector.classify_algorithm("KYBER1024", "key_exchange")
        assert c.status == "quantum_safe"

    def test_ml_dsa_65(self):
        c = self.detector.classify_algorithm("ML-DSA-65", "signature")
        assert c.status == "quantum_safe"
        assert "FIPS 204" in c.standard

    def test_slh_dsa(self):
        c = self.detector.classify_algorithm("SLH-DSA-SHA2-256f", "signature")
        assert c.status == "quantum_safe"
        assert "FIPS 205" in c.standard

    def test_dilithium3(self):
        c = self.detector.classify_algorithm("DILITHIUM3", "signature")
        assert c.status == "quantum_safe"

    # ── Draft PQC ──

    def test_falcon512(self):
        c = self.detector.classify_algorithm("FALCON512", "signature")
        assert c.status == "quantum_safe"
        assert c.is_draft is True

    def test_hqc_256(self):
        c = self.detector.classify_algorithm("HQC-256", "key_exchange")
        assert c.status == "quantum_safe"
        assert c.is_draft is True

    # ── Quantum-Vulnerable ──

    def test_ecdhe_vulnerable(self):
        c = self.detector.classify_algorithm("ECDHE", "key_exchange")
        assert c.status == "quantum_vulnerable"
        assert "Shor" in c.notes

    def test_rsa_vulnerable(self):
        c = self.detector.classify_algorithm("RSA", "key_exchange")
        assert c.status == "quantum_vulnerable"

    def test_ecdsa_signature(self):
        c = self.detector.classify_algorithm("ECDSA", "signature")
        assert c.status == "quantum_vulnerable"

    def test_dsa_signature(self):
        c = self.detector.classify_algorithm("DSA", "signature")
        assert c.status == "quantum_vulnerable"

    def test_ed25519_signature(self):
        c = self.detector.classify_algorithm("Ed25519", "public_key")
        assert c.status == "quantum_vulnerable"

    # ── Symmetric (quantum-resistant) ──

    def test_aes_256(self):
        c = self.detector.classify_algorithm("AES-256-GCM", "cipher")
        assert c.status == "quantum_resistant"
        assert "Grover" in c.notes

    def test_chacha20(self):
        c = self.detector.classify_algorithm("CHACHA20-POLY1305", "cipher")
        assert c.status == "quantum_resistant"

    # ── Unknown ──

    def test_unknown_algorithm(self):
        c = self.detector.classify_algorithm("MYSTERY-ALGO-42", "key_exchange")
        assert c.status == "unknown"


class TestAssessEndpoint:
    """Tests for PQCDetector.assess_endpoint()."""

    def setup_method(self):
        self.detector = PQCDetector()

    def test_quantum_vulnerable_endpoint(self):
        tls_result = {
            "host": "example.com",
            "port": 443,
            "key_exchange": "ECDHE",
            "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384",
            "certificate": {
                "signature_algorithm": "sha256WithRSAEncryption",
                "public_key_type": "RSA",
            },
        }
        assessment = self.detector.assess_endpoint(tls_result)
        assert assessment.overall_status == "quantum_vulnerable"
        assert assessment.is_quantum_safe is False
        assert assessment.risk_level == "HIGH"

    def test_quantum_safe_endpoint(self):
        tls_result = {
            "host": "pqc.example.com",
            "port": 443,
            "key_exchange": "ML-KEM-768",
            "cipher_suite": "ML-KEM-768-AES256-GCM",
            "certificate": {
                "signature_algorithm": "ML-DSA-65",
                "public_key_type": "ML-DSA-65",
            },
        }
        assessment = self.detector.assess_endpoint(tls_result)
        assert assessment.overall_status == "quantum_safe"
        assert assessment.is_quantum_safe is True
        assert assessment.risk_level == "LOW"

    def test_to_dict(self):
        tls_result = {
            "host": "test.com", "port": 443,
            "key_exchange": "ECDHE",
            "cipher_suite": "", "certificate": None,
        }
        assessment = self.detector.assess_endpoint(tls_result)
        d = assessment.to_dict()
        assert "host" in d
        assert "overall_status" in d
        assert isinstance(d["quantum_vulnerable_algorithms"], list)
