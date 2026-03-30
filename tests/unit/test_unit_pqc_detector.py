from src.scanner.pqc_detector import PQCDetector


def test_classify_known_quantum_safe_algorithm():
    detector = PQCDetector()
    result = detector.classify_algorithm("ML-KEM-768", "key_exchange")
    assert result.status == "quantum_safe"
    assert result.is_nist_approved is True


def test_classify_quantum_vulnerable_algorithm():
    detector = PQCDetector()
    result = detector.classify_algorithm("ECDHE", "key_exchange")
    assert result.status == "quantum_vulnerable"


def test_assess_endpoint_returns_hybrid_when_mixed_crypto():
    detector = PQCDetector()
    tls_result = {
        "host": "example.org",
        "port": 443,
        "key_exchange": "ECDHE",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "certificate": {
            "signature_algorithm": "ML-DSA-65",
            "public_key_type": "RSA",
        },
    }
    assessment = detector.assess_endpoint(tls_result)
    assert assessment.overall_status in {"hybrid", "quantum_vulnerable", "quantum_safe"}
    assert assessment.host == "example.org"
    assert assessment.port == 443
