from src.services.risk_profile_service import derive_risk_level, derive_risk_level_from_scan_report


def test_derive_risk_level_from_overview_score_only():
    assert derive_risk_level(overview_score=85, tls_results=None) == "Low"
    assert derive_risk_level(overview_score=65, tls_results=None) == "Medium"
    assert derive_risk_level(overview_score=45, tls_results=None) == "High"
    assert derive_risk_level(overview_score=20, tls_results=None) == "Critical"


def test_derive_risk_level_from_tls_telemetry_only():
    tls_rows = [
        {
            "tls_version": "TLS 1.0",
            "key_length": 1024,
            "cert_expired": True,
            "cipher_suite": "TLS_RSA_WITH_RC4_128_SHA",
        }
    ]
    assert derive_risk_level(overview_score=None, tls_results=tls_rows) == "Critical"


def test_derive_risk_level_prefers_conservative_score_when_both_present():
    report = {
        "overview": {"average_compliance_score": 92},
        "tls_results": [
            {
                "tls_version": "TLS 1.1",
                "key_length": 1024,
            }
        ],
    }
    # Overview is strong, but TLS telemetry is weak, so risk should remain conservative.
    assert derive_risk_level_from_scan_report(report) in {"High", "Critical"}


def test_derive_risk_level_fallback_when_no_data():
    assert derive_risk_level_from_scan_report({}, fallback="Medium") == "Medium"
