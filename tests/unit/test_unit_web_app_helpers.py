from web.app import _host_from_target, _score_to_risk, _validate_password_strength


def test_host_from_target_strips_protocol_and_path():
    assert _host_from_target("https://example.com:443/a/b") == "example.com"


def test_score_to_risk_thresholds():
    assert _score_to_risk(710) == "Low"
    assert _score_to_risk(500) == "Medium"
    assert _score_to_risk(250) == "High"
    assert _score_to_risk(100) == "Critical"


def test_validate_password_strength_rules():
    ok, _ = _validate_password_strength("ValidPassword#123")
    bad, _ = _validate_password_strength("weak")
    assert ok is True
    assert bad is False
