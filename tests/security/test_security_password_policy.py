from web.app import _validate_password_strength


def test_password_policy_accepts_strong_password():
    ok, message = _validate_password_strength("StrongP@ssword123")
    assert ok is True
    assert message == ""


def test_password_policy_rejects_missing_special_char():
    ok, message = _validate_password_strength("StrongPassword123")
    assert ok is False
    assert "special character" in message
