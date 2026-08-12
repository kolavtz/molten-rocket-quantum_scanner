import pytest
import pyotp
from unittest.mock import patch

def test_json_login_invalid_credentials(app_client):
    resp = app_client.post(
        "/login",
        json={"username": "nonexistent_user", "password": "wrongpassword"},
        headers={"X-Requested-With": "XMLHttpRequest"}
    )
    assert resp.status_code == 401
    data = resp.get_json()
    assert data["success"] is False
    assert "Invalid credentials" in data["error"]

def test_json_login_success_without_2fa(app_client):
    with patch("web.app.db.get_user_by_username") as mock_get_user, \
         patch("web.app.check_password_hash", return_value=True), \
         patch("web.app.db.mark_login_success"), \
         patch("web.app.REQUIRE_2FA", False):
        
        mock_get_user.return_value = {
            "id": 1,
            "username": "admin",
            "password_hash": "pbkdf2:sha256:...",
            "is_active": True,
            "two_factor_enabled": False,
            "must_change_password": False,
            "lockout_until": None,
        }

        resp = app_client.post(
            "/login",
            json={"username": "admin", "password": "correctpassword"},
            headers={"X-Requested-With": "XMLHttpRequest"}
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert "/dashboard" in data["redirect"]

def test_json_login_success_requiring_2fa(app_client):
    with patch("web.app.db.get_user_by_username") as mock_get_user, \
         patch("web.app.check_password_hash", return_value=True):
        
        mock_get_user.return_value = {
            "id": 2,
            "username": "user_2fa",
            "password_hash": "pbkdf2:sha256:...",
            "is_active": True,
            "two_factor_enabled": True,
            "must_change_password": False,
            "lockout_until": None,
        }

        resp = app_client.post(
            "/login",
            json={"username": "user_2fa", "password": "correctpassword"},
            headers={"X-Requested-With": "XMLHttpRequest"}
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["mfa_required"] is True
        assert "/2fa/login" in data["redirect"]

def test_json_2fa_login_verification(app_client):
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    valid_code = totp.now()

    with app_client.session_transaction() as sess:
        sess["pre_2fa_user_id"] = 2

    with patch("web.app.db.get_user_by_id") as mock_get_id, \
         patch("web.app.db._decrypt_data", return_value=secret), \
         patch("web.app.db.mark_login_success"):
        
        mock_get_id.return_value = {
            "id": 2,
            "username": "user_2fa",
            "two_factor_secret": "encrypted_secret",
            "lockout_until": None,
            "role": "operator"
        }

        resp = app_client.post(
            "/2fa/login",
            json={"otp": valid_code},
            headers={"X-Requested-With": "XMLHttpRequest"}
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert "/dashboard" in data["redirect"]
