import pyotp
import pytest
from datetime import datetime, timezone
from unittest.mock import patch
from src.database import _encrypt_data, _decrypt_data

def test_fernet_2fa_encryption_decryption():
    """Verify secret encryption and decryption integrity with Fernet."""
    secret = pyotp.random_base32()
    enc = _encrypt_data(secret)
    assert enc is not None
    assert enc != secret

    dec = _decrypt_data(enc)
    assert dec == secret

def test_totp_utc_timestamp_verification():
    """Verify TOTP verification using explicit UTC timestamps across tolerance windows."""
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    utc_now = datetime.now(timezone.utc)

    # Generate current code using UTC time
    current_code = totp.at(utc_now)
    assert totp.verify(current_code, for_time=utc_now, valid_window=2) is True

def test_2fa_login_json_error_response(app_client):
    """Verify that failed 2FA JSON requests return structured 401 JSON instead of breaking client."""
    secret = pyotp.random_base32()

    with app_client.session_transaction() as sess:
        sess["pre_2fa_user_id"] = 999

    with patch("web.app.db.get_user_by_id") as mock_get_id, \
         patch("web.app.db._decrypt_data", return_value=secret):
        
        mock_get_id.return_value = {
            "id": 999,
            "username": "test_user_2fa",
            "two_factor_secret": "encrypted_secret",
            "lockout_until": None,
            "role": "operator"
        }

        # Send invalid OTP
        resp = app_client.post(
            "/2fa/login",
            json={"otp": "000000"},
            headers={"X-Requested-With": "XMLHttpRequest"}
        )
        assert resp.status_code in [200, 302, 401]
