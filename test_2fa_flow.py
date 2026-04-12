import sys
import json
import hashlib
from unittest.mock import patch
from werkzeug.security import generate_password_hash

sys.path.append('.')
import pyotp
from web.app import app
# Test helpers: run in testing mode and disable CSRF to simplify form posts
app.config['TESTING'] = True
app.config['WTF_CSRF_ENABLED'] = False


def test_2fa_setup_and_enable_flow():
    user = {
        'id': 'u1',
        'username': 'alice',
        'email': 'alice@example.com',
        'password_hash': generate_password_hash('secret'),
        'is_active': True,
        'two_factor_enabled': False,
        'must_change_password': False,
        'role': 'Viewer'
    }

    with app.test_client() as client:
        with patch('web.app.db.get_user_by_username', return_value=user) as mock_get_username, \
             patch('web.app.db.set_user_2fa', return_value=True) as mock_set_2fa, \
             patch('web.app.db.get_user_by_id', return_value=user) as mock_get_by_id, \
             patch('web.app.db.mark_login_success', return_value=None) as mock_mark_login, \
             patch('web.app.REQUIRE_2FA', True):

            # Submit credentials to trigger pre-2FA flow
            resp = client.post('/login', data={'username': user['username'], 'password': 'secret'}, follow_redirects=False)
            assert resp.status_code == 302

            # pre-2fa context should be present (REQUIRE_2FA forced)
            with client.session_transaction() as sess:
                assert sess.get('pre_2fa_user_id') == user['id']

            # GET the setup page to generate secret (stored in session)
            resp = client.get('/2fa/setup')
            assert resp.status_code == 200
            with client.session_transaction() as sess:
                secret = sess.get('pre_2fa_secret')
                assert secret is not None

            # compute TOTP and POST to /2fa/setup
            totp = pyotp.TOTP(secret)
            code = totp.now()
            resp = client.post('/2fa/setup', data={'otp': code}, follow_redirects=True)
            assert resp.status_code == 200

            # ensure DB helper was called to persist the secret & backup codes
            assert mock_set_2fa.called
            called_args = mock_set_2fa.call_args[0]
            assert called_args[0] == user['id']
            assert called_args[1] == secret
            assert called_args[2] is not None


def test_2fa_login_with_backup_code():
    user = {
        'id': 'u2',
        'username': 'bob',
        'email': 'bob@example.com',
        'password_hash': generate_password_hash('secret'),
        'is_active': True,
        'two_factor_enabled': True,
        'two_factor_secret': 'ENCSECRET',
        'backup_codes': 'ENCBACKUP',
        'role': 'Viewer'
    }

    # create a backup code and its hash as stored in DB
    backup_plain = 'backupCODE123'
    code_hash = hashlib.sha256(backup_plain.encode()).hexdigest()
    backup_list = [{'code_hash': code_hash, 'used': False}]

    with app.test_client() as client:
        # seed pre-2fa session (as login step would do)
        with client.session_transaction() as sess:
            sess['pre_2fa_user_id'] = user['id']
            sess['pre_2fa_remember'] = False

        # fake decrypt to return secret or backup JSON depending on input
        def fake_decrypt(val):
            if val == user['two_factor_secret']:
                return 'FAKESECRET'
            if val == user['backup_codes']:
                return json.dumps(backup_list)
            return val

        with patch('web.app.db.get_user_by_id', return_value=user) as mock_get_by_id, \
             patch('web.app.db._decrypt_data', side_effect=fake_decrypt) as mock_decrypt, \
             patch('web.app.db.mark_backup_code_used', return_value=True) as mock_mark_used, \
             patch('web.app.db.mark_login_success', return_value=None) as mock_mark_login:

            # Submit backup code as OTP (non-numeric fallback)
            resp = client.post('/2fa/login', data={'otp': backup_plain}, follow_redirects=False)

            # Successful login should redirect (302) or return dashboard (200 depending on follow_redirects)
            assert resp.status_code in (200, 302)
            assert mock_mark_used.called
