import os
import sys

sys.path.append('.')
from web.app import app
from flask import g

class MockUser:
    id = 1
    role = 'Admin'
    is_authenticated = True
    is_active = True
    username = 'AdminUser'
    def get_id(self): return "1"

@app.login_manager.user_loader
def load_user(user_id):
    return MockUser()

with app.test_client() as client:
    with client.session_transaction() as sess:
        sess['_user_id'] = '1'
        sess['_fresh'] = True
    
    routes = ['/', '/asset-inventory', '/cbom-dashboard', '/pqc-posture', '/cyber-rating']
    for r in routes:
        try:
            resp = client.get(r, follow_redirects=True)
            print(f"{r}: {resp.status_code}")
        except Exception as e:
            print(f"{r}: FAILED - {e}")
