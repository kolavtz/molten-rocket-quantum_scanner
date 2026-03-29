#!/usr/bin/env python
"""Test bulk delete AJAX with proper CSRF handling"""
import json
import sys
sys.path.insert(0, '.')

from web.app import app
from src.db import db_session
from src.models import Asset
from unittest.mock import patch
from flask_wtf.csrf import generate_csrf as flask_generate_csrf

def _new_target(name):
    """Create a unique target"""
    import uuid
    return f"{name}-{uuid.uuid4().hex[:8]}"

app = app
# Test WITH CSRF enabled to simulate production
app.config["WTF_CSRF_ENABLED"] = True
app.config["TESTING"] = True
app.config["LOGIN_DISABLED"] = False

with app.app_context():
    # Clean up old test assets
    db_session.query(Asset).filter(Asset.target.ilike('%csrf-delete%')).delete()
    db_session.commit()
    
    # Create test assets
    asset_a = Asset(target=_new_target('csrf-delete'), asset_type='Web App', is_deleted=False)
    asset_b = Asset(target=_new_target('csrf-delete'), asset_type='Web App', is_deleted=False)
    db_session.add_all([asset_a, asset_b])
    db_session.commit()
    
    a_id, b_id = int(asset_a.id), int(asset_b.id)
    print(f"Created assets: {a_id}, {b_id}")
    
with app.test_client() as client:
    # First, do a GET request to establish a session and get CSRF token
    response = client.get('/assets')
    print(f"\nGET /assets status: {response.status_code}")
    
    # Get the CSRF token from the response
    csrf_token = ""
    if response.status_code == 200:
        # Try to extract from HTML meta tag
        html = response.get_data(as_text=True)
        import re
        match = re.search(r'<meta name="csrf-token" content="([^"]+)">', html)
        if match:
            csrf_token = match.group(1)
            print(f"Found CSRF token in HTML: {csrf_token[:20]}...")

    # Now test the AJAX endpoint with a valid CSRF token
    payload = {
        'selected_asset_ids': f'{a_id},{b_id}',
        'bulk_action': 'bulk-delete',
        'csrf_token': csrf_token
    }
    
    print(f"\nSending bulk delete with CSRF token (length: {len(csrf_token)})")
    
    # Test with a Manager user
    with patch('web.routes.assets.current_user') as mock_user:
        mock_user.role = 'Manager'
        mock_user.id = 999
        mock_user.username = 'test_manager'
        
        resp = client.post(
            '/api/assets/bulk-delete',
            data=json.dumps(payload),
            content_type='application/json',
            headers={
                'Accept': 'application/json',
                'X-CSRFToken': csrf_token
            }
        )
    
    print(f"\nResponse status: {resp.status_code}")
    if resp.status_code == 200:
        response_data = resp.get_json()
        print(f"Response data: {json.dumps(response_data, indent=2)}")
        
        with app.app_context():
            # Check if deletion worked
            reloaded_a = db_session.query(Asset).filter(Asset.id == a_id).first()
            reloaded_b = db_session.query(Asset).filter(Asset.id == b_id).first()
            
            print(f"\nAsset {a_id} is_deleted: {reloaded_a.is_deleted if reloaded_a else 'NOT FOUND'}")
            print(f"Asset {b_id} is_deleted: {reloaded_b.is_deleted if reloaded_b else 'NOT FOUND'}")
    else:
        print(f"Response Content-Type: {resp.content_type}")
        print(f"Response data (first 200 chars): {resp.get_data(as_text=True)[:200]}")

