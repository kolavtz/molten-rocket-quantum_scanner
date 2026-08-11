#!/usr/bin/env python
"""Test that bulk delete returns JSON error when CSRF is missing"""
import json
import sys
sys.path.insert(0, '.')

from web.app import app
from src.db import db_session
from src.models import Asset
from unittest.mock import patch

def _new_target(name):
    """Create a unique target"""
    import uuid
    return f"{name}-{uuid.uuid4().hex[:8]}"

app.config["WTF_CSRF_ENABLED"] = True
app.config["TESTING"] = True

with app.app_context():
    # Clean up old test assets
    db_session.query(Asset).filter(Asset.target.ilike('%csrf-error-test%')).delete()
    db_session.commit()
    
    # Create test assets
    asset_a = Asset(target=_new_target('csrf-error-test'), asset_type='Web App', is_deleted=False)
    asset_b = Asset(target=_new_target('csrf-error-test'), asset_type='Web App', is_deleted=False)
    db_session.add_all([asset_a, asset_b])
    db_session.commit()
    
    a_id, b_id = int(asset_a.id), int(asset_b.id)
    print(f"Created assets: {a_id}, {b_id}")

with app.test_client() as client:
    # Test bulk delete with MISSING csrf token (should return JSON error, not redirect)
    payload = {
        'selected_asset_ids': f'{a_id},{b_id}',
        'bulk_action': 'bulk-delete',
        'csrf_token': ''  # Empty token
    }
    
    print(f"\nSending bulk delete with MISSING CSRF token...")
    
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
                'X-CSRFToken': ''  # Empty token
            }
        )
    
    print(f"\nResponse status: {resp.status_code}")
    print(f"Response Content-Type: {resp.content_type}")
    
    if resp.content_type == 'application/json':
        response_data = resp.get_json()
        print(f"Response JSON: {json.dumps(response_data, indent=2)}")
        print(f"✓ Now returns JSON with proper error message!" if response_data.get('status') == 'error' else "✗ Error response format wrong")
    else:
        print(f"✗ Response is not JSON! Content: {resp.get_data(as_text=True)[:200]}")
