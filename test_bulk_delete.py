import sys
import os
sys.path.append(os.getcwd())

# Create a mock flask app context and hit the route function directly
from web.app import app
from src.db import db_session
from src.models import Asset, User

def test_bulk_delete():
    # Find an admin user to login as
    user = db_session.query(User).filter(User.role == "Admin").first()
    if not user:
        # Create one
        user = User(username="temp_admin", role="Admin")
        db_session.add(user)
        db_session.commit()
    
    # Get all active assets
    from src.services.asset_service import AssetService
    assets = AssetService().load_combined_assets()
    if len(assets) < 1:
        print("No assets for bulk delete test.")
        return
        
    target_id = assets[0]['id']
    print(f"Testing bulk delete for Asset ID: {target_id} using Admin User: {user.username}")
    
    with app.test_client() as client:
        with client.session_transaction() as sess:
            # Login user manually for Flask-Login
            sess['_user_id'] = str(user.id)
            sess['role'] = "Admin"
            
        # Verify user is logged in the request by doing a GET first
        # But we can just POST directly if the session stands.
        
        # Simulate CSRF if needed. If CSRF is enabled, test_client doesn't enforce it if not explicitly configured to block, or we can disable just for this test
        # Actually in test mode, Flask-WTF often needs a token or can be bypassed
        app.config['WTF_CSRF_ENABLED'] = False 
        
        res = client.post("/assets/bulk-delete", data={
            "bulk_action": "bulk-delete",
            "selected_asset_ids": str(target_id)
        }, follow_redirects=True)
        
        print(f"Status Code: {res.status_code}")
        
        assets_after = AssetService().load_combined_assets()
        found = any(a['id'] == target_id for a in assets_after)
        
        if found:
             print("FAIL: Bulk delete failed to remove asset!")
        else:
             print("SUCCESS: Bulk delete route deleted asset!")

if __name__ == "__main__":
    test_bulk_delete()
