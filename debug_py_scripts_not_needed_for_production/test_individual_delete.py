import sys
import os
sys.path.append(os.getcwd())

from web.app import app
from src.db import db_session
from src.models import Asset, User

def test_individual_delete():
    user = db_session.query(User).filter(User.role == "Admin").first()
    if not user:
        user = User(username="temp_admin", role="Admin")
        db_session.add(user)
        db_session.commit()
        
    from src.services.asset_service import AssetService
    assets = AssetService().load_combined_assets()
    if len(assets) < 1:
        print("No assets for delete test.")
        return
        
    target_id = assets[0]['id']
    print(f"Testing individual delete for Asset ID: {target_id}")
    
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess['_user_id'] = str(user.id)
            sess['role'] = "Admin"
            
        app.config['WTF_CSRF_ENABLED'] = False 
        
        # Hit the individual delete endpoint
        res = client.post(f"/assets/{target_id}/delete", follow_redirects=True)
        
        print(f"Status Code: {res.status_code}")
        
        assets_after = AssetService().load_combined_assets()
        found = any(a['id'] == target_id for a in assets_after)
        
        if found:
             print("FAIL: Individual delete route failed to remove asset!")
        else:
             print("SUCCESS: Individual delete route deleted asset!")

if __name__ == "__main__":
    test_individual_delete()
