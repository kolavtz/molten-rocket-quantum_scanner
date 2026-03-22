import sys
import os
sys.path.append(os.getcwd())

from src.db import db_session
from src.models import Asset
from src.services.asset_service import AssetService
from web.routes.assets import _soft_delete_asset

def test():
    service = AssetService()
    assets_before = service.load_combined_assets()
    print(f"Total Assets Before: {len(assets_before)}")
    
    if not assets_before:
        print("No assets to test with.")
        return
        
    target_id = assets_before[0]['id']
    print(f"Soft deleting asset ID: {target_id}")
    
    asset = db_session.get(Asset, target_id)
    # Simulate soft delete
    _soft_delete_asset(asset)
    db_session.commit()
    
    assets_after = service.load_combined_assets()
    print(f"Total Assets After: {len(assets_after)}")
    
    # Check if target asset is present in after
    found = any(a['id'] == target_id for a in assets_after)
    if found:
        print("FAIL: Deleted asset still in list!")
    else:
        print("SUCCESS: Deleted asset removed from list!")

if __name__ == "__main__":
    test()
