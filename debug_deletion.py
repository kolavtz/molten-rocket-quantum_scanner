import sys
import traceback
from datetime import datetime, timezone
from sqlalchemy import func

sys.path.append('.')
from src.db import db_session
from src.models import Asset, CBOMEntry, CBOMSummary, CyberRating, Certificate, ComplianceScore, DiscoveryItem, PQCClassification, Scan

class MockUser:
    id = "1786cc59-27f5-4ecf-8716-223b3bb1b287"

def _soft_delete_asset_test(asset: Asset, user_id) -> None:
    now = datetime.now(timezone.utc)
    asset.is_deleted = True
    asset.deleted_at = now
    asset.deleted_by_user_id = user_id

    for child in getattr(asset, 'discovery_items', []):
        child.is_deleted = True
        child.deleted_at = now
        child.deleted_by_user_id = user_id
    for child in getattr(asset, 'certificates', []):
        child.is_deleted = True
        child.deleted_at = now
        child.deleted_by_user_id = user_id

try:
    asset = db_session.query(Asset).filter(Asset.is_deleted == False).first()
    if not asset:
        asset = Asset(name="test-dummy", target="test-dummy", asset_type="Server")
        db_session.add(asset)
        db_session.commit()
    
    _soft_delete_asset_test(asset, MockUser.id)
    db_session.commit()

except Exception as e:
    with open("traceback.txt", "w") as f:
        f.write(traceback.format_exc())
    print("Crashed and logged traceback.")
    db_session.rollback()
