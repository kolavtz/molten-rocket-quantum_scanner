from src.db import db_session
from src.models import Asset

asset = db_session.query(Asset).filter(Asset.is_deleted == False).first()
if asset:
    print(f"SOFT_DELETE_SUCCESS:{asset.id}:{asset.name}")
    asset.is_deleted = True
    db_session.commit()
else:
    print("NO_ASSETS_FOUND")
