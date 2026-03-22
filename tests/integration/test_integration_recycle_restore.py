import json
from datetime import datetime, timezone
from unittest.mock import patch
from uuid import uuid4

from src.db import db_session
from src.models import Asset


def test_recycle_bin_restore_assets_json(app_client):
    target = f"restore-{uuid4().hex[:10]}.example"
    asset = Asset(target=target, asset_type="Web App", is_deleted=True, deleted_at=datetime.now(timezone.utc))
    db_session.add(asset)
    db_session.commit()

    with patch("web.app.current_user") as route_user:
        route_user.role = "Admin"
        route_user.id = 700
        route_user.username = "admin"
        resp = app_client.post(
            "/recycle-bin",
            data=json.dumps({"action": "restore_assets", "asset_ids": [asset.id]}),
            content_type="application/json",
            headers={"Accept": "application/json"},
        )
    assert resp.status_code == 200
    payload = json.loads(resp.data)
    assert payload.get("status") == "success"
