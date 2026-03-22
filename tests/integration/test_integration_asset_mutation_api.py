import json
from unittest.mock import patch
from uuid import uuid4

from src.db import db_session
from src.models import Asset


def test_dashboard_add_asset_api(app_client):
    target = f"asset-add-{uuid4().hex[:10]}.example"
    resp = app_client.post(
        "/dashboard/api/assets",
        data=json.dumps({"target": target, "type": "Web App", "owner": "SecOps", "risk_level": "Medium"}),
        content_type="application/json",
        headers={"Accept": "application/json"},
    )
    assert resp.status_code == 200
    payload = json.loads(resp.data)
    assert payload.get("status") == "success"


def test_asset_delete_api_with_manager_role(app_client):
    target = f"asset-del-{uuid4().hex[:10]}.example"
    asset = Asset(target=target, asset_type="Web App", is_deleted=False)
    db_session.add(asset)
    db_session.commit()

    with patch("web.routes.assets.current_user") as route_user:
        route_user.role = "Manager"
        route_user.id = 501
        route_user.username = "manager"
        resp = app_client.post(
            f"/api/assets/{asset.id}/delete",
            data=json.dumps({}),
            content_type="application/json",
            headers={"Accept": "application/json"},
        )

    assert resp.status_code == 200
    payload = json.loads(resp.data)
    assert payload.get("status") == "success"
