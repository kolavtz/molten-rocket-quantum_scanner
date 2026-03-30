import json


def test_dashboard_api_get(app_client):
    resp = app_client.get("/api/dashboard")
    assert resp.status_code == 200
    payload = json.loads(resp.data)
    assert payload.get("status") == "success"
    assert isinstance(payload.get("data"), dict)


def test_dashboard_api_refresh_action(app_client):
    resp = app_client.post(
        "/api/dashboard",
        data=json.dumps({"action": "dashboard.refresh"}),
        content_type="application/json",
    )
    assert resp.status_code == 200
    payload = json.loads(resp.data)
    assert payload.get("status") == "success"
