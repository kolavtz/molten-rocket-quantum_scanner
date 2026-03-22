import json


def test_unknown_api_route_returns_json_error(app_client):
    resp = app_client.get("/api/definitely-does-not-exist")
    assert resp.status_code == 404
    payload = json.loads(resp.data)
    assert payload.get("status") == "error"
    assert "message" in payload
