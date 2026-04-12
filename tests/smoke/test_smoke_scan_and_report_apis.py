import json


def test_api_scan_requires_target(app_client):
    resp = app_client.get("/api/scan")
    assert resp.status_code == 400
    payload = json.loads(resp.data)
    assert "error" in payload


def test_api_scans_list_returns_array(app_client):
    resp = app_client.get("/api/scans")
    assert resp.status_code == 200
    payload = json.loads(resp.data)
    assert "data" in payload
    assert isinstance(payload.get("data", {}).get("items", payload), list)


def test_report_schedules_endpoint_returns_list(app_client):
    resp = app_client.get("/report/schedules")
    assert resp.status_code == 200
    payload = json.loads(resp.data)
    # Could be list or standard envelope depending on migration state
    assert isinstance(payload, list) or isinstance(payload.get("data", {}).get("items", payload.get("data", payload)), list)
