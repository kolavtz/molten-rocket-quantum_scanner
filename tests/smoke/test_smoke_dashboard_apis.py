import json


API_ENDPOINTS = [
    "/api/assets",
    "/api/discovery",
    "/api/cbom",
    "/api/pqc-posture",
    "/api/cyber-rating",
    "/api/reports",
]


def test_api_endpoints_return_standard_envelope(app_client):
    expected_keys = {"items", "total", "page", "page_size", "total_pages", "kpis"}
    for path in API_ENDPOINTS:
        resp = app_client.get(path)
        assert resp.status_code == 200, f"{path} returned {resp.status_code}"
        payload = json.loads(resp.data)
        assert expected_keys.issubset(set(payload.keys())), f"{path} missing keys"


def test_api_assets_accepts_query_params(app_client):
    resp = app_client.get("/api/assets?page=1&page_size=10&sort=name&order=asc&q=test")
    assert resp.status_code == 200
    payload = json.loads(resp.data)
    assert payload["page"] == 1
    assert payload["page_size"] == 10
