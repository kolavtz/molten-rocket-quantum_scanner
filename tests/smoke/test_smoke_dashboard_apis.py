import json


API_ENDPOINTS = [
    "/api/assets",
    "/api/discovery",
    "/api/distributions/asset-types",
    "/api/distributions/risk-levels",
    "/api/distributions/ip-versions",
    "/api/distributions/cert-expiry",
    "/api/enterprise-metrics",
    "/api/cbom",
    "/api/pqc-posture",
    "/api/cyber-rating",
    "/api/reports",
]


def test_api_endpoints_return_standard_envelope(app_client):
    expected_top_level_keys = {"success", "data", "filters"}
    expected_data_keys = {"items", "total", "page", "page_size", "total_pages"}
    
    for path in API_ENDPOINTS:
        resp = app_client.get(path)
        assert resp.status_code == 200, f"{path} returned {resp.status_code}"
        payload = json.loads(resp.data)
        
        # Verify top-level structure
        assert expected_top_level_keys.issubset(set(payload.keys())), f"{path} missing top-level keys"
        
        # Verify data structure
        data = payload.get("data", {})
        assert expected_data_keys.issubset(set(data.keys())), f"{path} data missing keys"


def test_api_assets_accepts_query_params(app_client):
    resp = app_client.get("/api/assets?page=1&page_size=10&sort=name&order=asc&q=test")
    assert resp.status_code == 200
    payload = json.loads(resp.data)
    assert payload["success"] is True
    data = payload["data"]
    assert data["page"] == 1
    assert data["page_size"] == 10

    resp_search = app_client.get("/api/assets?page=1&page_size=10&sort=name&order=asc&search=test")
    assert resp_search.status_code == 200
    payload_search = json.loads(resp_search.data)
    assert payload_search["success"] is True
    filters = payload_search.get("filters", {})
    assert filters.get("search") == "test"
