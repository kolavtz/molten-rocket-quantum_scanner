import time


def test_dashboard_page_latency_under_threshold(app_client):
    start = time.perf_counter()
    resp = app_client.get("/dashboard/assets")
    elapsed = time.perf_counter() - start

    assert resp.status_code == 200
    assert elapsed < 5.0


def test_asset_inventory_page_latency_under_threshold(app_client):
    start = time.perf_counter()
    resp = app_client.get("/asset-inventory")
    elapsed = time.perf_counter() - start

    assert resp.status_code == 200
    assert elapsed < 5.0
