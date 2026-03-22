import time


def test_api_assets_latency_under_threshold(app_client):
    start = time.perf_counter()
    resp = app_client.get("/api/assets?page=1&page_size=25")
    elapsed = time.perf_counter() - start

    assert resp.status_code == 200
    assert elapsed < 5.0


def test_api_cyber_rating_latency_under_threshold(app_client):
    start = time.perf_counter()
    resp = app_client.get("/api/cyber-rating?page=1&page_size=25")
    elapsed = time.perf_counter() - start

    assert resp.status_code == 200
    assert elapsed < 5.0
