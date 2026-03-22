def test_asset_inventory_page(app_client):
    resp = app_client.get("/asset-inventory")
    assert resp.status_code == 200
    assert b"ASSET INVENTORY" in resp.data


def test_asset_discovery_page(app_client):
    resp = app_client.get("/asset-discovery")
    assert resp.status_code == 200
    assert b"ASSET DISCOVERY" in resp.data


def test_cbom_dashboard_page(app_client):
    resp = app_client.get("/cbom-dashboard")
    assert resp.status_code == 200
    assert b"CBOM" in resp.data


def test_pqc_posture_page(app_client):
    resp = app_client.get("/pqc-posture")
    assert resp.status_code == 200
    assert b"POSTURE" in resp.data


def test_cyber_rating_page(app_client):
    resp = app_client.get("/cyber-rating")
    assert resp.status_code == 200
    assert b"CYBER RATING" in resp.data


def test_reporting_page(app_client):
    resp = app_client.get("/reporting")
    assert resp.status_code == 200
    assert b"REPORTING" in resp.data
