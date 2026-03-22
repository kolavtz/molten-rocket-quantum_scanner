from unittest.mock import patch


def test_root_redirects_to_dashboard(app_client):
    resp = app_client.get("/")
    assert resp.status_code == 302
    assert "/dashboard/assets" in (resp.headers.get("Location") or "")


def test_dashboard_home_loads(app_client):
    resp = app_client.get("/dashboard/assets")
    assert resp.status_code == 200


def test_scan_center_loads_for_manager(app_client):
    with patch("web.app.current_user") as user:
        user.is_authenticated = True
        user.role = "Manager"
        user.username = "manager"
        resp = app_client.get("/scan-center")
    assert resp.status_code == 200
    assert b"SCAN CENTER" in resp.data
