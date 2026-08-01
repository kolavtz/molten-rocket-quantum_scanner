"""
Smoke tests for core app routes.

NOTE: app_client fixture sets LOGIN_DISABLED=True so the before_request
authentication guard is bypassed, matching @login_required behaviour.
Unauthenticated-redirect behaviour is verified via the
test_auth_gate_redirects_unauthenticated test below which uses a plain
test client WITHOUT LOGIN_DISABLED.
"""
from unittest.mock import patch

from web.app import app


def test_root_redirects_to_dashboard(app_client):
    """With LOGIN_DISABLED the root route reaches the dashboard redirect."""
    resp = app_client.get("/")
    assert resp.status_code == 302
    assert "/dashboard" in (resp.headers.get("Location") or "")


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


def test_auth_gate_redirects_unauthenticated():
    """Unauthenticated requests without LOGIN_DISABLED must redirect to /login."""
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    # Do NOT set LOGIN_DISABLED so the guard fires
    app.config.pop("LOGIN_DISABLED", None)
    with app.test_client() as c:
        rv = c.get("/")
        assert rv.status_code == 302
        location = rv.headers.get("Location", "")
        assert "/login" in location, f"Expected redirect to /login, got: {location}"

        rv2 = c.get("/dashboard/assets")
        assert rv2.status_code == 302
        location2 = rv2.headers.get("Location", "")
        assert "/login" in location2

        rv3 = c.get("/login")
        assert rv3.status_code == 200
