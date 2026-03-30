from web.app import app


def test_security_headers_present_on_login(app_client):
    resp = app_client.get("/login")
    assert resp.status_code == 200
    assert "X-Frame-Options" in resp.headers
    assert "X-Content-Type-Options" in resp.headers
    assert "Content-Security-Policy" in resp.headers


def test_login_csrf_missing_token_shows_user_friendly_message():
    # Force CSRF on for this scenario and ensure no token is sent.
    app.config["TESTING"] = True
    app.config["LOGIN_DISABLED"] = False
    app.config["WTF_CSRF_ENABLED"] = True

    with app.test_client() as client:
        resp = client.post("/login", data={"username": "fake", "password": "fake"}, follow_redirects=True)

    assert resp.status_code == 400
    assert b"Security check failed (CSRF token missing or invalid)" in resp.data
