def test_security_headers_present_on_login(app_client):
    resp = app_client.get("/login")
    assert resp.status_code == 200
    assert "X-Frame-Options" in resp.headers
    assert "X-Content-Type-Options" in resp.headers
    assert "Content-Security-Policy" in resp.headers
