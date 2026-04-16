import json


def test_unknown_api_route_returns_json_error(app_client):
    """Unknown /api/* routes should return a JSON error, not an HTML 404 page."""
    resp = app_client.get("/api/definitely-does-not-exist")
    assert resp.status_code == 404

    payload = json.loads(resp.data)

    # The app wraps errors in a nested envelope: {"success": False, "error": {...}}
    # OR a flat envelope: {"status": "error", "message": "..."}
    # Accept either shape so the test validates the *json* contract without being
    # overly brittle about the exact nesting.
    is_nested = isinstance(payload.get("error"), dict)
    is_flat = payload.get("status") == "error"

    assert is_nested or is_flat, (
        f"Expected a JSON error envelope with 'error' dict or top-level 'status'='error', "
        f"got: {payload}"
    )

    # At least one path must carry a human-readable message
    if is_nested:
        assert "message" in payload["error"], "Nested error should have a 'message' key"
    else:
        assert "message" in payload, "Flat error should have a top-level 'message' key"
