from flask import jsonify

from web.app import app, require_api_key


def test_require_api_key_rejects_missing_key_when_not_testing():
    @require_api_key
    def protected():
        return jsonify({"ok": True}), 200

    with app.test_request_context("/protected"):
        original_testing = app.config.get("TESTING", False)
        app.config["TESTING"] = False
        try:
            resp, code = protected()
        finally:
            app.config["TESTING"] = original_testing

    assert code == 401
    payload = resp.get_json()
    assert payload["error"] == "API key required"
