from flask import jsonify

from web.app import app, require_api_key


def test_require_api_key_allows_in_testing_mode():
    @require_api_key
    def sample():
        return jsonify({"ok": True}), 200

    with app.test_request_context("/internal"):
        original_testing = app.config.get("TESTING", False)
        app.config["TESTING"] = True
        try:
            resp, code = sample()
        finally:
            app.config["TESTING"] = original_testing

    assert code == 200
    assert resp.get_json()["ok"] is True
