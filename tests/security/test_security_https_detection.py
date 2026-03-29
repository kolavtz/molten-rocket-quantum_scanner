from web.app import _is_https_request, app


def test_is_https_request_true_for_forwarded_proto():
    with app.test_request_context("/", headers={"X-Forwarded-Proto": "https"}):
        assert _is_https_request() is True


def test_is_https_request_false_without_tls_signal():
    with app.test_request_context(
        "/",
        environ_overrides={"wsgi.url_scheme": "http"},
        headers={"X-Forwarded-Proto": "http"},
    ):
        assert _is_https_request() is False
