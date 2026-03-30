import pytest

from web.app import app


@pytest.fixture
def app_client():
    app.config["TESTING"] = True
    app.config["LOGIN_DISABLED"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as client:
        yield client
