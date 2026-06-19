import os

import pytest

os.environ["RATELIMIT_ENABLED"] = "false"

from web.app import app, limiter

try:
    limiter.enabled = False
except Exception:
    pass


@pytest.fixture
def app_client():
    app.config["TESTING"] = True
    app.config["LOGIN_DISABLED"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as client:
        yield client
