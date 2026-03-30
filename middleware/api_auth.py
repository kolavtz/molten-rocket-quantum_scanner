from __future__ import annotations

from functools import wraps
from typing import Callable, TypeVar

from flask import current_app, g, request
from flask_login import current_user

from src import database as db
from utils.api_helper import error_response

F = TypeVar("F", bound=Callable)


def api_guard(func: F) -> F:
    """Session-first API guard with optional API-key validation.

    - Always requires authenticated session (Flask-Login).
    - Validates API key when provided (`X-API-Key`, `api_key` query/json).
    - In TESTING mode, API key validation is skipped.
    """

    @wraps(func)
    def wrapped(*args, **kwargs):
        if current_app.config.get("TESTING", False) or current_app.config.get("LOGIN_DISABLED", False):
            return func(*args, **kwargs)

        if not getattr(current_user, "is_authenticated", False):
            return error_response("Authentication required.", 401)

        raw_key = (
            request.headers.get("X-API-Key", "")
            or request.args.get("api_key", "")
            or (request.get_json(silent=True) or {}).get("api_key", "")
        ).strip()

        # Keep browser/session UX working if key not explicitly provided.
        if not raw_key:
            return func(*args, **kwargs)

        api_user = db.get_user_by_api_key(raw_key)
        if not api_user:
            return error_response("Invalid API key.", 401)

        g.api_user = api_user
        return func(*args, **kwargs)

    return wrapped  # type: ignore[return-value]
