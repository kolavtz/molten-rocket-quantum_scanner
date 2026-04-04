"""
API Blueprint Initialization
Registers all API endpoints with the Flask application.

This module centralises blueprint registration and supports environment-driven
API versioning. By default blueprints are mounted under /api/v1. To change the
base prefix set the environment variable QSS_API_VERSION (set to empty string
to use /api root).
"""

import os
from flask import Blueprint, Flask


def _compute_prefixed_url(base_prefix: str, bp: Blueprint) -> str:
    """Return the effective url_prefix when mounting bp under base_prefix.

    Many existing blueprints declare url_prefix that begin with '/api' (e.g.
    '/api/cbom' or '/api'). To support a versioned base prefix we remove the
    leading '/api' from the blueprint's declared prefix and re-attach it to the
    chosen base prefix.
    """
    existing = getattr(bp, "url_prefix", "") or ""
    if existing.startswith("/api"):
        suffix = existing[4:]
        return base_prefix + suffix
    if existing:
        return base_prefix + existing
    return base_prefix


def register_api_blueprints(app: Flask, api_version: str | None = None) -> bool:
    """
    Register all API blueprints with the Flask application.

    If `api_version` is None this reads the environment variable
    QSS_API_VERSION (default: 'v1'). Set QSS_API_VERSION to an empty string to
    mount blueprints directly under '/api'.
    """

    if api_version is None:
        api_version = str(os.environ.get("QSS_API_VERSION", "v1")).strip()

    base_prefix = "/api" if api_version == "" else f"/api/{api_version}"

    try:
        # Core (non-overlapping) blueprints
        from web.blueprints.api_incidents import api_incidents
        from web.blueprints.api_docs import api_docs
        from web.blueprints.api_ai import api_ai
        from web.blueprints.api_root import api_root

        # Mount the API root (version metadata and health) at the base prefix
        app.register_blueprint(api_root, url_prefix=_compute_prefixed_url(base_prefix, api_root))

        app.register_blueprint(api_incidents, url_prefix=_compute_prefixed_url(base_prefix, api_incidents))
        app.register_blueprint(api_docs, url_prefix=_compute_prefixed_url(base_prefix, api_docs))
        app.register_blueprint(api_ai, url_prefix=_compute_prefixed_url(base_prefix, api_ai))

        # Optional fallback switch to restore legacy overlapping blueprint registrations.
        # Use only for temporary migration compatibility.
        if str(os.environ.get("QSS_ENABLE_LEGACY_DASHBOARD_API_BLUEPRINTS", "")).strip().lower() in {"1", "true", "yes", "on"}:
            from web.blueprints.api_home import api_home
            from web.blueprints.api_assets import api_assets
            from web.blueprints.api_cbom import api_cbom
            from web.blueprints.api_pqc import api_pqc
            from web.blueprints.api_cyber import api_cyber
            from web.blueprints.api_reports import api_reports

            app.register_blueprint(api_home, url_prefix=_compute_prefixed_url(base_prefix, api_home))
            app.register_blueprint(api_assets, url_prefix=_compute_prefixed_url(base_prefix, api_assets))
            app.register_blueprint(api_cbom, url_prefix=_compute_prefixed_url(base_prefix, api_cbom))
            app.register_blueprint(api_pqc, url_prefix=_compute_prefixed_url(base_prefix, api_pqc))
            app.register_blueprint(api_cyber, url_prefix=_compute_prefixed_url(base_prefix, api_cyber))
            app.register_blueprint(api_reports, url_prefix=_compute_prefixed_url(base_prefix, api_reports))
            print("⚠️ Legacy overlapping dashboard API blueprints are enabled via QSS_ENABLE_LEGACY_DASHBOARD_API_BLUEPRINTS")

        print(f"✅ API blueprints registered successfully at base prefix '{base_prefix}'")
        return True

    except ImportError as e:
        print(f"❌ Failed to register API blueprints: {e}")
        return False


def register_api_auth_model(db):
    """
    Register the APIKey model with the database.

    Call this after initializing your database.
    """

    try:
        from middleware.api_auth import APIKey
        from src.db import Base

        # This will ensure the api_keys table is created
        # Only call this if using SQLAlchemy's declarative base
        # Base.metadata.create_all(db.engine)

        print("✅ API Key model registered")
        return True

    except Exception as e:
        print(f"⚠️  Could not register API Key model: {e}")
        return False
