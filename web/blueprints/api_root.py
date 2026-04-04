"""
API Root / Version endpoints
Mounted at the computed base API prefix (e.g. /api or /api/v1)
"""

import os
from flask import Blueprint, jsonify, current_app

api_root = Blueprint("api_root", __name__, url_prefix="/api")


@api_root.route("/", methods=["GET"])
def index():
    """Return basic API metadata and a link to docs."""
    version = str(os.environ.get("QSS_API_VERSION", "v1")).strip()
    docs_path = f"/api/{version}/docs" if version != "" else "/api/docs"
    return jsonify({"success": True, "data": {"name": "QuantumShield API", "version": version, "docs": docs_path}}), 200


@api_root.route("/health", methods=["GET"])
def health():
    """Simple health endpoint used by load balancers or readiness checks."""
    return jsonify({"success": True, "status": "ok"}), 200


@api_root.route("/openapi.json", methods=["GET"])
def openapi():
    """Return the small OpenAPI-like spec published by api_docs (best-effort).

    This performs a delayed import of api_docs to avoid import-time cycles.
    """
    try:
        from web.blueprints.api_docs import API_ENDPOINTS_SPEC
        version = str(os.environ.get("QSS_API_VERSION", "v1")).strip()
        spec = dict(API_ENDPOINTS_SPEC)
        spec["baseUrl"] = (f"/api/{version}" if version != "" else "/api")
        return jsonify(spec), 200
    except Exception as e:
        current_app.logger.debug("Failed to load API_ENDPOINTS_SPEC: %s", e)
        return jsonify({"success": False, "message": "OpenAPI spec not available"}), 500
