"""Contract tests for universal API envelope across dashboard API-first endpoints."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest


def _assert_universal_success_envelope(payload: dict) -> None:
    assert isinstance(payload, dict)
    assert payload.get("success") is True
    assert "data" in payload and isinstance(payload["data"], dict)
    assert "filters" in payload and isinstance(payload["filters"], dict)

    data = payload["data"]
    assert "items" in data and isinstance(data["items"], list)
    assert "kpis" in data and isinstance(data["kpis"], dict)

    # Pagination fields are part of the contract shape.
    assert "total" in data
    assert "page" in data
    assert "page_size" in data
    assert "total_pages" in data


@pytest.mark.parametrize(
    "endpoint",
    [
        "/api/home/metrics",
        "/api/assets",
        "/api/discovery?tab=domains",
        "/api/discovery?tab=ssl",
        "/api/discovery?tab=ips",
        "/api/discovery?tab=software",
        "/api/distributions/asset-types",
        "/api/distributions/risk-levels",
        "/api/distributions/ip-versions",
        "/api/distributions/cert-expiry",
        "/api/enterprise-metrics",
        "/api/cbom/metrics",
        "/api/cbom/entries",
        "/api/cbom/summary?scan_id=contract-missing",
        "/api/cbom/charts",
        "/api/cbom",
        "/api/pqc-posture/metrics",
        "/api/pqc-posture/assets",
        "/api/pqc-posture",
        "/api/cyber-rating",
        "/api/reports/scheduled",
        "/api/reports/ondemand",
        "/api/reports",
        "/api/docs",
        "/api/config/theme",
    ],
)
def test_dashboard_api_success_envelope_contract(app_client, endpoint):
    resp = app_client.get(endpoint)
    assert resp.status_code == 200, f"Unexpected status for {endpoint}: {resp.status_code}"

    payload = json.loads(resp.data)
    _assert_universal_success_envelope(payload)


def test_dashboard_api_admin_metrics_envelope_contract(app_client):
    admin_user = SimpleNamespace(is_authenticated=True, role="Admin", id="admin-1", username="admin")

    with patch("flask_login.utils._get_user", return_value=admin_user):
        resp = app_client.get("/api/admin/metrics")

    assert resp.status_code == 200
    payload = json.loads(resp.data)
    _assert_universal_success_envelope(payload)


def test_dashboard_api_error_envelope_contract(app_client):
    resp = app_client.get("/api/discovery?tab=not-a-tab")
    assert resp.status_code == 400

    payload = json.loads(resp.data)
    assert payload.get("success") is False
    assert "error" in payload and isinstance(payload["error"], dict)
    assert "message" in payload["error"]
    assert payload["error"].get("status") == 400
