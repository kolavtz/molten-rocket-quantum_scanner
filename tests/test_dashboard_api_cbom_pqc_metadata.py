"""Tests for enriched CBOM/PQC API metadata payloads."""

from __future__ import annotations

import json

from web.routes import dashboard_api


def test_cbom_charts_includes_chart_explanations(app_client):
    resp = app_client.get("/api/cbom/charts")
    assert resp.status_code == 200

    payload = json.loads(resp.data)
    assert payload.get("success") is True
    items = payload.get("data", {}).get("items", [])
    assert isinstance(items, list)
    assert len(items) == 1

    chart_explanations = items[0].get("chart_explanations", {})
    assert "key_length_distribution" in chart_explanations
    assert "what_it_represents" in chart_explanations["key_length_distribution"]
    assert "minimum_elements" in chart_explanations


def test_cbom_charts_includes_minimum_elements_payload(app_client):
    resp = app_client.get("/api/cbom/charts")
    assert resp.status_code == 200

    payload = json.loads(resp.data)
    items = payload.get("data", {}).get("items", [])
    assert len(items) == 1

    minimum_elements = items[0].get("minimum_elements", {})
    assert isinstance(minimum_elements, dict)
    assert "field_coverage" in minimum_elements
    assert "coverage_summary" in minimum_elements


def test_cbom_minimum_elements_endpoint_available(app_client):
    resp = app_client.get("/api/cbom/minimum-elements")
    assert resp.status_code == 200

    payload = json.loads(resp.data)
    assert payload.get("success") is True
    data = payload.get("data", {})
    minimum_elements = data.get("minimum_elements", {})

    assert "field_definitions" in minimum_elements
    assert "field_coverage" in minimum_elements
    assert "coverage_summary" in minimum_elements


def test_cbom_minimum_elements_exposes_required_table9_fields(app_client):
    resp = app_client.get("/api/cbom/minimum-elements")
    assert resp.status_code == 200

    payload = json.loads(resp.data)
    minimum_elements = payload.get("data", {}).get("minimum_elements", {})
    field_definitions = minimum_elements.get("field_definitions", {})
    coverage_summary = minimum_elements.get("coverage_summary", {})

    required_subset = {
        "asset_type",
        "element_name",
        "primitive",
        "oid",
        "protocol_name",
        "protocol_version_name",
        "subject_name",
        "issuer_name",
        "signature_algorithm_reference",
    }
    assert required_subset.issubset(set(field_definitions.keys()))
    assert all(field_definitions[key].get("required") is True for key in required_subset)

    assert isinstance(coverage_summary.get("required_fields"), int)
    assert isinstance(coverage_summary.get("covered_fields"), int)
    assert 0 <= float(coverage_summary.get("coverage_pct", 0)) <= 100


def test_pqc_metrics_includes_status_bar_explanations(app_client):
    resp = app_client.get("/api/pqc-posture/metrics")
    assert resp.status_code == 200

    payload = json.loads(resp.data)
    assert payload.get("success") is True

    items = payload.get("data", {}).get("items", [])
    assert isinstance(items, list)
    assert len(items) == 1

    status_bar_chart = items[0].get("status_bar_chart", [])
    assert isinstance(status_bar_chart, list)
    expected = {"safe", "unsafe", "migration_advised", "unknown"}
    assert expected.issubset({row.get("status") for row in status_bar_chart})


def test_pqc_metrics_status_bars_include_descriptions_and_pct_bounds(app_client):
    resp = app_client.get("/api/pqc-posture/metrics")
    assert resp.status_code == 200

    payload = json.loads(resp.data)
    items = payload.get("data", {}).get("items", [])
    assert len(items) == 1

    bars = items[0].get("status_bar_chart", [])
    assert bars
    for row in bars:
        assert isinstance(row.get("description"), str)
        assert row.get("description")
        assert 0 <= float(row.get("pct", 0)) <= 100


def test_pqc_metrics_includes_tier_readiness_chart_payload(app_client):
    resp = app_client.get("/api/pqc-posture/metrics")
    assert resp.status_code == 200

    payload = json.loads(resp.data)
    items = payload.get("data", {}).get("items", [])
    assert len(items) == 1

    readiness = items[0].get("readiness_tier_bars", [])
    assert isinstance(readiness, list)
    assert {"elite", "standard", "legacy", "critical"}.issubset({str(r.get("tier") or "").lower() for r in readiness})
    for row in readiness:
        assert 0 <= float(row.get("pct", 0)) <= 100
        assert isinstance(row.get("description"), str)
        assert row.get("description")


def test_api_docs_lists_new_cbom_minimum_elements_endpoint(app_client):
    resp = app_client.get("/api/docs")
    assert resp.status_code == 200

    payload = json.loads(resp.data)
    items = payload.get("data", {}).get("items", [])
    assert len(items) == 1

    endpoints = items[0].get("endpoints", [])
    assert "GET /api/cbom/minimum-elements" in endpoints


def test_cbom_export_filters_entries_by_selected_keys(app_client, monkeypatch):
    def _fake_cbom_data(**_kwargs):
        return {
            "applications": [
                {"row_key": "certificate:101", "asset_name": "alpha"},
                {"row_key": "discovery_ssl:202", "asset_name": "beta"},
                {"row_key": "certificate:303", "asset_name": "gamma"},
            ],
            "page_data": {"total_pages": 1},
            "kpis": {},
            "key_length_distribution": {},
            "cipher_usage": {},
            "protocols": {},
            "top_cas": {},
            "minimum_elements": {},
        }

    monkeypatch.setattr(dashboard_api.CbomService, "get_cbom_dashboard_data", _fake_cbom_data)

    resp = app_client.get("/api/cbom/export?mode=x509&selected_keys=certificate:101,discovery_ssl:202")
    assert resp.status_code == 200

    payload = json.loads(resp.data)
    entries = payload.get("entries", [])
    assert payload.get("mode") == "x509"
    assert payload.get("selected_count") == 2
    assert [item.get("row_key") for item in entries] == ["certificate:101", "discovery_ssl:202"]


def test_cbom_export_filters_single_entry_by_row_key(app_client, monkeypatch):
    def _fake_cbom_data(**_kwargs):
        return {
            "applications": [
                {"row_key": "certificate:11", "asset_name": "one"},
                {"row_key": "certificate:22", "asset_name": "two"},
            ],
            "page_data": {"total_pages": 1},
            "kpis": {},
            "key_length_distribution": {},
            "cipher_usage": {},
            "protocols": {},
            "top_cas": {},
            "minimum_elements": {},
        }

    monkeypatch.setattr(dashboard_api.CbomService, "get_cbom_dashboard_data", _fake_cbom_data)

    resp = app_client.get("/api/cbom/export?mode=cbom&row_key=certificate:22")
    assert resp.status_code == 200

    payload = json.loads(resp.data)
    entries = payload.get("entries", [])
    assert payload.get("mode") == "cbom"
    assert [item.get("row_key") for item in entries] == ["certificate:22"]
