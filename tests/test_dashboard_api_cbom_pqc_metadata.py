"""Tests for enriched CBOM/PQC API metadata payloads."""

from __future__ import annotations

import json


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


def test_api_docs_lists_new_cbom_minimum_elements_endpoint(app_client):
    resp = app_client.get("/api/docs")
    assert resp.status_code == 200

    payload = json.loads(resp.data)
    items = payload.get("data", {}).get("items", [])
    assert len(items) == 1

    endpoints = items[0].get("endpoints", [])
    assert "GET /api/cbom/minimum-elements" in endpoints
