import json
from unittest.mock import patch


def test_scans_page_loads(app_client):
    resp = app_client.get("/scans")
    assert resp.status_code == 200
    assert b"SCANS" in resp.data


def test_scans_list_paginated_envelope(app_client):
    resp = app_client.get("/api/scans?page=1&page_size=10")
    assert resp.status_code == 200
    payload = json.loads(resp.data)
    assert {"items", "total", "page", "page_size", "total_pages", "kpis"}.issubset(set(payload.keys()))


def test_single_scan_submission_and_status_poll(app_client):
    fake_report = {
        "scan_id": "real-scan-100",
        "target": "example.com",
        "status": "complete",
        "total_assets": 2,
        "overview": {"average_compliance_score": 82},
    }

    with patch("web.routes.scans._can_scan", return_value=True), patch("web.app.run_scan_pipeline", return_value=fake_report):
        create_resp = app_client.post(
            "/api/scans",
            data=json.dumps({"target": "example.com", "ports": [443]}),
            content_type="application/json",
        )
        assert create_resp.status_code == 202
        created = json.loads(create_resp.data)
        status_resp = app_client.get(f"/api/scans/{created['scan_id']}/status")

    assert status_resp.status_code == 200
    status_payload = json.loads(status_resp.data)
    assert status_payload["status"] == "success"
    assert "data" in status_payload


def test_bulk_scan_submission_returns_tracking_scan_ids(app_client):
    fake_report = {
        "scan_id": "bulk-real-1",
        "target": "example.com",
        "status": "complete",
        "total_assets": 1,
        "overview": {"average_compliance_score": 75},
    }
    with patch("web.routes.scans._can_scan", return_value=True), patch("web.app.run_scan_pipeline", return_value=fake_report):
        resp = app_client.post(
            "/api/scans/bulk",
            data=json.dumps({"targets": ["example.com", "google.com"], "ports": [443]}),
            content_type="application/json",
        )
    assert resp.status_code == 202
    payload = json.loads(resp.data)
    assert payload["status"] == "accepted"
    assert len(payload.get("scan_ids", [])) == 2
