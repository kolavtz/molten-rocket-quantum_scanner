import json
from unittest.mock import patch


def test_scans_page_loads(app_client):
    with patch("web.routes.scans._can_scan", return_value=True):
        resp = app_client.get("/scans")
    assert resp.status_code == 200
    assert b"SCAN CENTER" in resp.data


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
    with patch("web.routes.scans._can_bulk_scan", return_value=True), patch("web.app.run_scan_pipeline", return_value=fake_report):
        resp = app_client.post(
            "/api/scans/bulk",
            data=json.dumps({"targets": ["example.com", "google.com"], "ports": [443]}),
            content_type="application/json",
        )
    assert resp.status_code == 202
    payload = json.loads(resp.data)
    assert payload["status"] == "accepted"
    assert len(payload.get("scan_ids", [])) == 2


def test_scan_metrics_endpoint_returns_universal_envelope(app_client):
    resp = app_client.get("/api/scans/metrics")
    assert resp.status_code == 200

    payload = json.loads(resp.data)
    assert payload.get("success") is True
    assert isinstance(payload.get("data"), dict)
    assert isinstance(payload.get("filters"), dict)

    data = payload["data"]
    assert isinstance(data.get("items"), list)
    assert "kpis" in data and isinstance(data["kpis"], dict)
    assert {"total", "page", "page_size", "total_pages"}.issubset(set(data.keys()))


def test_scan_certificate_details_endpoint_works_with_report_fallback(app_client):
    fake_report = {
        "scan_id": "scan-cert-1",
        "target": "example.com",
        "status": "complete",
        "tls_results": [
            {
                "host": "example.com",
                "port": 443,
                "tls_version": "TLS 1.3",
                "cipher_suite": "TLS_AES_256_GCM_SHA384",
                "subject_cn": "example.com",
                "issuer_cn": "Test CA",
                "serial_number": "ABC123",
                "key_length": 2048,
                "signature_algorithm": "sha256WithRSAEncryption",
                "cert_sha256": "AABBCCDDEEFF00112233445566778899",
                "san_domains": ["example.com", "www.example.com"],
                "certificate_chain_length": 2,
                "valid_to": "2030-01-01T00:00:00+00:00",
                "cert_days_remaining": 120,
                "cert_expired": False,
                "cert_status": "Valid",
            }
        ],
    }

    with patch("web.routes.scans._load_scan_report", return_value=fake_report):
        resp = app_client.get("/api/scans/scan-cert-1/certificates?page=1&page_size=10")

    assert resp.status_code == 200
    payload = json.loads(resp.data)
    assert payload.get("success") is True

    data = payload.get("data", {})
    assert isinstance(data.get("items"), list)
    assert data.get("total") == 1
    first = data["items"][0]
    assert first.get("subject_cn") == "example.com"
    assert first.get("tls_version") == "TLS 1.3"
    assert first.get("key_length") == 2048
