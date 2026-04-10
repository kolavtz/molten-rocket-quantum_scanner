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
    assert payload.get("success") is True
    assert isinstance(payload.get("data"), dict)
    assert payload.get("error") is None
    assert {"items", "total", "page", "page_size", "total_pages", "kpis"}.issubset(set(payload.keys()))
    assert {"items", "total", "page", "page_size", "total_pages", "kpis"}.issubset(set(payload["data"].keys()))


def test_scans_list_accepts_search_and_q_params(app_client):
    resp_search = app_client.get("/api/scans?page=1&page_size=10&search=example")
    assert resp_search.status_code == 200
    payload_search = json.loads(resp_search.data)
    assert payload_search.get("success") is True
    assert payload_search.get("search") == "example"
    assert payload_search.get("q") == "example"

    resp_q = app_client.get("/api/scans?page=1&page_size=10&q=legacy")
    assert resp_q.status_code == 200
    payload_q = json.loads(resp_q.data)
    assert payload_q.get("success") is True
    assert payload_q.get("search") == "legacy"
    assert payload_q.get("q") == "legacy"


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
        assert created.get("success") is True
        assert isinstance(created.get("data"), dict)
        assert created["data"].get("status_url", "").startswith("/api/scans/")
        status_resp = app_client.get(f"/api/scans/{created['scan_id']}/status")

    assert status_resp.status_code == 200
    status_payload = json.loads(status_resp.data)
    assert status_payload.get("success") is True
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


def test_bulk_scan_accepts_target_entries_with_ports(app_client):
    fake_report = {
        "scan_id": "bulk-real-csv-1",
        "target": "10.10.10.10",
        "status": "complete",
        "total_assets": 1,
        "overview": {"average_compliance_score": 70},
    }

    with patch("web.routes.scans._can_bulk_scan", return_value=True), patch("web.app.run_scan_pipeline", return_value=fake_report):
        resp = app_client.post(
            "/api/scans/bulk",
            data=json.dumps(
                {
                    "target_entries": [
                        {"target": "10.10.10.10", "ports": [443, 8443]},
                        {"target": "192.168.1.0/24", "ports": "80 443"},
                    ],
                    "autodiscovery": False,
                }
            ),
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
                "certificate_details": {
                    "certificate_version": "v3",
                    "serial_number": "ABC123",
                    "certificate_signature_algorithm": "sha256WithRSAEncryption",
                    "issuer": "CN=Test CA",
                    "validity": {
                        "not_before": "2024-01-01T00:00:00+00:00",
                        "not_after": "2030-01-01T00:00:00+00:00",
                    },
                    "subject": "CN=example.com",
                    "subject_public_key_info": {
                        "subject_public_key_algorithm": "RSA",
                        "subject_public_key_bits": 2048,
                        "subject_public_key": "-----BEGIN PUBLIC KEY-----...",
                    },
                    "extensions": ["subjectAltName", "keyUsage"],
                    "certificate_key_usage": ["digital_signature", "key_encipherment"],
                    "extended_key_usage": ["serverAuth"],
                    "certificate_basic_constraints": {"ca": False},
                    "certificate_subject_key_id": "A1B2C3",
                    "certificate_authority_key_id": "D4E5F6",
                    "authority_information_access": ["ocsp:http://ocsp.example.com"],
                    "certificate_subject_alternative_name": ["example.com", "www.example.com"],
                    "certificate_policies": ["2.23.140.1.2.1"],
                    "crl_distribution_points": ["http://crl.example.com/root.crl"],
                    "signed_certificate_timestamp_list": ["present"],
                },
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
    assert isinstance(first.get("certificate_details"), dict)
    assert first["certificate_details"].get("certificate_version") == "v3"
    assert first["certificate_details"].get("certificate_signature_algorithm") == "sha256WithRSAEncryption"


def test_scans_list_supports_type_status_and_date_filters(app_client):
    resp = app_client.get(
        "/api/scans?page=1&page_size=10&scan_type=single&status=completed&date_from=2020-01-01&date_to=2099-12-31"
    )
    assert resp.status_code == 200
    payload = json.loads(resp.data)
    assert "items" in payload
    assert "kpis" in payload


def test_promote_scan_requires_inventory_before_cbom(app_client):
    with patch("web.routes.scans._can_scan", return_value=True), \
         patch("web.routes.scans._resolve_result_scan_id", return_value="scan-123"), \
         patch("web.routes.scans.db_session") as mock_session:
        scan_row = type("ScanRow", (), {"add_to_inventory": False})()
        mock_query = mock_session.query.return_value
        mock_query.filter.return_value.order_by.return_value.first.return_value = scan_row

        resp = app_client.post(
            "/api/scans/scan-123/promote",
            data=json.dumps({"destination": "cbom"}),
            content_type="application/json",
        )

    assert resp.status_code == 400
    payload = json.loads(resp.data)
    assert payload.get("status") == "error"


def test_promote_scan_inventory_success(app_client):
    with patch("web.routes.scans._can_scan", return_value=True), \
         patch("web.routes.scans._resolve_result_scan_id", return_value="scan-abc"), \
         patch("web.routes.scans._load_scan_report", return_value={"target": "example.com"}), \
         patch("web.routes.scans._upsert_inventory_asset_from_scan") as mock_upsert, \
         patch("web.routes.scans.db_session") as mock_session:
        scan_row = type("ScanRow", (), {"add_to_inventory": False})()
        mock_query = mock_session.query.return_value
        mock_query.filter.return_value.order_by.return_value.first.return_value = scan_row

        resp = app_client.post(
            "/api/scans/scan-abc/promote",
            data=json.dumps({"destination": "inventory"}),
            content_type="application/json",
        )

    assert resp.status_code == 200
    payload = json.loads(resp.data)
    assert payload.get("status") == "success"
    mock_upsert.assert_called_once()


def test_scan_schedule_detail_and_patch_update(app_client):
    with patch("web.routes.scans._can_bulk_scan", return_value=True):
        create_resp = app_client.post(
            "/api/scan-schedules",
            data=json.dumps(
                {
                    "target": "example.com",
                    "frequency": "daily",
                    "scheduled_time": "08:30",
                    "timezone": "UTC",
                    "auto_add_to_inventory": False,
                }
            ),
            content_type="application/json",
        )

        assert create_resp.status_code == 201
        created = json.loads(create_resp.data)
        schedule_id = created["data"]["id"]

        detail_resp = app_client.get(f"/api/scan-schedules/{schedule_id}")
        assert detail_resp.status_code == 200
        detail_payload = json.loads(detail_resp.data)
        assert detail_payload.get("status") == "success"
        assert detail_payload["data"].get("target") == "example.com"

        update_resp = app_client.patch(
            f"/api/scan-schedules/{schedule_id}",
            data=json.dumps(
                {
                    "target": "api.example.com",
                    "frequency": "weekly",
                    "scheduled_time": "21:45",
                    "timezone": "Asia/Kolkata",
                    "auto_add_to_inventory": True,
                }
            ),
            content_type="application/json",
        )

        assert update_resp.status_code == 200
        update_payload = json.loads(update_resp.data)
        assert update_payload.get("status") == "updated"
        assert update_payload["data"].get("target") == "api.example.com"
        assert update_payload["data"].get("frequency") == "weekly"
        assert update_payload["data"].get("scheduled_time") == "21:45"
        assert update_payload["data"].get("timezone") == "Asia/Kolkata"
        assert update_payload["data"].get("auto_add_to_inventory") is True


def test_scan_schedule_put_requires_valid_fields(app_client):
    with patch("web.routes.scans._can_bulk_scan", return_value=True):
        create_resp = app_client.post(
            "/api/scan-schedules",
            data=json.dumps(
                {
                    "target": "example.com",
                    "frequency": "daily",
                    "scheduled_time": "09:00",
                    "timezone": "UTC",
                }
            ),
            content_type="application/json",
        )
        assert create_resp.status_code == 201
        schedule_id = json.loads(create_resp.data)["data"]["id"]

        bad_resp = app_client.put(
            f"/api/scan-schedules/{schedule_id}",
            data=json.dumps(
                {
                    "target": "example.com",
                    "frequency": "yearly",
                    "scheduled_time": "25:12",
                    "timezone": "UTC",
                }
            ),
            content_type="application/json",
        )

        assert bad_resp.status_code == 400
        payload = json.loads(bad_resp.data)
        assert payload.get("status") == "error"


def test_scan_schedule_detail_not_found(app_client):
    with patch("web.routes.scans._can_bulk_scan", return_value=True):
        resp = app_client.get("/api/scan-schedules/sched_missing")
    assert resp.status_code == 404
    payload = json.loads(resp.data)
    assert payload.get("status") == "error"
