import io
import json
import os
from unittest.mock import patch

import web.app as web_app


def test_results_view_renders_and_shows_cbom(app_client, tmp_path):
    scan_id = 'abcd1234'
    tmp_dir = str(tmp_path)

    # Write a small CBOM file into the temp RESULTS_DIR
    cbom = {"bomFormat": "CycloneDX", "components": [{"name": "TLS-Cipher"}]}
    cbom_path = tmp_path / f"{scan_id}_cbom.json"
    cbom_path.write_text(json.dumps(cbom), encoding="utf-8")

    # Prepare a minimal report and inject into scan_store
    report = {
        "scan_id": scan_id,
        "status": "complete",
        "target": "example.test",
        "generated_at": "2026-04-06T00:00:00Z",
        "overview": {
            "average_compliance_score": 75,
            "total_assets": 1,
            "quantum_safe": 0,
            "quantum_vulnerable": 1,
        },
        "discovered_services": [{"host": "example.test", "port": 443, "service": "https", "is_tls": True, "banner": "nginx"}],
        "tls_results": [
            {
                "host": "example.test",
                "port": 443,
                "subject_cn": "example.test",
                "issuer_cn": "TestCA",
                "serial_number": "1234",
                "cert_sha256": "abcd",
                "certificate_details": {"k": "v"},
                "valid_from": "2026-01-01",
                "valid_to": "2027-01-01",
                "cert_status": "Valid",
                "key_length": 2048,
            }
        ],
        "pqc_assessments": [],
        "recommendations_detailed": [{"title": "Upgrade TLS", "description": "Upgrade to TLS 1.3", "server_configs": {"Nginx": "ssl_protocols TLSv1.3;"}}],
        "severity_breakdown": {"low": 1, "high": 0},
        "risk_distribution": {"high": 1, "low": 0},
    }

    web_app.scan_store[scan_id] = report

    # Patch the runtime RESULTS_DIR so results() finds the CBOM file we wrote
    with patch.object(web_app, "RESULTS_DIR", tmp_dir):
        resp = app_client.get(f"/results/{scan_id}")
        assert resp.status_code == 200
        html = resp.data.decode("utf-8")
        assert "CBOM" in html
        assert "Download full CBOM JSON" in html
        # Certificate serial should be visible in the certs tab content
        assert "1234" in html
        assert "example.test" in html


def test_cbom_download_serves_file_and_headers(app_client, tmp_path):
    scan_id = 'abcd1234'
    tmp_dir = str(tmp_path)
    cbom_data = {"hello": "world"}
    p = tmp_path / f"{scan_id}_cbom.json"
    p.write_text(json.dumps(cbom_data), encoding="utf-8")

    with patch.object(web_app, "RESULTS_DIR", tmp_dir):
        resp = app_client.get(f"/cbom/{scan_id}")
        assert resp.status_code == 200
        assert resp.mimetype == "application/json"
        # Expect our JSON content in response body
        assert b'"hello"' in resp.data
        # Sent as attachment
        assert "attachment" in (resp.headers.get("Content-Disposition") or "")


def test_export_pdf_route_returns_pdf(app_client):
    scan_id = 'abcd1234'
    report = {"scan_id": scan_id, "status": "complete", "target": "example.test", "overview": {"average_compliance_score": 80, "total_assets": 1, "quantum_safe": 1, "quantum_vulnerable": 0}}
    web_app.scan_store[scan_id] = report

    fake_pdf = io.BytesIO(b"%PDF-1.4\n%fakepdf\n")
    with patch.object(web_app, "generate_report_pdf", return_value=fake_pdf):
        resp = app_client.get(f"/results/{scan_id}/export_pdf")
        assert resp.status_code == 200
        assert resp.mimetype == "application/pdf"
        assert resp.data.startswith(b"%PDF")


    def test_results_view_certificate_kpi_server_side(app_client):
        scan_id = 'certkpi123'
        report = {
            "scan_id": scan_id,
            "status": "complete",
            "target": "example.test",
            "generated_at": "2026-04-06T00:00:00Z",
            "overview": {"average_compliance_score": 75, "total_assets": 1, "quantum_safe": 0, "quantum_vulnerable": 1},
            "tls_results": [
                {"host": "example.test", "port": 443, "cert_status": "Expired", "serial_number": "abcd", "cert_days_remaining": -1, "key_length": 1024, "certificate_details": {"subject_cn": "example.test"}}
            ],
        }
        web_app.scan_store[scan_id] = report

        resp = app_client.get(f"/results/{scan_id}")
        assert resp.status_code == 200
        html = resp.data.decode("utf-8")
        # Expect certificate KPI cards and counts to appear
        assert "Certificates" in html
        assert "Expired" in html
        assert "1" in html
