import json


def test_generate_report_returns_pdf(app_client):
    resp = app_client.post(
        "/report/generate",
        data=json.dumps({"report_type": "Executive Reporting", "sections": []}),
        content_type="application/json",
    )
    assert resp.status_code == 200
    assert resp.content_type == "application/pdf"
    assert resp.data[:4] == b"%PDF"


def test_schedule_report_returns_ok(app_client):
    resp = app_client.post(
        "/report/schedule",
        data=json.dumps(
            {
                "report_type": "Executive Summary Report",
                "frequency": "Weekly",
                "assets": "All Assets",
                "sections": ["Asset Inventory"],
                "timezone": "UTC",
            }
        ),
        content_type="application/json",
    )
    assert resp.status_code == 200
    payload = json.loads(resp.data)
    assert payload.get("status") == "ok"
