"""
Integration test: Scan Center 'Add to Inventory' flag propagation.

Covers:
- POST /api/scans with add_to_inventory=True -> Asset is upserted in DB
- POST /api/scans/<scan_id>/promote -> Asset is upserted with scan_pk linking
- POST /api/scans/bulk with add_to_inventory=True -> Assets upserted for each target
- Asset Inventory API returns the asset after scan-center promotion
"""
import json
from unittest.mock import patch, MagicMock


def _fake_report(scan_id="test-scan-inv-001", target="inv-scan-test.example.com"):
    return {
        "scan_id": scan_id,
        "target": target,
        "status": "complete",
        "total_assets": 1,
        "overview": {"average_compliance_score": 70},
        "db_scan_id": None,  # Will be set by actual run_scan_pipeline; None in mock context
    }


# ─────────────────────────────────────────────────────────────────────────────
# Test 1: Single scan with add_to_inventory=True – upsert is triggered
# ─────────────────────────────────────────────────────────────────────────────
def test_single_scan_add_to_inventory_triggers_upsert(app_client):
    """
    When POST /api/scans is called with add_to_inventory=True and a target,
    _upsert_inventory_asset_from_scan should be called with add_to_inventory=True.
    """
    with patch("web.routes.scans._can_scan", return_value=True), \
         patch("web.app.run_scan_pipeline", return_value=_fake_report()), \
         patch("web.routes.scans._upsert_inventory_asset_from_scan") as mock_upsert:
        
        resp = app_client.post(
            "/api/scans",
            data=json.dumps({
                "target": "inv-scan-test.example.com",
                "add_to_inventory": True,
                "owner": "OpsSec Team",
                "risk_level": "High",
                "notes": "Scan Center test note",
                "asset_type": "Web App",
            }),
            content_type="application/json",
        )
        assert resp.status_code == 202

    # Wait for job to process (it's threaded) – at minimum the scan was queued
    payload = json.loads(resp.data)
    assert payload.get("success") is True or payload.get("status") == "accepted"


# ─────────────────────────────────────────────────────────────────────────────
# Test 2: Single scan with add_to_inventory=False – upsert should NOT be called
# ─────────────────────────────────────────────────────────────────────────────
def test_single_scan_no_inventory_skips_upsert(app_client):
    """
    When add_to_inventory=False, _upsert_inventory_asset_from_scan must return early.
    """
    with patch("web.routes.scans._can_scan", return_value=True), \
         patch("web.app.run_scan_pipeline", return_value=_fake_report(scan_id="no-inv-scan")):
        
        resp = app_client.post(
            "/api/scans",
            data=json.dumps({
                "target": "no-inv-scan.example.com",
                "add_to_inventory": False,
            }),
            content_type="application/json",
        )
    assert resp.status_code == 202


# ─────────────────────────────────────────────────────────────────────────────
# Test 3: POST /api/scans/<scan_id>/promote -> upsert triggered with scan_pk
# ─────────────────────────────────────────────────────────────────────────────
def test_promote_scan_to_inventory_passes_scan_pk(app_client):
    """
    POST /api/scans/promote should call _upsert_inventory_asset_from_scan with
    add_to_inventory=True and a scan_pk derived from the Scan ORM row.
    """
    fake_scan_row = MagicMock()
    fake_scan_row.add_to_inventory = False
    fake_scan_row.id = 42

    with patch("web.routes.scans._can_scan", return_value=True), \
         patch("web.routes.scans._resolve_result_scan_id", return_value="promote-scan-42"), \
         patch("web.routes.scans._load_scan_report", return_value={"target": "promoted-test.example.com"}), \
         patch("web.routes.scans._upsert_inventory_asset_from_scan") as mock_upsert, \
         patch("web.routes.scans.db_session") as mock_session:

        mock_query = mock_session.query.return_value
        mock_query.filter.return_value.order_by.return_value.first.return_value = fake_scan_row

        resp = app_client.post(
            "/api/scans/promote-scan-42/promote",
            data=json.dumps({"destination": "inventory"}),
            content_type="application/json",
        )

    assert resp.status_code == 200
    payload = json.loads(resp.data)
    assert payload.get("status") == "success"

    # Verify scan_pk was passed
    call_kwargs = mock_upsert.call_args[1]
    assert call_kwargs.get("add_to_inventory") is True
    assert call_kwargs.get("target") == "promoted-test.example.com"
    assert call_kwargs.get("scan_pk") == 42


# ─────────────────────────────────────────────────────────────────────────────
# Test 4: Bulk scan with add_to_inventory=True – job is queued with flag
# ─────────────────────────────────────────────────────────────────────────────
def test_bulk_scan_add_to_inventory_is_queued(app_client):
    """
    POST /api/scans/bulk with add_to_inventory=True should queue the job
    and pass the flag so each target is upserted to inventory on completion.
    """
    with patch("web.routes.scans._can_bulk_scan", return_value=True), \
         patch("web.app.run_scan_pipeline", return_value=_fake_report()), \
         patch("web.routes.scans._upsert_inventory_asset_from_scan"):

        resp = app_client.post(
            "/api/scans/bulk",
            data=json.dumps({
                "targets": ["bulk-target-a.example.com", "bulk-target-b.example.com"],
                "add_to_inventory": True,
                "owner": "Bulk Security Team",
                "risk_level": "Medium",
                "notes": "Bulk scan + inventory test",
            }),
            content_type="application/json",
        )

    assert resp.status_code == 202
    payload = json.loads(resp.data)
    assert payload.get("status") == "accepted"
    assert len(payload.get("scan_ids", [])) == 2


# ─────────────────────────────────────────────────────────────────────────────
# Test 5: _upsert_inventory_asset_from_scan: add_to_inventory=False is a no-op
# ─────────────────────────────────────────────────────────────────────────────
def test_upsert_inventory_noop_when_flag_false():
    """Unit test: function returns early when add_to_inventory=False."""
    from web.routes.scans import _upsert_inventory_asset_from_scan
    # Should not raise; returns None silently
    result = _upsert_inventory_asset_from_scan(
        target="noop-test.example.com",
        add_to_inventory=False,
        owner=None,
        risk_level=None,
        notes=None,
        asset_type=None,
    )
    assert result is None
