import json
from unittest.mock import patch

import web.app as web_app_module


def test_discovery_graph_empty_shape(app_client):
    with patch.dict(web_app_module.scan_store, {}, clear=True):
        resp = app_client.get("/api/discovery-graph")
    assert resp.status_code == 200
    payload = json.loads(resp.data)
    assert isinstance(payload.get("nodes"), list)
    assert isinstance(payload.get("edges"), list)


def test_discovery_graph_has_domain_node(app_client):
    sample_scan = {
        "scan_id": "smokegraph1",
        "target": "example.org",
        "status": "complete",
        "generated_at": "2026-03-15T10:00:00Z",
        "discovered_services": [],
        "tls_results": [],
    }
    with patch.dict(web_app_module.scan_store, {"smokegraph1": sample_scan}, clear=True):
        resp = app_client.get("/api/discovery-graph")
    assert resp.status_code == 200
    payload = json.loads(resp.data)
    node_ids = {n.get("id") for n in payload.get("nodes", [])}
    assert "domain:example.org" in node_ids
