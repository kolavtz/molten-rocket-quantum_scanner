import json
from unittest.mock import patch

import web.app as web_app_module


def test_discovery_graph_live_payload_has_links(app_client):
    sample_scan = {
        "scan_id": "intgraph1",
        "target": "example.org",
        "status": "complete",
        "generated_at": "2026-03-15T10:00:00Z",
        "discovered_services": [
            {"host": "203.0.113.10", "port": 443, "service": "https", "banner": "nginx/1.25.5", "is_tls": True}
        ],
        "tls_results": [{"tls_version": "TLS 1.3", "cipher_suites": ["TLS_AES_256_GCM_SHA384"]}],
    }
    with patch.dict(web_app_module.scan_store, {"intgraph1": sample_scan}, clear=True):
        resp = app_client.get("/api/discovery-graph")

    assert resp.status_code == 200
    payload = json.loads(resp.data)
    edges = payload.get("edges", [])
    assert any(e.get("from") == "domain:example.org" for e in edges)
