import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from web.app import app
from web.routes.assets import _make_action_html


def test_inventory_view_button_targets_scan_results():
    with app.test_request_context("/assets"):
        html = _make_action_html(
            {
                "id": 42,
                "name": "example.com",
                "url": "https://example.com",
                "owner": "security",
                "risk_level": "Medium",
                "last_scan": "2026-04-14",
                "last_scan_id": "4b0984fe",
            },
            "csrf-token-placeholder",
        )

    assert 'data-open-scan-result' in html
    assert 'data-last-scan-id="4b0984fe"' in html
    assert '/results/4b0984fe' in html
    assert 'data-open-asset-details' not in html