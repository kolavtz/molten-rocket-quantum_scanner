import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from web.blueprints.api_assets import _derive_cluster_label


def test_cluster_label_groups_subdomains_by_registrable_domain():
    assert _derive_cluster_label("portal.app.example.com") == "example.com"
    assert _derive_cluster_label("api.example.com:443") == "example.com"


def test_cluster_label_handles_multi_part_public_suffixes():
    assert _derive_cluster_label("gateway.finance.gov.uk") == "finance.gov.uk"
    assert _derive_cluster_label("scan.ops.co.in") == "ops.co.in"


def test_cluster_label_keeps_ip_ranges_for_ips():
    assert _derive_cluster_label("203.0.113.10") == "203.0.113.0/24"
