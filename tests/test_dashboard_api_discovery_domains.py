import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from web.routes.dashboard_api import _split_discovery_tab_query


class _FakeResult:
    def __init__(self, rows=None, scalar_value=None):
        self._rows = rows or []
        self._scalar_value = scalar_value

    def mappings(self):
        return self

    def all(self):
        return self._rows

    def scalar(self):
        return self._scalar_value


def test_split_discovery_domains_includes_registrar_and_domain_name():
    fake_session = MagicMock()
    fake_session.execute.side_effect = [
        _FakeResult([
            {
                "id": 101,
                "name": "example.com",
                "status": "new",
                "detection_date": "2026-04-14T10:00:00",
                "asset_id": 55,
                "asset_name": "example.com",
                "owner": "security",
                "registrar": "Cloudflare, Inc.",
            }
        ]),
        _FakeResult(scalar_value=1),
    ]

    params = {"search": "", "page": 1, "page_size": 25, "sort": "name", "order": "asc"}

    with patch("web.routes.dashboard_api.db_session", fake_session), patch("web.routes.dashboard_api._table_exists", return_value=True):
        items, total = _split_discovery_tab_query("domains", params)

    assert total == 1
    assert items[0]["domain_name"] == "example.com"
    assert items[0]["registrar"] == "Cloudflare, Inc."
    assert items[0]["name"] == "example.com"