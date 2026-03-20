"""Regression tests for asset service robustness across legacy ORM shapes."""

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import patch

from src.services.asset_service import AssetService


class _FakeQuery:
    def __init__(self, result):
        self._result = result

    def filter_by(self, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def all(self):
        return self._result

    def first(self):
        return self._result


class _FakeSession:
    def __init__(self, assets, latest_scan):
        self._assets = assets
        self._latest_scan = latest_scan

    def query(self, model):
        name = getattr(model, "__name__", "")
        if name == "Asset":
            return _FakeQuery(self._assets)
        return _FakeQuery(self._latest_scan)


def test_load_combined_assets_handles_missing_notes_and_overview_attributes():
    service = AssetService()

    # Legacy-shaped objects: no Asset.notes and no Scan.overview
    legacy_asset = SimpleNamespace(
        id=1,
        name="example.com",
        url=None,
        asset_type="Web App",
        owner="Ops",
        risk_level="Medium",
    )
    legacy_scan = SimpleNamespace(
        target="example.com",
        status="complete",
        overall_pqc_score=61,
        completed_at=datetime(2026, 3, 20, 10, 0, 0),
        certificates=[],
    )

    fake_session = _FakeSession([legacy_asset], legacy_scan)

    with patch("src.db.db_session", fake_session):
        assets = service.load_combined_assets()

    assert len(assets) == 1
    row = assets[0]
    assert row["asset_name"] == "example.com"
    assert row["notes"] == ""
    assert row["overview"] == {}
