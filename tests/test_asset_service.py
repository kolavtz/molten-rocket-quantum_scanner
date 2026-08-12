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


def test_load_combined_assets_includes_certificate_valid_from_and_valid_until():
    service = AssetService()

    asset = SimpleNamespace(
        id=42,
        name="secure.domain.com",
        target="secure.domain.com",
        url="https://secure.domain.com",
        asset_type="Web App",
        owner="Security",
        risk_level="Low",
        is_deleted=False,
    )
    cert = SimpleNamespace(
        id=99,
        asset_id=42,
        endpoint="secure.domain.com:443",
        valid_from=datetime(2025, 1, 1, 0, 0, 0),
        valid_until=datetime(2027, 1, 1, 0, 0, 0),
        is_current=True,
        is_deleted=False,
        key_length=2048,
        tls_version="TLS 1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        ca="DigiCert",
        issuer="DigiCert Global Root CA",
    )

    class _CustomSession(_FakeSession):
        def query(self, model):
            name = getattr(model, "__name__", "")
            if name == "Asset":
                return _FakeQuery([asset])
            if name == "Certificate":
                return _FakeQuery([cert])
            return _FakeQuery([])

    fake_session = _CustomSession([asset], [])

    with patch("src.db.db_session", fake_session):
        assets = service.load_combined_assets()

    assert len(assets) == 1
    row = assets[0]
    assert row["cert_valid_from"] == "2025-01-01"
    assert row["cert_valid_until"] == "2027-01-01"
    assert row["cert_status"] == "Valid"

