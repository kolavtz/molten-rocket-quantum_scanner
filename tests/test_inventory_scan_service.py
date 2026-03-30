"""Unit tests for inventory scan service transaction resilience."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import cast

from sqlalchemy.exc import IntegrityError

from src.db import db_session
from src.models import Asset, Scan
from src.services.inventory_scan_service import InventoryScanService


class _FlakyAsset:
    def __init__(self) -> None:
        self._broken = False
        self._id = 99123
        self._name = "google.com"
        self.owner = "qa"

    @property
    def id(self):
        if self._broken:
            raise RuntimeError("asset id expired")
        return self._id

    @property
    def name(self):
        if self._broken:
            raise RuntimeError("asset name expired")
        return self._name


def test_scan_asset_exception_path_uses_captured_identity(monkeypatch):
    asset = _FlakyAsset()

    def _runner(_target, **_kwargs):
        asset._broken = True
        raise RuntimeError("forced runner failure")

    service = InventoryScanService(scan_runner=_runner)

    rollback_called = {"value": False}

    def _rollback():
        rollback_called["value"] = True

    monkeypatch.setattr("src.services.inventory_scan_service.db_session.rollback", _rollback)

    result = service.scan_asset(cast(Asset, asset))

    assert result["status"] == "failed"
    assert result["asset_id"] == 99123
    assert result["asset_name"] == "google.com"
    assert "forced runner failure" in result["errors"][0]
    assert rollback_called["value"] is True


def test_sync_asset_metrics_failure_rolls_back_nested_savepoint(monkeypatch):
    target = f"svc-metrics-{datetime.now(timezone.utc).timestamp():.0f}.example"
    asset = Asset(target=target, asset_type="Web App", is_deleted=False)
    db_session.add(asset)
    db_session.flush()

    scan = Scan(
        scan_id=f"scan-metrics-{int(datetime.now(timezone.utc).timestamp())}",
        target=target,
        status="complete",
        report_json="{}",
        is_deleted=False,
    )
    db_session.add(scan)
    db_session.commit()

    service = InventoryScanService(scan_runner=None)

    class _Savepoint:
        def __init__(self) -> None:
            self.rolled_back = False
            self.committed = False

        def rollback(self) -> None:
            self.rolled_back = True

        def commit(self) -> None:
            self.committed = True

    savepoint = _Savepoint()

    monkeypatch.setattr(
        "src.services.inventory_scan_service.db_session.begin_nested",
        lambda: savepoint,
    )

    def _raise_integrity(*_args, **_kwargs):
        raise IntegrityError("INSERT INTO asset_metrics", {}, Exception("dup"))

    monkeypatch.setattr(
        "src.services.pqc_calculation_service.PQCCalculationService.calculate_and_store_pqc_metrics",
        _raise_integrity,
    )

    service._sync_asset_from_report(asset, {"overview": {}, "discovered_services": []})

    assert savepoint.rolled_back is True
    assert savepoint.committed is False
