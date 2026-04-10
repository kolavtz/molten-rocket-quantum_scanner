from __future__ import annotations

import json
import os
import re

import pytest

from src.services import inventory_scan_service


def test_run_scan_pipeline_persists_raw_artifact(tmp_path, monkeypatch):
    def _fake_runner(target, **_kwargs):
        return {
            "scan_id": "unit-scan-1",
            "target": target,
            "status": "complete",
            "overview": {"average_compliance_score": 91},
        }

    monkeypatch.setattr(inventory_scan_service, "RESULTS_DIR", str(tmp_path))

    report = inventory_scan_service.run_scan_pipeline(
        "https://example.com:443/path?q=1",
        ports=[443],
        options={"scan_type": "api_single", "scanned_by": "pytest", "add_to_inventory": True},
        scan_runner=_fake_runner,
    )

    raw_path = str(report.get("raw_result_path") or "")
    assert raw_path
    assert os.path.exists(raw_path)
    assert re.search(r"scan_\d{8}T\d{6}Z_[0-9a-f]{32}\.json$", raw_path)

    with open(raw_path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)
    assert payload.get("scan_id") == "unit-scan-1"
    assert payload.get("target") == "example.com"


def test_submit_scan_pipeline_returns_future(tmp_path, monkeypatch):
    monkeypatch.setattr(inventory_scan_service, "RESULTS_DIR", str(tmp_path))

    def _fake_runner(target, **_kwargs):
        return {"scan_id": "unit-scan-2", "target": target, "status": "complete"}

    future = inventory_scan_service.submit_scan_pipeline(
        "example.org",
        options={"scan_type": "api_single"},
        scan_runner=_fake_runner,
    )

    result = future.result(timeout=5)
    assert result.get("scan_id") == "unit-scan-2"
    assert os.path.exists(str(result.get("raw_result_path") or ""))


def test_run_scan_pipeline_rejects_invalid_target():
    with pytest.raises(ValueError):
        inventory_scan_service.run_scan_pipeline("example.com;rm -rf /")
