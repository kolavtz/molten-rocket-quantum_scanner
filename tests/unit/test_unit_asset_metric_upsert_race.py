import importlib

import pytest
from sqlalchemy.exc import IntegrityError


class _FakeSavepoint:
    def __init__(self):
        self.committed = False
        self.rolled_back = False

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True


class _FakeQuery:
    def __init__(self, first_values):
        self._first_values = first_values

    def filter(self, *_args, **_kwargs):
        return self

    def first(self):
        if self._first_values:
            return self._first_values.pop(0)
        return None


class _FakeSession:
    def __init__(self, first_values, fail_on_flush):
        self._first_values = first_values
        self.fail_on_flush = fail_on_flush
        self.added = []
        self.savepoint = _FakeSavepoint()

    def query(self, *_args, **_kwargs):
        return _FakeQuery(self._first_values)

    def begin_nested(self):
        return self.savepoint

    def add(self, obj):
        self.added.append(obj)

    def flush(self):
        if self.fail_on_flush:
            raise IntegrityError(
                "INSERT INTO asset_metrics (asset_id) VALUES (%(asset_id)s)",
                {"asset_id": 735},
                Exception("Duplicate entry '735' for key 'asset_metrics.PRIMARY'"),
            )


@pytest.mark.parametrize(
    "module_path,class_name",
    [
        ("src.services.pqc_calculation_service", "PQCCalculationService"),
        ("src.services.risk_calculation_service", "RiskCalculationService"),
        ("src.services.digital_label_service", "DigitalLabelService"),
    ],
)
def test_get_or_create_asset_metric_handles_duplicate_insert(monkeypatch, module_path, class_name):
    module = importlib.import_module(module_path)
    service_cls = getattr(module, class_name)

    existing_metric = object()
    fake_session = _FakeSession(first_values=[None, existing_metric], fail_on_flush=True)
    monkeypatch.setattr(module, "db_session", fake_session)

    metric = service_cls._get_or_create_asset_metric(735)

    assert metric is existing_metric
    assert fake_session.savepoint.rolled_back is True
    assert fake_session.savepoint.committed is False


@pytest.mark.parametrize(
    "module_path,class_name",
    [
        ("src.services.pqc_calculation_service", "PQCCalculationService"),
        ("src.services.risk_calculation_service", "RiskCalculationService"),
        ("src.services.digital_label_service", "DigitalLabelService"),
    ],
)
def test_get_or_create_asset_metric_creates_when_missing(monkeypatch, module_path, class_name):
    module = importlib.import_module(module_path)
    service_cls = getattr(module, class_name)

    fake_session = _FakeSession(first_values=[None], fail_on_flush=False)
    monkeypatch.setattr(module, "db_session", fake_session)

    metric = service_cls._get_or_create_asset_metric(735)

    assert metric is fake_session.added[0]
    assert fake_session.savepoint.committed is True
    assert fake_session.savepoint.rolled_back is False
