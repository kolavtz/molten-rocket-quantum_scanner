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
    """Minimal SQLAlchemy session mock that supports both legacy
    .query()/.filter()/.first() and the modern .get(model, pk) API."""

    def __init__(self, get_return_values, first_values=None, fail_on_flush=False):
        # get_return_values: list consumed by .get() calls in order
        self._get_return_values = list(get_return_values)
        self._first_values = list(first_values or [])
        self.fail_on_flush = fail_on_flush
        self.added = []
        self.new = []  # pending objects (mirrors SQLAlchemy session.new)
        self.savepoint = _FakeSavepoint()

    def get(self, model, pk):
        """Mock Session.get(Model, primary_key)."""
        if self._get_return_values:
            return self._get_return_values.pop(0)
        return None

    def query(self, *_args, **_kwargs):
        return _FakeQuery(self._first_values)

    def begin_nested(self):
        return self.savepoint

    def add(self, obj):
        self.added.append(obj)
        self.new.append(obj)  # mirror session.new

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
def test_get_or_create_asset_metric_creates_when_missing(monkeypatch, module_path, class_name):
    """When db_session.get() returns None (no existing row), the service
    creates a new AssetMetric and adds it to the session."""
    module = importlib.import_module(module_path)
    service_cls = getattr(module, class_name)

    # .get() returns None → miss → should create
    fake_session = _FakeSession(get_return_values=[None], fail_on_flush=False)
    monkeypatch.setattr(module, "db_session", fake_session)

    metric = service_cls._get_or_create_asset_metric(735)

    assert metric is fake_session.added[0], "expected a newly created object"


@pytest.mark.parametrize(
    "module_path,class_name",
    [
        ("src.services.pqc_calculation_service", "PQCCalculationService"),
        ("src.services.risk_calculation_service", "RiskCalculationService"),
        ("src.services.digital_label_service", "DigitalLabelService"),
    ],
)
def test_get_or_create_asset_metric_returns_existing(monkeypatch, module_path, class_name):
    """When db_session.get() returns an existing row, the service returns it
    without creating a duplicate."""
    module = importlib.import_module(module_path)
    service_cls = getattr(module, class_name)

    existing_metric = object()
    fake_session = _FakeSession(get_return_values=[existing_metric], fail_on_flush=False)
    monkeypatch.setattr(module, "db_session", fake_session)

    metric = service_cls._get_or_create_asset_metric(735)

    assert metric is existing_metric, "expected the existing row to be returned"
    assert len(fake_session.added) == 0, "should not have added any new objects"


@pytest.mark.parametrize(
    "module_path,class_name",
    [
        ("src.services.pqc_calculation_service", "PQCCalculationService"),
        ("src.services.risk_calculation_service", "RiskCalculationService"),
        ("src.services.digital_label_service", "DigitalLabelService"),
    ],
)
def test_get_or_create_asset_metric_handles_duplicate_insert(monkeypatch, module_path, class_name):
    """Legacy test kept for compatibility: if .get() returns None twice (first miss,
    then second check after a hypothetical concurrent insert), the service returns
    the newly created object from session.new."""
    module = importlib.import_module(module_path)
    service_cls = getattr(module, class_name)

    # Both .get() calls return None → service creates a new metric
    fake_session = _FakeSession(get_return_values=[None, None], fail_on_flush=False)
    monkeypatch.setattr(module, "db_session", fake_session)

    metric = service_cls._get_or_create_asset_metric(735)

    # The returned metric should be the newly created one that was added
    assert metric is not None
