from src.services.cbom_service import CbomService


def test_build_scan_filters_ignores_invalid_dates():
    filters = CbomService._build_scan_filters(start_date="invalid-date", end_date="also-invalid")
    assert len(filters) >= 3


def test_build_cert_filters_with_asset_id():
    filters = CbomService._build_cert_filters(asset_id=42)
    assert len(filters) >= 4
