"""
Unit tests for CbomService class.
"""
from unittest.mock import Mock, patch

from src.services.cbom_service import CbomService


def make_query_mock():
    q = Mock()
    q.filter.return_value = q
    q.join.return_value = q
    q.group_by.return_value = q
    q.order_by.return_value = q
    q.limit.return_value = q
    q.count.return_value = 0
    q.scalar.return_value = 0
    q.all.return_value = []
    q.with_entities.return_value = q
    return q


@patch('src.services.cbom_service.db_session')
def test_get_cbom_dashboard_data_empty(mock_db_session):
    # All queries returning default zero/empty values should produce empty kpis and no rows
    mock_db_session.query.side_effect = lambda *args, **kwargs: make_query_mock()

    data = CbomService.get_cbom_dashboard_data(asset_id=None, start_date=None, end_date=None, limit=10)

    assert data['kpis']['total_applications'] == 0
    assert data['kpis']['sites_surveyed'] == 0
    assert data['kpis']['active_certificates'] == 0
    assert data['kpis']['weak_cryptography'] == 0
    assert data['kpis']['certificate_issues'] == 0
    assert data['key_length_distribution'] == {'No Data': 0}
    assert data['cipher_usage'] == {'No Data': 0}
    assert data['top_cas'] == {'No Data': 0}
    assert data['protocols'] == {'No Data': 0}
    assert data['applications'] == []


@patch('src.services.cbom_service.db_session')
def test_get_cbom_dashboard_data_weak_values(mock_db_session):
    q = make_query_mock()
    q.count.return_value = 1
    q.scalar.return_value = 1
    q.all.return_value = []
    mock_db_session.query.return_value = q

    data = CbomService.get_cbom_dashboard_data(asset_id=1, start_date=None, end_date=None, limit=10)

    assert data['kpis']['total_applications'] == 1
    assert data['kpis']['sites_surveyed'] == 1
    assert data['kpis']['active_certificates'] == 1
    assert data['kpis']['weak_cryptography'] == 4  # weak_tls+weak_key+expired+self_signed from expected query paths
    assert 'weakness_heatmap' in data
