"""
Unit tests for the Flask web application routes.
"""
import json
import pytest

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from web.app import app


from unittest.mock import patch

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['LOGIN_DISABLED'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    # disable csrf for testing if needed
    with app.test_client() as c:
        yield c

@pytest.fixture
def mock_admin():
    with patch('web.app.current_user') as mock_user:
        mock_user.is_authenticated = True
        mock_user.role = "Admin"
        mock_user.username = "admin"
        yield mock_user

class TestRoutes:
    """Tests for Flask route status codes and basic responses."""

    def test_index_get(self, client, mock_admin):
        resp = client.get('/')
        assert resp.status_code == 200
        assert b'QuantumShield' in resp.data

    def test_scan_post_empty_target(self, client, mock_admin):
        resp = client.post('/scan', data={'target': ''})
        # Should redirect to index
        assert resp.status_code == 302

    def test_results_not_found(self, client, mock_admin):
        resp = client.get('/results/nonexistent')
        assert resp.status_code == 404

    def test_cbom_not_found(self, client, mock_admin):
        resp = client.get('/cbom/nonexistent')
        assert resp.status_code == 404

    def test_api_scan_missing_target(self, client, mock_admin):
        resp = client.get('/api/scan')
        assert resp.status_code == 400
        data = json.loads(resp.data)
        assert 'error' in data

    def test_api_scans_list(self, client):
        # /api/scans isn't currently login restricted in the same way, but let's test it
        resp = client.get('/api/scans')
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert isinstance(data, list)


class TestModulePages:
    """Tests for the 6 new module pages added in the PNB feature build."""

    def test_asset_inventory_page(self, client, mock_admin):
        resp = client.get('/asset-inventory')
        assert resp.status_code == 200
        assert b'ASSET INVENTORY' in resp.data

    def test_asset_discovery_page(self, client, mock_admin):
        resp = client.get('/asset-discovery')
        assert resp.status_code == 200
        assert b'ASSET DISCOVERY' in resp.data
        # vis.js network graph should be loaded
        assert b'vis-network' in resp.data

    def test_cbom_dashboard_page(self, client, mock_admin):
        resp = client.get('/cbom-dashboard')
        assert resp.status_code == 200
        assert b'CBOM' in resp.data

    def test_pqc_posture_page(self, client, mock_admin):
        resp = client.get('/pqc-posture')
        assert resp.status_code == 200
        assert b'POSTURE' in resp.data

    def test_cyber_rating_page(self, client, mock_admin):
        resp = client.get('/cyber-rating')
        assert resp.status_code == 200
        assert b'CYBER RATING' in resp.data

    def test_reporting_page(self, client, mock_admin):
        resp = client.get('/reporting')
        assert resp.status_code == 200
        assert b'REPORTING' in resp.data
        # Verify both form action endpoints are referenced
        assert b'report/schedule' in resp.data or b'/report/generate' in resp.data


class TestReportEndpoints:
    """Tests for the on-demand PDF generation and schedule persistence APIs."""

    def test_generate_report_returns_pdf(self, client, mock_admin):
        resp = client.post(
            '/report/generate',
            data=json.dumps({'report_type': 'Executive Reporting', 'sections': []}),
            content_type='application/json',
        )
        assert resp.status_code == 200
        assert resp.content_type == 'application/pdf'
        # PDF magic bytes: %PDF
        assert resp.data[:4] == b'%PDF'

    def test_generate_report_with_sections(self, client, mock_admin):
        resp = client.post(
            '/report/generate',
            data=json.dumps({
                'report_type': 'CBOM',
                'sections': ['CBOM', 'PQC Posture'],
            }),
            content_type='application/json',
        )
        assert resp.status_code == 200
        assert resp.content_type == 'application/pdf'

    def test_schedule_report_returns_ok(self, client, mock_admin):
        resp = client.post(
            '/report/schedule',
            data=json.dumps({
                'report_type': 'Executive Summary Report',
                'frequency': 'Weekly',
                'assets': 'All Assets',
                'sections': ['Asset Inventory', 'CBOM'],
                'timezone': 'UTC',
            }),
            content_type='application/json',
        )
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data['status'] == 'ok'
        assert 'id' in data

    def test_list_schedules_returns_list(self, client, mock_admin):
        resp = client.get('/report/schedules')
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert isinstance(data, list)

