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
