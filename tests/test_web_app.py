"""
Unit tests for the Flask web application routes.
"""
import json
import pytest

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from web.app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as c:
        yield c


class TestRoutes:
    """Tests for Flask route status codes and basic responses."""

    def test_index_get(self, client):
        resp = client.get('/')
        assert resp.status_code == 200
        assert b'QuantumShield' in resp.data

    def test_scan_post_empty_target(self, client):
        resp = client.post('/scan', data={'target': ''})
        # Should redirect to index
        assert resp.status_code == 302

    def test_results_not_found(self, client):
        resp = client.get('/results/nonexistent')
        assert resp.status_code == 404

    def test_cbom_not_found(self, client):
        resp = client.get('/cbom/nonexistent')
        assert resp.status_code == 404

    def test_api_scan_missing_target(self, client):
        resp = client.get('/api/scan')
        assert resp.status_code == 400
        data = json.loads(resp.data)
        assert 'error' in data

    def test_api_scans_list(self, client):
        resp = client.get('/api/scans')
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert isinstance(data, list)
