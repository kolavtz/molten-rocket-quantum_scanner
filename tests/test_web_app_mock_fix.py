import pytest
from unittest.mock import patch
import json
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from web.app import app
import web.app as web_app_module

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    with app.test_client() as c:
        yield c

def test_index_get(client):
    """Test index get with mocking correct db paths."""
    # Since login might be required depending on config, but client() fixture configures it.
    # In dashboard.py / index.html, it calls `asset_service.load_combined_assets()`
    with patch('src.database.list_scans', return_value=[]), \
         patch('src.database.list_assets', return_value=[]):
        resp = client.get('/', follow_redirects=True)
        assert resp.status_code == 200

def test_discovery_graph_empty_mock(client):
    """Test graph empty payload with correctly mock scan_store."""
    # If using dictionary mock:
    with patch.dict('web.app.scan_store', {}, clear=True):
        resp = client.get('/api/discovery-graph')
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data['nodes'] == []
