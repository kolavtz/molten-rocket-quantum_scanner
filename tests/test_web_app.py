"""
Unit tests for the Flask web application routes.
"""
import json
import pytest
from datetime import datetime, timezone
from uuid import uuid4

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from web.app import app
import web.app as web_app_module
from web.routes.assets import build_assets_page_context
from src.db import db_session
from src.models import Asset, User


from unittest.mock import patch


def _new_target(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:10]}.example"

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


@pytest.fixture
def mock_manager():
    with patch('web.app.current_user') as mock_user:
        mock_user.is_authenticated = True
        mock_user.role = "Manager"
        mock_user.username = "manager"
        yield mock_user

class TestRoutes:
    """Tests for Flask route status codes and basic responses."""

    def test_index_get(self, client, mock_admin):
        resp = client.get('/')
        assert resp.status_code == 302
        assert "/dashboard/assets" in (resp.headers.get("Location") or "")

    def test_scan_center_get(self, client, mock_admin):
        resp = client.get('/scan-center')
        assert resp.status_code == 200
        assert b'SCAN CENTER' in resp.data

    def test_scan_post_empty_target(self, client, mock_admin):
        resp = client.post('/scan', data={'target': ''})
        # Should redirect to index
        assert resp.status_code == 302

    def test_scan_manual_asset_class_forwarded(self, client, mock_admin):
        fake_report = {
            'scan_id': 'manual001',
            'status': 'complete',
            'overview': {
                'average_compliance_score': 80,
                'total_assets': 1,
                'quantum_safe': 1,
                'quantum_vulnerable': 0,
            }
        }
        with patch('web.app.run_scan_pipeline', return_value=fake_report) as mocked_pipeline:
            resp = client.post(
                '/scan',
                data={
                    'target': 'example.com',
                    'asset_class_mode': 'manual',
                    'asset_class_value': 'Payment Gateway',
                },
            )
            assert resp.status_code == 302
            mocked_pipeline.assert_called_once()
            _, kwargs = mocked_pipeline.call_args
            assert kwargs.get('asset_class_hint') == 'Payment Gateway'

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

    def test_asset_inventory_uses_server_table_mode(self, client, mock_admin):
        asset = Asset(target=_new_target('inventory-render'), asset_type='Web App', is_deleted=False)
        db_session.add(asset)
        db_session.commit()

        resp = client.get('/asset-inventory')
        assert resp.status_code == 200
        assert b'data-table-mode="server"' in resp.data
        assert b'data-table-shell' in resp.data
        assert b'data-bulk-form' in resp.data

    def test_asset_inventory_context_excludes_deleted_assets(self, client, mock_admin):
        active = Asset(target=_new_target('inventory-active'), asset_type='Web App', is_deleted=False)
        deleted = Asset(
            target=_new_target('inventory-deleted'),
            asset_type='Web App',
            is_deleted=True,
            deleted_at=datetime.now(timezone.utc),
        )
        active_target = active.target
        deleted_target = deleted.target
        db_session.add_all([active, deleted])
        db_session.commit()

        previous_testing = app.config['TESTING']
        app.config['TESTING'] = False
        try:
            with app.test_request_context('/asset-inventory'):
                ctx = build_assets_page_context()
        finally:
            app.config['TESTING'] = previous_testing

        asset_targets = {row['name'] for row in ctx['vm']['assets']}
        assert active_target in asset_targets
        assert deleted_target not in asset_targets
        assert ctx['page_data'].total_count >= 1
        assert ctx['page_data'].total_count == len(ctx['vm']['assets'])

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


class TestDiscoveryGraph:
    """Tests for the realtime discovery graph payload endpoint."""

    def test_discovery_graph_empty_payload(self, client, mock_admin):
        with patch.dict(web_app_module.scan_store, {}, clear=True):
            resp = client.get('/api/discovery-graph')
            assert resp.status_code == 200
            data = json.loads(resp.data)
            assert isinstance(data.get('nodes'), list)
            assert isinstance(data.get('edges'), list)
            assert data['nodes'] == []
            assert data['edges'] == []

    def test_discovery_graph_live_payload(self, client, mock_admin):
        sample_scan = {
            'scan_id': 'abc12345',
            'target': 'example.org',
            'status': 'complete',
            'generated_at': '2026-03-15T10:00:00Z',
            'discovered_services': [
                {'host': '203.0.113.10', 'port': 443, 'service': 'https', 'banner': 'nginx/1.25.5', 'is_tls': True}
            ],
            'tls_results': [
                {
                    'tls_version': 'TLS 1.3',
                    'cipher_suites': ['TLS_AES_256_GCM_SHA384'],
                    'issuer': {'O': 'Test CA', 'CN': 'Test CA Root'}
                }
            ],
        }
        with patch.dict(web_app_module.scan_store, {'abc12345': sample_scan}, clear=True):
            resp = client.get('/api/discovery-graph')
            assert resp.status_code == 200
            data = json.loads(resp.data)
            node_ids = {n['id'] for n in data.get('nodes', [])}
            assert 'domain:example.org' in node_ids
            assert 'ip:203.0.113.10' in node_ids
            assert any(e.get('from') == 'domain:example.org' and e.get('to') == 'ip:203.0.113.10' for e in data.get('edges', []))


class TestUnifiedDashboardApi:
    """Tests for the single unified dashboard API endpoint."""

    def test_dashboard_api_get(self, client, mock_admin):
        resp = client.get('/api/dashboard')
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data.get('status') == 'success'
        assert isinstance(data.get('data'), dict)
        assert 'inventory' in data.get('data', {})

    def test_dashboard_api_refresh_action(self, client, mock_admin):
        resp = client.post(
            '/api/dashboard',
            data=json.dumps({'action': 'dashboard.refresh'}),
            content_type='application/json',
        )
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data.get('status') == 'success'
        assert isinstance(data.get('data'), dict)


class TestAssetDeletionRoutes:
    def test_asset_delete_allows_manager_role(self, client, mock_manager):
        target = _new_target('mgr-del')
        asset = Asset(target=target, asset_type='Web App', is_deleted=False)
        db_session.add(asset)
        db_session.commit()
        asset_id = int(asset.id)

        with patch('web.routes.assets.current_user') as route_user:
            route_user.role = 'Manager'
            route_user.id = 42
            route_user.username = 'manager'
            resp = client.post(f'/assets/{asset_id}/delete')

        assert resp.status_code == 302
        reloaded = db_session.query(Asset).filter(Asset.id == asset_id).first()
        assert reloaded is not None
        assert reloaded.is_deleted is True

    def test_asset_bulk_delete_allows_manager_role(self, client, mock_manager):
        target_a = _new_target('mgr-bulk-a')
        target_b = _new_target('mgr-bulk-b')
        a = Asset(target=target_a, asset_type='Web App', is_deleted=False)
        b = Asset(target=target_b, asset_type='Web App', is_deleted=False)
        db_session.add_all([a, b])
        db_session.commit()
        a_id = int(a.id)
        b_id = int(b.id)

        payload = {'selected_asset_ids': f'{a_id},{b_id}', 'bulk_action': 'bulk-delete'}
        with patch('web.routes.assets.current_user') as route_user:
            route_user.role = 'Manager'
            route_user.id = 99
            route_user.username = 'manager'
            resp = client.post('/assets/bulk-delete', data=payload)

        assert resp.status_code == 302
        reloaded = db_session.query(Asset).filter(Asset.id.in_([a_id, b_id])).all()
        assert len(reloaded) == 2
        assert all(row.is_deleted for row in reloaded)

    def test_asset_bulk_delete_accepts_native_checkbox_submission(self, client, mock_manager):
        target_a = _new_target('mgr-native-a')
        target_b = _new_target('mgr-native-b')
        a = Asset(target=target_a, asset_type='Web App', is_deleted=False)
        b = Asset(target=target_b, asset_type='Web App', is_deleted=False)
        db_session.add_all([a, b])
        db_session.commit()
        a_id = int(a.id)
        b_id = int(b.id)

        payload = {'asset_ids': [str(a_id), str(b_id)], 'bulk_action': 'bulk-delete'}
        with patch('web.routes.assets.current_user') as route_user:
            route_user.role = 'Manager'
            route_user.id = 100
            route_user.username = 'manager'
            resp = client.post('/assets/bulk-delete', data=payload)

        assert resp.status_code == 302
        reloaded = db_session.query(Asset).filter(Asset.id.in_([a_id, b_id])).all()
        assert len(reloaded) == 2
        assert all(row.is_deleted for row in reloaded)

    def test_asset_delete_api_allows_manager_role(self, client, mock_manager):
        target = _new_target('mgr-api-del')
        asset = Asset(target=target, asset_type='Web App', is_deleted=False)
        db_session.add(asset)
        db_session.commit()
        asset_id = int(asset.id)

        with patch('web.routes.assets.current_user') as route_user:
            route_user.role = 'Manager'
            route_user.id = 142
            route_user.username = 'manager'
            resp = client.post(
                f'/api/assets/{asset_id}/delete',
                data=json.dumps({}),
                content_type='application/json',
                headers={'Accept': 'application/json'},
            )

        assert resp.status_code == 200
        payload = json.loads(resp.data)
        assert payload['status'] == 'success'
        assert asset_id in payload.get('deleted_ids', [])
        reloaded = db_session.query(Asset).filter(Asset.id == asset_id).first()
        assert reloaded is not None
        assert reloaded.is_deleted is True

    def test_asset_bulk_delete_api_allows_manager_role(self, client, mock_manager):
        target_a = _new_target('mgr-api-bulk-a')
        target_b = _new_target('mgr-api-bulk-b')
        a = Asset(target=target_a, asset_type='Web App', is_deleted=False)
        b = Asset(target=target_b, asset_type='Web App', is_deleted=False)
        db_session.add_all([a, b])
        db_session.commit()
        a_id = int(a.id)
        b_id = int(b.id)

        with patch('web.routes.assets.current_user') as route_user:
            route_user.role = 'Manager'
            route_user.id = 143
            route_user.username = 'manager'
            resp = client.post(
                '/api/assets/bulk-delete',
                data=json.dumps({'selected_asset_ids': f'{a_id},{b_id}'}),
                content_type='application/json',
                headers={'Accept': 'application/json'},
            )

        assert resp.status_code == 200
        payload = json.loads(resp.data)
        assert payload['status'] == 'success'
        deleted_ids = payload.get('deleted_ids', [])
        assert a_id in deleted_ids and b_id in deleted_ids
        reloaded = db_session.query(Asset).filter(Asset.id.in_([a_id, b_id])).all()
        assert len(reloaded) == 2
        assert all(row.is_deleted for row in reloaded)

    def test_asset_edit_api_updates_asset(self, client, mock_manager):
        target = _new_target('mgr-api-edit')
        asset = Asset(target=target, asset_type='Web App', owner='Old', risk_level='Low', is_deleted=False)
        db_session.add(asset)
        db_session.commit()

        with patch('web.routes.assets.current_user') as route_user:
            route_user.role = 'Manager'
            route_user.id = 144
            route_user.username = 'manager'
            resp = client.post(
                f'/api/assets/{asset.id}/edit',
                data=json.dumps({'owner': 'New Team', 'risk_level': 'Critical'}),
                content_type='application/json',
                headers={'Accept': 'application/json'},
            )

        assert resp.status_code == 200
        payload = json.loads(resp.data)
        assert payload['status'] == 'success'
        reloaded = db_session.query(Asset).filter(Asset.id == asset.id).first()
        assert reloaded is not None
        assert reloaded.owner == 'New Team'
        assert reloaded.risk_level == 'Critical'


class TestNonInventoryApiMutations:
    def test_dashboard_add_asset_api(self, client, mock_admin):
        target = _new_target('discovery-api-add')
        resp = client.post(
            '/dashboard/api/assets',
            data=json.dumps({'target': target, 'type': 'Web App', 'owner': 'SecOps', 'risk_level': 'Medium'}),
            content_type='application/json',
            headers={'Accept': 'application/json'},
        )

        assert resp.status_code == 200
        payload = json.loads(resp.data)
        assert payload.get('status') == 'success'
        created = db_session.query(Asset).filter(Asset.target == target).first()
        assert created is not None
        assert created.is_deleted is False

    def test_recycle_bin_restore_assets_json(self, client, mock_admin):
        target = _new_target('recycle-json-restore')
        asset = Asset(
            target=target,
            asset_type='Web App',
            is_deleted=True,
            deleted_at=datetime.now(timezone.utc),
        )
        db_session.add(asset)
        db_session.commit()

        resp = client.post(
            '/recycle-bin',
            data=json.dumps({'action': 'restore_assets', 'asset_ids': [asset.id]}),
            content_type='application/json',
            headers={'Accept': 'application/json'},
        )

        assert resp.status_code == 200
        payload = json.loads(resp.data)
        assert payload.get('status') == 'success'
        assert payload.get('restored_count') == 1
        reloaded = db_session.query(Asset).filter(Asset.id == asset.id).first()
        assert reloaded is not None
        assert reloaded.is_deleted is False


class TestAdminUserApiMutations:
    """Tests for admin user management table-row actions via JSON API."""

    def test_admin_update_user_json(self, client, mock_admin):
        # Create a test user using db module
        from werkzeug.security import generate_password_hash
        import uuid
        from src import database as db
        
        db.init_db()  # Ensure DB exists
        
        username = f'test_user_{uuid.uuid4().hex[:8]}'
        email = f'{username}@example.com'
        
        # Get or create a valid created_by user (using None avoids FK constraint issues)
        updated_user_username = f'test_target_{uuid.uuid4().hex[:8]}'
        
        user_id = db.create_invited_user(
            employee_id=f'EMP-{uuid.uuid4().hex[:8]}',
            username=updated_user_username,
            email=email,
            role='Viewer',
            created_by=None,  # Avoid FK constraint
            password_hash=generate_password_hash('Test123!')
        )
        assert user_id is not None

        with patch('web.app.current_user') as route_user:
            route_user.role = 'Admin'
            route_user.id = 999
            route_user.username = 'admin'
            resp = client.post(
                f'/admin/users/{user_id}/update',
                data=json.dumps({'role': 'Manager', 'is_active': False}),
                content_type='application/json',
                headers={'Accept': 'application/json'},
            )

        assert resp.status_code == 200
        payload = json.loads(resp.data)
        assert payload['status'] == 'success'
        assert payload['role'] == 'Manager'
        assert payload['is_active'] is False

    def test_admin_reset_password_json(self, client, mock_admin):
        # Create a test user with email
        from werkzeug.security import generate_password_hash
        import uuid
        from src import database as db
        
        db.init_db()
        
        username = f'test_reset_{uuid.uuid4().hex[:8]}'
        email = f'{username}@example.com'
        
        user_id = db.create_invited_user(
            employee_id=f'EMP-{uuid.uuid4().hex[:8]}',
            username=username,
            email=email,
            role='Viewer',
            created_by=None,
            password_hash=generate_password_hash('Test123!')
        )
        assert user_id is not None

        with patch('web.app.current_user') as route_user, \
             patch('web.app.mail.send') as mock_send:
            route_user.role = 'Admin'
            route_user.id = 999
            route_user.username = 'admin'
            resp = client.post(
                f'/admin/users/{user_id}/reset-password',
                data=json.dumps({}),
                content_type='application/json',
                headers={'Accept': 'application/json'},
            )

        assert resp.status_code == 200
        payload = json.loads(resp.data)
        assert payload['status'] == 'success'
        assert payload['message'] == 'Password reset email sent.'
        assert payload['user_id'] == user_id

    def test_admin_regen_api_key_json(self, client, mock_admin):
        # Create a test user
        from werkzeug.security import generate_password_hash
        import uuid
        from src import database as db
        
        db.init_db()
        
        username = f'test_api_key_{uuid.uuid4().hex[:8]}'
        email = f'{username}@example.com'
        
        user_id = db.create_invited_user(
            employee_id=f'EMP-{uuid.uuid4().hex[:8]}',
            username=username,
            email=email,
            role='Viewer',
            created_by=None,
            password_hash=generate_password_hash('Test123!')
        )
        assert user_id is not None

        with patch('web.app.current_user') as route_user:
            route_user.role = 'Admin'
            route_user.id = 999
            route_user.username = 'admin'
            resp = client.post(
                f'/admin/users/{user_id}/regen-api-key',
                data=json.dumps({}),
                content_type='application/json',
                headers={'Accept': 'application/json'},
            )

        assert resp.status_code == 200
        payload = json.loads(resp.data)
        assert payload['status'] == 'success'
        assert 'api_key' in payload
        assert payload['api_key'].startswith('qss_')
