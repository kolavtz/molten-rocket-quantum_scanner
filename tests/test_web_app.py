"""
Unit tests for the Flask web application routes.
"""
import json
import pytest
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from web.app import app
import web.app as web_app_module
from web.routes.assets import build_asset_detail_api_response, build_assets_page_context, build_comprehensive_asset_dto
from src.db import db_session
from src.models import Asset, Certificate, Scan, User
from sqlalchemy import text


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
        payload = json.loads(resp.data)
        assert "data" in payload
        assert "items" in payload["data"]


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
        assert b'data-open-asset-details' in resp.data
        assert b'>View</button>' in resp.data
        assert b'>Details</button>' not in resp.data
        assert b'>Scans</button>' not in resp.data

    def test_header_hides_reset_and_exposes_mobile_menu_hooks(self, client, mock_admin):
        resp = client.get('/asset-inventory')
        assert resp.status_code == 200
        assert b'id="themeReset"' not in resp.data
        assert b'id="navHamburger"' in resp.data
        assert b'id="navLinks"' in resp.data
        assert b'aria-controls="navLinks"' in resp.data

    def test_admin_theme_page_keeps_reset_in_theme_settings(self, client, mock_admin):
        resp = client.get('/admin/theme')
        assert resp.status_code == 200
        assert b'name="reset_colors"' in resp.data
        assert b'RESET BOTH TO SYSTEM DEFAULTS' in resp.data

    def test_admin_theme_quick_switch_dark_mode_persists(self, client, mock_admin, tmp_path):
        theme_file = tmp_path / "theme.json"
        with patch.object(web_app_module, "THEME_FILE", str(theme_file)):
            resp = client.post('/admin/theme', data={'quick_mode': 'dark'})
            assert resp.status_code == 302
            assert theme_file.exists()

            with open(theme_file, 'r', encoding='utf-8') as f:
                saved = json.load(f)

            assert saved.get('mode') == 'dark'
            assert isinstance(saved.get('dark'), dict)
            assert isinstance(saved.get('light'), dict)

    def test_admin_theme_reset_night_defaults_restores_dark_palette(self, client, mock_admin, tmp_path):
        theme_file = tmp_path / "theme.json"
        custom_theme = {
            "mode": "light",
            "dark": {
                "bg_navbar": "#111111",
                "bg_primary": "#111111",
                "bg_secondary": "#111111",
                "bg_card": "#111111",
                "bg_input": "#111111",
                "border_subtle": "#111111",
                "border_hover": "#111111",
                "text_primary": "#eeeeee",
                "text_secondary": "#dddddd",
                "text_muted": "#cccccc",
                "accent_color": "#ff00ff",
                "text_on_accent": "#ffffff",
                "safe": "#22c55e",
                "warn": "#f59e0b",
                "danger": "#ef4444",
            },
            "light": dict(web_app_module.THEME_DEFAULTS["light"]),
        }
        with open(theme_file, 'w', encoding='utf-8') as f:
            json.dump(custom_theme, f)

        with patch.object(web_app_module, "THEME_FILE", str(theme_file)):
            resp = client.post('/admin/theme', data={'reset_palette': 'dark'})
            assert resp.status_code == 302

            with open(theme_file, 'r', encoding='utf-8') as f:
                saved = json.load(f)

            assert saved.get('dark', {}).get('bg_primary') == web_app_module.THEME_DEFAULTS['dark']['bg_primary']
            assert saved.get('dark', {}).get('accent_color') == web_app_module.THEME_DEFAULTS['dark']['accent_color']
            assert saved.get('mode') == 'dark'

    def test_admin_audit_export_rejects_short_password_json(self, client, mock_admin):
        resp = client.post(
            '/admin/audit/export',
            data=json.dumps({'password': 'short', 'limit': 200}),
            content_type='application/json',
        )
        assert resp.status_code == 400
        payload = json.loads(resp.data)
        assert payload.get('status') == 'error'

    def test_admin_audit_export_returns_encrypted_attachment(self, client, mock_admin):
        fake_logs = [
            {
                'id': 1,
                'event_category': 'auth',
                'event_type': 'login_success',
                'status': 'success',
                'created_at': datetime.now(timezone.utc).isoformat(),
            }
        ]
        with patch('web.app.db.list_audit_logs', return_value=fake_logs), \
             patch('web.app.db.verify_audit_log_chain', return_value=(True, [])), \
             patch('web.app._build_encrypted_audit_export_blob', return_value=b'{"ok":true}'):
            resp = client.post(
                '/admin/audit/export',
                data=json.dumps({'password': 'VeryStrong#123', 'limit': 200}),
                content_type='application/json',
            )

        assert resp.status_code == 200
        assert resp.headers.get('X-Audit-Encrypted') == 'true'
        assert 'attachment; filename="audit_export_encrypted_' in (resp.headers.get('Content-Disposition') or '')
        assert resp.data == b'{"ok":true}'

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

    def test_asset_details_page_renders(self, client, mock_admin):
        target = _new_target('asset-details-page')
        asset = Asset(
            target=target,
            url=f"https://{target}",
            asset_type='Web App',
            owner='Security Team',
            risk_level='Medium',
            is_deleted=False,
        )
        db_session.add(asset)
        db_session.commit()

        resp = client.get(f'/assets/{asset.id}')
        assert resp.status_code == 200
        assert b'ASSET DETAILS' in resp.data
        assert target.encode() in resp.data

    def test_dashboard_home_ssl_table_exposes_certificate_details_column(self, client, mock_admin):
        with open('web/templates/index.html', 'r', encoding='utf-8') as f:
            html = f.read()
        assert 'SSL Certificate Intelligence' in html
        assert 'CERTIFICATE DETAILS' in html
        assert 'Show X.509 details' in html

    def test_build_comprehensive_asset_dto_includes_certificate_details(self, client, mock_admin):
        target = _new_target('asset-comprehensive-cert-details')
        asset = Asset(
            target=target,
            url=f"https://{target}",
            asset_type='Web App',
            owner='Security Team',
            risk_level='Medium',
            is_deleted=False,
        )
        db_session.add(asset)
        db_session.commit()

        cert_payload = {
            'subject': f'CN={target}',
            'issuer': 'CN=Test Root CA',
            'valid_from': '2026-01-01T00:00:00+00:00',
            'valid_until': '2027-01-01T00:00:00+00:00',
            'days_to_expiry': 250,
            'is_expired': False,
            'key_algorithm': 'RSA',
            'key_length': 2048,
            'signature_algorithm': 'sha256WithRSAEncryption',
            'tls_version': 'TLS 1.3',
            'certificate_details': {
                'certificate_version': 'v3',
                'serial_number': 'ABCD1234',
                'certificate_signature_algorithm': 'sha256WithRSAEncryption',
                'certificate_subject_alternative_name': [target, f'www.{target}'],
            },
        }

        with patch('web.routes.assets.CertificateTelemetryService.get_latest_certificate_for_asset', return_value=cert_payload):
            dto = build_comprehensive_asset_dto(int(asset.id))

        assert dto is not None
        certificate = ((dto or {}).get('security') or {}).get('certificate') or {}
        assert certificate.get('subject') == f'CN={target}'
        assert certificate.get('issuer') == 'CN=Test Root CA'
        assert certificate.get('tls_version') == 'TLS 1.3'
        assert isinstance(certificate.get('certificate_details'), dict)
        assert certificate['certificate_details'].get('certificate_version') == 'v3'
        assert certificate['certificate_details'].get('serial_number') == 'ABCD1234'

    def test_asset_inventory_pagination_count_after_delete(self, client, mock_admin):
        """Verify asset count decreases in pagination after soft-delete."""
        # Create 3 test assets and remember their targets
        targets = [_new_target(f'pag-test-{i}') for i in range(3)]
        for target in targets:
            asset = Asset(target=target, asset_type='Web App', is_deleted=False)
            db_session.add(asset)
        db_session.commit()
        
        # Query assets from DB to get their IDs 
        fresh_assets = db_session.query(Asset).filter(Asset.target.in_(targets)).all()
        assert len(fresh_assets) == 3, f"Expected 3 assets but found {len(fresh_assets)}"
        asset_id_to_delete = int(fresh_assets[0].id)
        
        # Get first page with page_size=2
        resp = client.get('/api/assets?page=1&page_size=2')
        assert resp.status_code == 200, f"Failed to get /api/assets: {resp.status_code}"
        data = json.loads(resp.data)
        initial_total = data['total']
        assert initial_total >= 3, f"Expected at least 3 total assets, got {initial_total}"
        
        # Delete one asset via POST
        with patch('web.routes.assets.current_user') as route_user:
            route_user.role = 'Manager'
            route_user.id = 1
            route_user.username = 'manager'
            delete_resp = client.post(f'/assets/{asset_id_to_delete}/delete')
        
        assert delete_resp.status_code == 302, f"Delete failed with status {delete_resp.status_code}"
        
        # Query pagination again
        resp_after = client.get('/api/assets?page=1&page_size=2')
        assert resp_after.status_code == 200
        data_after = json.loads(resp_after.data)
        
        # Verify count decreased by 1
        assert data_after['total'] == initial_total - 1, f"Expected total={initial_total - 1}, got {data_after['total']}"

    def test_api_asset_scans_returns_paginated_history(self, client, mock_admin):
        target = _new_target('asset-scan-history')
        asset = Asset(target=target, asset_type='Web App', is_deleted=False)
        db_session.add(asset)
        db_session.flush()

        scan = Scan(
            scan_id=f"scan-{uuid4().hex[:12]}",
            target=target,
            status='completed',
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            report_json='{}',
            overall_pqc_score=72.5,
            is_deleted=False,
        )
        db_session.add(scan)
        db_session.commit()

        resp = client.get(f'/api/assets/{asset.id}/scans?page=1&page_size=10')
        assert resp.status_code == 200
        payload = json.loads(resp.data)

        assert payload.get('success') is True
        data = payload.get('data', {})
        assert data.get('page') == 1
        assert data.get('page_size') == 10
        assert data.get('total', 0) >= 1
        assert isinstance(data.get('items'), list)
        assert data['items'][0].get('scan_id')

    def test_api_asset_create_runs_scan_pipeline(self, client, mock_admin):
        target = _new_target('api-create-scan')

        def fake_runner(scan_target, scan_kind="manual", scanned_by=None, add_to_inventory=True, **kwargs):
            started_at = datetime.now(timezone.utc).replace(tzinfo=None)
            report = {
                'scan_id': f"scan-{uuid4().hex[:8]}",
                'target': scan_target,
                'status': 'complete',
                'overview': {'average_compliance_score': 88.5},
                'discovered_services': [{'host': '203.0.113.10', 'port': 443, 'service': 'https', 'is_tls': True}],
                'tls_results': [{'host': '203.0.113.10', 'port': 443, 'protocol_version': 'TLS 1.3'}],
                'pqc_assessments': [{'algorithm': 'ML-KEM', 'status': 'safe', 'score': 88.5}],
                'cbom_path': 'results/test_cbom.json',
            }
            scan = Scan(
                scan_id=report['scan_id'],
                target=scan_target,
                status='complete',
                started_at=started_at,
                completed_at=started_at,
                scanned_at=started_at,
                report_json=json.dumps(report),
                overall_pqc_score=88.5,
                quantum_safe=1,
                is_deleted=False,
                add_to_inventory=add_to_inventory
            )
            try:
                db_session.add(scan)
                db_session.commit()
            except Exception as e:
                print("FAKE RUNNER EXCEPTION:", e)
                db_session.rollback()
            return report

        with patch.dict(app.config, {'RUN_SCAN_PIPELINE_FUNC': fake_runner}, clear=False):
            resp = client.post(
                '/api/assets',
                data=json.dumps({
                    'target': target,
                    'type': 'Web App',
                    'owner': 'Infra Team',
                    'risk_level': 'Medium',
                }),
                content_type='application/json',
                headers={'Accept': 'application/json'},
            )

        print(resp.data); assert resp.status_code == 201
        payload = json.loads(resp.data)
        assert payload.get('success') is True
        assert payload.get('data', {}).get('scan', {}).get('status') == 'complete'
        workflow = payload.get('data', {}).get('workflow', {})
        assert workflow.get('status') == 'complete'
        assert len(workflow.get('stages', [])) == 7

        created = db_session.query(Asset).filter(Asset.target == target).first()
        assert created is not None
        assert created.is_deleted is False
        assert created.last_scan_id is not None

    def test_api_asset_detail_returns_workflow(self, client, mock_admin):
        target = _new_target('api-detail-workflow')
        asset = Asset(target=target, asset_type='Web App', owner='Ops', risk_level='High', is_deleted=False)
        db_session.add(asset)
        db_session.flush()

        scan = Scan(
            scan_id=f"scan-{uuid4().hex[:8]}",
            target=target,
            status='complete',
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            report_json=json.dumps({
                'discovered_services': [{'host': '203.0.113.11', 'port': 443, 'service': 'https', 'is_tls': True}],
                'tls_results': [{'host': '203.0.113.11', 'port': 443, 'protocol_version': 'TLS 1.3'}],
                'pqc_assessments': [{'algorithm': 'ML-KEM', 'status': 'safe', 'score': 91.0}],
            }),
            overall_pqc_score=91.0,
            quantum_safe=1,
            is_deleted=False,
        )
        db_session.add(scan)
        db_session.commit()

        asset.last_scan_id = scan.id
        db_session.commit()

        resp = client.get(f'/api/assets/{asset.id}')
        assert resp.status_code == 200
        payload = json.loads(resp.data)
        assert payload.get('success') is True
        data = payload.get('data', {})
        assert data.get('asset_name') == target
        assert data.get('workflow', {}).get('status') == 'complete'
        assert len(data.get('workflow', {}).get('stages', [])) == 7

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


class TestScanPipelinePersistence:
    def test_run_scan_pipeline_persists_rich_certificate_and_discovery_rows(self, client):
        target_suffix = uuid4().hex[:6]
        target = f"quantum-vault-{target_suffix}.internal"
        scan_id = f"test-rich-id-{target_suffix}"
        
        # We now use a stable file-based DB for tests, so we use unique targets per run.
        fingerprint = (uuid4().hex + uuid4().hex).upper()
        fake_service = SimpleNamespace(
            host='203.0.113.10',
            port=443,
            service='https',
            is_tls=True,
            banner='nginx/1.25.5',
        )
        fake_tls_result = {
            'host': '203.0.113.10',
            'port': 443,
            'protocol_version': 'TLS 1.3',
            'cipher_suite': 'TLS_AES_256_GCM_SHA384',
            'cipher_bits': 256,
            'key_exchange': 'TLS1.3-ECDHE',
            'certificate_chain_length': 2,
            'certificate': {
                'subject': {
                    'commonName': target,
                    'organizationName': 'Example Corp',
                    'organizationalUnitName': 'Security',
                },
                'issuer': {
                    'commonName': 'Test Root CA',
                    'organizationName': 'Test PKI',
                    'organizationalUnitName': 'Issuing',
                },
                'subject_cn': target,
                'subject_o': 'Example Corp',
                'subject_ou': 'Security',
                'issuer_cn': 'Test Root CA',
                'issuer_o': 'Test PKI',
                'issuer_ou': 'Issuing',
                'serial_number': f'{uuid4().hex[:16]}',
                'not_before': 'Mar 01 00:00:00 2026 GMT',
                'not_after': 'Mar 01 00:00:00 2027 GMT',
                'signature_algorithm': 'sha256WithRSAEncryption',
                'public_key_type': 'RSA',
                'public_key_bits': 2048,
                'public_key_pem': '-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqh\\n-----END PUBLIC KEY-----',
                'san_domains': [target, f'www.{target}'],
                'is_expired': False,
                'days_until_expiry': 365,
                'fingerprint_sha256': fingerprint,
            },
        }

        with patch('web.app.NetworkScanner') as scanner_cls, \
             patch('web.app.TLSAnalyzer') as analyzer_cls, \
             patch('web.app.PQCDetector') as detector_cls, \
             patch('web.app.CBOMBuilder') as builder_cls, \
             patch('web.app.QuantumSafeChecker') as checker_cls, \
             patch('web.app.CertificateIssuer') as issuer_cls, \
             patch('web.app.RecommendationEngine') as rec_engine_cls, \
             patch('web.app.ReportGenerator') as reporter_cls, \
             patch('web.app.CycloneDXGenerator') as cdx_cls, \
             patch('web.app._collect_dns_records', return_value=[{'record_type': 'A', 'record_value': '203.0.113.10'}]), \
             patch('web.app._geolocate_ip', return_value={'ip': '203.0.113.10', 'lat': 12.9, 'lon': 77.6, 'city': 'Bengaluru', 'region': 'KA', 'country': 'India'}):

            asset = Asset(target=target, asset_type='Web App', owner='tester', risk_level='Medium', is_deleted=False)
            db_session.add(asset)
            db_session.flush()
            db_session.commit()

            scanner = scanner_cls.return_value
            scanner.discover_services.return_value = [fake_service]
            scanner.discover_targets.return_value = []

            analyzer = analyzer_cls.return_value
            analyzer.analyze_endpoint.return_value = SimpleNamespace(is_successful=True, to_dict=lambda: fake_tls_result)

            detector = detector_cls.return_value
            detector.assess_endpoint.return_value = SimpleNamespace(
                to_dict=lambda: {
                    'algorithm': 'ML-KEM-768',
                    'category': 'key_exchange',
                    'status': 'safe',
                    'nist_status': 'approved',
                    'score': 92.0,
                    'overall_status': 'quantum_safe',
                    'is_quantum_safe': True,
                    'risk_level': 'LOW',
                }
            )

            builder = builder_cls.return_value
            builder.build.return_value = SimpleNamespace(
                to_dict=lambda: {
                    'components': [{'name': 'TLS_AES_256_GCM_SHA384', 'type': 'algorithm'}]
                }
            )

            checker = checker_cls.return_value
            checker.validate.return_value = SimpleNamespace(
                to_dict=lambda: {
                    'label': 'Needs Upgrade',
                    'findings': [{'category': 'protocol', 'severity': 'MEDIUM'}],
                }
            )

            issuer = issuer_cls.return_value
            issuer.issue_labels.return_value = [SimpleNamespace(to_dict=lambda: {'label': 'watch'})]

            rec_engine = rec_engine_cls.return_value
            rec_engine.get_recommendations.return_value = [
                {'title': 'Upgrade to TLS 1.3', 'description': 'Keep TLS modern', 'impact': 'High'}
            ]

            reporter = reporter_cls.return_value
            reporter.generate_summary.return_value = {
                'timestamp': '2026-03-23T00:00:00+00:00',
                'overview': {
                    'average_compliance_score': 92,
                    'total_assets': 1,
                    'quantum_safe': 1,
                    'quantum_vulnerable': 0,
                },
            }

            report = web_app_module.run_scan_pipeline(target, scan_kind='asset_inventory_api', scanned_by='tester')

        assert report['status'] == 'complete'
        assert report['orm_persisted'] is True
        
        asset = db_session.query(Asset).filter(Asset.target == target).order_by(Asset.id.desc()).first()
        assert asset is not None
        
        cert = (
            db_session.query(Certificate)
            .filter(Certificate.asset_id == asset.id, Certificate.is_deleted == False)
            .order_by(Certificate.id.desc())
            .first()
        )
        assert cert is not None
        
        # Verify fields
        latest_cert = report.get('latest_certificate', {})
        assert latest_cert.get('fingerprint_sha256').lower() == fingerprint.lower()
        assert cert.subject_cn == target
        assert cert.subject_o == 'Example Corp'
        assert cert.issuer_cn == 'Test Root CA'
        assert cert.endpoint == '203.0.113.10:443'

        detail_resp = db_session.execute(
            text("SELECT COUNT(*) FROM discovery_ssl WHERE asset_id = :asset_id"),
            {"asset_id": int(asset.id)},
        ).scalar()
        assert int(detail_resp or 0) >= 1

        discovery_row = db_session.execute(
            text(
                """
                SELECT pqc_score, pqc_assessment, promoted_to_inventory
                FROM discovery_ssl
                WHERE asset_id = :asset_id
                ORDER BY id DESC
                LIMIT 1
                """
            ),
            {"asset_id": int(asset.id)},
        ).mappings().first()
        assert discovery_row is not None
        assert float(discovery_row.get("pqc_score") or 0) == pytest.approx(92.0)
        assert str(discovery_row.get("pqc_assessment") or "").lower() == "safe"
        assert bool(discovery_row.get("promoted_to_inventory")) is False

        asset_detail = build_asset_detail_api_response(int(asset.id))
        latest_cert = (asset_detail or {}).get('latest_certificate') or {}
        assert latest_cert.get('subject_o') == 'Example Corp'
        assert latest_cert.get('issuer_cn') == 'Test Root CA'
        assert latest_cert.get('fingerprint_sha256').lower() == fingerprint.lower()
        assert isinstance(latest_cert.get('certificate_details'), dict)
        assert latest_cert['certificate_details'].get('certificate_signature_algorithm') == 'sha256WithRSAEncryption'


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

    def test_asset_bulk_scan_selected_api(self, client, mock_manager):
        target_a = _new_target('mgr-api-bulk-scan-a')
        target_b = _new_target('mgr-api-bulk-scan-b')
        a = Asset(target=target_a, asset_type='Web App', is_deleted=False)
        b = Asset(target=target_b, asset_type='Web App', is_deleted=False)
        db_session.add_all([a, b])
        db_session.commit()
        a_id = int(a.id)
        b_id = int(b.id)

        with patch('web.routes.assets.InventoryScanService') as scan_service_cls:
            scan_service = scan_service_cls.return_value
            scan_service.scan_asset.side_effect = [
                {'status': 'complete', 'scan_id': f'scan-{uuid4().hex[:8]}'},
                {'status': 'complete', 'scan_id': f'scan-{uuid4().hex[:8]}'},
            ]

            resp = client.post(
                '/api/assets/bulk-scan',
                data=json.dumps({'selected_asset_ids': f'{a_id},{b_id}', 'bulk_action': 'bulk-scan-selected'}),
                content_type='application/json',
                headers={'Accept': 'application/json'},
            )

        assert resp.status_code == 200
        payload = json.loads(resp.data)
        assert payload['status'] == 'success'
        assert payload.get('attempted') == 2
        assert payload.get('completed') == 2
        assert payload.get('failed') == 0
        assert scan_service.scan_asset.call_count == 2

    def test_asset_bulk_scan_all_api_excludes_deleted_assets(self, client, mock_manager):
        target_active = _new_target('mgr-api-scan-all-active')
        target_deleted = _new_target('mgr-api-scan-all-deleted')
        active_asset = Asset(target=target_active, asset_type='Web App', is_deleted=False)
        deleted_asset = Asset(
            target=target_deleted,
            asset_type='Web App',
            is_deleted=True,
            deleted_at=datetime.now(timezone.utc),
        )
        db_session.add_all([active_asset, deleted_asset])
        db_session.commit()
        active_id = int(active_asset.id)
        deleted_id = int(deleted_asset.id)

        with patch('web.routes.assets.InventoryScanService') as scan_service_cls:
            scan_service = scan_service_cls.return_value

            def _fake_scan(asset, scan_kind='asset_inventory_bulk'):
                return {'status': 'complete', 'scan_id': f"scan-{asset.id}"}

            scan_service.scan_asset.side_effect = _fake_scan

            resp = client.post(
                '/api/assets/bulk-scan',
                data=json.dumps({'bulk_action': 'bulk-scan-all', 'scan_scope': 'all'}),
                content_type='application/json',
                headers={'Accept': 'application/json'},
            )

        assert resp.status_code == 200
        payload = json.loads(resp.data)
        assert payload['status'] == 'success'

        result_ids = {int(item.get('asset_id')) for item in payload.get('results', []) if item.get('asset_id') is not None}
        assert active_id in result_ids
        assert deleted_id not in result_ids

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

    def test_setup_password_api_validation(self, client):
        from werkzeug.security import generate_password_hash
        import uuid
        from src import database as db

        db.init_db()

        username = f'test_setup_{uuid.uuid4().hex[:8]}'
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

        token = db.create_password_setup_token(user_id, expires_hours=1)
        assert token is not None

        # mismatch confirmation
        resp = client.post(
            f'/setup-password/{token}',
            data={'password': 'Abcd1234!@#1', 'confirm_password': 'Mismatch123!'},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b'Password and confirmation do not match.' in resp.data

        # too long password
        long_pass = 'Abcd1234!@#1234567890'  # 21 chars
        resp = client.post(
            f'/setup-password/{token}',
            data={'password': long_pass, 'confirm_password': long_pass},
        )
        assert resp.status_code == 200
        assert b'Password must be no more than 20 characters long.' in resp.data

        # valid password set
        valid_pass = 'Aa1!Aa1!Aa1!'
        resp = client.post(
            f'/setup-password/{token}',
            data={'password': valid_pass, 'confirm_password': valid_pass},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b'Password set successfully. You can now log in.' in resp.data

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
