"""
Integration tests for the certificate telemetry REST endpoints in dashboard blueprint.
Covers HTTP status, filtering, limit, and weak crypto toggles.
"""

import json
from unittest.mock import patch, Mock

import pytest
from web.app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['LOGIN_DISABLED'] = True
    with app.test_client() as c:
        yield c


class TestCertificateTelemetryEndpoints:
    def test_get_certificates_telemetry(self, client):
        sample_payload = {
            "kpis": {"total_certificates": 10, "expiring_certificates": 2, "expired_certificates": 1},
            "expiry_timeline": {"0-30": 2, "30-60": 5, "60-90": 2, ">90": 1},
            "tls_version_distribution": {"TLS 1.3": 6},
            "key_length_distribution": {"2048": 8},
            "certificate_inventory": [{"certificate_id": 1, "issuer": "Test", "status": "Valid"}],
            "certificate_authority_distribution": [{"ca": "TestCA", "count": 10}],
            "cipher_suite_distribution": [{"cipher_suite": "TLS_AES_256_GCM_SHA384", "count": 10}],
            "weak_cryptography": {"weak_keys": 1, "weak_tls": 0, "expired": 1, "self_signed": 0},
            "cert_issues_count": 2,
        }

        with patch('web.blueprints.dashboard.CertificateTelemetryService') as cert_service_cls:
            cert_service = cert_service_cls.return_value
            cert_service.get_complete_certificate_telemetry.return_value = sample_payload

            resp = client.get('/dashboard/api/certificates/telemetry?limit=1&include_weak=false')
            assert resp.status_code == 200
            data = json.loads(resp.data)
            assert data['status'] == 'ok'
            assert 'data' in data
            payload = data['data']
            assert 'weak_cryptography' not in payload
            assert payload['certificate_inventory'] == sample_payload['certificate_inventory'][:1]

    def test_get_certificate_inventory_with_filters(self, client):
        inv = [
            {"certificate_id": 1, "issuer": "DigiCert", "status": "Expired"},
            {"certificate_id": 2, "issuer": "LetsEncrypt", "status": "Valid"},
        ]

        with patch('web.blueprints.dashboard.CertificateTelemetryService') as cert_service_cls:
            cert_service = cert_service_cls.return_value
            cert_service.get_certificate_inventory.return_value = inv

            resp = client.get('/dashboard/api/certificates/inventory?status=Expired&issuer=digicert')
            assert resp.status_code == 200
            data = json.loads(resp.data)
            assert data['status'] == 'ok'
            assert data['count'] == 1
            assert data['data'][0]['certificate_id'] == 1

    def test_get_weak_cryptography_endpoint(self, client):
        with patch('web.blueprints.dashboard.CertificateTelemetryService') as cert_service_cls:
            cert_service = cert_service_cls.return_value
            cert_service.get_weak_cryptography_metrics.return_value = {
                "weak_keys": 4,
                "weak_tls": 2,
                "expired": 1,
                "self_signed": 1,
            }

            resp = client.get('/dashboard/api/certificates/weak')
            assert resp.status_code == 200
            data = json.loads(resp.data)
            assert data['data']['weak_keys'] == 4

    def test_tls_key_ca_distribution_endpoints(self, client):
        with patch('web.blueprints.dashboard.CertificateTelemetryService') as cert_service_cls:
            cert_service = cert_service_cls.return_value
            cert_service.get_tls_version_distribution.return_value = {"TLS 1.3": 8}
            cert_service.get_key_length_distribution.return_value = {"2048": 7}
            cert_service.get_certificate_authority_distribution.return_value = [{"ca": "Let's Encrypt", "count": 7}]

            r1 = client.get('/dashboard/api/certificates/distribution/tls')
            r2 = client.get('/dashboard/api/certificates/distribution/keys')
            r3 = client.get('/dashboard/api/certificates/distribution/ca?limit=5')

            assert r1.status_code == 200
            assert r2.status_code == 200
            assert r3.status_code == 200

            assert json.loads(r1.data)['data']['TLS 1.3'] == 8
            assert json.loads(r2.data)['data']['2048'] == 7
            assert json.loads(r3.data)['data'][0]['ca'] == "Let's Encrypt"

    @patch('src.db.db_session')
    def test_cbom_dashboard_renders_with_db_metrics(self, mock_db_session, client):
        from src.models import Scan, Certificate, CBOMEntry, CBOMSummary

        def make_query():
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

        scan_query = make_query()
        cert_query = make_query()
        cbom_entry_query = make_query()
        cbom_summary_query = make_query()

        def query_side_effect(model, *args, **kwargs):
            if model is Scan:
                return scan_query
            if model is Certificate:
                return cert_query
            if model is CBOMEntry:
                return cbom_entry_query
            if model is CBOMSummary:
                return cbom_summary_query
            return make_query()

        mock_db_session.query.side_effect = query_side_effect

        resp = client.get('/cbom-dashboard')
        assert resp.status_code == 200
        assert b'CBOM' in resp.data
        # Ensure fallback empty-state and no server traceback
        assert b'No CBOM telemetry available yet.' in resp.data or b'TOTAL APPLICATIONS' in resp.data


class TestCyberReportingEndpoints:
    def test_get_cyber_metrics_contract(self, client):
        sample_payload = {
            "kpis": {"elite_pct": 25.0, "standard_pct": 25.0, "legacy_pct": 25.0, "critical_count": 1, "avg_score": 62.5},
            "grade_counts": {"Elite": 1, "Standard": 1, "Legacy": 1, "Critical": 1},
            "status_distribution": {"Elite": 25.0, "Standard": 25.0, "Legacy": 25.0, "Critical": 25.0},
            "risk_heatmap": [{"x": "Cyber Tier", "y": "Elite", "value": 1}],
            "recommendations": ["Test recommendation"],
            "applications": [{"asset_id": 1, "target": "example.com", "score": 80, "tier": "Elite"}],
            "meta": {"total_assets": 4, "scored_assets": 4},
        }

        with patch('src.services.cyber_reporting_service.CyberReportingService.get_cyber_rating_data', return_value=sample_payload):
            resp = client.get('/dashboard/api/cyber/metrics')
            assert resp.status_code == 200
            data = json.loads(resp.data)
            assert data['status'] == 'ok'
            assert 'timestamp' in data
            assert data['data']['kpis']['avg_score'] == 62.5
            assert data['data']['grade_counts']['Elite'] == 1

    def test_get_cyber_inventory_contract(self, client):
        sample_payload = {
            "kpis": {},
            "grade_counts": {},
            "status_distribution": {},
            "risk_heatmap": [],
            "recommendations": [],
            "applications": [
                {"asset_id": 10, "target": "a.example", "score": 44.0, "tier": "Legacy"},
                {"asset_id": 11, "target": "b.example", "score": 82.0, "tier": "Elite"},
            ],
            "meta": {"total_assets": 2, "scored_assets": 2},
        }

        with patch('src.services.cyber_reporting_service.CyberReportingService.get_cyber_rating_data', return_value=sample_payload):
            resp = client.get('/dashboard/api/cyber/inventory?limit=2')
            assert resp.status_code == 200
            data = json.loads(resp.data)
            assert data['status'] == 'ok'
            assert data['count'] == 2
            assert data['data'][0]['target'] == 'a.example'

    def test_get_reporting_summary_contract(self, client):
        summary = {
            "discovery": "Targets: 4 | Complete Scans: 4 | Assessed Endpoints: 4",
            "pqc": "Assessed endpoints: 4 | Average PQC Score: 75%",
            "cbom": "Total certificates: 10 | Weak cryptography: 2",
            "cyber_rating": "Average enterprise score: 75/100",
            "inventory": "Assets: 4 | Critical Apps: 1 | Legacy: 1",
        }
        cleanup_sql = ["DELETE ..."]

        with patch('src.services.cyber_reporting_service.CyberReportingService.get_reporting_summary', return_value=summary), \
             patch('src.services.cyber_reporting_service.CyberReportingService.get_orphan_cleanup_sql_examples', return_value=cleanup_sql):
            resp = client.get('/dashboard/api/reporting/summary')
            assert resp.status_code == 200
            data = json.loads(resp.data)
            assert data['status'] == 'ok'
            assert data['data']['summary']['inventory'].startswith('Assets: 4')
            assert data['data']['orphan_cleanup_sql_examples'] == cleanup_sql
