"""
Unit tests for AssetService integration points with certificate telemetry.
"""

from unittest.mock import patch, Mock
from src.services.asset_service import AssetService


def test_get_inventory_view_model_testing_mode():
    service = AssetService()
    payload = service.get_inventory_view_model(testing_mode=True)

    assert payload['empty'] is True
    assert payload['kpis']['total_assets'] == 0
    assert payload['kpis']['weak_crypto_issues'] == 0
    assert payload['weak_cryptography']['weak_keys'] == 0


def test_get_inventory_view_model_uses_certificate_telemetry():
    service = AssetService()

    with patch.object(AssetService, 'load_combined_assets', return_value=[{
        'id': 1,
        'name': 'test.example.com',
        'asset_name': 'test.example.com',
        'cert_status': 'Expiring',
        'cert_days': 20,
        'type': 'Web App',
        'risk': 'High',
        'owner': 'Ops',
        'tls_version': 'TLS 1.2',
        'cipher_suite': 'TLS_AES_256_GCM_SHA384',
        'ca': 'TestCA',
        'last_scan': '2026-03-20 12:00:00',
        'risk_level': 'High',
        'key_length': 2048,
    }]):
        with patch('src.services.asset_service.CertificateTelemetryService') as cert_service_cls:
            cert_service = cert_service_cls.return_value
            cert_service.get_weak_cryptography_metrics.return_value = {
                'weak_keys': 1,
                'weak_tls': 0,
                'expired': 0,
                'self_signed': 0,
            }
            cert_service.get_certificate_issues_count.return_value = 1
            cert_service.get_expired_certificates_count.return_value = 0

            result = service.get_inventory_view_model()
            assert result['empty'] is False
            assert result['kpis']['expired_certificates'] == 0
            assert result['kpis']['weak_crypto_issues'] == 1
            assert result['weak_cryptography']['weak_keys'] == 1
            assert result['cert_issues_count'] == 1


def test_get_inventory_view_model_handles_certificate_telemetry_failure():
    service = AssetService()

    with patch.object(AssetService, 'load_combined_assets', return_value=[]):
        with patch('src.services.asset_service.CertificateTelemetryService', side_effect=Exception('DB down')):
            result = service.get_inventory_view_model()
            assert result['kpis']['weak_crypto_issues'] == 0
            assert result['kpis']['expired_certificates'] == 0
            assert result['cert_issues_count'] == 0
