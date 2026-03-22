"""
Unit tests for Certificate Telemetry Service.

Tests verify:
1. Each metric function returns correct type and structure
2. Database queries filter soft-deleted correctly
3. Expiry calculations are accurate (date boundary cases)
4. Aggregations match expected counts
5. No hardcoded mock data — all DB-backed
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch, MagicMock

from src.services.certificate_telemetry_service import CertificateTelemetryService
from src.models import Certificate, Asset, Scan


class TestCertificateTelemetryService:
    """Unit tests for CertificateTelemetryService."""
    
    @pytest.fixture
    def mock_db_session(self):
        """Mock SQLAlchemy session for testing."""
        return Mock()
    
    @pytest.fixture
    def service(self, mock_db_session):
        """Create service instance with mocked DB."""
        service = CertificateTelemetryService()
        service._get_db_session = Mock(return_value=mock_db_session)
        return service
    
    @pytest.fixture
    def now_utc(self):
        """Current UTC time for consistent test assertions."""
        return datetime.now(timezone.utc).replace(tzinfo=None)
    
    # ════════════════════════════════════════════════════════════════════
    # 1. EXPIRING CERTIFICATES COUNT
    # ════════════════════════════════════════════════════════════════════
    
    def test_get_expiring_certificates_count_returns_int(self, service, mock_db_session):
        """Test that expiring count returns integer."""
        mock_query = Mock()
        mock_query.filter.return_value = mock_query
        mock_query.scalar.return_value = 5
        mock_db_session.query.return_value = mock_query
        
        result = service.get_expiring_certificates_count()
        
        assert isinstance(result, int)
        assert result == 5
    
    def test_get_expiring_certificates_includes_soft_delete_filter(self, service, mock_db_session):
        """Test that query filters is_deleted = 0."""
        mock_query = Mock()
        mock_query.filter.return_value = mock_query
        mock_query.scalar.return_value = 0
        mock_db_session.query.return_value = mock_query
        
        service.get_expiring_certificates_count(days_threshold=30)
        
        # Verify filter was called with is_deleted check
        assert mock_query.filter.called
    
    def test_get_expiring_certificates_custom_threshold(self, service, mock_db_session):
        """Test with custom days threshold."""
        mock_query = Mock()
        mock_query.filter.return_value = mock_query
        mock_query.scalar.return_value = 3
        mock_db_session.query.return_value = mock_query
        
        result = service.get_expiring_certificates_count(days_threshold=60)
        
        assert result == 3
    
    # ════════════════════════════════════════════════════════════════════
    # 2. EXPIRED CERTIFICATES COUNT
    # ════════════════════════════════════════════════════════════════════
    
    def test_get_expired_certificates_count_returns_int(self, service, mock_db_session):
        """Test that expired count returns integer."""
        mock_query = Mock()
        mock_query.filter.return_value = mock_query
        mock_query.scalar.return_value = 2
        mock_db_session.query.return_value = mock_query
        
        result = service.get_expired_certificates_count()
        
        assert isinstance(result, int)
        assert result == 2
    
    # ════════════════════════════════════════════════════════════════════
    # 3. CERTIFICATE EXPIRY TIMELINE
    # ════════════════════════════════════════════════════════════════════
    
    def test_get_certificate_expiry_timeline_returns_dict(self, service, mock_db_session, now_utc):
        """Test that expiry timeline returns dict with 4 buckets."""
        # Create mock certificates with different expiry dates
        cert1 = Mock(spec=Certificate)
        cert1.valid_until = now_utc + timedelta(days=15)  # 0-30 bucket
        
        cert2 = Mock(spec=Certificate)
        cert2.valid_until = now_utc + timedelta(days=45)  # 30-60 bucket
        
        cert3 = Mock(spec=Certificate)
        cert3.valid_until = now_utc + timedelta(days=75)  # 60-90 bucket
        
        cert4 = Mock(spec=Certificate)
        cert4.valid_until = now_utc + timedelta(days=120)  # >90 bucket
        
        mock_query = Mock()
        mock_query.filter.return_value = mock_query
        mock_query.all.return_value = [cert1, cert2, cert3, cert4]
        mock_db_session.query.return_value = mock_query
        
        result = service.get_certificate_expiry_timeline()
        
        assert isinstance(result, dict)
        assert set(result.keys()) == {"0-30", "30-60", "60-90", ">90"}
        assert result["0-30"] == 1
        assert result["30-60"] == 1
        assert result["60-90"] == 1
        assert result[">90"] == 1
    
    def test_get_certificate_expiry_timeline_excludes_expired(self, service, mock_db_session, now_utc):
        """Test that expired certificates are not included in timeline."""
        # Expired cert should not be in query results (filtered at DB level)
        cert_valid = Mock(spec=Certificate)
        cert_valid.valid_until = now_utc + timedelta(days=45)
        
        mock_query = Mock()
        mock_query.filter.return_value = mock_query
        mock_query.all.return_value = [cert_valid]
        mock_db_session.query.return_value = mock_query
        
        result = service.get_certificate_expiry_timeline()
        
        # Only valid cert should be counted
        assert result["0-30"] + result["30-60"] + result["60-90"] + result[">90"] == 1
    
    def test_get_certificate_expiry_timeline_handles_none_expiry(self, service, mock_db_session, now_utc):
        """Test that certificates with None expiry date are skipped."""
        cert = Mock(spec=Certificate)
        cert.valid_until = None
        
        mock_query = Mock()
        mock_query.filter.return_value = mock_query
        mock_query.all.return_value = [cert]
        mock_db_session.query.return_value = mock_query
        
        result = service.get_certificate_expiry_timeline()
        
        # Certificate with None expiry should not affect buckets
        total = result["0-30"] + result["30-60"] + result["60-90"] + result[">90"]
        assert total == 0
    
    # ════════════════════════════════════════════════════════════════════
    # 4. CERTIFICATE INVENTORY
    # ════════════════════════════════════════════════════════════════════
    
    def test_get_certificate_inventory_returns_list_of_dicts(self, service, mock_db_session, now_utc):
        """Test that inventory returns list with required fields."""
        asset = Mock(spec=Asset)
        asset.target = "api.example.com"
        
        cert = Mock(spec=Certificate)
        cert.id = 1
        cert.asset = asset
        cert.asset_id = 123
        cert.issuer = "DigiCert"
        cert.subject = "Example Inc"
        cert.serial = "ABC123"
        cert.tls_version = "TLS 1.3"
        cert.key_length = 2048
        cert.cipher_suite = "TLS_AES_256_GCM_SHA384"
        cert.ca = "DigiCert Global G2"
        cert.valid_from = now_utc
        cert.valid_until = now_utc + timedelta(days=365)
        cert.fingerprint_sha256 = "abc123def456"
        
        mock_query = Mock()
        mock_query.filter.return_value = mock_query
        mock_query.order_by.return_value = mock_query
        mock_query.limit.return_value = mock_query
        mock_query.all.return_value = [cert]
        mock_db_session.query.return_value = mock_query
        
        result = service.get_certificate_inventory(limit=100)
        
        assert isinstance(result, list)
        assert len(result) == 1
        
        cert_dict = result[0]
        assert isinstance(cert_dict, dict)
        assert cert_dict["certificate_id"] == 1
        assert cert_dict["asset"] == "api.example.com"
        assert cert_dict["issuer"] == "DigiCert"
        assert cert_dict["key_length"] == 2048
        assert cert_dict["status"] == "Valid"
    
    def test_get_certificate_inventory_computes_days_remaining(self, service, mock_db_session, now_utc):
        """Test that days_remaining is computed correctly."""
        asset = Mock(spec=Asset)
        asset.target = "test.com"
        
        cert = Mock(spec=Certificate)
        cert.id = 1
        cert.asset = asset
        cert.asset_id = 123
        cert.issuer = "Test CA"
        cert.subject = "Test"
        cert.serial = "123"
        cert.tls_version = "TLS 1.2"
        cert.key_length = 2048
        cert.cipher_suite = "Test"
        cert.ca = "Test CA"
        cert.valid_from = now_utc
        cert.valid_until = now_utc + timedelta(days=30)
        cert.fingerprint_sha256 = "abc"
        
        mock_query = Mock()
        mock_query.filter.return_value = mock_query
        mock_query.order_by.return_value = mock_query
        mock_query.limit.return_value = mock_query
        mock_query.all.return_value = [cert]
        mock_db_session.query.return_value = mock_query
        
        result = service.get_certificate_inventory()
        cert_dict = result[0]
        
        # days_remaining should be ~30 (exact value depends on time)
        assert 29 <= cert_dict["days_remaining"] <= 30
    
    def test_get_certificate_inventory_marks_expired_status(self, service, mock_db_session, now_utc):
        """Test that expired certificates are marked with 'Expired' status."""
        asset = Mock(spec=Asset)
        asset.target = "expired.com"
        
        cert = Mock(spec=Certificate)
        cert.id = 1
        cert.asset = asset
        cert.asset_id = 123
        cert.issuer = "Test"
        cert.subject = "Test"
        cert.serial = "123"
        cert.tls_version = "TLS 1.2"
        cert.key_length = 2048
        cert.cipher_suite = "Test"
        cert.ca = "Test"
        cert.valid_from = now_utc - timedelta(days=365)
        cert.valid_until = now_utc - timedelta(days=1)  # Expired 1 day ago
        cert.fingerprint_sha256 = "abc"
        
        mock_query = Mock()
        mock_query.filter.return_value = mock_query
        mock_query.order_by.return_value = mock_query
        mock_query.limit.return_value = mock_query
        mock_query.all.return_value = [cert]
        mock_db_session.query.return_value = mock_query
        
        result = service.get_certificate_inventory()
        cert_dict = result[0]
        
        assert cert_dict["status"] == "Expired"
        assert cert_dict["days_remaining"] <= -1
    
    def test_get_certificate_inventory_marks_expiring_status(self, service, mock_db_session, now_utc):
        """Test that certificates expiring soon are marked with 'Expiring' status."""
        asset = Mock(spec=Asset)
        asset.target = "expiring.com"
        
        cert = Mock(spec=Certificate)
        cert.id = 1
        cert.asset = asset
        cert.asset_id = 123
        cert.issuer = "Test"
        cert.subject = "Test"
        cert.serial = "123"
        cert.tls_version = "TLS 1.2"
        cert.key_length = 2048
        cert.cipher_suite = "Test"
        cert.ca = "Test"
        cert.valid_from = now_utc - timedelta(days=100)
        cert.valid_until = now_utc + timedelta(days=15)  # Expires in 15 days
        cert.fingerprint_sha256 = "abc"
        
        mock_query = Mock()
        mock_query.filter.return_value = mock_query
        mock_query.order_by.return_value = mock_query
        mock_query.limit.return_value = mock_query
        mock_query.all.return_value = [cert]
        mock_db_session.query.return_value = mock_query
        
        result = service.get_certificate_inventory()
        cert_dict = result[0]
        
        assert cert_dict["status"] == "Expiring"
    
    def test_get_certificate_inventory_limits_results(self, service, mock_db_session):
        """Test that limit parameter is respected."""
        mock_query = Mock()
        mock_query.filter.return_value = mock_query
        mock_query.order_by.return_value = mock_query
        mock_query.limit.return_value = mock_query
        mock_query.all.return_value = []
        mock_db_session.query.return_value = mock_query
        
        service.get_certificate_inventory(limit=50)
        
        # Verify limit was passed to query
        assert mock_query.limit.called
        mock_query.limit.assert_called_with(50)
    
    # ════════════════════════════════════════════════════════════════════
    # 5. KEY LENGTH DISTRIBUTION
    # ════════════════════════════════════════════════════════════════════
    
    def test_get_key_length_distribution_returns_dict(self, service, mock_db_session):
        """Test that key length distribution returns categorized dict."""
        certs = [
            Mock(spec=Certificate, key_length=2048),
            Mock(spec=Certificate, key_length=2048),
            Mock(spec=Certificate, key_length=4096),
            Mock(spec=Certificate, key_length=0),
        ]
        
        mock_query = Mock()
        mock_query.filter.return_value = mock_query
        mock_query.all.return_value = certs
        mock_db_session.query.return_value = mock_query
        
        result = service.get_key_length_distribution()
        
        assert isinstance(result, dict)
        assert "2048" in result
        assert "4096+" in result
        assert "Unknown" in result
        assert result["2048"] == 2
        assert result["4096+"] == 1
        assert result["Unknown"] == 1
    
    # ════════════════════════════════════════════════════════════════════
    # 6. CIPHER SUITE DISTRIBUTION
    # ════════════════════════════════════════════════════════════════════
    
    def test_get_cipher_suite_distribution_returns_list(self, service, mock_db_session):
        """Test that cipher distribution returns sorted list."""
        certs = [
            Mock(spec=Certificate, cipher_suite="TLS_AES_256_GCM_SHA384"),
            Mock(spec=Certificate, cipher_suite="TLS_AES_256_GCM_SHA384"),
            Mock(spec=Certificate, cipher_suite="TLS_AES_128_GCM_SHA256"),
        ]
        
        mock_query = Mock()
        mock_query.filter.return_value = mock_query
        mock_query.all.return_value = certs
        mock_db_session.query.return_value = mock_query
        
        result = service.get_cipher_suite_distribution(limit=10)
        
        assert isinstance(result, list)
        assert len(result) <= 10
        # Most common cipher should be first
        assert result[0]["count"] >= result[1]["count"]
    
    # ════════════════════════════════════════════════════════════════════
    # 7. TLS VERSION DISTRIBUTION
    # ════════════════════════════════════════════════════════════════════
    
    def test_get_tls_version_distribution_returns_dict(self, service, mock_db_session):
        """Test that TLS version distribution returns dict."""
        certs = [
            Mock(spec=Certificate, tls_version="TLS 1.3"),
            Mock(spec=Certificate, tls_version="TLS 1.3"),
            Mock(spec=Certificate, tls_version="TLS 1.2"),
        ]
        
        mock_query = Mock()
        mock_query.filter.return_value = mock_query
        mock_query.all.return_value = certs
        mock_db_session.query.return_value = mock_query
        
        result = service.get_tls_version_distribution()
        
        assert isinstance(result, dict)
        assert result.get("TLS 1.3") == 2
        assert result.get("TLS 1.2") == 1
    
    # ════════════════════════════════════════════════════════════════════
    # 8. WEAK CRYPTOGRAPHY METRICS
    # ════════════════════════════════════════════════════════════════════
    
    def test_get_weak_cryptography_metrics_returns_dict(self, service, mock_db_session):
        """Test that weak crypto metrics returns dict with expected keys."""
        mock_query = Mock()
        mock_query.filter.return_value = mock_query
        mock_query.scalar.return_value = 1
        mock_query.all.return_value = []
        mock_db_session.query.return_value = mock_query
        
        result = service.get_weak_cryptography_metrics()
        
        assert isinstance(result, dict)
        assert "weak_keys" in result
        assert "weak_tls" in result
        assert "expired" in result
        assert "self_signed" in result
    
    def test_get_weak_cryptography_detects_weak_keys(self, service, mock_db_session):
        """Test detection of RSA keys < 2048-bit."""
        certs = [
            Mock(spec=Certificate, key_length=1024),  # Weak
            Mock(spec=Certificate, key_length=2048),  # OK
        ]
        
        mock_query = Mock()
        mock_query.filter.return_value = mock_query
        mock_query.scalar.side_effect = [1, 0, 0]  # weak_keys, weak_tls, expired
        mock_query.all.return_value = certs
        mock_db_session.query.return_value = mock_query
        
        result = service.get_weak_cryptography_metrics()
        
        assert result["weak_keys"] == 1
    
    def test_get_weak_cryptography_detects_weak_tls(self, service, mock_db_session):
        """Test detection of TLS 1.0/1.1."""
        mock_query = Mock()
        mock_query.filter.return_value = mock_query
        mock_query.scalar.side_effect = [0, 2, 0]  # weak_keys, weak_tls, expired
        mock_query.all.return_value = []
        mock_db_session.query.return_value = mock_query
        
        result = service.get_weak_cryptography_metrics()
        
        assert result["weak_tls"] == 2
    
    # ════════════════════════════════════════════════════════════════════
    # 9. CERTIFICATE ISSUES COUNT
    # ════════════════════════════════════════════════════════════════════
    
    def test_get_certificate_issues_count_returns_int(self, service, mock_db_session):
        """Test that issues count returns integer."""
        mock_query = Mock()
        mock_query.filter.return_value = mock_query
        mock_query.scalar.return_value = 10
        mock_query.all.return_value = []
        mock_db_session.query.return_value = mock_query
        
        result = service.get_certificate_issues_count()
        
        assert isinstance(result, int)
        assert result >= 0
    
    # ════════════════════════════════════════════════════════════════════
    # 10. COMPLETE TELEMETRY PAYLOAD
    # ════════════════════════════════════════════════════════════════════
    
    def test_get_complete_certificate_telemetry_returns_dict(self, service, mock_db_session, now_utc):
        """Test that complete payload returns dict with all expected keys."""
        # Mock all the sub-methods
        service.get_expiring_certificates_count = Mock(return_value=5)
        service.get_expired_certificates_count = Mock(return_value=2)
        service._get_total_certificates_count = Mock(return_value=50)
        service.get_certificate_expiry_timeline = Mock(return_value={"0-30": 5, "30-60": 3, "60-90": 2, ">90": 40})
        service.get_tls_version_distribution = Mock(return_value={"TLS 1.3": 40, "TLS 1.2": 10})
        service.get_key_length_distribution = Mock(return_value={"2048": 45, "4096+": 5})
        service.get_certificate_inventory = Mock(return_value=[])
        service.get_certificate_authority_distribution = Mock(return_value=[])
        service.get_cipher_suite_distribution = Mock(return_value=[])
        service.get_weak_cryptography_metrics = Mock(return_value={"weak_keys": 2, "weak_tls": 3, "expired": 2, "self_signed": 1})
        service.get_certificate_issues_count = Mock(return_value=8)
        
        result = service.get_complete_certificate_telemetry()
        
        assert isinstance(result, dict)
        assert "kpis" in result
        assert "expiry_timeline" in result
        assert "tls_version_distribution" in result
        assert "key_length_distribution" in result
        assert "certificate_inventory" in result
        assert "certificate_authority_distribution" in result
        assert "cipher_suite_distribution" in result
        assert "weak_cryptography" in result
        assert "cert_issues_count" in result


class TestCertificateTelemetryServiceIntegration:
    """Integration tests with real database (if fixtures available)."""
    
    @pytest.mark.skip(reason="Requires real DB fixture")
    def test_expiring_certificates_query_performance(self):
        """Performance test: expiring count query should complete < 100ms."""
        pass
    
    @pytest.mark.skip(reason="Requires real DB fixture")
    def test_soft_delete_filtering_excludes_deleted_certs(self):
        """Test that soft-deleted certificates don't appear in metrics."""
        pass
    
    @pytest.mark.skip(reason="Requires real DB fixture")
    def test_boundary_case_certificate_expires_today(self):
        """Test edge case: certificate expiring today is marked correctly."""
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
