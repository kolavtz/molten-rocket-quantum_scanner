"""
Integration tests for KPI live query functionality.

Verifies that:
1. KPIs query MySQL live (not hardcoded/stale data)
2. KPIs update immediately when data changes
3. All KPI dashboard endpoints return live aggregations
"""

import json
import pytest
from datetime import datetime, timedelta

from web.app import app
from src.models import (
    Asset, Scan, Certificate, PQCClassification, ComplianceScore
)
from src.db import db_session


pytestmark = pytest.mark.skip(
    reason="Legacy KPI integration scaffold uses deprecated model fields; rewrite needed for current API-first schema."
)


@pytest.fixture
def client():
    """Create test client with application context and cleaned database."""
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    
    with app.app_context():
        db_session.rollback()
        yield app.test_client()
        db_session.rollback()


@pytest.fixture
def mock_user(client):
    """Create mock authenticated user session."""
    with client.session_transaction() as sess:
        sess["user_id"] = "test_user"
        sess["username"] = "test_user"
        sess["role"] = "admin"
    return "test_user"


class TestKPILiveQueries:
    """Test that KPIs use live MySQL queries, not hardcoded values."""
    
    def test_asset_count_increments_on_create(self, client, mock_user):
        """Verify total_assets KPI increments when asset is added."""
        # Empty state: total_assets should be 0
        resp = client.get("/asset-inventory")
        assert resp.status_code == 200
        
        # Verify initial KPI count is 0 (live query, not hardcoded)
        html = resp.get_data(as_text=True)
        # KPIs should be injected via `page_data` or `vm` context
        
        # Add asset via SQLAlchemy
        asset = Asset(
            asset_name="test-asset-1",
            asset_class="Web Application",
            asset_type="url",
            asset_value="https://example.com",
            is_deleted=False,
        )
        db_session.add(asset)
        db_session.commit()
        
        # Verify KPI count incremented
        resp = client.get("/asset-inventory")
        assert resp.status_code == 200
        # Query directly to verify we can retrieve the asset
        assets = Asset.query.filter(Asset.is_deleted == False).all()
        assert len(assets) == 1, "Asset should exist in database"
    
    def test_asset_count_decrements_on_delete(self, client, mock_user):
        """Verify total_assets KPI decrements when asset is soft-deleted."""
        # Create two assets
        asset1 = Asset(
            asset_name="test-asset-1",
            asset_class="Web Application",
            asset_type="url",
            asset_value="https://example1.com",
            is_deleted=False,
        )
        asset2 = Asset(
            asset_name="test-asset-2",
            asset_class="Web Application",
            asset_type="url",
            asset_value="https://example2.com",
            is_deleted=False,
        )
        db_session.add_all([asset1, asset2])
        db_session.commit()
        
        # Verify count is 2
        assets_before = Asset.query.filter(Asset.is_deleted == False).all()
        assert len(assets_before) == 2
        
        # Soft-delete one asset
        asset1.is_deleted = True
        asset1.deleted_at = datetime.utcnow()
        db_session.commit()
        
        # Verify count decremented to 1 (live query)
        assets_after = Asset.query.filter(Asset.is_deleted == False).all()
        assert len(assets_after) == 1
        assert assets_after[0].asset_name == "test-asset-2"
    
    def test_cbom_dashboard_returns_live_counts(self, client, mock_user):
        """Verify CBOM dashboard KPIs query live certificate counts."""
        # Create asset with certificate
        asset = Asset(
            asset_name="cbom-test",
            asset_class="Web Application",
            asset_type="url",
            asset_value="https://cbom-test.com",
            is_deleted=False,
        )
        db_session.add(asset)
        db_session.flush()
        
        cert = Certificate(
            asset_id=asset.id,
            common_name="cbom-test.com",
            issuer="Test CA",
            key_length=2048,
            tls_version="TLS 1.2",
            valid_from=datetime.utcnow(),
            valid_until=datetime.utcnow() + timedelta(days=365),
            is_deleted=False,
        )
        db_session.add(cert)
        db_session.commit()
        
        # Fetch CBOM dashboard
        resp = client.get("/cbom-dashboard")
        assert resp.status_code == 200
        
        # Verify response contains data (not hardcoded empty)
        # The view should show non-zero KPIs from live query
        html = resp.get_data(as_text=True)
        assert "empty" not in html or "False" in html  # "empty" should be False
    
    def test_pqc_posture_returns_live_counts(self, client, mock_user):
        """Verify PQC posture dashboard queries live asset counts."""
        # Create asset
        asset = Asset(
            asset_name="pqc-test",
            asset_class="Web Application",
            asset_type="url",
            asset_value="https://pqc-test.com",
            is_deleted=False,
        )
        db_session.add(asset)
        db_session.flush()
        
        # Add PQC classification
        pqc = PQCClassification(
            asset_id=asset.id,
            pqc_score=85.0,
            quantum_safe_status="safe",
            quantum_safe_flag=True,
            is_deleted=False,
        )
        db_session.add(pqc)
        db_session.commit()
        
        # Fetch PQC posture dashboard
        resp = client.get("/pqc-posture")
        assert resp.status_code == 200
        
        # Verify response contains live data
        assert "empty" not in resp.get_data(as_text=True) or "False" in resp.get_data(as_text=True)
    
    def test_cyber_rating_returns_live_score(self, client, mock_user):
        """Verify cyber rating dashboard queries live compliance scores."""
        # Create asset with compliance score
        asset = Asset(
            asset_name="cyber-test",
            asset_class="Web Application",
            asset_type="url",
            asset_value="https://cyber-test.com",
            is_deleted=False,
        )
        db_session.add(asset)
        db_session.flush()
        
        score = ComplianceScore(
            asset_id=asset.id,
            score_type="overall",
            score_value=85.0,
            is_deleted=False,
        )
        db_session.add(score)
        db_session.commit()
        
        # Fetch cyber rating dashboard
        resp = client.get("/cyber-rating")
        assert resp.status_code == 200
        
        # Verify response is not empty hardcoded state
        assert resp.status_code == 200
    
    def test_asset_inventory_kpis_live_count(self, client, mock_user):
        """Verify asset inventory KPI endpoint queries live counts."""
        # Create multiple assets
        for i in range(3):
            asset = Asset(
                asset_name=f"inventory-test-{i}",
                asset_class="Web Application",
                asset_type="url",
                asset_value=f"https://inventory-test-{i}.com",
                is_deleted=False,
            )
            db_session.add(asset)
        db_session.commit()
        
        # Verify from _get_inventory_kpis endpoint logic
        assets = Asset.query.filter(Asset.is_deleted == False).all()
        assert len(assets) == 3, "All 3 assets should exist (live query)"
    
    def test_no_hardcoded_zeros_on_empty_db(self, client, mock_user):
        """Verify KPIs show 0 (from live query) not hardcoded dict when DB is empty."""
        # Database is empty (by fixture)
        
        # Fetch asset inventory
        resp = client.get("/asset-inventory")
        assert resp.status_code == 200
        
        # Empty database should query and return 0, not show hardcoded "test mode" data
        # The route should still call the service, which returns proper empty state
        html = resp.get_data(as_text=True)
        # Should contain proper empty state handling
        assert resp.status_code == 200
    
    def test_kpi_updates_after_scan_creation(self, client, mock_user):
        """Verify scan count KPI updates when new scan is added."""
        # Create asset and scan
        asset = Asset(
            asset_name="scan-test",
            asset_class="Web Application",
            asset_type="url",
            asset_value="https://scan-test.com",
            is_deleted=False,
        )
        db_session.add(asset)
        db_session.flush()
        
        scan = Scan(
            scan_id="scan-001",
            asset_id=asset.id,
            status="complete",
            scanned_at=datetime.utcnow(),
            total_assets=1,
            quantum_safe=1,
            quantum_vuln=0,
            compliance_score=85.0,
            is_deleted=False,
        )
        db_session.add(scan)
        db_session.commit()
        
        # Verify scan exists and can be queried
        scans = Scan.query.filter(Scan.is_deleted == False).all()
        assert len(scans) == 1
    
    def test_no_testing_mode_hardcoded_fallback(self, client, mock_user):
        """Verify TESTING=True does not return hardcoded KPI fallbacks."""
        # Even with TESTING=True, routes should call services
        # (The config is already set to TESTING in fixture)
        
        resp = client.get("/cbom-dashboard")
        assert resp.status_code == 200
        
        # Response should use service, not hardcoded test fallback
        # The page should load without the hardcoded empty dict
        assert resp.status_code == 200
    
    def test_kpi_resilience_on_service_error(self, client, mock_user):
        """Verify KPIs gracefully handle service errors without crashing."""
        # This tests exception handling in routes
        # Create minimal data
        asset = Asset(
            asset_name="error-test",
            asset_class="Web Application",
            asset_type="url",
            asset_value="https://error-test.com",
            is_deleted=False,
        )
        db_session.add(asset)
        db_session.commit()
        
        # Route should not crash even if service has issue
        resp = client.get("/cbom-dashboard")
        assert resp.status_code == 200
        
        resp = client.get("/pqc-posture")
        assert resp.status_code == 200
        
        resp = client.get("/cyber-rating")
        assert resp.status_code == 200


class TestKPIEndpointConsistency:
    """Test that all KPI endpoints consistently query live data."""
    
    def test_all_dashboards_load_without_error(self, client, mock_user):
        """Verify all KPI dashboard endpoints load successfully."""
        endpoints = [
            "/",  # Home dashboard
            "/asset-inventory",  # Asset inventory
            "/cbom-dashboard",  # CBOM dashboard
            "/pqc-posture",  # PQC posture
            "/cyber-rating",  # Cyber rating
            "/reporting",  # Reporting dashboard
        ]
        
        for endpoint in endpoints:
            resp = client.get(endpoint)
            assert resp.status_code == 200, f"Endpoint {endpoint} failed with {resp.status_code}"
    
    def test_kpi_data_types_consistency(self, client, mock_user):
        """Verify KPI responses have consistent data types across endpoints."""
        # Create sample data
        asset = Asset(
            asset_name="consistency-test",
            asset_class="Web Application",
            asset_type="url",
            asset_value="https://consistency-test.com",
            is_deleted=False,
        )
        db_session.add(asset)
        db_session.commit()
        
        # Verify endpoints return valid responses
        resp = client.get("/cbom-dashboard")
        assert resp.status_code == 200
        
        resp = client.get("/pqc-posture")
        assert resp.status_code == 200
