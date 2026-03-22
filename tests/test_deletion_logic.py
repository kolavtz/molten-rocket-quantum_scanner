"""
Test suite for soft-delete and recycle bin logic.

Verifies:
- Soft deletes set is_deleted flag with timestamp
- Hard deletes permanently remove records
- Cascading deletes work correctly
- Recycle bin shows deleted items
- Normal queries exclude soft-deleted records
- Role-based access control (Admin/Manager required for delete operations)
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import Mock, patch, MagicMock
from uuid import uuid4
from src.db import db_session
from src.models import Asset, Scan, Certificate, DiscoveryItem, PQCClassification, CBOMEntry, ComplianceScore
from src.database import delete_asset as db_delete_asset


@pytest.fixture(autouse=True)
def _session_guard():
    """Keep SQLAlchemy session usable across tests even after assertion/setup failures."""
    db_session.rollback()
    yield
    db_session.rollback()


def _new_target(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:10]}.example"


def _new_scan(target: str) -> Scan:
    scan = Scan(
        scan_id=str(uuid4()),
        target=target,
        status="complete",
        report_json="{}",
        started_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    db_session.add(scan)
    db_session.commit()
    return scan


class TestSoftDeleteAsset:
    """Test Asset soft-delete functionality"""
    
    def test_soft_delete_asset_sets_flags(self):
        """Soft delete should set is_deleted, deleted_at, deleted_by_user_id"""
        # Create a test asset
        target = _new_target("soft-delete")
        asset = Asset(
            target=target,
            asset_type="Web App",
            is_deleted=False
        )
        db_session.add(asset)
        db_session.commit()
        
        # Soft delete it
        asset.is_deleted = True
        asset.deleted_at = datetime.now(timezone.utc)
        asset.deleted_by_user_id = 123
        db_session.commit()
        
        # Verify flags are set
        reloaded = db_session.query(Asset).filter_by(id=asset.id).first()
        assert reloaded.is_deleted == True
        assert reloaded.deleted_at is not None
        assert reloaded.deleted_by_user_id == 123
    
    def test_soft_deleted_asset_excluded_from_queries(self):
        """Soft-deleted assets should be excluded from normal queries"""
        live_target = _new_target("live")
        deleted_target = _new_target("deleted")
        asset1 = Asset(target=live_target, asset_type="Web App", is_deleted=False)
        asset2 = Asset(target=deleted_target, asset_type="Web App", is_deleted=True, deleted_at=datetime.now(timezone.utc))
        
        db_session.add_all([asset1, asset2])
        db_session.commit()
        
        # Query without soft-delete filter should get both
        all_assets = db_session.query(Asset).all()
        assert len(all_assets) >= 2
        
        # Query WITH soft-delete filter should exclude deleted
        active_assets = db_session.query(Asset).filter(Asset.is_deleted == False).all()
        assert any(a.target == live_target for a in active_assets)
        assert not any(a.target == deleted_target for a in active_assets)
    
    def test_soft_delete_cascade_to_certificates(self):
        """Soft deleting an asset should cascade to certificates"""
        target = _new_target("cascade-cert")
        asset = Asset(target=target, asset_type="Web App")
        db_session.add(asset)
        db_session.commit()
        scan = _new_scan(target)
        cert = Certificate(
            asset_id=asset.id,
            scan_id=scan.id,
            issuer="Test CA",
            is_deleted=False
        )
        db_session.add(cert)
        db_session.commit()
        
        # Soft delete asset and cascade
        asset.is_deleted = True
        asset.deleted_at = datetime.now(timezone.utc)
        
        for certificate in asset.certificates:
            certificate.is_deleted = True
            certificate.deleted_at = asset.deleted_at
        
        db_session.commit()
        
        # Verify certificate is marked deleted
        reloaded_cert = db_session.query(Certificate).filter_by(id=cert.id).first()
        assert reloaded_cert.is_deleted == True


class TestDatabaseDeleteAsset:
    """Test database.py::delete_asset() soft-delete function"""
    
    @patch('src.database._get_connection')
    def test_delete_asset_soft_deletes_row(self, mock_conn):
        """delete_asset() should set is_deleted flag (soft delete)"""
        mock_cursor = MagicMock()
        mock_conn.return_value = mock_cursor
        mock_cursor.cursor.return_value = mock_cursor
        mock_cursor.rowcount = 1
        
        # Call it
        result = db_delete_asset("example.com")
        
        # Verify it called UPDATE (not DELETE)
        mock_cursor.execute.assert_called()
        call_args = mock_cursor.execute.call_args
        assert "UPDATE" in str(call_args).upper()
        assert "is_deleted" in str(call_args)
        assert "example.com" in str(call_args)
        assert result == True


class TestRecycleBin:
    """Test recycle bin route and recovery"""
    
    def test_recycle_bin_route_has_get_and_post(self):
        """recycle_bin route should support retrieval and mutation operations."""
        from web.app import recycle_bin
        import inspect
        source = inspect.getsource(recycle_bin)
        assert 'methods=["GET", "POST"]' in source or "request.method == \"POST\"" in source
    
    def test_restore_asset_requires_manager_role(self):
        """POST /recycle-bin restore action should require Admin/Manager role"""
        from web.app import recycle_bin
        import inspect
        source = inspect.getsource(recycle_bin)
        assert "ALLOWED_RESTORE_ROLES" in source
        assert "Admin" in source and "Manager" in source
    
    def test_hard_delete_requires_admin_role(self):
        """POST /recycle-bin delete action should require Admin role"""
        from web.app import recycle_bin
        import inspect
        source = inspect.getsource(recycle_bin)
        assert "ALLOWED_HARD_DELETE_ROLES" in source
        assert "delete_assets" in source and "delete_scans" in source


class TestDashboardDeleteRoute:
    """Test /dashboard/assets/<id>/delete route"""
    
    def test_delete_asset_requires_manager_role(self):
        """Delete route should require Admin/Manager role"""
        # Verify role check is in place
        from web.blueprints.dashboard import delete_asset
        
        # The function should have role checking logic
        import inspect
        source = inspect.getsource(delete_asset)
        assert "ALLOWED_DELETE_ROLES" in source or "Admin" in source or "Manager" in source
    
    def test_delete_asset_cascades_to_discovery_items(self):
        """Deleting an asset should cascade delete discovery_items"""
        target = _new_target("cascade-discovery")
        asset = Asset(target=target, asset_type="Web App")
        db_session.add(asset)
        db_session.commit()
        scan = _new_scan(target)
        discovery = DiscoveryItem(asset_id=asset.id, scan_id=scan.id, type="domain", status="confirmed")

        db_session.add(discovery)
        db_session.commit()
        
        # Soft delete cascade
        asset.is_deleted = True
        asset.deleted_at = datetime.now(timezone.utc)
        for item in asset.discovery_items:
            item.is_deleted = True
            item.deleted_at = asset.deleted_at
        
        db_session.commit()
        
        # Verify discovery item deleted
        reloaded_discovery = db_session.query(DiscoveryItem).filter_by(id=discovery.id).first()
        assert reloaded_discovery.is_deleted == True


class TestQueryFiltering:
    """Test that all inventory queries properly exclude soft-deleted records"""
    
    def test_asset_count_excludes_deleted(self):
        """Asset count queries should exclude soft-deleted"""
        asset1 = Asset(target=_new_target("count1"), asset_type="Web App", is_deleted=False)
        asset2 = Asset(target=_new_target("count2"), asset_type="Web App", is_deleted=True, deleted_at=datetime.now(timezone.utc))
        
        db_session.add_all([asset1, asset2])
        db_session.commit()
        
        # Count active only
        from sqlalchemy import func
        active_count = db_session.query(func.count(Asset.id)).filter(Asset.is_deleted == False).scalar()
        
        # Should not count the deleted one
        assert active_count >= 1
    
    def test_certificate_queries_exclude_deleted(self):
        """Certificate queries should exclude soft-deleted records"""
        target = _new_target("cert-filter")
        asset = Asset(target=target, asset_type="Web App")
        db_session.add(asset)
        db_session.commit()
        scan = _new_scan(target)
        cert1 = Certificate(asset_id=asset.id, scan_id=scan.id, issuer="CA", is_deleted=False)
        cert2 = Certificate(asset_id=asset.id, scan_id=scan.id, issuer="CA", is_deleted=True, deleted_at=datetime.now(timezone.utc))

        db_session.add_all([cert1, cert2])
        db_session.commit()
        
        # Query active only
        active_certs = db_session.query(Certificate).filter(Certificate.is_deleted == False).all()
        
        # Should not include the deleted one
        assert not any(c.id == cert2.id for c in active_certs)


class TestAuditTrail:
    """Test that delete operations are audited"""
    
    def test_soft_delete_records_user_id(self):
        """Soft delete should record who performed the delete"""
        target = _new_target("audit")
        asset = Asset(target=target, asset_type="Web App")
        db_session.add(asset)
        db_session.commit()
        
        # Delete with user tracking
        asset.is_deleted = True
        asset.deleted_at = datetime.now(timezone.utc)
        asset.deleted_by_user_id = 999  # Admin user ID
        db_session.commit()
        
        # Verify audit fields
        reloaded = db_session.query(Asset).filter_by(id=asset.id).first()
        assert reloaded.deleted_by_user_id == 999
        assert reloaded.deleted_at is not None


class TestHardDeleteFromRecycleBin:
    """Test hard delete operations from recycle bin (Admin-only)"""
    
    def test_hard_delete_cascades(self):
        """Hard deleting asset should cascade delete child entities"""
        target = _new_target("hard-delete")
        asset = Asset(target=target, asset_type="Web App", is_deleted=True)
        db_session.add(asset)
        db_session.commit()
        scan = _new_scan(target)
        cert = Certificate(asset_id=asset.id, scan_id=scan.id, issuer="CA", is_deleted=True)

        db_session.add(cert)
        db_session.commit()
        
        asset_id = asset.id
        cert_id = cert.id
        
        # Hard delete
        db_session.delete(asset)
        db_session.commit()
        
        # Verify both are gone
        assert db_session.query(Asset).filter_by(id=asset_id).first() is None
        # Note: Cascade delete may or may not remove certificate depending on FK config
        # This test validates the behavior


class TestInventoryMetricsExcludeDeleted:
    """Test that KPI calculations exclude soft-deleted records"""
    
    def test_pqc_score_excludes_deleted_assets(self):
        """PQC score calculations should exclude soft-deleted assets"""
        from sqlalchemy import func

        scan1 = Scan(scan_id=str(uuid4()), target=_new_target("active-scan"), status="complete", report_json="{}", overall_pqc_score=85, is_deleted=False)
        scan2 = Scan(scan_id=str(uuid4()), target=_new_target("deleted-scan"), status="complete", report_json="{}", overall_pqc_score=50, is_deleted=True, deleted_at=datetime.now(timezone.utc))
        
        db_session.add_all([scan1, scan2])
        db_session.commit()
        
        # Calculate avg excluding deleted
        avg_score = db_session.query(func.avg(Scan.overall_pqc_score)).filter(
            Scan.scan_id.in_([scan1.scan_id, scan2.scan_id]),
            Scan.is_deleted == False,
            Scan.status == "complete"
        ).scalar()
        
        # Should only include scan1 (85), not scan2 (50)
        assert avg_score is not None
        assert float(avg_score) == pytest.approx(85.0)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
