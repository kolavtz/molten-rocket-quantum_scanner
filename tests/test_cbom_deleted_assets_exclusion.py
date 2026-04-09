import uuid
from datetime import datetime, timezone

from src.db import db_session
from src.models import Asset, Scan, CBOMEntry
from src.services.cbom_service import CbomService


def test_cbom_entries_exclude_deleted_assets():
    # Create a scan (complete) and three CBOM entries:
    # - one linked to an active asset
    # - one linked to a soft-deleted asset
    # - one with no asset association
    scan = Scan(target=f"cbom-scan-{uuid.uuid4().hex[:8]}", status="complete", report_json='{}')
    db_session.add(scan)
    db_session.flush()

    asset_active = Asset(target=f"active-{uuid.uuid4().hex[:8]}", asset_type="Web App", is_deleted=False)
    asset_deleted = Asset(target=f"deleted-{uuid.uuid4().hex[:8]}", asset_type="Web App", is_deleted=True, deleted_at=datetime.now(timezone.utc))
    db_session.add_all([asset_active, asset_deleted])
    db_session.flush()

    entry_active = CBOMEntry(scan_id=scan.id, asset_id=asset_active.id, algorithm_name="active-algo", asset_type="Web App", is_deleted=False)
    entry_deleted = CBOMEntry(scan_id=scan.id, asset_id=asset_deleted.id, algorithm_name="deleted-algo", asset_type="Web App", is_deleted=False)
    entry_none = CBOMEntry(scan_id=scan.id, asset_id=None, algorithm_name="noasset-algo", asset_type="Web App", is_deleted=False)

    db_session.add_all([entry_active, entry_deleted, entry_none])
    db_session.commit()

    try:
        q = CbomService._build_cbom_entries_query(asset_id=None, start_date=None, end_date=None, search_term="")
        rows = q.all()
        names = [getattr(entry, "algorithm_name", None) for entry, asset, scan in rows]

        assert "active-algo" in names
        assert "noasset-algo" in names
        # The entry linked to the soft-deleted asset must NOT be present
        assert "deleted-algo" not in names
    finally:
        # Clean up created rows to avoid polluting other tests
        try:
            db_session.query(CBOMEntry).filter(CBOMEntry.algorithm_name.in_(["active-algo", "deleted-algo", "noasset-algo"])) .delete(synchronize_session=False)
            db_session.query(Asset).filter(Asset.target.like("active-%") | Asset.target.like("deleted-%")).delete(synchronize_session=False)
            db_session.query(Scan).filter(Scan.target.like("cbom-scan-%")).delete(synchronize_session=False)
            db_session.commit()
        except Exception:
            db_session.rollback()
