
from tests.test_web_app import TestScanPipelinePersistence
import pytest
def test_debug():
    t = TestScanPipelinePersistence()
    try:
        t.test_run_scan_pipeline_persists_rich_certificate_and_discovery_rows()
    except Exception as e:
        import traceback
        traceback.print_exc()
        from web.app import db_session
        from src.models import Certificate
        certs = db_session.query(Certificate).all()
        for c in certs:
            print(f'Cert: id={c.id}, asset_id={c.asset_id}, is_deleted={c.is_deleted}, subject={c.subject}')
