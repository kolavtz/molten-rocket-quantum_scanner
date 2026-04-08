import sys, os
sys.path.insert(0, os.getcwd())
from src.db import db_session, engine
from src.models import Asset
from sqlalchemy import text

print('Inserting test asset')
a = Asset(target='unit-test-example', asset_type='Web App', is_deleted=False)
db_session.add(a)
try:
    db_session.commit()
    print('Inserted asset id:', a.id)
except Exception as e:
    print('Error during insert:', repr(e))
    try:
        db_session.rollback()
    except Exception:
        pass
    # Inspect table schema
    with engine.connect() as c:
        res = c.execute(text("SELECT sql FROM sqlite_master WHERE type='table' AND name='assets'"))
        row = res.fetchone()
        print('Assets table DDL:', row[0] if row else None)
