from src.db import engine
from sqlalchemy import text

with engine.connect() as conn:
    try:
        conn.execute(text("UPDATE assets SET is_deleted = 0"))
        conn.execute(text("UPDATE scans SET is_deleted = 0"))
        conn.commit()
        print("BACKFILL_SUCCESS")
        
        # Soft delete one
        res = conn.execute(text("SELECT id, target FROM assets LIMIT 1"))
        row = res.fetchone()
        if row:
            conn.execute(text(f"UPDATE assets SET is_deleted = 1 WHERE id = {row[0]}"))
            conn.commit()
            print(f"SOFT_DELETE_SEED_SUCCESS:{row[0]}:{row[1]}")
        else:
            print("NO_ASSETS_IN_DB_TO_TEST")
    except Exception as e:
        print(f"ERROR: {e}")
