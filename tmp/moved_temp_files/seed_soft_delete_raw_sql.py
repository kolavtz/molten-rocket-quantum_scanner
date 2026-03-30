from src.db import engine
from sqlalchemy import text
import traceback

with engine.connect() as conn:
    try:
        # Check describing again
        print("RUNNING SELECT...")
        # explicitly quoting just in case
        res = conn.execute(text("SELECT id FROM assets WHERE is_deleted = 0 LIMIT 1"))
        row = res.fetchone()
        if row:
            aid = row[0]
            print(f"SOFT_DELETE_SUCCESS:{aid}")
            conn.execute(text(f"UPDATE assets SET is_deleted = 1 WHERE id = {aid}"))
            conn.commit()
        else:
            print("NO_ASSETS_FOUND")
    except Exception as e:
        print("--- EXCEPTION ---")
        traceback.print_exc()
        print(f"ERROR: {e}")
