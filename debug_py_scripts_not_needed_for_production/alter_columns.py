import sys
from sqlalchemy import text
sys.path.append('.')
from src.db import db_session

tables = [
    "assets", "scans", "discovery_items", "certificates",
    "pqc_classifications", "cbom_entries", "compliance_scores",
    "cbom_summaries", "cyber_ratings"
]

try:
    with db_session.get_bind().connect() as conn:
        # First drop Foreign key constraints if they exist to avoid conflict on modify
        try:
            conn.execute(text("SET FOREIGN_KEY_CHECKS = 0"))
        except Exception:
            pass

        for table in tables:
            try:
                print(f"Altering table {table}...")
                conn.execute(text(f"ALTER TABLE {table} MODIFY deleted_by_user_id VARCHAR(36) NULL"))
                print(f"Success altering {table}")
            except Exception as e:
                print(f"Error altering {table}: {e}")

        conn.execute(text("SET FOREIGN_KEY_CHECKS = 1"))
        print("Completed altering columns.")
except Exception as e:
    print(f"Fatal error executing migration: {e}")
