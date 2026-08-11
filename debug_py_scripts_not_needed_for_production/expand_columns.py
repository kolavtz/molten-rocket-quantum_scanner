import sys
from sqlalchemy import text
sys.path.append('.')
from src.db import db_session

find_query = """
SELECT TABLE_NAME, COLUMN_NAME, COLUMN_TYPE 
FROM INFORMATION_SCHEMA.COLUMNS 
WHERE COLUMN_NAME = 'deleted_by_user_id' 
  AND TABLE_SCHEMA = DATABASE()
"""

try:
    with db_session.get_bind().connect() as conn:
        print("--- Expanding Columns to 128 ---")
        columns = list(conn.execute(text(find_query)))
        
        # Turn off foreign key checks for safer alters
        try:
            conn.execute(text("SET FOREIGN_KEY_CHECKS = 0"))
        except Exception:
            pass

        for row in columns:
            table_name = row[0]
            print(f"Altering {table_name}...")
            try:
                conn.execute(text(f"ALTER TABLE {table_name} MODIFY deleted_by_user_id VARCHAR(128) NULL"))
                print(f"Success altering {table_name}")
            except Exception as e:
                print(f"Error altering {table_name}: {e}")

        try:
            conn.execute(text("SET FOREIGN_KEY_CHECKS = 1"))
        except Exception:
            pass
            
        print("Completed expanding columns.")
except Exception as e:
    print(f"Fatal error expanding columns: {e}")
