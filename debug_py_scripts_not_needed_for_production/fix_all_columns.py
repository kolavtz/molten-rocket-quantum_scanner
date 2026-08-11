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
        print("--- Checking Columns ---")
        columns = list(conn.execute(text(find_query)))
        for row in columns:
            table_name = row[0]
            col_type = row[2]
            print(f"Table: {table_name}, Type: {col_type}")
            
            if 'varchar' not in col_type.lower():
                print(f"Altering {table_name}...")
                try:
                    conn.execute(text(f"ALTER TABLE {table_name} MODIFY deleted_by_user_id VARCHAR(36) NULL"))
                    print(f"Success altering {table_name}")
                except Exception as e:
                    print(f"Error altering {table_name}: {e}")
        print("Completed fixing columns.")
except Exception as e:
    print(f"Fatal error executing migration: {e}")
