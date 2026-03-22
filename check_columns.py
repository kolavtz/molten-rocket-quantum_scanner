import sys
from sqlalchemy import text
sys.path.append('.')
from src.db import db_session

query = """
SELECT TABLE_NAME, COLUMN_NAME, COLUMN_TYPE 
FROM INFORMATION_SCHEMA.COLUMNS 
WHERE COLUMN_NAME = 'deleted_by_user_id' 
  AND TABLE_SCHEMA = DATABASE()
"""

try:
    with db_session.get_bind().connect() as conn:
        print("--- Existing deleted_by_user_id Columns ---")
        for row in conn.execute(text(query)):
            print(f"Table: {row[0]}, Column: {row[1]}, Type: {row[2]}")
except Exception as e:
    print(f"Error checking schema: {e}")
