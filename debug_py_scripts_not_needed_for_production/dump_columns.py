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
        columns = list(conn.execute(text(find_query)))
        with open("all_columns.txt", "w") as f:
            for row in columns:
                f.write(f"Table: {row[0]}, Type: {row[2]}\n")
        print("Written all_columns.txt")
except Exception as e:
    print(f"Error checking schema: {e}")
