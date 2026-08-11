import sys
from sqlalchemy import text
sys.path.append('.')
from src.db import db_session

try:
    with db_session.get_bind().connect() as conn:
        print("--- Table: users ---")
        for row in conn.execute(text("DESCRIBE users")):
            print(row)
        print("\n--- Table: assets ---")
        for row in conn.execute(text("DESCRIBE assets")):
            print(row)
except Exception as e:
    print(f"Error describing tables: {e}")
