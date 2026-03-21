from src.db import engine
from sqlalchemy import text

with engine.connect() as conn:
    try:
        res = conn.execute(text("DESCRIBE assets"))
        print("--- ASSETS COLUMNS ---")
        for row in res.fetchall():
            print(row[0])
        res = conn.execute(text("DESCRIBE scans"))
        print("--- SCANS COLUMNS ---")
        for row in res.fetchall():
            print(row[0])
    except Exception as e:
        print(f"ERROR: {e}")
