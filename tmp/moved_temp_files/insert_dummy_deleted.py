from src.db import engine
from sqlalchemy import text

with engine.connect() as conn:
    try:
        conn.execute(text("INSERT INTO assets (target, type, owner, risk_level, notes, is_deleted) VALUES ('test.local', 'Web App', 'Admin', 'Low', 'Test', 1)"))
        conn.commit()
        print("INSERT_SUCCESS")
    except Exception as e:
        print(f"ERROR: {e}")
