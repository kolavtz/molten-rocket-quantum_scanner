from src.db import engine
from sqlalchemy import text

with engine.connect() as conn:
    try:
        print("Altering 'assets' table...")
        conn.execute(text("ALTER TABLE assets ADD COLUMN is_deleted BOOLEAN DEFAULT 0"))
        
        print("Altering 'scans' table...")
        conn.execute(text("ALTER TABLE scans ADD COLUMN is_deleted BOOLEAN DEFAULT 0"))
        
        conn.commit()
        print("ALTER SUCCESS")
    except Exception as e:
        print(f"ERROR: {e}")
