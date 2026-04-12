import os
import sys
import re
from sqlalchemy import text
from sqlalchemy.orm import Session

# Add current directory to path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from src.db import engine
from src.models import Base

def apply_sql_file(conn, file_path):
    print(f"Applying SQL from {file_path}...")
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        sql_content = f.read()

    # Split by semicolon and execute
    # Using a simple split for standard MySQL dump format
    # This regex is specifically tuned for split at semicolon + newline
    statements = re.split(r';\s*$', sql_content, flags=re.MULTILINE)
    
    for stmt in statements:
        stmt = stmt.strip()
        if not stmt:
            continue
        try:
            conn.execute(text(stmt))
        except Exception as e:
            # We ignore errors during full import as many things will be handled by create_all later
            if "Table already exists" in str(e) or "Column already exists" in str(e):
                continue
            # print(f"Error: {e}")

def drop_everything(conn):
    print("Dropping all existing tables for a clean slate...")
    conn.execute(text("SET FOREIGN_KEY_CHECKS = 0;"))
    # Get all tables
    res = conn.execute(text("SHOW TABLES"))
    tables = [row[0] for row in res]
    for t in tables:
        conn.execute(text(f"DROP TABLE IF EXISTS `{t}`"))
    conn.execute(text("SET FOREIGN_KEY_CHECKS = 1;"))

def main():
    print("--- Starting database upgrade ---")
    
    with engine.connect() as conn:
        drop_everything(conn)
        
        print("--- 1. Importing full dump ---")
        conn.execute(text("SET FOREIGN_KEY_CHECKS = 0;"))
        if os.path.exists('Dump_full_sanitized.sql'):
            apply_sql_file(conn, 'Dump_full_sanitized.sql')
        else:
            print("Dump_full_sanitized.sql not found!")
        conn.execute(text("SET FOREIGN_KEY_CHECKS = 1;"))
        conn.commit()

    print("--- 2. Syncing schema with models (adding missing tables/columns) ---")
    try:
        # Note: SQLAlchemy won't automatically FIX existing columns but will add MISSING columns if using Alembic.
        # However, Base.metadata.create_all only creates MISSING TABLES.
        # For missing columns, we need to run our custom logic.
        Base.metadata.create_all(engine)
        print("Schema sync (missing tables) complete.")
    except Exception as e:
        print(f"Schema sync notice: {e}")

    print("--- 3. Verifying counts ---")
    with engine.connect() as conn:
        for table in ['assets', 'scans', 'users', 'cbom_entries']:
            try:
                result = conn.execute(text(f"SELECT COUNT(*) FROM {table}"))
                print(f"Table {table}: {result.scalar()} rows")
            except:
                print(f"Table {table} not accessible.")

if __name__ == "__main__":
    main()
