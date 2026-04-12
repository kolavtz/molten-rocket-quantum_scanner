import os
import sys
import re
from sqlalchemy import text

# Add current directory to path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from src.db import engine

def main():
    if not os.path.exists('Dump_full_sanitized_fixed.sql'):
        print("Dump_full_sanitized_fixed.sql not found!")
        return

    print("Reading dump...")
    with open('Dump_full_sanitized_fixed.sql', 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Split by semicolon and ensure it's a valid SQL statement
    statements = re.split(r';\s*$', content, flags=re.MULTILINE)
    
    print(f"Executing {len(statements)} statements...")
    with engine.connect() as conn:
        print("Disabling foreign key checks...")
        conn.execute(text("SET FOREIGN_KEY_CHECKS = 0;"))
        
        for i, s in enumerate(statements):
            stmt = s.strip()
            if not stmt:
                continue
            try:
                conn.execute(text(stmt))
                if i % 100 == 0:
                    print(f"Progress: {i}/{len(statements)}")
            except Exception as e:
                # Ignore duplicate entries as we might be re-running portions
                if "Duplicate entry" not in str(e):
                    print(f"Error at statement {i}: {e}")
        
        print("Re-enabling foreign key checks...")
        conn.execute(text("SET FOREIGN_KEY_CHECKS = 1;"))
        conn.commit()
    
    print("Data import from dump complete.")

if __name__ == "__main__":
    main()
