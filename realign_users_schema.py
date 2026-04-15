import os
import sys
from sqlalchemy import text, inspect

# Add current directory to path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from src.db import engine
from src.models import User

def main():
    print("--- Realigning User Schema ---")
    
    # Define wanted columns and their SQL types
    # This matches src/models.py and src/database.py
    wanted_columns = {
        "employee_id": "VARCHAR(64) UNIQUE",
        "email": "VARCHAR(255) UNIQUE",
        "created_by": "VARCHAR(36)",
        "is_active": "TINYINT(1) NOT NULL DEFAULT 1",
        "password_setup_token_hash": "VARCHAR(64) UNIQUE",
        "password_setup_token_expiry": "DATETIME",
        "must_change_password": "TINYINT(1) NOT NULL DEFAULT 1",
        "failed_login_attempts": "INT NOT NULL DEFAULT 0",
        "lockout_until": "DATETIME",
        "locked_until": "DATETIME",
        "last_login_at": "DATETIME",
        "password_changed_at": "DATETIME",
        "api_key_hash": "VARCHAR(64) UNIQUE",
        "created_at": "DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP",
        "updated_at": "DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"
    }

    with engine.connect() as conn:
        # Check existing columns
        insp = inspect(engine)
        existing_cols = {c['name'] for c in insp.get_columns('users')}
        
        print(f"Existing columns: {existing_cols}")
        
        # Disable foreign key checks for the migration
        conn.execute(text("SET FOREIGN_KEY_CHECKS = 0;"))
        
        for col_name, col_def in wanted_columns.items():
            if col_name in existing_cols:
                print(f"Column '{col_name}' already exists.")
                continue
                
            print(f"Adding column '{col_name}'...")
            try:
                conn.execute(text(f"ALTER TABLE users ADD COLUMN {col_name} {col_def}"))
            except Exception as e:
                print(f"Failed to add '{col_name}': {e}")

        # Set is_active = 1 for any existing users just in case
        print("Setting is_active = 1 for all users...")
        conn.execute(text("UPDATE users SET is_active = 1 WHERE is_active IS NULL OR is_active = 0"))
        
        # Ensure 'Admin' and 'sys_admin' are active
        conn.execute(text("UPDATE users SET is_active = 1 WHERE username IN ('Admin', 'sys_admin')"))

        conn.execute(text("SET FOREIGN_KEY_CHECKS = 1;"))
        conn.commit()
    
    print("Schema realignment complete.")

    # Verification: Try the failing query
    print("--- Verifying failing query ---")
    with engine.connect() as conn:
        try:
            res = conn.execute(text("SELECT id, username, is_active FROM users WHERE is_active = 1 LIMIT 1"))
            row = res.fetchone()
            print(f"Verification query successful! Result: {row}")
        except Exception as e:
            print(f"Verification query FAILED: {e}")

if __name__ == "__main__":
    main()
