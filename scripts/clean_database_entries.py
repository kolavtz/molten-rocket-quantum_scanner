import os
import sys
import urllib.parse
from pathlib import Path
from dotenv import load_dotenv
from sqlalchemy import create_engine, inspect, text

# ---------------------------------------------------------------------------
# 1. Load Environment Variables (.env.local takes priority over .env)
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent

env_local_path = ROOT_DIR / ".env.local"
env_path = ROOT_DIR / ".env"

if env_local_path.is_file():
    load_dotenv(dotenv_path=env_local_path, override=True)
    print(f"[INFO] Loaded environment from: {env_local_path}")
elif env_path.is_file():
    load_dotenv(dotenv_path=env_path, override=True)
    print(f"[INFO] Loaded environment from: {env_path}")
else:
    print("[WARNING] Neither .env.local nor .env found in root directory.")

# ---------------------------------------------------------------------------
# 2. Extract MySQL & SQLite Configuration
# ---------------------------------------------------------------------------
mysql_host = os.getenv("MYSQL_HOST", "localhost")
mysql_port = os.getenv("MYSQL_PORT", "3306")
mysql_user = os.getenv("MYSQL_USER", "")
mysql_password = os.getenv("MYSQL_PASSWORD", "")
mysql_db = os.getenv("MYSQL_DATABASE", "")

database_url = os.getenv("DATABASE_URL")

if not database_url:
    if mysql_db:
        # Safely URL-encode user and password to handle special characters (@, :, /, etc.)
        encoded_user = urllib.parse.quote_plus(mysql_user)
        encoded_password = urllib.parse.quote_plus(mysql_password)
        
        database_url = f"mysql+pymysql://{encoded_user}:{encoded_password}@{mysql_host}:{mysql_port}/{mysql_db}"
    else:
        # SQLite fallback if no database name is provided
        database_url = f"sqlite:///{ROOT_DIR / 'app.db'}"

# ---------------------------------------------------------------------------
# 3. Tables to Exclude from Deletion
# ---------------------------------------------------------------------------
PRESERVED_TABLES = {"users", "user"}
MIGRATION_TABLES = {"alembic_version", "flyway_schema_history", "schema_migrations"}

EXCLUDED_TABLES = PRESERVED_TABLES.union(MIGRATION_TABLES)

# ---------------------------------------------------------------------------
# 4. Database Wiping Logic
# ---------------------------------------------------------------------------
def clean_database():
    try:
        engine = create_engine(database_url)
        dialect_name = engine.dialect.name.lower()
    except Exception as e:
        print(f"[ERROR] Failed to initialize database engine: {e}")
        sys.exit(1)

    try:
        inspector = inspect(engine)
        all_tables = inspector.get_table_names()
    except Exception as e:
        print(f"[ERROR] Could not connect to database: {e}")
        sys.exit(1)

    tables_to_clear = [
        table for table in all_tables 
        if table.lower() not in EXCLUDED_TABLES
    ]

    if not tables_to_clear:
        print("[INFO] No tables to clean.")
        return

    print(f"[INFO] Dialect detected: {dialect_name}")
    print(f"[INFO] Preserving tables: {', '.join(EXCLUDED_TABLES)}")
    print(f"[INFO] Cleaning {len(tables_to_clear)} table(s)...")

    with engine.begin() as connection:
        if dialect_name in ("mysql", "mariadb"):
            connection.execute(text("SET FOREIGN_KEY_CHECKS = 0;"))
            for table in tables_to_clear:
                connection.execute(text(f"TRUNCATE TABLE `{table}`;"))
                print(f"  - Cleared: {table}")
            connection.execute(text("SET FOREIGN_KEY_CHECKS = 1;"))

        elif dialect_name == "sqlite":
            connection.execute(text("PRAGMA foreign_keys = OFF;"))
            for table in tables_to_clear:
                connection.execute(text(f"DELETE FROM \"{table}\";"))
                try:
                    connection.execute(text(f"DELETE FROM sqlite_sequence WHERE name='{table}';"))
                except Exception:
                    pass
                print(f"  - Cleared: {table}")
            connection.execute(text("PRAGMA foreign_keys = ON;"))

        else:
            for table in tables_to_clear:
                connection.execute(text(f"DELETE FROM \"{table}\";"))
                print(f"  - Cleared: {table}")

    print("[SUCCESS] Operation complete. Table structures and user data preserved.")

if __name__ == "__main__":
    clean_database()