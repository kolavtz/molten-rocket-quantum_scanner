import pymysql
import os
from dotenv import load_dotenv

load_dotenv()

conn = pymysql.connect(
    host=os.environ.get("MYSQL_HOST", "localhost"),
    port=int(os.environ.get("MYSQL_PORT", "3306")),
    user=os.environ.get("MYSQL_USER", os.environ.get("sql_user", "root")),
    password=os.environ.get("MYSQL_PASSWORD", os.environ.get("sql_password", "")),
    database=os.environ.get("MYSQL_DATABASE", "quantumshield"),
    cursorclass=pymysql.cursors.DictCursor
)

try:
    with conn.cursor() as cur:
        # Check existing columns
        cur.execute("DESCRIBE users")
        cols = [r['Field'] for r in cur.fetchall()]
        print(f"Existing columns: {cols}")

        alters = []
        if 'password_hash' not in cols:
            alters.append("ADD COLUMN password_hash VARCHAR(255) NOT NULL")
        if 'email' not in cols:
            alters.append("ADD COLUMN email VARCHAR(255) UNIQUE")
        if 'is_active' not in cols:
            alters.append("ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT TRUE")
        if 'lockout_until' not in cols:
            alters.append("ADD COLUMN lockout_until DATETIME")
        if 'must_change_password' not in cols:
            alters.append("ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT FALSE")

        if alters:
            sql = f"ALTER TABLE users {', '.join(alters)}"
            print(f"Executing: {sql}")
            cur.execute(sql)
            conn.commit()
            print("Table altered successfully.")
        else:
            print("No alters needed.")
finally:
    conn.close()
print("Schema verification complete.")
