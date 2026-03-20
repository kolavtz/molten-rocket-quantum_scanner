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
        # Replicate _get_users_id_column_type
        cur.execute(
            """
            SELECT COLUMN_TYPE
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = %s
              AND TABLE_NAME = 'users'
              AND COLUMN_NAME = 'id'
            LIMIT 1
            """,
            (os.environ.get("MYSQL_DATABASE", "quantumshield"),),
        )
        row = cur.fetchone()
        print(f"Resolved User ID Column Type: {row}")
finally:
    conn.close()
print("Complete.")
