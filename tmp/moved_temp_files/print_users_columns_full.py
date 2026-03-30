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
        cur.execute("DESCRIBE users")
        rows = cur.fetchall()
        with open("users_columns.txt", "w") as f:
            f.write("COLUMNS IN USERS TABLE:\n")
            for r in rows:
                f.write(str(r) + "\n")
finally:
    conn.close()
print("Saved description to users_columns.txt")
