import pymysql
import os
from dotenv import load_dotenv

load_dotenv()

MYSQL_HOST = os.environ.get("MYSQL_HOST", "::1")
if MYSQL_HOST == "::1":
    MYSQL_HOST = "localhost"
MYSQL_PORT = int(os.environ.get("MYSQL_PORT", 3306))
MYSQL_USER = os.environ.get("MYSQL_USER", "db_local")
MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", "test123@Abcd")
MYSQL_DATABASE = os.environ.get("MYSQL_DATABASE", "quantumshield")

def run():
    print(f"Connecting to {MYSQL_DATABASE}...")
    conn = pymysql.connect(
        host=MYSQL_HOST,
        port=MYSQL_PORT,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DATABASE
    )
    try:
        cur = conn.cursor()
        print("Adding started_at...")
        try:
            cur.execute("ALTER TABLE scans ADD COLUMN started_at DATETIME NULL")
            print("started_at added.")
        except Exception as e:
            print(f"started_at note: {e}")
            
        print("Adding completed_at...")
        try:
            cur.execute("ALTER TABLE scans ADD COLUMN completed_at DATETIME NULL")
            print("completed_at added.")
        except Exception as e:
            print(f"completed_at note: {e}")
            
        conn.commit()
        print("Done!")
    finally:
        conn.close()

if __name__ == '__main__':
    run()
