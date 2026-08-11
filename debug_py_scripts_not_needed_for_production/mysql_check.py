import os
import sys
import pymysql

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from config import MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE

def check():
    conn = pymysql.connect(
        host=MYSQL_HOST, user=MYSQL_USER, password=MYSQL_PASSWORD, database=MYSQL_DATABASE
    )
    with conn.cursor() as cur:
        for t in ['scans', 'assets', 'certificates', 'cbom_entries', 'findings']:
            try:
                cur.execute(f"SHOW CREATE TABLE {t}")
                print(f"--- {t} ---")
                print(cur.fetchone()[1])
            except Exception as e:
                print(f"Table {t} error: {e}")
    conn.close()

if __name__ == "__main__":
    check()
