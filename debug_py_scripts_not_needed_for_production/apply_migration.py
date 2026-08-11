import os
import sys
import pymysql
from pymysql.constants import CLIENT

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from config import MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE

def apply():
    conn = pymysql.connect(
        host=MYSQL_HOST, 
        user=MYSQL_USER, 
        password=MYSQL_PASSWORD, 
        database=MYSQL_DATABASE,
        client_flag=CLIENT.MULTI_STATEMENTS
    )
    with conn.cursor() as cur:
        with open('migrations/001_add_findings_and_metrics_tables.sql', 'r', encoding='utf-8') as f:
            sql = f.read()
        cur.execute(sql)
    conn.commit()
    conn.close()
    print("Migration applied successfully with MULTI_STATEMENTS!")

if __name__ == "__main__":
    apply()
