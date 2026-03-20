import pymysql
import os
from dotenv import load_dotenv

load_dotenv()

conn = pymysql.connect(
    host=os.environ.get("MYSQL_HOST", "localhost"),
    port=int(os.environ.get("MYSQL_PORT", "3306")),
    user=os.environ.get("MYSQL_USER", "root"),
    password=os.environ.get("MYSQL_PASSWORD", ""),
    database=os.environ.get("MYSQL_DATABASE", "quantumshield"),
)

try:
    with conn.cursor() as cur:
        # Check if column exists first to be idempotent
        cur.execute("""
            SELECT COUNT(*) 
            FROM information_schema.COLUMNS 
            WHERE TABLE_SCHEMA = %s 
              AND TABLE_NAME = 'assets' 
              AND COLUMN_NAME = 'notes'
        """, (os.environ.get("MYSQL_DATABASE", "quantumshield"),))
        
        if cur.fetchone()[0] == 0:
            print("Adding 'notes' column to 'assets' table...")
            cur.execute("ALTER TABLE assets ADD COLUMN notes TEXT")
            conn.commit()
            print("Column added successfully.")
        else:
            print("'notes' column already exists.")

finally:
    conn.close()
print("Complete.")
