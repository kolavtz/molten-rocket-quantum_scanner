import os
import pymysql
from dotenv import load_dotenv

load_dotenv()

host = os.getenv("MYSQL_HOST", "127.0.0.1")
port = int(os.getenv("MYSQL_PORT", 3306))
user = os.getenv("MYSQL_USER", "root")
password = os.getenv("MYSQL_PASSWORD", "")
db = os.getenv("MYSQL_DATABASE", "quantumshield")

out_path = r"c:\Users\saura\Downloads\hf-proj\molten-rocket-quantum_scanner\check_assets_out.txt"

try:
    connection = pymysql.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=db,
        cursorclass=pymysql.cursors.DictCursor
    )
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM assets")
        rows = cursor.fetchall()
        with open(out_path, "w") as f:
            f.write(f"--- ASSETS TABLE ({len(rows)} ROWS) ---\n")
            for r in rows:
                f.write(f"{r}\n")
    print(f"Written to {out_path}")
except Exception as e:
    with open(out_path, "w") as f:
        f.write(f"MySQL Query Error: {e}\n")
    print(f"Error: {e}")
finally:
    if 'connection' in locals():
        connection.close()
