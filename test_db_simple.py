import mysql.connector
import time
from dotenv import load_dotenv
import os

load_dotenv()

host = os.environ.get("MYSQL_HOST")
if host == "localhost":
    host = "::1"
port = int(os.environ.get("MYSQL_PORT", 3306))


user = os.environ.get("MYSQL_USER")
password = os.environ.get("MYSQL_PASSWORD")
database = os.environ.get("MYSQL_DATABASE")

print(f"[*] Trying to connect to {user}@{host}:{port}/{database}...")

start = time.time()
try:
    conn = mysql.connector.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=database,
        connect_timeout=3
    )
    print(f"[✅] Connected in {time.time() - start:.2f} seconds!")
    
    start_ping = time.time()
    conn.ping(reconnect=True, attempts=1, delay=0)
    print(f"[✅] Pinged in {time.time() - start_ping:.2f} seconds!")
    
    conn.close()
except Exception as e:
    print(f"[!] Failed after {time.time() - start:.2f} seconds: {e}")
