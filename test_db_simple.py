import mysql.connector
import time

from config import MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE

host = MYSQL_HOST
if host == "localhost":
    host = "::1"
port = int(MYSQL_PORT)

user = MYSQL_USER
password = MYSQL_PASSWORD
database = MYSQL_DATABASE

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
