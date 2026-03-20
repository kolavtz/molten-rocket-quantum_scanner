import pymysql
import os
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

load_dotenv()

MYSQL_HOST = os.environ.get("MYSQL_HOST", "localhost")
MYSQL_PORT = int(os.environ.get("MYSQL_PORT", "3306"))
MYSQL_USER = os.environ.get("MYSQL_USER", os.environ.get("sql_user", "root"))
MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", os.environ.get("sql_password", ""))
MYSQL_DATABASE = os.environ.get("MYSQL_DATABASE", "quantumshield")

# USER PROVIDED CREDENTIALS
USERNAME = "admin"
PASSWORD = "Admin@12345678"

try:
    conn = pymysql.connect(
        host=MYSQL_HOST,
        port=MYSQL_PORT,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DATABASE,
        cursorclass=pymysql.cursors.DictCursor
    )
    with conn.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE username = %s", (USERNAME,))
        existing_user = cursor.fetchone()
        
        hashed_pw = generate_password_hash(PASSWORD)
        
        if existing_user:
            print(f"User '{USERNAME}' exists. Updating password and making Active Admin.")
            cursor.execute(
                "UPDATE users SET password_hash=%s, role='Admin', is_active=TRUE WHERE username=%s",
                (hashed_pw, USERNAME)
            )
        else:
            print(f"Creating '{USERNAME}' with Admin role.")
            cursor.execute(
                "INSERT INTO users (username, password_hash, role, is_active, email) VALUES (%s, %s, %s, %s, %s)",
                (USERNAME, hashed_pw, "Admin", True, "admin@localhost")
            )
    conn.commit()
    conn.close()
    print("Admin user synced successfully.")
except Exception as e:
    print(f"Error syncing admin user: {e}")
