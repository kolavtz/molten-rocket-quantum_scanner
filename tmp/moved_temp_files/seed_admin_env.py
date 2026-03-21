import sys
import os
import uuid
import datetime
from dotenv import load_dotenv

# Add src to python path to import database and workspace
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from src.database import _get_connection, _utcnow
from werkzeug.security import generate_password_hash

def main():
    load_dotenv()
    
    admin_username = os.environ.get("QSS_ADMIN_USERNAME", "admin")
    admin_email = os.environ.get("QSS_ADMIN_EMAIL", "admin@localhost")
    admin_employee_id = os.environ.get("QSS_ADMIN_EMPLOYEE_ID", "ADMIN-001")
    admin_pass = os.environ.get("QSS_ADMIN_PASSWORD", "admin123")
    
    print(f"[*] Admin Username: {admin_username}")
    print(f"[*] Admin Email: {admin_email}")
    print(f"[*] Admin Pass Found: {'Yes' if admin_pass else 'No'}")

    if not admin_pass:
        print("[!] QSS_ADMIN_PASSWORD not set in environment.")
        return

    print("[*] Connecting to database (calling _get_connection())...")
    conn = _get_connection()
    print("[*] _get_connection() returned.")
    if not conn:

        print("[!] Failed to connect to database.")
        return

    try:
        cur = conn.cursor()
        
        # Check if user exists
        cur.execute("SELECT id FROM users WHERE username = %s", (admin_username,))
        row = cur.fetchone()
        
        pw_hash = generate_password_hash(admin_pass)
        
        if row:
            user_id = row[0]
            print(f"[*] Admin user '{admin_username}' exists (ID: {user_id}). Updating password...")
            cur.execute(
                "UPDATE users SET password_hash = %s, email = %s, employee_id = %s WHERE id = %s",
                (pw_hash, admin_email, admin_employee_id, user_id)
            )
        else:
            print(f"[*] Creating Admin user '{admin_username}'...")
            cur.execute(
                """
                INSERT INTO users 
                (id, employee_id, username, email, password_hash, role, is_active, must_change_password, password_changed_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    str(uuid.uuid4()),
                    admin_employee_id,
                    admin_username,
                    admin_email,
                    pw_hash,
                    "Admin",
                    True,
                    False,
                    datetime.datetime.now()
                )
            )
        conn.commit()
        print("[✅] Admin credentials established in database.")
        
    except Exception as e:
        conn.rollback()
        print(f"[!] Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    main()
