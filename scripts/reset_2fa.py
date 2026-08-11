#!/usr/bin/env python3
"""Reset 2FA (Two-Factor Authentication) for a user in QuantumShield MySQL database.

Usage:
    python scripts/reset_2fa.py [username]

Loads environment variables from .env and .env.local.
If no username is provided, resets 2FA for the user defined by QSS_ADMIN_USERNAME (default: Admin).
"""
import os
import sys
import pymysql

# Ensure project root is on sys.path so `import config` works when running from scripts/
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, project_root)

from dotenv import load_dotenv  # type: ignore

# Load .env and override with .env.local if present
load_dotenv(os.path.join(project_root, ".env"))
_env_local = os.path.join(project_root, ".env.local")
if os.path.exists(_env_local):
    load_dotenv(_env_local, override=True)

from config import MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE


def main():
    if len(sys.argv) > 1:
        target_username = sys.argv[1]
    else:
        target_username = os.environ.get("QSS_ADMIN_USERNAME", "Admin")

    print(f"[*] Target username for 2FA reset: {target_username}")

    try:
        conn = pymysql.connect(
            host=MYSQL_HOST,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DATABASE,
            port=int(MYSQL_PORT),
        )
    except Exception as e:
        print(f"[!] Failed to connect to MySQL database ({MYSQL_DATABASE}@{MYSQL_HOST}:{MYSQL_PORT}): {e}")
        return 1

    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, username, email, two_factor_enabled FROM users WHERE LOWER(username) = LOWER(%s)",
                (target_username,),
            )
            rows = cur.fetchall()

            if not rows:
                print(f"[!] No user found matching username: '{target_username}'")
                return 1

            for row in rows:
                user_id, uname, email, tfa_enabled = row[0], row[1], row[2], row[3]
                print(f"[+] Found user: ID={user_id}, Username={uname}, Email={email}, Current 2FA={tfa_enabled}")

                cur.execute(
                    """
                    UPDATE users
                    SET two_factor_enabled = FALSE,
                        two_factor_secret = NULL,
                        backup_codes = NULL,
                        failed_login_attempts = 0,
                        lockout_until = NULL
                    WHERE id = %s
                    """,
                    (user_id,),
                )
            conn.commit()
            print(f"[OK] Successfully reset/disabled 2FA and lifted lockout for '{target_username}'.")

            # Verification
            cur.execute(
                "SELECT id, username, two_factor_enabled, two_factor_secret, failed_login_attempts, lockout_until FROM users WHERE LOWER(username) = LOWER(%s)",
                (target_username,),
            )
            print("[After Reset]", cur.fetchall())
    finally:
        conn.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
