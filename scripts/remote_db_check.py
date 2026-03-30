"""Quick connectivity check for a remote MySQL database.

Usage:
    python scripts/remote_db_check.py

Reads connection settings from environment variables:
    REMOTE_MYSQL_HOST
    REMOTE_MYSQL_PORT
    REMOTE_MYSQL_USER
    REMOTE_MYSQL_PASSWORD
    REMOTE_MYSQL_DATABASE

Falls back to MYSQL_* variables if REMOTE_* are not provided.
"""

from __future__ import annotations

import os
import sys

import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv


def _get_env(name: str, fallback: str = "") -> str:
    return str(os.environ.get(name, fallback) or "").strip()


def main() -> int:
    load_dotenv()

    host = _get_env("REMOTE_MYSQL_HOST", _get_env("MYSQL_HOST", "localhost"))
    port = int(_get_env("REMOTE_MYSQL_PORT", _get_env("MYSQL_PORT", "3306")))
    user = _get_env("REMOTE_MYSQL_USER", _get_env("MYSQL_USER", "root"))
    password = _get_env("REMOTE_MYSQL_PASSWORD", _get_env("MYSQL_PASSWORD", ""))
    database = _get_env("REMOTE_MYSQL_DATABASE", _get_env("MYSQL_DATABASE", "quantumshield"))

    if not host or not user or not database:
        print("[ERROR] Missing required DB connection values.")
        print("Set REMOTE_MYSQL_HOST, REMOTE_MYSQL_USER, REMOTE_MYSQL_DATABASE (and password).")
        return 1

    connection = None
    cursor = None

    try:
        connection = mysql.connector.connect(
            host=host,
            database=database,
            user=user,
            password=password,
            port=port,
            connection_timeout=10,
        )

        if connection.is_connected():
            db_info = connection.get_server_info()
            print(f"[OK] Connected to MySQL server version: {db_info}")
            cursor = connection.cursor()
            cursor.execute("SELECT DATABASE();")
            record = cursor.fetchone()

            active_database = database
            if isinstance(record, (tuple, list)) and record:
                active_database = str(record[0])
            elif isinstance(record, dict):
                active_database = str(
                    record.get("DATABASE()")
                    or record.get("database")
                    or database
                )

            print(f"[OK] Active database: {active_database}")
            return 0

        print("[ERROR] Connection object created but not connected.")
        return 2

    except Error as exc:
        print(f"[ERROR] MySQL connection failed: {exc}")
        return 3
    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None and connection.is_connected():
            connection.close()
            print("[INFO] MySQL connection closed.")


if __name__ == "__main__":
    raise SystemExit(main())
