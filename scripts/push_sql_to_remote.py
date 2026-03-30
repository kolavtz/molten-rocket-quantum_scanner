"""Push SQL schema/data files to a remote MySQL host.

Usage examples:
    python scripts/push_sql_to_remote.py --file schema_v2_inventory_api_first.sql
    python scripts/push_sql_to_remote.py --file schema_v2_inventory_api_first.sql --file migrations/001_add_findings_and_metrics_tables.sql

Connection values are read from:
    REMOTE_MYSQL_HOST / PORT / USER / PASSWORD / DATABASE
with fallback to MYSQL_*.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv


def _get_env(name: str, fallback: str = "") -> str:
    return str(os.environ.get(name, fallback) or "").strip()


def _connect():
    host = _get_env("REMOTE_MYSQL_HOST", _get_env("MYSQL_HOST", "localhost"))
    port = int(_get_env("REMOTE_MYSQL_PORT", _get_env("MYSQL_PORT", "3306")))
    user = _get_env("REMOTE_MYSQL_USER", _get_env("MYSQL_USER", "root"))
    password = _get_env("REMOTE_MYSQL_PASSWORD", _get_env("MYSQL_PASSWORD", ""))
    database = _get_env("REMOTE_MYSQL_DATABASE", _get_env("MYSQL_DATABASE", "quantumshield"))

    return mysql.connector.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=database,
        autocommit=False,
        connection_timeout=15,
    )


def _run_sql_file(connection, file_path: Path) -> None:
    sql = file_path.read_text(encoding="utf-8")
    try:
        for _ in connection.cmd_query_iter(sql):
            pass
        connection.commit()
        print(f"[OK] Applied: {file_path}")
    finally:
        pass


def main() -> int:
    load_dotenv()

    parser = argparse.ArgumentParser(description="Apply SQL files to remote MySQL")
    parser.add_argument(
        "--file",
        dest="files",
        action="append",
        required=True,
        help="SQL file path to apply (can be passed multiple times)",
    )
    args = parser.parse_args()

    files = [Path(f).resolve() for f in args.files]
    for file_path in files:
        if not file_path.exists() or not file_path.is_file():
            print(f"[ERROR] File not found: {file_path}")
            return 1

    connection = None
    try:
        connection = _connect()
        if not connection.is_connected():
            print("[ERROR] Unable to establish MySQL connection.")
            return 2

        print("[INFO] Connected to remote MySQL. Applying SQL files...")
        for file_path in files:
            _run_sql_file(connection, file_path)

        print("[OK] All SQL files applied successfully.")
        return 0

    except Error as exc:
        if connection is not None:
            connection.rollback()
        print(f"[ERROR] Failed to apply SQL: {exc}")
        return 3
    finally:
        if connection is not None and connection.is_connected():
            connection.close()
            print("[INFO] MySQL connection closed.")


if __name__ == "__main__":
    raise SystemExit(main())
