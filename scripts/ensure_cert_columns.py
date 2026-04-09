#!/usr/bin/env python3
"""Ensure required certificate columns exist in the database.

This script connects to the MySQL database configured in `config.py` and
adds missing columns and indexes used by the application (fingerprint_sha1,
fingerprint_md5, public_key_fingerprint_sha256, certificate_format,
dedup_algorithm, dedup_value, dedup_hash). It is safe to run multiple times.

Usage:
    python scripts/ensure_cert_columns.py

Note: configure the DB connection via environment variables (see `.env`) or
the project's `config.py` values (MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD,
MYSQL_DATABASE).
"""

from __future__ import annotations

import os
import sys
from pymysql.constants import CLIENT
import pymysql

# Make config importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
try:
    from config import MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE
except Exception as e:
    print("Failed to import DB configuration from config.py:", e)
    raise


def column_exists(conn, schema: str, table: str, column: str) -> bool:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT COUNT(*) FROM information_schema.columns
            WHERE table_schema=%s AND table_name=%s AND column_name=%s
            """,
            (schema, table, column),
        )
        r = cur.fetchone()
        return bool(r and r[0] > 0)


def index_exists(conn, schema: str, table: str, index_name: str) -> bool:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT COUNT(*) FROM information_schema.statistics
            WHERE table_schema=%s AND table_name=%s AND index_name=%s
            """,
            (schema, table, index_name),
        )
        r = cur.fetchone()
        return bool(r and r[0] > 0)


def ensure_columns(conn):
    adds = []
    schema = MYSQL_DATABASE
    table = 'certificates'

    # Columns to ensure (type choices aligned with src/models.py)
    if not column_exists(conn, schema, table, 'fingerprint_sha1'):
        adds.append("ADD COLUMN fingerprint_sha1 VARCHAR(40) NULL")
    if not column_exists(conn, schema, table, 'fingerprint_md5'):
        adds.append("ADD COLUMN fingerprint_md5 VARCHAR(32) NULL")
    if not column_exists(conn, schema, table, 'public_key_fingerprint_sha256'):
        adds.append("ADD COLUMN public_key_fingerprint_sha256 VARCHAR(64) NULL")
    if not column_exists(conn, schema, table, 'certificate_format'):
        adds.append("ADD COLUMN certificate_format VARCHAR(50) NULL")
    if not column_exists(conn, schema, table, 'certificate_version'):
        adds.append("ADD COLUMN certificate_version VARCHAR(50) NULL")

    # Dedup metadata
    if not column_exists(conn, schema, table, 'dedup_algorithm'):
        adds.append("ADD COLUMN dedup_algorithm VARCHAR(20) NULL")
    if not column_exists(conn, schema, table, 'dedup_value'):
        adds.append("ADD COLUMN dedup_value VARCHAR(128) NULL")
    if not column_exists(conn, schema, table, 'dedup_hash'):
        adds.append("ADD COLUMN dedup_hash VARCHAR(64) NULL")

    if adds:
        sql = "ALTER TABLE `certificates`\n  " + ",\n  ".join(adds) + ";"
        print("Applying schema changes:\n", sql)
        with conn.cursor() as cur:
            cur.execute(sql)
        print("Columns added (or already present).")
    else:
        print("All required certificate columns already exist.")

    # Create indexes if missing
    with conn.cursor() as cur:
        if not index_exists(conn, schema, table, 'idx_cert_fp_sha1'):
            print("Creating index idx_cert_fp_sha1")
            cur.execute("CREATE INDEX idx_cert_fp_sha1 ON `certificates` (fingerprint_sha1)")
        if not index_exists(conn, schema, table, 'idx_cert_fp_md5'):
            print("Creating index idx_cert_fp_md5")
            cur.execute("CREATE INDEX idx_cert_fp_md5 ON `certificates` (fingerprint_md5)")
        if not index_exists(conn, schema, table, 'idx_cert_pubkey_fp'):
            print("Creating index idx_cert_pubkey_fp")
            cur.execute("CREATE INDEX idx_cert_pubkey_fp ON `certificates` (public_key_fingerprint_sha256)")
        if not index_exists(conn, schema, table, 'idx_cert_dedup_value'):
            print("Creating index idx_cert_dedup_value")
            cur.execute("CREATE INDEX idx_cert_dedup_value ON `certificates` (dedup_value)")
        if not index_exists(conn, schema, table, 'idx_cert_dedup_hash'):
            print("Creating index idx_cert_dedup_hash")
            cur.execute("CREATE INDEX idx_cert_dedup_hash ON `certificates` (dedup_hash)")
    conn.commit()
    print("Index checks/creates complete.")


def main():
    print(f"Connecting to MySQL {MYSQL_HOST}/{MYSQL_DATABASE} as {MYSQL_USER}")
    conn = pymysql.connect(
        host=MYSQL_HOST,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DATABASE,
        client_flag=CLIENT.MULTI_STATEMENTS,
        autocommit=False,
    )
    try:
        ensure_columns(conn)
    finally:
        conn.close()


if __name__ == '__main__':
    main()
