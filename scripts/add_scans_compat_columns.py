#!/usr/bin/env python3
"""Add missing compatibility columns to `scans` table and backfill simple defaults.

This is a safe, idempotent one-off helper to bring legacy databases in line with the
ORM's expectations (adds `requested_target`, `normalized_target`, `scan_kind`, etc.).
Run from project root using the project venv: `.venv\Scripts\python.exe scripts\add_scans_compat_columns.py`
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE
import pymysql


DESIRED_COLUMNS = {
    "requested_target": "VARCHAR(512) NULL",
    "normalized_target": "VARCHAR(512) NULL",
    "scan_kind": "VARCHAR(32) NULL",
    "initiated_by": "VARCHAR(36) NULL",
    "total_discovered": "INT DEFAULT 0",
    "total_promoted": "INT DEFAULT 0",
    "cbom_path": "VARCHAR(500) NULL",
    "error_message": "LONGTEXT NULL",
    "report_json": "LONGTEXT NULL",
    "correlation_id": "VARCHAR(36) NULL",
    "scanner_version": "VARCHAR(50) NULL",
    "deleted_by": "VARCHAR(36) NULL",
}


def main():
    conn = pymysql.connect(host=MYSQL_HOST, user=MYSQL_USER, password=MYSQL_PASSWORD, database=MYSQL_DATABASE, port=int(MYSQL_PORT))
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=%s AND TABLE_NAME='scans'", (MYSQL_DATABASE,))
            existing = {row[0] for row in cur.fetchall()}

            to_add = [c for c in DESIRED_COLUMNS.keys() if c not in existing]
            if not to_add:
                print('[+] No compatibility columns to add on scans; nothing to do')
                return 0

            for col in to_add:
                col_def = DESIRED_COLUMNS[col]
                try:
                    print(f"[*] Adding column {col} {col_def} ...")
                    cur.execute(f"ALTER TABLE scans ADD COLUMN {col} {col_def}")
                except Exception as e:
                    print(f"[!] Could not add {col}: {e}")

            # Backfill some sensible defaults for newly-added columns
            if 'requested_target' in to_add:
                try:
                    print('[*] Backfilling requested_target from target where empty...')
                    cur.execute("UPDATE scans SET requested_target = target WHERE requested_target IS NULL OR requested_target = ''")
                except Exception as e:
                    print('[!] Backfill requested_target failed:', e)

            if 'normalized_target' in to_add:
                try:
                    print('[*] Backfilling normalized_target from target (lowercased) where empty...')
                    cur.execute("UPDATE scans SET normalized_target = LOWER(target) WHERE normalized_target IS NULL OR normalized_target = ''")
                except Exception as e:
                    print('[!] Backfill normalized_target failed:', e)

            if 'scan_kind' in to_add:
                try:
                    print('[*] Setting default scan_kind to "manual" where empty...')
                    cur.execute("UPDATE scans SET scan_kind = 'manual' WHERE scan_kind IS NULL OR scan_kind = ''")
                except Exception as e:
                    print('[!] Default scan_kind failed:', e)

            # commit and finish
            conn.commit()
            print('[✅] Added compatibility columns and backfilled defaults.')
    finally:
        conn.close()

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
