#!/usr/bin/env python3
"""One-off migration: ensure `scan_uid` column exists on `scans` and is populated.

Usage: run from project root: .venv\Scripts\python.exe scripts\add_scan_uid_column.py
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE
import pymysql


def main():
    conn = pymysql.connect(host=MYSQL_HOST, user=MYSQL_USER, password=MYSQL_PASSWORD, database=MYSQL_DATABASE, port=int(MYSQL_PORT))
    try:
        with conn.cursor() as cur:
            # Check existing columns
            cur.execute("SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=%s AND TABLE_NAME='scans'", (MYSQL_DATABASE,))
            cols = {row[0] for row in cur.fetchall()}
            if 'scan_uid' in cols:
                print('[+] scans.scan_uid already exists; no action needed')
                return 0

            print('[*] Adding scan_uid column to scans...')
            cur.execute("ALTER TABLE scans ADD COLUMN scan_uid VARCHAR(36) NULL")

            print('[*] Backfilling scan_uid from scan_id where available...')
            cur.execute("UPDATE scans SET scan_uid = scan_id WHERE (scan_uid IS NULL OR scan_uid = '') AND scan_id IS NOT NULL AND scan_id <> ''")

            print('[*] Generating UUID for remaining empty scan_uid rows...')
            cur.execute("UPDATE scans SET scan_uid = UUID() WHERE scan_uid IS NULL OR scan_uid = ''")

            try:
                print('[*] Setting scan_uid NOT NULL...')
                cur.execute("ALTER TABLE scans MODIFY COLUMN scan_uid VARCHAR(36) NOT NULL")
            except Exception as e:
                print('[!] Could not set NOT NULL for scan_uid:', e)

            try:
                print('[*] Creating unique index on scan_uid...')
                cur.execute('CREATE UNIQUE INDEX uq_scans_scan_uid ON scans(scan_uid)')
            except Exception as e:
                print('[!] Could not create unique index on scan_uid (may already exist):', e)

            conn.commit()
            print('[✅] Migration complete. scan_uid added and populated.')
    finally:
        conn.close()

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
