#!/usr/bin/env python3
"""One-time backfill for legacy issuer/subject/validity fields.

Backfills from `certificates` into:
- discovery_ssl.issuer
- discovery_ssl.valid_until
- cbom_entries.issuer_name
- cbom_entries.subject_name
- cbom_entries.not_valid_before
- cbom_entries.not_valid_after

Default: dry-run (ROLLBACK)
Use: --apply (COMMIT)
"""

from __future__ import annotations

import argparse
import os
import sys

import pymysql

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from config import MYSQL_DATABASE, MYSQL_HOST, MYSQL_PASSWORD, MYSQL_PORT, MYSQL_USER


def _table_exists(cur, table_name: str) -> bool:
    cur.execute(
        """
        SELECT COUNT(*)
        FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s
        """,
        (MYSQL_DATABASE, table_name),
    )
    return int((cur.fetchone() or [0])[0] or 0) > 0


def _column_exists(cur, table_name: str, column_name: str) -> bool:
    cur.execute(
        """
        SELECT COUNT(*)
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND COLUMN_NAME = %s
        """,
        (MYSQL_DATABASE, table_name, column_name),
    )
    return int((cur.fetchone() or [0])[0] or 0) > 0


def _count_missing(cur, table_name: str, where_sql: str) -> int:
    cur.execute(f"SELECT COUNT(*) FROM {table_name} WHERE {where_sql}")
    return int((cur.fetchone() or [0])[0] or 0)


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill discovery_ssl / cbom_entries issuer & validity fields")
    parser.add_argument("--apply", action="store_true", help="Commit changes (default is dry-run rollback)")
    args = parser.parse_args()

    conn = pymysql.connect(
        host=MYSQL_HOST,
        port=int(MYSQL_PORT),
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DATABASE,
        autocommit=False,
    )

    try:
        with conn.cursor() as cur:
            required = {
                "certificates": [
                    "asset_id", "scan_id", "endpoint", "subject_cn", "subject",
                    "issuer", "issuer_cn", "issuer_o", "ca",
                    "valid_from", "valid_until", "is_current", "is_deleted",
                    "last_seen_at", "updated_at", "id",
                ],
                "discovery_ssl": ["asset_id", "scan_id", "endpoint", "subject_cn", "issuer", "valid_until", "is_deleted"],
                "cbom_entries": ["asset_id", "scan_id", "issuer_name", "subject_name", "not_valid_before", "not_valid_after", "is_deleted"],
            }

            for t, cols in required.items():
                if not _table_exists(cur, t):
                    print(f"[!] Required table missing: {t}")
                    return 1
                for c in cols:
                    if not _column_exists(cur, t, c):
                        print(f"[!] Required column missing: {t}.{c}")
                        return 1

            before = {
                "discovery_ssl.issuer": _count_missing(cur, "discovery_ssl", "is_deleted=0 AND (issuer IS NULL OR TRIM(issuer)='')"),
                "discovery_ssl.valid_until": _count_missing(cur, "discovery_ssl", "is_deleted=0 AND valid_until IS NULL"),
                "cbom_entries.issuer_name": _count_missing(cur, "cbom_entries", "is_deleted=0 AND asset_id IS NOT NULL AND (issuer_name IS NULL OR TRIM(issuer_name)='')"),
                "cbom_entries.subject_name": _count_missing(cur, "cbom_entries", "is_deleted=0 AND asset_id IS NOT NULL AND (subject_name IS NULL OR TRIM(subject_name)='')"),
                "cbom_entries.not_valid_before": _count_missing(cur, "cbom_entries", "is_deleted=0 AND asset_id IS NOT NULL AND not_valid_before IS NULL"),
                "cbom_entries.not_valid_after": _count_missing(cur, "cbom_entries", "is_deleted=0 AND asset_id IS NOT NULL AND not_valid_after IS NULL"),
            }
            for k, v in before.items():
                print(f"[*] Missing before -> {k}: {v}")

            # 1) discovery_ssl.issuer
            cur.execute(
                """
                UPDATE discovery_ssl d
                SET d.issuer = (
                    SELECT COALESCE(NULLIF(c.issuer_cn,''), NULLIF(c.issuer_o,''), NULLIF(c.issuer,''), NULLIF(c.ca,''))
                    FROM certificates c
                    WHERE c.is_deleted=0
                      AND c.asset_id=d.asset_id
                    ORDER BY
                      CASE WHEN d.scan_id IS NOT NULL AND c.scan_id=d.scan_id THEN 0 ELSE 1 END,
                      CASE WHEN d.endpoint IS NOT NULL AND d.endpoint<>'' AND c.endpoint=d.endpoint THEN 0 ELSE 1 END,
                      CASE WHEN d.subject_cn IS NOT NULL AND d.subject_cn<>'' AND c.subject_cn=d.subject_cn THEN 0 ELSE 1 END,
                      CASE WHEN c.is_current=1 THEN 0 ELSE 1 END,
                      c.last_seen_at DESC,
                      c.updated_at DESC,
                      c.id DESC
                    LIMIT 1
                )
                WHERE d.is_deleted=0
                  AND (d.issuer IS NULL OR TRIM(d.issuer)='')
                """
            )
            updated_dssl_issuer = int(cur.rowcount or 0)

            # 2) discovery_ssl.valid_until
            cur.execute(
                """
                UPDATE discovery_ssl d
                SET d.valid_until = (
                    SELECT c.valid_until
                    FROM certificates c
                    WHERE c.is_deleted=0
                      AND c.asset_id=d.asset_id
                      AND c.valid_until IS NOT NULL
                    ORDER BY
                      CASE WHEN d.scan_id IS NOT NULL AND c.scan_id=d.scan_id THEN 0 ELSE 1 END,
                      CASE WHEN d.endpoint IS NOT NULL AND d.endpoint<>'' AND c.endpoint=d.endpoint THEN 0 ELSE 1 END,
                      CASE WHEN d.subject_cn IS NOT NULL AND d.subject_cn<>'' AND c.subject_cn=d.subject_cn THEN 0 ELSE 1 END,
                      CASE WHEN c.is_current=1 THEN 0 ELSE 1 END,
                      c.valid_until DESC,
                      c.last_seen_at DESC,
                      c.updated_at DESC,
                      c.id DESC
                    LIMIT 1
                )
                WHERE d.is_deleted=0
                  AND d.valid_until IS NULL
                """
            )
            updated_dssl_valid_until = int(cur.rowcount or 0)

            # 3) cbom_entries.issuer_name
            cur.execute(
                """
                UPDATE cbom_entries e
                SET e.issuer_name = (
                    SELECT COALESCE(NULLIF(c.issuer_cn,''), NULLIF(c.issuer_o,''), NULLIF(c.issuer,''), NULLIF(c.ca,''))
                    FROM certificates c
                    WHERE c.is_deleted=0
                      AND c.asset_id=e.asset_id
                    ORDER BY
                      CASE WHEN e.scan_id IS NOT NULL AND c.scan_id=e.scan_id THEN 0 ELSE 1 END,
                      CASE WHEN c.is_current=1 THEN 0 ELSE 1 END,
                      c.last_seen_at DESC,
                      c.updated_at DESC,
                      c.id DESC
                    LIMIT 1
                )
                WHERE e.is_deleted=0
                  AND e.asset_id IS NOT NULL
                  AND (e.issuer_name IS NULL OR TRIM(e.issuer_name)='')
                """
            )
            updated_cbom_issuer = int(cur.rowcount or 0)

            # 4) cbom_entries.subject_name
            cur.execute(
                """
                UPDATE cbom_entries e
                SET e.subject_name = (
                    SELECT COALESCE(NULLIF(c.subject_cn,''), NULLIF(c.subject,''))
                    FROM certificates c
                    WHERE c.is_deleted=0
                      AND c.asset_id=e.asset_id
                    ORDER BY
                      CASE WHEN e.scan_id IS NOT NULL AND c.scan_id=e.scan_id THEN 0 ELSE 1 END,
                      CASE WHEN c.is_current=1 THEN 0 ELSE 1 END,
                      c.last_seen_at DESC,
                      c.updated_at DESC,
                      c.id DESC
                    LIMIT 1
                )
                WHERE e.is_deleted=0
                  AND e.asset_id IS NOT NULL
                  AND (e.subject_name IS NULL OR TRIM(e.subject_name)='')
                """
            )
            updated_cbom_subject = int(cur.rowcount or 0)

            # 5) cbom_entries.not_valid_before
            cur.execute(
                """
                UPDATE cbom_entries e
                SET e.not_valid_before = (
                    SELECT c.valid_from
                    FROM certificates c
                    WHERE c.is_deleted=0
                      AND c.asset_id=e.asset_id
                      AND c.valid_from IS NOT NULL
                    ORDER BY
                      CASE WHEN e.scan_id IS NOT NULL AND c.scan_id=e.scan_id THEN 0 ELSE 1 END,
                      CASE WHEN c.is_current=1 THEN 0 ELSE 1 END,
                      c.valid_from DESC,
                      c.last_seen_at DESC,
                      c.updated_at DESC,
                      c.id DESC
                    LIMIT 1
                )
                WHERE e.is_deleted=0
                  AND e.asset_id IS NOT NULL
                  AND e.not_valid_before IS NULL
                """
            )
            updated_cbom_not_before = int(cur.rowcount or 0)

            # 6) cbom_entries.not_valid_after
            cur.execute(
                """
                UPDATE cbom_entries e
                SET e.not_valid_after = (
                    SELECT c.valid_until
                    FROM certificates c
                    WHERE c.is_deleted=0
                      AND c.asset_id=e.asset_id
                      AND c.valid_until IS NOT NULL
                    ORDER BY
                      CASE WHEN e.scan_id IS NOT NULL AND c.scan_id=e.scan_id THEN 0 ELSE 1 END,
                      CASE WHEN c.is_current=1 THEN 0 ELSE 1 END,
                      c.valid_until DESC,
                      c.last_seen_at DESC,
                      c.updated_at DESC,
                      c.id DESC
                    LIMIT 1
                )
                WHERE e.is_deleted=0
                  AND e.asset_id IS NOT NULL
                  AND e.not_valid_after IS NULL
                """
            )
            updated_cbom_not_after = int(cur.rowcount or 0)

            after = {
                "discovery_ssl.issuer": _count_missing(cur, "discovery_ssl", "is_deleted=0 AND (issuer IS NULL OR TRIM(issuer)='')"),
                "discovery_ssl.valid_until": _count_missing(cur, "discovery_ssl", "is_deleted=0 AND valid_until IS NULL"),
                "cbom_entries.issuer_name": _count_missing(cur, "cbom_entries", "is_deleted=0 AND asset_id IS NOT NULL AND (issuer_name IS NULL OR TRIM(issuer_name)='')"),
                "cbom_entries.subject_name": _count_missing(cur, "cbom_entries", "is_deleted=0 AND asset_id IS NOT NULL AND (subject_name IS NULL OR TRIM(subject_name)='')"),
                "cbom_entries.not_valid_before": _count_missing(cur, "cbom_entries", "is_deleted=0 AND asset_id IS NOT NULL AND not_valid_before IS NULL"),
                "cbom_entries.not_valid_after": _count_missing(cur, "cbom_entries", "is_deleted=0 AND asset_id IS NOT NULL AND not_valid_after IS NULL"),
            }

            print(f"[+] Updated rows -> discovery_ssl.issuer: {updated_dssl_issuer}")
            print(f"[+] Updated rows -> discovery_ssl.valid_until: {updated_dssl_valid_until}")
            print(f"[+] Updated rows -> cbom_entries.issuer_name: {updated_cbom_issuer}")
            print(f"[+] Updated rows -> cbom_entries.subject_name: {updated_cbom_subject}")
            print(f"[+] Updated rows -> cbom_entries.not_valid_before: {updated_cbom_not_before}")
            print(f"[+] Updated rows -> cbom_entries.not_valid_after: {updated_cbom_not_after}")
            for k, v in after.items():
                print(f"[*] Missing after  -> {k}: {v}")

            if args.apply:
                conn.commit()
                print("[OK] Backfill committed.")
            else:
                conn.rollback()
                print("[INFO] Dry-run complete (rolled back). Re-run with --apply to commit.")

    except Exception as exc:
        conn.rollback()
        print(f"[!] Backfill failed: {exc}")
        return 1
    finally:
        conn.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
