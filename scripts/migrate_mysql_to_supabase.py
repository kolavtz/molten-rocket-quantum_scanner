"""Migrate data from MySQL to Supabase/PostgreSQL.

Usage:
    python scripts/migrate_mysql_to_supabase.py
    python scripts/migrate_mysql_to_supabase.py --tables users assets scans

Reads source from MYSQL_* env variables and target from SUPABASE_DATABASE_URL.
Creates target schema from SQLAlchemy models before copying rows.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Iterable

from dotenv import load_dotenv
from sqlalchemy import MetaData, Table, create_engine, inspect, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.engine.url import URL


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _mysql_uri() -> str:
    host = os.environ.get("MYSQL_HOST", "localhost")
    port = os.environ.get("MYSQL_PORT", "3306")
    user = os.environ.get("MYSQL_USER", "root")
    password = os.environ.get("MYSQL_PASSWORD", "")
    database = os.environ.get("MYSQL_DATABASE", "quantumshield")
    return URL.create(
        "mysql+pymysql",
        username=user,
        password=password,
        host=host,
        port=int(port),
        database=database,
    ).render_as_string(hide_password=False)


def _postgres_uri() -> str:
    raw = str(os.environ.get("SUPABASE_DATABASE_URL") or "").strip()
    if raw.startswith("postgresql+psycopg2://"):
        return raw
    if raw.startswith("postgresql://"):
        return "postgresql+psycopg2://" + raw[len("postgresql://"):]
    raise RuntimeError("SUPABASE_DATABASE_URL is missing or invalid.")


def _ordered_tables(existing: set[str]) -> list[str]:
    preferred = [
        "users",
        "scans",
        "assets",
        "asset_dns_records",
        "discovery_domains",
        "discovery_ips",
        "discovery_software",
        "discovery_ssl",
        "certificates",
        "pqc_classification",
        "cbom_summary",
        "cbom_entries",
        "compliance_scores",
        "cyber_rating",
        "findings",
        "asset_metrics",
        "org_pqc_metrics",
        "cert_expiry_buckets",
        "tls_compliance_scores",
        "digital_labels",
        "audit_log_chain",
        "audit_logs",
        "report_schedules",
        "cbom_reports",
    ]
    ordered = [t for t in preferred if t in existing]
    ordered.extend(sorted(existing - set(ordered)))
    return ordered


def _chunked(iterable: Iterable[dict], size: int = 500):
    batch: list[dict] = []
    for item in iterable:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def migrate(tables: list[str] | None = None, truncate: bool = True) -> None:
    source_engine = create_engine(_mysql_uri(), pool_pre_ping=True)
    target_engine = create_engine(_postgres_uri(), pool_pre_ping=True)

    # Ensure destination schema exists per current ORM models.
    from src.models import Base

    Base.metadata.create_all(target_engine)

    src_inspector = inspect(source_engine)
    dst_inspector = inspect(target_engine)

    src_tables = set(src_inspector.get_table_names())
    dst_tables = set(dst_inspector.get_table_names())

    selected = set(tables) if tables else src_tables
    selected = {t for t in selected if t in src_tables and t in dst_tables}
    ordered = _ordered_tables(selected)

    if not ordered:
        raise RuntimeError("No overlapping source/target tables found for migration.")

    print(f"[INFO] Migrating {len(ordered)} tables from MySQL -> Supabase")

    src_meta = MetaData()
    dst_meta = MetaData()

    with source_engine.connect() as src_conn, target_engine.begin() as dst_conn:
        if truncate:
            for table_name in reversed(ordered):
                dst_conn.execute(text(f'TRUNCATE TABLE "{table_name}" RESTART IDENTITY CASCADE'))

        for table_name in ordered:
            src_table = Table(table_name, src_meta, autoload_with=source_engine)
            dst_table = Table(table_name, dst_meta, autoload_with=target_engine)

            src_cols = [c.name for c in src_table.columns]
            dst_cols = {c.name for c in dst_table.columns}
            common_cols = [c for c in src_cols if c in dst_cols]

            if not common_cols:
                print(f"[SKIP] {table_name}: no matching columns")
                continue

            query = select(*[src_table.c[c] for c in common_cols])
            rows = (dict(r) for r in src_conn.execute(query).mappings())

            inserted = 0
            for batch in _chunked(rows, size=500):
                dst_conn.execute(dst_table.insert(), batch)
                inserted += len(batch)

            print(f"[OK] {table_name}: {inserted} rows")

    print("[DONE] Migration completed successfully.")


def main() -> int:
    load_dotenv()

    parser = argparse.ArgumentParser(description="Migrate MySQL data to Supabase/PostgreSQL")
    parser.add_argument("--tables", nargs="*", help="Optional list of tables to migrate")
    parser.add_argument("--no-truncate", action="store_true", help="Do not truncate target tables first")
    args = parser.parse_args()

    migrate(tables=args.tables, truncate=not args.no_truncate)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
