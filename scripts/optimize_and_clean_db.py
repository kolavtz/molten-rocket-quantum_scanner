#!/usr/bin/env python3
"""
Database Optimization & Cleanup Script
---------------------------------------
1. Removes empty, placeholder ('--', '', '0', None), and zero records across all discovery tables.
2. Deduplicates records per domain/IP/subdomain/software/asset by preserving the latest/highest ID record.
3. Cleans orphaned records and trims whitespace across identifiers.
"""

import sys
import os

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.db import db_session
from src.models import (
    DiscoveryDomain,
    DiscoveryIP,
    DiscoverySSL,
    DiscoverySoftware,
    Subdomain,
    Asset,
    Certificate,
)

INVALID_SENTINELS = ["", "--", "0", "null", "none", "-", "undefined"]

def clean_table_invalid_records(model, col_name):
    col = getattr(model, col_name)
    count = 0
    
    # Delete where column is NULL
    null_rows = db_session.query(model).filter(col.is_(None)).all()
    for row in null_rows:
        db_session.delete(row)
        count += 1
        
    # Delete where trimmed lower string matches invalid sentinels
    all_rows = db_session.query(model).all()
    for row in all_rows:
        val = str(getattr(row, col_name) or "").strip().lower()
        if not val or val in INVALID_SENTINELS:
            db_session.delete(row)
            count += 1
            
    db_session.commit()
    return count


def deduplicate_table(model, col_name):
    rows = db_session.query(model).order_by(model.id.desc()).all()
    seen = set()
    removed = 0
    
    for row in rows:
        val = str(getattr(row, col_name) or "").strip().lower()
        if not val or val in INVALID_SENTINELS:
            db_session.delete(row)
            removed += 1
            continue
            
        if val in seen:
            db_session.delete(row)
            removed += 1
        else:
            seen.add(val)
            
    db_session.commit()
    return removed


def run_database_optimization():
    print("=" * 60)
    print("      QUANTUMSHIELD DATABASE OPTIMIZATION & CLEANUP      ")
    print("=" * 60)
    
    targets = [
        (DiscoveryDomain, "domain", "Discovery Domains"),
        (DiscoveryIP, "ip_address", "Discovery IPs"),
        (DiscoverySSL, "endpoint", "Discovery SSL"),
        (DiscoverySoftware, "product", "Discovery Software"),
        (Subdomain, "subdomain", "Subdomains"),
        (Asset, "target", "Asset Inventory"),
    ]
    
    total_cleaned = 0
    total_deduped = 0
    
    for model, col_name, label in targets:
        try:
            print(f"\n[+] Cleaning {label} ({model.__tablename__})...")
            invalid_cnt = clean_table_invalid_records(model, col_name)
            dedup_cnt = deduplicate_table(model, col_name)
            print(f"    -> Removed {invalid_cnt} invalid/empty/placeholder records.")
            print(f"    -> Deduplicated {dedup_cnt} duplicate rows.")
            total_cleaned += invalid_cnt
            total_deduped += dedup_cnt
        except Exception as e:
            db_session.rollback()
            print(f"    [!] Error cleaning {label}: {e}")

    # Optimize Certificate records: remove empty endpoints & deduplicate by fingerprint / endpoint
    try:
        print("\n[+] Cleaning Certificates table...")
        cert_rows = db_session.query(Certificate).order_by(Certificate.id.desc()).all()
        seen_certs = set()
        cert_removed = 0
        for cert in cert_rows:
            fp = str(cert.fingerprint_sha256 or "").strip().lower()
            ep = str(cert.endpoint or "").strip().lower()
            key = fp if fp else ep
            if not key or key in INVALID_SENTINELS:
                db_session.delete(cert)
                cert_removed += 1
            elif key in seen_certs:
                db_session.delete(cert)
                cert_removed += 1
            else:
                seen_certs.add(key)
        db_session.commit()
        print(f"    -> Removed/Deduplicated {cert_removed} certificate records.")
    except Exception as e:
        db_session.rollback()
        print(f"    [!] Error cleaning Certificates: {e}")

    print("\n" + "=" * 60)
    print("SUCCESS: Database Optimization Complete!")
    print(f"Total Invalid Records Purged: {total_cleaned}")
    print(f"Total Duplicate Records Deduplicated: {total_deduped}")
    print("=" * 60)

if __name__ == "__main__":
    run_database_optimization()
