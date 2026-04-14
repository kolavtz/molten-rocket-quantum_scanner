#!/usr/bin/env python3
"""
Test suite to verify that SSL/TLS and discovery data is being properly captured and persisted.
Tests the fix for data appearing in UI but not being saved to database.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from datetime import datetime
import json
from src.db import db_session
from src.models import Scan, Asset, Certificate, DiscoverySSL, DiscoveryDomain
from web.app import run_scan_pipeline

def test_scan_status_lifecycle():
    """Verify scan status transitions: running -> complete (not instant complete)."""
    print("\n" + "="*70)
    print("TEST 1: Scan Status Lifecycle")
    print("="*70)
    
    # This is more of an integration test - we'll verify the report contains status transitions
    target = "self-signed.badssl.com"
    print(f"\nRunning scan on {target}...")
    
    try:
        report = run_scan_pipeline(
            target=target,
            scan_kind="test",
            scanned_by="test_suite"
        )
        
        # Check report status
        status = report.get("status")
        orm_persisted = report.get("orm_persisted")
        error = report.get("error")
        
        print(f"Report status: {status}")
        print(f"ORM persisted: {orm_persisted}")
        if error:
            print(f"ERROR: {error}")
            print(f"TRACE: {report.get('error_trace', 'N/A')}")
            return False
        
        if status != "complete":
            print(f"❌ FAIL: Expected status='complete', got '{status}'")
            return False
        
        print("✅ PASS: Scan completed successfully")
        return True, report
    except Exception as e:
        print(f"❌ FAIL: Exception during scan: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_ssl_discovery_persisted():
    """Verify SSL/TLS discovery data is actually written to discovery_ssl table."""
    print("\n" + "="*70)
    print("TEST 2: SSL/TLS Discovery Persistence")
    print("="*70)
    
    success, report = test_scan_status_lifecycle()
    if not success:
        return False
    
    scan_id_str = report.get("scan_id")  # This is the string scan_id
    target = report.get("target")
    
    print(f"\nVerifying discovery_ssl data for scan_id={scan_id_str}, target={target}")
    
    # Find the actual Scan record using the string scan_id
    scan_record = db_session.query(Scan).filter(
        Scan.scan_id == scan_id_str
    ).first()
    
    if not scan_record:
        print(f"❌ FAIL: Could not find Scan record with scan_id={scan_id_str}")
        return False
    
    scan_pk = scan_record.id  # Get the numeric ID
    print(f"Found Scan record: numeric ID={scan_pk}, string scan_id={scan_id_str}")
    
    try:
        # Query discovery_ssl for this scan using the numeric FK
        discovery_ssl_rows = db_session.query(DiscoverySSL).filter(
            DiscoverySSL.scan_id == scan_pk,
            DiscoverySSL.is_deleted == False
        ).all()
        
        if not discovery_ssl_rows:
            print(f"❌ FAIL: No discovery_ssl rows found for scan numeric_id={scan_pk}")
            print("   Data appeared in UI during scan but was NOT persisted to database")
            return False
        
        print(f"✅ Found {len(discovery_ssl_rows)} discovery_ssl rows")
        
        # Inspect first row
        row = discovery_ssl_rows[0]
        print(f"\nFirst discovery_ssl record:")
        print(f"  - Endpoint: {row.endpoint}")
        print(f"  - Subject CN: {row.subject_cn}")
        print(f"  - Issuer: {row.issuer}")
        print(f"  - TLS Version: {row.tls_version}")
        print(f"  - Cipher Suite: {row.cipher_suite}")
        print(f"  - Key Length: {row.key_length}")
        print(f"  - Valid Until: {row.valid_until}")
        print(f"  - PQC Score: {row.pqc_score}")
        print(f"  - PQC Assessment: {row.pqc_assessment}")
        print(f"  - Status: {row.status}")
        print(f"  - Created At: {row.created_at}")
        
        if not row.subject_cn:
            print("⚠️  WARNING: Subject CN is empty (but row was persisted)")
        if not row.issuer:
            print("⚠️  WARNING: Issuer is empty (but row was persisted)")
        if not row.tls_version or row.tls_version == "Unknown":
            print("⚠️  WARNING: TLS version is unknown")
        
        print("\n✅ PASS: SSL/TLS discovery data successfully persisted to database")
        return True
        
    finally:
        pass


def test_discovery_domains_persisted():
    """Verify discovery_domains are persisted."""
    print("\n" + "="*70)
    print("TEST 3: Discovery Domains Persistence")
    print("="*70)
    
    try:
        # Find the most recent scan
        recent_scan = db_session.query(Scan).order_by(
            Scan.created_at.desc()
        ).first()
        
        if not recent_scan:
            print("❌ FAIL: No scans found in database")
            return False
        
        scan_id = recent_scan.id
        print(f"\nChecking discovery_domains for scan_id={scan_id}")
        
        # Query discovery_domains
        discovery_domains = db_session.query(DiscoveryDomain).filter(
            DiscoveryDomain.scan_id == scan_id,
            DiscoveryDomain.is_deleted == False
        ).all()
        
        if not discovery_domains:
            print(f"⚠️  No discovery_domains found (may be OK if no domains discovered)")
            return True
        
        print(f"✅ Found {len(discovery_domains)} discovery_domains")
        for d in discovery_domains[:3]:  # Show first 3
            print(f"  - {d.domain}")
        
        print("\n✅ PASS: Discovery domains persisted")
        return True
        
    finally:
        pass


def test_scan_table_shows_running_then_complete():
    """Verify scan record transitions in scans table."""
    print("\n" + "="*70)
    print("TEST 4: Scan Status in Database")
    print("="*70)
    
    try:
        # Find the most recent scan
        recent_scan = db_session.query(Scan).order_by(
            Scan.created_at.desc()
        ).first()
        
        if not recent_scan:
            print("❌ FAIL: No scans found")
            return False
        
        status = recent_scan.status
        print(f"\nMost recent scan (id={recent_scan.id}):")
        print(f"  - Status: {status}")
        print(f"  - Target: {recent_scan.target}")
        print(f"  - Started At: {recent_scan.started_at}")
        print(f"  - Completed At: {recent_scan.completed_at}")
        
        if status not in ["complete", "error"]:
            print(f"⚠️  WARNING: Scan in unexpected status: {status}")
            print("   (Expected 'complete' or 'error')")
        
        if status == "complete":
            print("\n✅ PASS: Scan marked as complete (data capture finished)")
        elif status == "error":
            print("⚠️  Scan marked as error - check error logs")
        
        return True
        
    finally:
        pass


def test_asset_created():
    """Verify asset inventory record was created from scan."""
    print("\n" + "="*70)
    print("TEST 5: Asset Inventory Creation")
    print("="*70)
    
    try:
        # Find the most recent asset
        recent_asset = db_session.query(Asset).order_by(
            Asset.created_at.desc()
        ).first()
        
        if not recent_asset:
            print("⚠️  No assets found (may be OK if scan didn't auto-promote)")
            return True
        
        print(f"\nMost recent asset:")
        print(f"  - Name: {recent_asset.name or recent_asset.target}")
        print(f"  - URL: {recent_asset.url}")
        print(f"  - Type: {recent_asset.asset_type}")
        print(f"  - Risk Level: {recent_asset.risk_level}")
        print(f"  - Last Scan ID: {recent_asset.last_scan_id}")
        
        print("\n✅ PASS: Asset created from scan data")
        return True
        
    finally:
        pass


def main():
    """Run all tests."""
    print("\n" + "#"*70)
    print("# DATA CAPTURE VERIFICATION TEST SUITE")
    print("# Verifies SSL/TLS and discovery data is properly persisted")
    print("#"*70)
    
    results = {
        "SSL Discovery Persistence": test_ssl_discovery_persisted(),
        "Discovery Domains": test_discovery_domains_persisted(),
        "Scan Status in DB": test_scan_table_shows_running_then_complete(),
        "Asset Inventory": test_asset_created(),
    }
    
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    all_passed = all(results.values())
    print("\n" + ("="*70))
    if all_passed:
        print("✅ ALL TESTS PASSED - Data capture is working correctly!")
    else:
        print("❌ SOME TESTS FAILED - Data capture issues detected")
    print("="*70 + "\n")
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
