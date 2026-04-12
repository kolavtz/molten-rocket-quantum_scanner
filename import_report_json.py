import os
import sys
import json
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import select

# Add current directory to path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from src.db import engine
from src.models import Scan, Asset, Certificate, Base

def import_report(file_path):
    print(f"Importing report data from {file_path}...")
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    with Session(engine) as session:
        # 1. Asset
        target = data.get('target', 'unknown')
        asset = session.execute(select(Asset).where(Asset.target == target)).scalars().first()
        if not asset:
            print(f"Creating asset for {target}...")
            asset = Asset(target=target, asset_type="website")
            session.add(asset)
            session.flush()

        # 2. Scan
        scan_id = data.get('scan_id', 'imported-' + datetime.now().strftime('%Y%H%M%S'))
        scan = session.execute(select(Scan).where(Scan.scan_id == scan_id)).scalars().first()
        if not scan:
            print(f"Creating scan {scan_id}...")
            scan = Scan(
                scan_id=scan_id,
                target=target,
                status=data.get('status', 'complete'),
                scan_kind=data.get('scan_kind', 'imported'),
                scanned_at=datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00')) if 'timestamp' in data else datetime.now(),
                report_json=json.dumps(data)
            )
            session.add(scan)
            session.flush()

        # 3. Certificates / TLS Results
        for tls in data.get('tls_results', []):
            cert = Certificate(
                asset_id=asset.id,
                scan_id=scan.id,
                endpoint=tls.get('host'),
                port=tls.get('port'),
                issuer_cn=tls.get('issuer', {}).get('commonName'),
                subject_cn=tls.get('subject', {}).get('commonName'),
                serial=tls.get('serial_number'),
                fingerprint_sha256=tls.get('cert_sha256'),
                tls_version=tls.get('tls_version'),
                key_length=tls.get('key_length'),
                key_algorithm=tls.get('key_type'),
                cipher_suite=tls.get('cipher_suite'),
                signature_algorithm=tls.get('signature_algorithm'),
                valid_from=datetime.fromisoformat(tls.get('valid_from')) if tls.get('valid_from') else None,
                valid_until=datetime.fromisoformat(tls.get('valid_to')) if tls.get('valid_to') else None,
                is_current=True
            )
            session.add(cert)
        
        session.commit()
        print("Report JSON import complete.")

if __name__ == "__main__":
    if os.path.exists('report.json'):
        import_report('report.json')
    else:
        print("report.json not found!")
