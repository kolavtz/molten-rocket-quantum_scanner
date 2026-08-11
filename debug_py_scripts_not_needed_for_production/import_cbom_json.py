import os
import sys
import json
from sqlalchemy.orm import Session
from sqlalchemy import select

# Add current directory to path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from src.db import engine
from src.models import CBOMEntry, Scan, Asset

def import_json(file_path):
    print(f"Importing data from {file_path}...")
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    with Session(engine) as session:
        # We need a scan and an asset to associate with these entries.
        # Let's find or create a dummy scan/asset if none exist, 
        # or use the first available one from the database (since we just imported the dump).
        scan = session.execute(select(Scan)).scalars().first()
        asset = session.execute(select(Asset)).scalars().first()
        
        if not scan:
            print("No scan found in database! Creating a dummy scan...")
            scan = Scan(scan_id="cbom-import-placeholder", target="example.com", status="complete", report_json="{}")
            session.add(scan)
            session.flush()
        
        if not asset:
            print("No asset found in database! Creating a dummy asset...")
            asset = Asset(target="example.com", asset_type="website")
            session.add(asset)
            session.flush()

        for comp in data.get('components', []):
            name = comp.get('name')
            version = comp.get('version')
            desc = comp.get('description')
            properties = {p.get('name'): p.get('value') for p in comp.get('properties', [])}
            
            # Map properties to CBOMEntry fields
            entry = CBOMEntry(
                scan_id=scan.id,
                asset_id=asset.id,
                algorithm_name=name,
                category=comp.get('type', 'cryptographic-asset'),
                element_name=name,
                protocol_version=version,
                # Additional fields from properties if they match our schema
                nist_status=properties.get('quantum-safe:pqc_status', 'unknown'),
                # Add more mapping as needed...
            )
            session.add(entry)
        
        session.commit()
        print("CBOM JSON import complete.")

if __name__ == "__main__":
    if os.path.exists('example_cbom.json'):
        import_json('example_cbom.json')
    else:
        print("example_cbom.json not found!")
