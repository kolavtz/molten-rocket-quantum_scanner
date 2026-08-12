import logging
from src.db import db_session
from src.models import Asset
from src.services.subdomain_service import SubdomainService

logging.basicConfig(level=logging.INFO)

TARGET_DOMAIN = "manipurrural.bank.in"  # Test domain

def test_active_discovery():
    print(f"=== Testing Active Subdomain Discovery: {TARGET_DOMAIN} ===")
    
    # 1. Run direct discovery
    subdomains = SubdomainService.run_domain_discovery(TARGET_DOMAIN)
    print(f"\n[Subfinder Scan] Discovered {len(subdomains)} unique subdomains:")
    for sub in subdomains:
        print(f" - {sub}")

    # 2. Run nested discovery & DB save
    print(f"\n=== Testing Nested Subdomain Discovery & Persistence ===")
    nested_results = SubdomainService.discover_nested_subdomains(
        target_domain=TARGET_DOMAIN,
        max_depth=2
    )
    print(f"[Nested Sync] Processed {len(nested_results)} subdomains:")
    for item in nested_results:
        print(f" - {item.get('subdomain')} (IP: {item.get('ip')})")

def check_db():
    print(f"\n=== Checking Database Records ===")
    asset = db_session.query(Asset).filter(Asset.target == TARGET_DOMAIN).first()
    if not asset:
        print(f"Notice: No parent Asset record found in DB for '{TARGET_DOMAIN}'. Creating temporary Asset to test DB insertion...")
        asset = Asset(target=TARGET_DOMAIN, asset_type='Domain', risk_level='Low')
        db_session.add(asset)
        db_session.commit()

    db_subs = SubdomainService.get_subdomains_for_asset(parent_asset_id=asset.id, include_inventoried=True)
    print(f"DB currently has {len(db_subs)} saved subdomains for Asset ID {asset.id}:")
    for s in db_subs:
        print(f" - ID: {s.id} | Domain: {s.subdomain} | Inventoried: {s.is_inventoried}")

if __name__ == "__main__":
    try:
        test_active_discovery()
        check_db()
    finally:
        db_session.close()