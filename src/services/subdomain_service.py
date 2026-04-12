"""
Subdomain Discovery Service
Manages the identification, tracking, and promotion of subdomains discovered during scans.
"""
import logging
from datetime import datetime, timezone
from sqlalchemy import and_, func

from src.db import db_session
from src.models import Asset, Subdomain, Certificate, Scan

logger = logging.getLogger(__name__)

class SubdomainService:
    @staticmethod
    def get_subdomains_for_asset(parent_asset_id: int, include_inventoried: bool = False):
        """Fetch discovered subdomains for a specific parent asset."""
        query = db_session.query(Subdomain).filter(
            Subdomain.parent_asset_id == parent_asset_id,
            Subdomain.is_deleted == False
        )
        if not include_inventoried:
            query = query.filter(Subdomain.is_inventoried == False)
        
        return query.order_by(Subdomain.subdomain.asc()).all()

    @staticmethod
    def sync_from_certificate(asset_id: int, scan_id: int):
        """
        Extract subdomains from the certificate associated with a scan 
        and populate the subdomains table.
        """
        try:
            asset = db_session.query(Asset).filter(Asset.id == asset_id).first()
            if not asset:
                return 0

            parent_domain = str(asset.target or "").lower().strip()
            if not parent_domain:
                return 0

            # Get the certificate captured in this scan
            cert = db_session.query(Certificate).filter(
                Certificate.asset_id == asset_id,
                Certificate.scan_id == scan_id
            ).first()

            if not cert:
                return 0

            candidates = set()
            # 1. Subject CN
            if cert.subject_cn:
                candidates.add(cert.subject_cn.lower().strip())
            
            # 2. SAN Domains
            if cert.san_domains:
                for d in cert.san_domains.split(','):
                    d = d.strip().lower()
                    if d:
                        candidates.add(d)

            count = 0
            for domain in candidates:
                # Basic subdomain check: ends with .parent_domain and is not the parent domain itself
                if domain.endswith(f".{parent_domain}") and domain != parent_domain:
                    # Check if already exists in subdomains
                    existing = db_session.query(Subdomain).filter(
                        Subdomain.parent_asset_id == asset_id,
                        Subdomain.subdomain == domain
                    ).first()

                    if not existing:
                        new_sub = Subdomain(
                            parent_asset_id=asset_id,
                            subdomain=domain,
                            record_type='A', # Default assumption
                            is_inventoried=False,
                            discovered_at=datetime.now(timezone.utc).replace(tzinfo=None)
                        )
                        db_session.add(new_sub)
                        count += 1
            
            if count > 0:
                db_session.commit()
                logger.info("Discovered %x new subdomains for asset %s", count, asset_id)
            
            return count

        except Exception as e:
            db_session.rollback()
            logger.exception("Failed to sync subdomains from certificate for asset %s", asset_id)
            return 0

    @staticmethod
    def promote_to_inventory(subdomain_id: int, owner: str = "System"):
        """
        Promote a discovered subdomain to a full Asset.
        """
        try:
            sub = db_session.query(Subdomain).filter(Subdomain.id == subdomain_id).first()
            if not sub or sub.is_inventoried:
                return None

            # Check if an asset with this target already exists
            existing_asset = db_session.query(Asset).filter(
                func.lower(Asset.target) == sub.subdomain.lower()
            ).first()

            if existing_asset:
                # Just mark as inventoried if it matches
                sub.is_inventoried = True
                db_session.commit()
                return existing_asset

            # Create new asset
            new_asset = Asset(
                target=sub.subdomain,
                asset_type='Subdomain',
                owner=owner,
                risk_level='Medium', # Default
                created_at=datetime.now(timezone.utc).replace(tzinfo=None)
            )
            db_session.add(new_asset)
            db_session.flush() # Get ID

            sub.is_inventoried = True
            db_session.commit()
            
            logger.info("Promoted subdomain %s to asset inventory (ID: %s)", sub.subdomain, new_asset.id)
            return new_asset

        except Exception as e:
            db_session.rollback()
            logger.exception("Failed to promote subdomain %s", subdomain_id)
            return None
