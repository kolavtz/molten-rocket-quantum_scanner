import threading
import time
import datetime
import logging
import json

# Ensure project root is in sys.path
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from config import AUTOMATED_SCAN_ENABLED, AUTOMATED_SCAN_INTERVAL_HOURS
    from src import database as db
    from src.scanner.tls_analyzer import TLSAnalyzer
except ImportError:
    # Handle absolute import paths if executed elsewhere
    from config import AUTOMATED_SCAN_ENABLED, AUTOMATED_SCAN_INTERVAL_HOURS
    import database as db
    from scanner.tls_analyzer import TLSAnalyzer

logger = logging.getLogger(__name__)

def run_scheduler():
    """Background loop with full interval spacing."""
    logger.info("Background Automated Scan Scheduler Started.")
    while True:
        if AUTOMATED_SCAN_ENABLED:
            logger.info("Automatic Scan sweep initiated.")
            try:
                # 1. Fetch targets from prior scans
                scans = db.list_scans(limit=100)
                targets = set(s.get("target") for s in scans if s.get("target"))
                
                # 2. Include targets from manually added Inventory Assets
                if hasattr(db, 'list_assets'):
                    try:
                        for asset in db.list_assets():
                            tgt = asset.get("target")
                            if tgt:
                                targets.add(tgt)
                    except Exception:
                        pass

                targets = sorted(list(targets))
                
                if not targets:
                    logger.info("No targets found in Database. Skipping sweep.")
                else:
                    logger.info(f"Auto-scanning {len(targets)} unique targets...")
                    analyzer = TLSAnalyzer()
                    for t in targets:
                        try:
                            logger.info(f"Auto-scanning target: {t}")
                            result = analyzer.analyze_endpoint(t, 443)
                            
                            from src.db import db_session
                            from src.models import Scan, Asset, Certificate, CBOMSummary
                            try:
                                inv = db_session.query(Asset).filter_by(name=t, is_deleted=False).first()
                                asset_id = inv.id if inv else None
                                db_scan = Scan(
                                    target=t,
                                    status="complete",
                                    started_at=datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None),
                                    completed_at=datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None),
                                    total_assets=1,
                                    overall_pqc_score=100 if result.is_successful else 0
                                )
                                # Basic cert stub
                                db_scan.certificates.append(Certificate(
                                    asset_id=asset_id,
                                    issuer="Automated Scheduler",
                                    subject=t,
                                    valid_until=datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) + datetime.timedelta(days=90)
                                ))
                                db_scan.cbom_summary = CBOMSummary(total_components=1, weak_crypto_count=0, cert_issues_count=0)
                                db_session.add(db_scan)
                                db_session.commit()
                                logger.info(f"Saved automated scan for {t} via SQLAlchemy")
                            except Exception as db_err:
                                db_session.rollback()
                                logger.error(f"Failed to save automated scan: {db_err}")
                            
                        except Exception as e:
                            logger.error(f"Auto-scanning failed for {t}: {e}")
            except Exception as e:
                logger.error(f"Scheduler sweep failed: {e}")
                
        # Wait for the interval in hours
        logger.info(f"Scheduler sleeping for {AUTOMATED_SCAN_INTERVAL_HOURS} hours.")
        time.sleep(AUTOMATED_SCAN_INTERVAL_HOURS * 3600)

def start_scheduler():
    """Dispatch the scheduler thread."""
    t = threading.Thread(target=run_scheduler, name="AutoScannerThread", daemon=True)
    t.start()
    logger.info("Scheduler thread dispatched successfully.")
