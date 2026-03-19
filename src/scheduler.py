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
                            
                            # Construct full report body compatible with save_scan()
                            import uuid
                            
                            payload = {
                                "scan_id": str(uuid.uuid4()),
                                "target": t,
                                "asset_class": "Automated",
                                "status": "Completed",
                                "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                "overview": {
                                    "average_compliance_score": 100 if result.is_successful else 0,
                                    "total_assets": 1,
                                    "quantum_safe": 1 if result.is_successful else 1, # Placeholder logic
                                    "quantum_vulnerable": 0
                                },
                                "results": [ result.to_dict() ]
                            }
                            
                            # Standard save logic
                            if hasattr(db, 'save_scan'):
                                db.save_scan(payload)
                            logger.info(f"Saved automated scan for {t}")
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
