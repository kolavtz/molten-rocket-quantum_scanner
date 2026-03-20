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
            logger.info("=== Automatic Inventory Scan Sweep Initiated ===")
            try:
                # Use the new comprehensive inventory scan service
                from src.services.inventory_scan_service import InventoryScanService
                
                scan_service = InventoryScanService()
                result = scan_service.scan_all_assets(background=False)
                
                if result.get("status") == "complete":
                    summary = result.get("summary", {})
                    logger.info(f"✓ Automated inventory scan complete: {summary.get('successful')} successful, {summary.get('failed')} failed")
                else:
                    logger.error(f"✗ Automated inventory scan failed: {result.get('error', 'Unknown error')}")
                    
            except Exception as e:
                logger.error(f"Scheduler sweep failed: {e}")
                import traceback
                traceback.print_exc()
                
        # Wait for the interval in hours
        logger.info(f"Scheduler sleeping for {AUTOMATED_SCAN_INTERVAL_HOURS} hours.")
        time.sleep(AUTOMATED_SCAN_INTERVAL_HOURS * 3600)

def start_scheduler():
    """Dispatch the scheduler thread."""
    t = threading.Thread(target=run_scheduler, name="AutoScannerThread", daemon=True)
    t.start()
    logger.info("Scheduler thread dispatched successfully.")

