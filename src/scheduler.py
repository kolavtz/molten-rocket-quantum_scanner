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


def _report_dispatch_window_key(schedule: dict, now: datetime.datetime) -> str:
    """Build a stable key so a schedule only dispatches once per window."""
    schedule_date = str(schedule.get("schedule_date") or "").strip()
    schedule_time = str(schedule.get("schedule_time") or "").strip()
    frequency = str(schedule.get("frequency") or "").strip().lower()

    if schedule_date or schedule_time:
        return f"{schedule.get('id')}::{schedule_date}::{schedule_time}"
    if frequency == "daily":
        return f"{schedule.get('id')}::{now:%Y-%m-%d}"
    if frequency == "weekly":
        return f"{schedule.get('id')}::{now:%G-W%V}"
    if frequency == "monthly":
        return f"{schedule.get('id')}::{now:%Y-%m}"
    if frequency == "quarterly":
        quarter = ((now.month - 1) // 3) + 1
        return f"{schedule.get('id')}::{now.year}-Q{quarter}"
    return f"{schedule.get('id')}::{now:%Y-%m-%d}"


def run_report_dispatcher_once() -> None:
    """Dispatch due report schedules once.

    This is cron-friendly and safe to call repeatedly. It uses the audit log
    as a dedupe source so a schedule only sends once per logical window.
    """
    try:
        from web.app import _make_pdf_report, _send_report_email
    except Exception as exc:
        logger.error("Report dispatcher unavailable: %s", exc)
        return

    try:
        now = datetime.datetime.now(datetime.timezone.utc)
        schedules = db.list_report_schedules(limit=1000, include_password=True)
        audit_logs = db.list_audit_logs(limit=2000)
    except Exception as exc:
        logger.error("Report dispatcher load failed: %s", exc)
        return

    sent = 0
    for schedule in schedules:
        if not bool(schedule.get("enabled", True)):
            continue

        window_key = _report_dispatch_window_key(schedule, now)
        already_sent = any(
            log.get("event_type") == "scheduled_report_sent"
            and str((log.get("details") or {}).get("window_key") or "") == window_key
            and str((log.get("details") or {}).get("schedule_id") or "") == str(schedule.get("id"))
            for log in audit_logs
        )
        if already_sent:
            continue

        report_type = str(schedule.get("report_type") or "Executive Reporting")
        sections = schedule.get("sections") if isinstance(schedule.get("sections"), list) else []
        username = str(schedule.get("created_by") or "scheduler")
        pdf_password = str(schedule.get("pdf_password") or "").strip() or None
        pdf_bytes = _make_pdf_report(report_type, username, sections, pdf_password=pdf_password)
        safe_type = "".join(ch for ch in report_type if ch.isalnum() or ch in ("-", "_"))[:40] or "Report"
        filename = f"QuantumShield_{safe_type}_{now.strftime('%Y%m%d_%H%M%S')}.pdf"

        ok, dispatch_status = _send_report_email(
            str(schedule.get("email_list") or ""),
            report_type,
            filename,
            pdf_bytes,
        )

        db.append_audit_log(
            event_category="report",
            event_type="scheduled_report_sent",
            status="success" if ok else "failed",
            actor_username="scheduler",
            details={
                "schedule_id": schedule.get("id"),
                "window_key": window_key,
                "report_type": report_type,
                "dispatch_status": dispatch_status,
                "email_list": schedule.get("email_list"),
                "password_protected": bool(pdf_password),
            },
        )
        if ok:
            sent += 1

    if sent:
        logger.info("Dispatched %s report schedule(s).", sent)

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
                
                status = str(result.get("status") or "").lower()
                if status == "complete":
                    summary = result.get("summary", {})
                    logger.info(
                        "Automated inventory scan complete: %s successful, %s failed",
                        summary.get("successful"),
                        summary.get("failed"),
                    )
                elif status == "in_progress":
                    logger.info(
                        "Automated inventory scan skipped: another scan is already in progress"
                    )
                else:
                    logger.error(
                        "Automated inventory scan failed: %s",
                        result.get("error") or result.get("message") or "Unknown error",
                    )
                    
            except Exception as e:
                logger.error(f"Scheduler sweep failed: {e}")
                import traceback
                traceback.print_exc()

            try:
                run_report_dispatcher_once()
            except Exception as e:
                logger.error("Scheduled report dispatch failed: %s", e)
                
        # Wait for the interval in hours
        logger.info(f"Scheduler sleeping for {AUTOMATED_SCAN_INTERVAL_HOURS} hours.")
        time.sleep(AUTOMATED_SCAN_INTERVAL_HOURS * 3600)

def start_scheduler():
    """Dispatch the scheduler thread."""
    t = threading.Thread(target=run_scheduler, name="AutoScannerThread", daemon=True)
    t.start()
    logger.info("Scheduler thread dispatched successfully.")
