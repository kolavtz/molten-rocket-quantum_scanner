"""Conservative backfill for certificates.certificate_details from scans.report_json.

This script will iterate certificate rows that lack `certificate_details` and attempt
to find matching TLS rows in the associated Scan.report_json. Matching prefers:
  1) fingerprint (SHA-256) equality
  2) serial number equality
  3) endpoint (host:port) equality

Only conservative matches will be applied. The script is idempotent and safe to run
multiple times. It writes certificate_details as a JSON-serialized string.

Usage: python scripts/backfill_certificate_details.py
"""
import os
import sys
import json
import logging
import re

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.db import db_session
from src.models import Certificate, Scan
from sqlalchemy import or_

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _normalize_fingerprint(value):
    if value is None:
        return None
    txt = str(value or '').strip()
    if not txt:
        return None
    txt = re.sub(r'[^0-9a-fA-F]', '', txt)
    if not txt:
        return None
    return txt.lower()


def _build_minimal_details(row: dict) -> dict:
    if not isinstance(row, dict):
        return {}
    details = {
        "certificate_version": "",
        "serial_number": str(row.get("serial_number") or row.get("serial") or ""),
        "certificate_signature_algorithm": str(row.get("signature_algorithm") or ""),
        "certificate_signature": "",
        "issuer": str(row.get("issuer") or row.get("issuer_cn") or ""),
        "validity": {
            "not_before": str(row.get("valid_from") or ""),
            "not_after": str(row.get("valid_to") or ""),
        },
        "subject": str(row.get("subject") or row.get("subject_cn") or ""),
        "subject_public_key_info": {
            "subject_public_key_algorithm": str(row.get("key_type") or ""),
            "subject_public_key_bits": int(row.get("key_length") or row.get("key_size") or 0),
            "subject_public_key": str(row.get("public_key_pem") or ""),
        },
        "extensions": [],
        "certificate_key_usage": [],
        "extended_key_usage": [],
        "certificate_basic_constraints": {},
        "certificate_subject_key_id": "",
        "certificate_authority_key_id": "",
        "authority_information_access": [],
        "certificate_subject_alternative_name": [str(x) for x in (row.get("san_domains") or []) if str(x or '').strip()],
        "certificate_policies": [],
        "crl_distribution_points": [],
        "signed_certificate_timestamp_list": [],
    }
    return details


def run_backfill(dry_run: bool = False) -> dict:
    updated = 0
    scanned = 0
    skipped = 0

    certs = db_session.query(Certificate).filter(or_(Certificate.certificate_details == None, Certificate.certificate_details == "")).all()
    logger.info("Found %d certificates eligible for backfill", len(certs))

    for cert in certs:
        scanned += 1
        try:
            if not getattr(cert, 'scan_id', None):
                skipped += 1
                continue

            scan = db_session.query(Scan).filter(Scan.id == int(cert.scan_id)).first()
            if not scan or not getattr(scan, 'report_json', None):
                skipped += 1
                continue

            report = scan.report_json if isinstance(scan.report_json, dict) else json.loads(scan.report_json)
            tls_rows = report.get('tls_results') if isinstance(report.get('tls_results'), list) else []

            cert_fp = _normalize_fingerprint(getattr(cert, 'fingerprint_sha256', None))
            cert_serial = str(getattr(cert, 'serial', '') or '').strip() or None
            cert_endpoint = str(getattr(cert, 'endpoint', '') or '').strip().lower() or None

            matched = False
            for row in tls_rows:
                if not isinstance(row, dict):
                    continue
                row_fp = _normalize_fingerprint(row.get('cert_sha256') or row.get('fingerprint'))
                row_serial = str(row.get('serial_number') or row.get('serial') or '').strip() or None
                host = str(row.get('host') or '').strip()
                port = int(row.get('port') or 0) if str(row.get('port') or '').strip() else None
                row_endpoint = f"{host}:{port}" if host and port else (host or None)

                # Match by fingerprint
                if cert_fp and row_fp and cert_fp == row_fp:
                    details = row.get('certificate_details') if isinstance(row.get('certificate_details'), dict) else _build_minimal_details(row)
                # Match by serial
                elif cert_serial and row_serial and cert_serial.lower() == row_serial.lower():
                    details = row.get('certificate_details') if isinstance(row.get('certificate_details'), dict) else _build_minimal_details(row)
                # Match by endpoint
                elif cert_endpoint and row_endpoint and cert_endpoint == str(row_endpoint).strip().lower():
                    details = row.get('certificate_details') if isinstance(row.get('certificate_details'), dict) else _build_minimal_details(row)
                else:
                    continue

                # Verify details are non-trivial
                if not isinstance(details, dict):
                    details = _build_minimal_details(row)

                useful = any(
                    str(details.get(k) or '').strip()
                    for k in ('serial_number', 'subject', 'subject_public_key_info')
                )
                if not useful:
                    # conservative: skip empty detail payloads
                    continue

                if dry_run:
                    logger.info("Would backfill cert id=%s from scan=%s", cert.id, scan.id)
                else:
                    cert.certificate_details = json.dumps(details, default=str)
                    if not getattr(cert, 'fingerprint_sha256', None) and row_fp:
                        cert.fingerprint_sha256 = row_fp
                    db_session.add(cert)
                    db_session.commit()
                    updated += 1

                matched = True
                break

            if not matched:
                skipped += 1

        except Exception as exc:
            logger.exception("Failed to backfill certificate id=%s: %s", getattr(cert, 'id', 'unknown'), exc)
            try:
                db_session.rollback()
            except Exception:
                pass

    return {"scanned": scanned, "updated": updated, "skipped": skipped}


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run', action='store_true', help='Do not write changes; only show potential updates')
    args = parser.parse_args()

    result = run_backfill(dry_run=bool(args.dry_run))
    logger.info("Backfill complete: %s", result)
