"""SSL Capture Worker

Run as a standalone worker to probe an asset's TLS/SSL surface, parse
certificate and TLS profile information, and persist results atomically
into the application's MySQL database.

Usage:
    python -m src.scanner.ssl_worker --asset-id 1 --host pnb.bank.in --port 443 --correlation-id <uuid>

This worker uses the existing TLSAnalyzer in the repo for probing.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import socket
import ssl
import sys
import uuid
from typing import Optional

from dotenv import load_dotenv
import os
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '..', '.env'))

import mysql.connector

# Import TLSAnalyzer from local module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from scanner.tls_analyzer import TLSAnalyzer
from scanner.dedup_utils import compute_dedup_values


def normalize_hostname(raw: str) -> str:
    host = raw.strip().lower()
    if host.startswith('http://') or host.startswith('https://'):
        host = host.split('://', 1)[1]
    # strip path
    host = host.split('/', 1)[0]
    # strip default port
    if host.endswith(':443'):
        host = host[:-4]
    return host


def is_private_ip(ip: str) -> bool:
    # Basic RFC1918 + loopback checks
    if ip.startswith('10.') or ip.startswith('127.') or ip.startswith('192.168.'):
        return True
    if ip.startswith('172.'):
        # 172.16.0.0 – 172.31.255.255
        try:
            second = int(ip.split('.')[1])
            return 16 <= second <= 31
        except Exception:
            return False
    if ':' in ip:  # very basic IPv6 private checks
        if ip.startswith('fc') or ip.startswith('fd') or ip == '::1' or ip.startswith('fe80'):
            return True
    return False


def validate_and_resolve(host: str, timeout: float = 5.0):
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise RuntimeError(f"DNS resolution failed: {e}")
    addrs = []
    for info in infos:
        addr = info[4][0]
        addrs.append(addr)
        if is_private_ip(addr):
            raise RuntimeError(f"Resolved address {addr} is in a private range (SSRF protection)")
    return list(dict.fromkeys(addrs))


def sha256_hex(data: bytes) -> str:
    # Use lowercase hex to match application dedup hash convention
    return hashlib.sha256(data).hexdigest()


class SSLWorker:
    def __init__(self, db_cfg: dict):
        self.db_cfg = db_cfg
        self.conn = mysql.connector.connect(**db_cfg)
        # ensure UTF-8 results
        try:
            self.conn.set_charset_collation('utf8mb4', 'utf8mb4_unicode_ci')
        except Exception:
            pass

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass

    def create_scan_row(self, asset_id: int, hostname: str, correlation_id: Optional[str], scan_kind: str = 'manual') -> int:
        cur = self.conn.cursor()
        scan_uid = str(uuid.uuid4())
        now = datetime.datetime.utcnow()
        insert_sql = (
            "INSERT INTO scans (scan_uid, scan_id, requested_target, normalized_target, status, scan_kind, initiated_by, started_at, created_at, updated_at, correlation_id) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
        )
        params = (
            scan_uid,
            scan_uid,
            hostname,
            hostname,
            'running',
            scan_kind,
            'ssl_worker',
            now,
            now,
            now,
            correlation_id,
        )
        cur.execute(insert_sql, params)
        scan_id = cur.lastrowid
        cur.close()
        return scan_id

    def persist_results(self, asset_id: int, scan_id: int, correlation_id: Optional[str], result) -> None:
        cur = self.conn.cursor()
        now = datetime.datetime.utcnow()

        # Prepare report JSON
        report = result.to_dict()
        report_json = json.dumps(report, default=str)

        # Start transaction
        self.conn.start_transaction()
        try:
            # Update scans.report_json and completed_at later (after success)
            cur.execute("UPDATE scans SET report_json=%s, completed_at=%s, status=%s, updated_at=%s WHERE id=%s", (report_json, now, 'complete' if result.is_successful else 'partial', now, scan_id))

            # Handle certificate
            cert = result.certificate
            cert_row_id = None
            if cert:
                # compute dedup values using shared helper
                dedup_algorithm, dedup_value, dedup_hash = compute_dedup_values(asset_id, cert)

                # Check existing by dedup_hash
                cur.execute("SELECT id FROM certificates WHERE dedup_hash=%s AND asset_id=%s LIMIT 1", (dedup_hash, asset_id))
                r = cur.fetchone()
                if r:
                    cert_row_id = r[0]
                    # update tracking fields and any newly available metadata including dedup fields
                    try:
                        pk_fp = (cert.certificate_details.get('subject_public_key_info', {}) or {}).get('public_key_fingerprint_sha256')
                    except Exception:
                        pk_fp = None
                    if pk_fp:
                        cur.execute(
                            "UPDATE certificates SET last_seen_at=%s, updated_at=%s, is_current=1, public_key_fingerprint_sha256=%s, dedup_algorithm=%s, dedup_value=%s, dedup_hash=%s WHERE id=%s",
                            (now, now, pk_fp, dedup_algorithm, dedup_value, dedup_hash, cert_row_id),
                        )
                    else:
                        cur.execute(
                            "UPDATE certificates SET last_seen_at=%s, updated_at=%s, is_current=1, dedup_algorithm=%s, dedup_value=%s, dedup_hash=%s WHERE id=%s",
                            (now, now, dedup_algorithm, dedup_value, dedup_hash, cert_row_id),
                        )
                else:
                    # insert new certificate row (best-effort mapping to columns present)
                    insert_cert = (
                        "INSERT INTO certificates (asset_id, scan_id, issuer, subject, subject_cn, serial, valid_from, valid_until, expiry_days, fingerprint_sha256, fingerprint_sha1, fingerprint_md5, tls_version, key_length, key_algorithm, cipher_suite, signature_algorithm, ca, san_domains, certificate_details, dedup_algorithm, dedup_value, is_current, first_seen_at, last_seen_at, dedup_hash, created_at, updated_at) "
                        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,1,%s,%s,%s,%s,%s)"
                    )
                    san_json = json.dumps(cert.san_domains or [])
                    cert_details_json = json.dumps(cert.certificate_details or {})
                    params = (
                        asset_id,
                        scan_id,
                        cert.issuer.get('commonName') or cert.issuer.get('organizationName') or None,
                        cert.subject.get('commonName') or cert.subject.get('organizationName') or None,
                        cert.subject_cn or None,
                        cert.serial_number or None,
                        cert.not_before or None,
                        cert.not_after or None,
                        cert.days_until_expiry or None,
                        (cert.fingerprint_sha256 or None),
                        (cert.certificate_details.get('fingerprint_sha1') if cert.certificate_details else None),
                        (cert.certificate_details.get('fingerprint_md5') if cert.certificate_details else None),
                        result.protocol_version or None,
                        cert.public_key_bits or None,
                        cert.public_key_type or None,
                        result.cipher_suite or None,
                        cert.signature_algorithm or None,
                        cert.issuer.get('organizationName') or None,
                        san_json,
                        cert_details_json,
                        dedup_algorithm or None,
                        dedup_value or None,
                        now,
                        now,
                        dedup_hash,
                        now,
                        now,
                    )
                    cur.execute(insert_cert, params)
                    cert_row_id = cur.lastrowid

                # Ensure previous certs for this asset are marked is_current=0 (except our row)
                cur.execute("UPDATE certificates SET is_current=0 WHERE asset_id=%s AND is_current=1 AND id<>%s", (asset_id, cert_row_id))

            # Insert TLS profile into asset_ssl_profiles
            asp_insert = (
                "INSERT INTO asset_ssl_profiles (asset_id, scan_id, supports_tls_1_0, supports_tls_1_1, supports_tls_1_2, supports_tls_1_3, preferred_cipher, cipher_list_json, weak_cipher_count, insecure_protocol_count, hsts_enabled, first_seen_at, last_seen_at, is_current, created_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,1,%s)"
            )
            cipher_list_json = json.dumps(result.all_cipher_suites or [])
            supports = {v: 0 for v in ('TLSv1.0','TLSv1.1','TLSv1.2','TLSv1.3')}
            for p in result.supported_protocols or []:
                supports[p] = 1

            asp_params = (
                asset_id,
                scan_id,
                supports.get('TLSv1.0', 0),
                supports.get('TLSv1.1', 0),
                supports.get('TLSv1.2', 0),
                supports.get('TLSv1.3', 0),
                result.cipher_suite or None,
                cipher_list_json,
                0,
                0,
                1 if result.hsts_enabled else 0,
                now,
                now,
                now,
            )
            cur.execute(asp_insert, asp_params)
            asp_id = cur.lastrowid

            # Mark previous ASP rows not current
            cur.execute("UPDATE asset_ssl_profiles SET is_current=0 WHERE asset_id=%s AND is_current=1 AND id<>%s", (asset_id, asp_id))

            # Update domain_current_state (upsert)
            if cert_row_id:
                dcs_sql = (
                    "INSERT INTO domain_current_state (asset_id, latest_scan_id, current_ssl_certificate_id, current_risk_score, last_successful_scan_at, freshness_status, updated_at) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s) "
                    "ON DUPLICATE KEY UPDATE latest_scan_id=VALUES(latest_scan_id), current_ssl_certificate_id=VALUES(current_ssl_certificate_id), current_risk_score=VALUES(current_risk_score), last_successful_scan_at=VALUES(last_successful_scan_at), freshness_status=VALUES(freshness_status), updated_at=VALUES(updated_at)"
                )
                dcs_params = (
                    asset_id,
                    scan_id,
                    cert_row_id,
                    0.0,
                    now,
                    'fresh' if result.is_successful else 'degraded',
                    now,
                )
                cur.execute(dcs_sql, dcs_params)

            # Emit domain_events if certificate changed from previous current
            if cert_row_id:
                cur.execute("SELECT fingerprint_sha256 FROM certificates WHERE asset_id=%s AND id<>%s ORDER BY created_at DESC LIMIT 1", (asset_id, cert_row_id))
                prev = cur.fetchone()
                if prev:
                    prev_fp = prev[0]
                    if prev_fp and cert.fingerprint_sha256 and prev_fp != cert.fingerprint_sha256:
                        title = 'Certificate rotated'
                        desc = json.dumps({'old_fp': prev_fp, 'new_fp': cert.fingerprint_sha256})
                        cur.execute("INSERT INTO domain_events (asset_id, scan_id, event_type, event_title, event_description, severity, correlation_id, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)", (asset_id, scan_id, 'cert_rotated', title, desc, 'info', correlation_id, now))

            # Commit transaction
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        finally:
            cur.close()

    def run_once(self, asset_id: int, hostname: str, port: int = 443, correlation_id: Optional[str] = None):
        hostname = normalize_hostname(hostname)
        print(f"[worker] Starting SSL probe for {hostname}:{port} (asset={asset_id})")

        # Resolve and block private addresses
        addrs = validate_and_resolve(hostname)
        print(f"[worker] Resolved addresses: {addrs}")

        # Create scan record
        scan_id = self.create_scan_row(asset_id, hostname, correlation_id)
        analyzer = TLSAnalyzer()
        result = analyzer.analyze_endpoint(hostname, port)

        # Persist results atomically
        try:
            self.persist_results(asset_id, scan_id, correlation_id, result)
            print(f"[worker] Persisted scan {scan_id} for asset {asset_id}")
        except Exception as e:
            print(f"[worker][ERROR] Failed to persist results: {e}")
            # update scan status to failed
            cur = self.conn.cursor()
            now = datetime.datetime.utcnow()
            cur.execute("UPDATE scans SET status=%s, error_message=%s, completed_at=%s, updated_at=%s WHERE id=%s", ('failed', str(e), now, now, scan_id))
            self.conn.commit()
            cur.close()


def get_db_cfg_from_env():
    return {
        'host': os.getenv('MYSQL_HOST', 'localhost'),
        'port': int(os.getenv('MYSQL_PORT', '3306')),
        'user': os.getenv('MYSQL_USER') or os.getenv('DB_USER'),
        'password': os.getenv('MYSQL_PASSWORD') or os.getenv('DB_PASSWORD'),
        'database': os.getenv('MYSQL_DATABASE') or os.getenv('DB_NAME'),
        'autocommit': False,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--asset-id', type=int, required=True)
    p.add_argument('--host', required=True)
    p.add_argument('--port', type=int, default=443)
    p.add_argument('--correlation-id', default=str(uuid.uuid4()))
    args = p.parse_args()

    db_cfg = get_db_cfg_from_env()
    worker = SSLWorker(db_cfg)
    try:
        worker.run_once(args.asset_id, args.host, args.port, args.correlation_id)
    finally:
        worker.close()


if __name__ == '__main__':
    main()
