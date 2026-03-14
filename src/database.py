"""
Database Module — MySQL Redundant Storage

Provides MySQL persistence alongside JSON file storage for scan results
and CBOM reports.  All public functions are designed to fail gracefully:
if MySQL is unavailable the caller receives ``None`` and the application
continues using JSON files only.

Tables
------
- ``scans``        — structured scan metadata + full JSON blob
- ``cbom_reports`` — CBOM JSON keyed by scan_id

Functions
---------
- ``init_db()``        — create database and tables if they don't exist
- ``save_scan()``      — INSERT a scan report
- ``save_cbom()``      — INSERT a CBOM document
- ``get_scan()``       — SELECT one scan by ID
- ``list_scans()``     — SELECT recent scans
- ``get_cbom()``       — SELECT CBOM by scan ID
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config import (
    MYSQL_HOST,
    MYSQL_PORT,
    MYSQL_USER,
    MYSQL_PASSWORD,
    MYSQL_DATABASE,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_connection():
    """Return a fresh MySQL connection or *None* on failure."""
    try:
        import mysql.connector
        return mysql.connector.connect(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DATABASE,
            connect_timeout=5,
        )
    except Exception as exc:
        logger.warning("MySQL connection failed: %s", exc)
        return None


def _get_server_connection():
    """Connect to the MySQL *server* (no database selected)."""
    try:
        import mysql.connector
        return mysql.connector.connect(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            connect_timeout=5,
        )
    except Exception as exc:
        logger.warning("MySQL server connection failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def init_db() -> bool:
    """Create the database and tables if they don't exist.

    Returns ``True`` on success, ``False`` if MySQL is unreachable.
    """
    conn = _get_server_connection()
    if conn is None:
        logger.info("MySQL unavailable — running in JSON-only mode.")
        return False

    try:
        cur = conn.cursor()
        cur.execute(
            f"CREATE DATABASE IF NOT EXISTS `{MYSQL_DATABASE}` "
            "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
        )
        cur.execute(f"USE `{MYSQL_DATABASE}`")

        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            INT AUTO_INCREMENT PRIMARY KEY,
                username      VARCHAR(64) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role          VARCHAR(16) DEFAULT 'Viewer'
            ) ENGINE=InnoDB
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id          VARCHAR(16)  PRIMARY KEY,
                target           VARCHAR(512) NOT NULL,
                status           VARCHAR(32),
                compliance_score INT          DEFAULT 0,
                total_assets     INT          DEFAULT 0,
                quantum_safe     INT          DEFAULT 0,
                quantum_vuln     INT          DEFAULT 0,
                scanned_at       DATETIME,
                report_json      JSON         NOT NULL
            ) ENGINE=InnoDB
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS cbom_reports (
                scan_id   VARCHAR(16) PRIMARY KEY,
                cbom_json JSON NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                    ON DELETE CASCADE
            ) ENGINE=InnoDB
        """)

        # Seed default admin if no users exist
        cur.execute("SELECT COUNT(*) FROM users")
        if cur.fetchone()[0] == 0:
            from werkzeug.security import generate_password_hash
            # Default creds: admin / admin123
            # In a real production app, this should be set via env var on first boot
            admin_pass = os.environ.get("QSS_ADMIN_PASSWORD", "admin123")
            cur.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
                ("admin", generate_password_hash(admin_pass), "Admin")
            )
            logger.info("Default admin user created.")

        conn.commit()
        logger.info("MySQL database '%s' initialised.", MYSQL_DATABASE)
        return True
    except Exception as exc:
        logger.error("MySQL init_db error: %s", exc)
        return False
    finally:
        conn.close()


def save_scan(report: Dict[str, Any]) -> bool:
    """Persist a scan report to MySQL.  Returns ``True`` on success."""
    conn = _get_connection()
    if conn is None:
        return False

    try:
        overview = report.get("overview") or {}
        ts_str = report.get("generated_at") or report.get("timestamp")
        scanned_at = None
        if ts_str:
            try:
                scanned_at = datetime.fromisoformat(
                    ts_str.replace("Z", "+00:00")
                )
            except (ValueError, AttributeError):
                scanned_at = datetime.now(timezone.utc)

        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO scans
                (scan_id, target, status, compliance_score,
                 total_assets, quantum_safe, quantum_vuln,
                 scanned_at, report_json)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                status           = VALUES(status),
                compliance_score = VALUES(compliance_score),
                total_assets     = VALUES(total_assets),
                quantum_safe     = VALUES(quantum_safe),
                quantum_vuln     = VALUES(quantum_vuln),
                scanned_at       = VALUES(scanned_at),
                report_json      = VALUES(report_json)
            """,
            (
                report.get("scan_id", ""),
                report.get("target", ""),
                report.get("status", ""),
                overview.get("average_compliance_score", 0),
                overview.get("total_assets", 0),
                overview.get("quantum_safe", 0),
                overview.get("quantum_vulnerable", 0),
                scanned_at,
                json.dumps(report, ensure_ascii=False),
            ),
        )
        conn.commit()
        return True
    except Exception as exc:
        logger.error("MySQL save_scan error: %s", exc)
        return False
    finally:
        conn.close()


def save_cbom(scan_id: str, cbom_dict: Dict[str, Any]) -> bool:
    """Persist a CBOM document to MySQL.  Returns ``True`` on success."""
    conn = _get_connection()
    if conn is None:
        return False

    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO cbom_reports (scan_id, cbom_json)
            VALUES (%s, %s)
            ON DUPLICATE KEY UPDATE cbom_json = VALUES(cbom_json)
            """,
            (scan_id, json.dumps(cbom_dict, ensure_ascii=False)),
        )
        conn.commit()
        return True
    except Exception as exc:
        logger.error("MySQL save_cbom error: %s", exc)
        return False
    finally:
        conn.close()


def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    """Load a scan report from MySQL.  Returns ``None`` if not found."""
    conn = _get_connection()
    if conn is None:
        return None

    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT report_json FROM scans WHERE scan_id = %s", (scan_id,)
        )
        row = cur.fetchone()
        if row:
            data = row[0]
            return json.loads(data) if isinstance(data, str) else data
        return None
    except Exception as exc:
        logger.error("MySQL get_scan error: %s", exc)
        return None
    finally:
        conn.close()


def list_scans(limit: int = 50) -> List[Dict[str, Any]]:
    """Return recent scans ordered by timestamp (newest first)."""
    conn = _get_connection()
    if conn is None:
        return []

    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT report_json FROM scans ORDER BY scanned_at DESC LIMIT %s",
            (limit,),
        )
        results = []
        for (data,) in cur.fetchall():
            report = json.loads(data) if isinstance(data, str) else data
            results.append(report)
        return results
    except Exception as exc:
        logger.error("MySQL list_scans error: %s", exc)
        return []
    finally:
        conn.close()


def get_latest_scan_by_target(target: str) -> Optional[Dict[str, Any]]:
    """Load the most recent scan record for a specific target. Returns ``None`` if not found."""
    conn = _get_connection()
    if conn is None:
        return None

    try:
        cur = conn.cursor()
        # Ensure we match the target exactly, ordering by timestamp to get the latest
        cur.execute(
            "SELECT report_json FROM scans WHERE target = %s ORDER BY scanned_at DESC LIMIT 1",
            (target,)
        )
        row = cur.fetchone()
        if row:
            data = row[0]
            return json.loads(data) if isinstance(data, str) else data
        return None
    except Exception as exc:
        logger.error("MySQL get_latest_scan_by_target error: %s", exc)
        return None
    finally:
        conn.close()


def get_cbom(scan_id: str) -> Optional[Dict[str, Any]]:
    """Load a CBOM document from MySQL.  Returns ``None`` if not found."""
    conn = _get_connection()
    if conn is None:
        return None

    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT cbom_json FROM cbom_reports WHERE scan_id = %s",
            (scan_id,),
        )
        row = cur.fetchone()
        if row:
            data = row[0]
            return json.loads(data) if isinstance(data, str) else data
        return None
    except Exception as exc:
        logger.error("MySQL get_cbom error: %s", exc)
        return None
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# RBAC User Management
# ---------------------------------------------------------------------------

def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """Load a user by ID."""
    conn = _get_connection()
    if conn is None: return None
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        return cur.fetchone()
    finally:
        conn.close()

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Load a user by username."""
    conn = _get_connection()
    if conn is None: return None
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        return cur.fetchone()
    finally:
        conn.close()

def create_user(username: str, password_hash: str, role: str = 'Viewer') -> bool:
    """Create a new user."""
    conn = _get_connection()
    if conn is None: return False
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
            (username, password_hash, role)
        )
        conn.commit()
        return True
    except Exception as exc:
        logger.error("MySQL create_user error: %s", exc)
        return False
    finally:
        conn.close()
