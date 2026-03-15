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
import secrets
import hashlib
import sys
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple
from cryptography.fernet import Fernet, InvalidToken  # type: ignore

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config import (
    MYSQL_HOST,
    MYSQL_PORT,
    MYSQL_USER,
    MYSQL_PASSWORD,
    MYSQL_DATABASE,
    ENCRYPTION_KEY,
    AUDIT_HASH_SECRET,
)  # type: ignore

logger = logging.getLogger(__name__)

VALID_ROLES = {"Admin", "Manager", "SingleScan", "Viewer"}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def normalize_role(role: str) -> str:
    """Normalize user-submitted role names to supported internal roles."""
    role_val = (role or "").strip().lower()
    aliases = {
        "admin": "Admin",
        "manager": "Manager",
        "viewer": "Viewer",
        "scanner": "SingleScan",
        "singlescan": "SingleScan",
        "single_scan": "SingleScan",
        "single-scan": "SingleScan",
    }
    normalized = aliases.get(role_val, role)
    return normalized if normalized in VALID_ROLES else "Viewer"


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _canonical_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _compute_audit_hash(payload: Dict[str, Any], prev_hash: str) -> str:
    digest_input = f"{prev_hash}|{_canonical_json(payload)}|{AUDIT_HASH_SECRET}"
    return hashlib.sha256(digest_input.encode("utf-8")).hexdigest()

# ---------------------------------------------------------------------------
# Encryption Helpers
# ---------------------------------------------------------------------------
_fernet_instance = None

def _get_fernet() -> Optional[Fernet]:
    global _fernet_instance
    if _fernet_instance is not None:
        return _fernet_instance
    if ENCRYPTION_KEY:
        try:
            _fernet_instance = Fernet(ENCRYPTION_KEY.encode('utf-8'))
            return _fernet_instance
        except Exception as e:
            logger.error(f"Failed to initialize Fernet: {e}")
    return None

def _encrypt_data(data: str) -> Optional[str]:
    f = _get_fernet()
    if f:
        return f.encrypt(data.encode('utf-8')).decode('utf-8')
    return None

def _decrypt_data(encrypted_data: str) -> str:
    f = _get_fernet()
    if f:
        try:
            return f.decrypt(encrypted_data.encode('utf-8')).decode('utf-8')
        except InvalidToken:
            logger.error("Failed to decrypt data (InvalidToken).")
            return encrypted_data # Fallback to returning raw data, though it will likely fail JSON parsing
    return encrypted_data

# ---------------------------------------------------------------------------
# Internal helpers — connection with retry + pool
# ---------------------------------------------------------------------------

_CONNECT_RETRIES = 3
_CONNECT_RETRY_DELAY = 0.4  # seconds between retries

def _get_connection():
    """Return a MySQL connection with retry logic, or *None* on failure.

    Retries up to _CONNECT_RETRIES times with a short back-off to survive
    transient 'too many connections' or network hiccups.
    """
    import time as _time
    try:
        import mysql.connector
        from mysql.connector import pooling as _pooling  # noqa – checked below
    except ImportError:
        logger.error("mysql-connector-python not installed.")
        return None

    last_exc: Optional[Exception] = None
    for attempt in range(1, _CONNECT_RETRIES + 1):
        try:
            conn = mysql.connector.connect(
                host=MYSQL_HOST,
                port=MYSQL_PORT,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                database=MYSQL_DATABASE,
                connect_timeout=5,
                connection_timeout=10,
            )
            # Verify the connection is alive (avoids stale-conn bugs)
            conn.ping(reconnect=True, attempts=2, delay=1)
            return conn
        except Exception as exc:
            last_exc = exc
            if attempt < _CONNECT_RETRIES:
                _time.sleep(_CONNECT_RETRY_DELAY * attempt)
    logger.warning("MySQL connection failed after %d attempts: %s", _CONNECT_RETRIES, last_exc)
    return None


def _get_server_connection():
    """Connect to the MySQL *server* (no database selected) with retry."""
    import time as _time
    try:
        import mysql.connector
    except ImportError:
        logger.error("mysql-connector-python not installed.")
        return None

    last_exc: Optional[Exception] = None
    for attempt in range(1, _CONNECT_RETRIES + 1):
        try:
            conn = mysql.connector.connect(
                host=MYSQL_HOST,
                port=MYSQL_PORT,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                connect_timeout=5,
            )
            conn.ping(reconnect=True, attempts=2, delay=1)
            return conn
        except Exception as exc:
            last_exc = exc
            if attempt < _CONNECT_RETRIES:
                _time.sleep(_CONNECT_RETRY_DELAY * attempt)
    logger.warning("MySQL server connection failed after %d attempts: %s", _CONNECT_RETRIES, last_exc)
    return None


def _create_trigger_if_missing(cur, trigger_name: str, create_sql: str) -> None:
    cur.execute(
        """
        SELECT COUNT(*)
        FROM information_schema.TRIGGERS
        WHERE TRIGGER_SCHEMA = %s AND TRIGGER_NAME = %s
        """,
        (MYSQL_DATABASE, trigger_name),
    )
    exists = cur.fetchone()[0] > 0
    if not exists:
        cur.execute(create_sql)


def _get_users_id_column_type(cur) -> str:
    """Return users.id SQL type from information_schema (e.g. varchar(36), int(11))."""
    cur.execute(
        """
        SELECT COLUMN_TYPE
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = %s
          AND TABLE_NAME = 'users'
          AND COLUMN_NAME = 'id'
        LIMIT 1
        """,
        (MYSQL_DATABASE,),
    )
    row = cur.fetchone()
    if row and row[0]:
        return str(row[0])
    return "varchar(36)"


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
                id                          VARCHAR(36) PRIMARY KEY,
                employee_id                 VARCHAR(64) UNIQUE,
                username                    VARCHAR(150) UNIQUE NOT NULL,
                email                       VARCHAR(255) UNIQUE,
                password_hash               VARCHAR(255) NOT NULL,
                role                        VARCHAR(50) NOT NULL,
                created_by                  VARCHAR(36),
                is_active                   BOOLEAN DEFAULT TRUE,
                password_setup_token_hash   CHAR(64) UNIQUE,
                password_setup_token_expiry DATETIME,
                must_change_password        BOOLEAN DEFAULT TRUE,
                failed_login_attempts       INT DEFAULT 0,
                lockout_until               DATETIME,
                last_login_at               DATETIME,
                password_changed_at         DATETIME,
                created_at                  DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at                  DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users(id)
                    ON DELETE SET NULL
            ) ENGINE=InnoDB
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id          VARCHAR(36)  PRIMARY KEY,
                target           VARCHAR(512) NOT NULL,
                status           VARCHAR(32),
                compliance_score INT          DEFAULT 0,
                total_assets     INT          DEFAULT 0,
                quantum_safe     INT          DEFAULT 0,
                quantum_vuln     INT          DEFAULT 0,
                scanned_at       DATETIME,
                report_json      LONGTEXT     NOT NULL,
                is_encrypted     BOOLEAN      DEFAULT FALSE
            ) ENGINE=InnoDB
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS cbom_reports (
                scan_id      VARCHAR(36) PRIMARY KEY,
                cbom_json    LONGTEXT NOT NULL,
                is_encrypted BOOLEAN  DEFAULT FALSE,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                    ON DELETE CASCADE
            ) ENGINE=InnoDB
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_log_chain (
                id             TINYINT PRIMARY KEY,
                last_entry_id  BIGINT,
                last_hash      CHAR(64),
                updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP
            ) ENGINE=InnoDB
        """)

        user_id_column_type = _get_users_id_column_type(cur)

        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id               BIGINT AUTO_INCREMENT PRIMARY KEY,
                actor_user_id    {user_id_column_type},
                actor_username   VARCHAR(150),
                event_category   VARCHAR(64) NOT NULL,
                event_type       VARCHAR(128) NOT NULL,
                target_user_id   {user_id_column_type},
                target_scan_id   VARCHAR(36),
                ip_address       VARCHAR(64),
                user_agent       VARCHAR(512),
                request_method   VARCHAR(16),
                request_path     VARCHAR(255),
                status           VARCHAR(32) NOT NULL,
                details_json     LONGTEXT,
                previous_hash    CHAR(64) NOT NULL,
                entry_hash       CHAR(64) NOT NULL UNIQUE,
                created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (actor_user_id) REFERENCES users(id)
                    ON DELETE SET NULL,
                FOREIGN KEY (target_user_id) REFERENCES users(id)
                    ON DELETE SET NULL,
                FOREIGN KEY (target_scan_id) REFERENCES scans(scan_id)
                    ON DELETE SET NULL,
                INDEX idx_audit_created_at (created_at),
                INDEX idx_audit_category (event_category),
                INDEX idx_audit_actor (actor_user_id),
                INDEX idx_audit_target_user (target_user_id),
                INDEX idx_audit_target_scan (target_scan_id)
            ) ENGINE=InnoDB
        """)

        # Attempt to migrate existing tables gracefully
        for alter_cmd in [
            "ALTER TABLE users ADD COLUMN email VARCHAR(255) UNIQUE",
            "ALTER TABLE users ADD COLUMN reset_token VARCHAR(255) UNIQUE",
            "ALTER TABLE users ADD COLUMN token_expiry DATETIME",
            "ALTER TABLE users ADD COLUMN employee_id VARCHAR(64) UNIQUE",
            "ALTER TABLE users ADD COLUMN created_by VARCHAR(36)",
            "ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT TRUE",
            "ALTER TABLE users ADD COLUMN password_setup_token_hash CHAR(64) UNIQUE",
            "ALTER TABLE users ADD COLUMN password_setup_token_expiry DATETIME",
            "ALTER TABLE users ADD COLUMN must_change_password BOOLEAN DEFAULT TRUE",
            "ALTER TABLE users ADD COLUMN failed_login_attempts INT DEFAULT 0",
            "ALTER TABLE users ADD COLUMN lockout_until DATETIME",
            "ALTER TABLE users ADD COLUMN last_login_at DATETIME",
            "ALTER TABLE users ADD COLUMN password_changed_at DATETIME",
            "ALTER TABLE users ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP",
            "ALTER TABLE users ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP",
            "ALTER TABLE users ADD CONSTRAINT fk_users_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL",
            "ALTER TABLE scans ADD COLUMN is_encrypted BOOLEAN DEFAULT FALSE",
            "ALTER TABLE cbom_reports ADD COLUMN is_encrypted BOOLEAN DEFAULT FALSE",
            "ALTER TABLE scans MODIFY COLUMN report_json LONGTEXT NOT NULL",
            "ALTER TABLE cbom_reports MODIFY COLUMN cbom_json LONGTEXT NOT NULL",
            # API key column — graceful; ignored if already present
            "ALTER TABLE users ADD COLUMN api_key_hash CHAR(64) UNIQUE",
        ]:
            try:
                cur.execute(alter_cmd)
            except Exception:
                pass # Column likely already exists

        cur.execute(
            "INSERT IGNORE INTO audit_log_chain (id, last_entry_id, last_hash) VALUES (1, NULL, %s)",
            ("0" * 64,),
        )

        _create_trigger_if_missing(
            cur,
            "audit_logs_no_update",
            """
            CREATE TRIGGER audit_logs_no_update
            BEFORE UPDATE ON audit_logs
            FOR EACH ROW
            SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'audit_logs is append-only';
            """,
        )
        _create_trigger_if_missing(
            cur,
            "audit_logs_no_delete",
            """
            CREATE TRIGGER audit_logs_no_delete
            BEFORE DELETE ON audit_logs
            FOR EACH ROW
            SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'audit_logs cannot be deleted';
            """,
        )
        _create_trigger_if_missing(
            cur,
            "audit_log_chain_no_delete",
            """
            CREATE TRIGGER audit_log_chain_no_delete
            BEFORE DELETE ON audit_log_chain
            FOR EACH ROW
            SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'audit_log_chain cannot be deleted';
            """,
        )

        # Seed default admin if no users exist
        cur.execute("SELECT COUNT(*) FROM users")
        if cur.fetchone()[0] == 0:
            from werkzeug.security import generate_password_hash  # type: ignore

            admin_username = os.environ.get("QSS_ADMIN_USERNAME", "admin")
            admin_email = os.environ.get("QSS_ADMIN_EMAIL", "admin@localhost")
            admin_employee_id = os.environ.get("QSS_ADMIN_EMPLOYEE_ID", "ADMIN-001")
            admin_pass = os.environ.get("QSS_ADMIN_PASSWORD", "admin123")
            cur.execute(
                """
                INSERT INTO users
                    (id, employee_id, username, email, password_hash, role, is_active, must_change_password, password_changed_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    str(uuid.uuid4()),
                    admin_employee_id,
                    admin_username,
                    admin_email,
                    generate_password_hash(admin_pass),
                    "Admin",
                    True,
                    False,
                    _utcnow(),
                ),
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
    return False


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
        json_str = json.dumps(report, ensure_ascii=False)
        is_encrypted = False
        encrypted_str = _encrypt_data(json_str)
        if encrypted_str:
            json_str = encrypted_str
            is_encrypted = True

        cur.execute(
            """
            INSERT INTO scans
                (scan_id, target, status, compliance_score,
                 total_assets, quantum_safe, quantum_vuln,
                 scanned_at, report_json, is_encrypted)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                status           = VALUES(status),
                compliance_score = VALUES(compliance_score),
                total_assets     = VALUES(total_assets),
                quantum_safe     = VALUES(quantum_safe),
                quantum_vuln     = VALUES(quantum_vuln),
                scanned_at       = VALUES(scanned_at),
                report_json      = VALUES(report_json),
                is_encrypted     = VALUES(is_encrypted)
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
                json_str,
                is_encrypted
            ),
        )
        conn.commit()
        return True
    except Exception as exc:
        logger.error("MySQL save_scan error: %s", exc)
        return False
    finally:
        conn.close()
    return False


def save_cbom(scan_id: str, cbom_dict: Dict[str, Any]) -> bool:
    """Persist a CBOM document to MySQL.  Returns ``True`` on success."""
    conn = _get_connection()
    if conn is None:
        return False

    try:
        cur = conn.cursor()
        json_str = json.dumps(cbom_dict, ensure_ascii=False)
        is_encrypted = False
        encrypted_str = _encrypt_data(json_str)
        if encrypted_str:
            json_str = encrypted_str
            is_encrypted = True

        cur.execute(
            """
            INSERT INTO cbom_reports (scan_id, cbom_json, is_encrypted)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE 
                cbom_json = VALUES(cbom_json),
                is_encrypted = VALUES(is_encrypted)
            """,
            (scan_id, json_str, is_encrypted),
        )
        conn.commit()
        return True
    except Exception as exc:
        logger.error("MySQL save_cbom error: %s", exc)
        return False
    finally:
        conn.close()
    return False


def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    """Load a scan report from MySQL.  Returns ``None`` if not found."""
    conn = _get_connection()
    if conn is None:
        return None

    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT report_json, is_encrypted FROM scans WHERE scan_id = %s", (scan_id,)
        )
        row = cur.fetchone()
        if row:
            data, is_encrypted = row
            if is_encrypted and isinstance(data, str):
                data = _decrypt_data(data)
            return json.loads(data) if isinstance(data, str) else data
        return None
    except Exception as exc:
        logger.error("MySQL get_scan error: %s", exc)
        return None
    finally:
        conn.close()
    return None


def list_scans(limit: int = 50) -> List[Dict[str, Any]]:
    """Return recent scans ordered by timestamp (newest first)."""
    conn = _get_connection()
    if conn is None:
        return []

    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT report_json, is_encrypted FROM scans ORDER BY scanned_at DESC LIMIT %s",
            (limit,),
        )
        results = []
        for row in cur.fetchall():
            data, is_encrypted = row
            if is_encrypted and isinstance(data, str):
                data = _decrypt_data(data)
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
            "SELECT report_json, is_encrypted FROM scans WHERE target = %s ORDER BY scanned_at DESC LIMIT 1",
            (target,)
        )
        row = cur.fetchone()
        if row:
            data, is_encrypted = row
            if is_encrypted and isinstance(data, str):
                data = _decrypt_data(data)
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
            "SELECT cbom_json, is_encrypted FROM cbom_reports WHERE scan_id = %s",
            (scan_id,),
        )
        row = cur.fetchone()
        if row:
            data, is_encrypted = row
            if is_encrypted and isinstance(data, str):
                data = _decrypt_data(data)
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

def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Load an active user by ID."""
    conn = _get_connection()
    if conn is None:
        return None
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE id = %s AND is_active = TRUE", (str(user_id),))
        user = cur.fetchone()
        if user:
            user["role"] = normalize_role(user.get("role", "Viewer"))
        return user
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Load an active user by username."""
    conn = _get_connection()
    if conn is None:
        return None
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE username = %s AND is_active = TRUE", (username,))
        user = cur.fetchone()
        if user:
            user["role"] = normalize_role(user.get("role", "Viewer"))
        return user
    finally:
        conn.close()


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Look up an active user by email address (case-insensitive)."""
    conn = _get_connection()
    if conn is None:
        return None
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT * FROM users WHERE LOWER(email) = LOWER(%s) AND is_active = TRUE",
            (email,),
        )
        user = cur.fetchone()
        if user:
            user["role"] = normalize_role(user.get("role", "Viewer"))
        return user
    except Exception as exc:
        logger.error("get_user_by_email failed: %s", exc)
        return None
    finally:
        conn.close()


def list_users() -> List[Dict[str, Any]]:
    conn = _get_connection()
    if conn is None:
        return []
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """
            SELECT id, employee_id, username, email, role, is_active, created_by,
                   last_login_at, created_at,
                   (api_key_hash IS NOT NULL) AS api_key_hash
            FROM users
            ORDER BY created_at DESC
            """
        )
        users = cur.fetchall() or []
        for user in users:
            user["role"] = normalize_role(user.get("role", "Viewer"))
        return users
    finally:
        conn.close()


def create_invited_user(
    employee_id: str,
    username: str,
    email: str,
    role: str,
    created_by: str,
    password_hash: str,
) -> Optional[str]:
    """Create a user invited by an admin/manager and return the new user ID."""
    conn = _get_connection()
    if conn is None:
        return None
    user_id = str(uuid.uuid4())
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO users
                (id, employee_id, username, email, password_hash, role, created_by,
                 is_active, must_change_password, failed_login_attempts)
            VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE, TRUE, 0)
            """,
            (
                user_id,
                employee_id,
                username,
                email,
                password_hash,
                normalize_role(role),
                created_by,
            ),
        )
        conn.commit()
        return user_id
    except Exception as exc:
        logger.error("MySQL create_invited_user error: %s", exc)
        return None
    finally:
        conn.close()


def update_user_profile(user_id: str, role: Optional[str] = None, is_active: Optional[bool] = None) -> bool:
    conn = _get_connection()
    if conn is None:
        return False
    updates = []
    params: List[Any] = []
    if role is not None:
        updates.append("role = %s")
        params.append(normalize_role(role))
    if is_active is not None:
        updates.append("is_active = %s")
        params.append(bool(is_active))
    if not updates:
        conn.close()
        return True
    params.append(str(user_id))
    try:
        cur = conn.cursor()
        cur.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = %s", tuple(params))
        conn.commit()
        return cur.rowcount > 0
    except Exception as exc:
        logger.error("MySQL update_user_profile error: %s", exc)
        return False
    finally:
        conn.close()


def mark_login_success(user_id: str) -> None:
    conn = _get_connection()
    if conn is None:
        return
    try:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE users
            SET failed_login_attempts = 0,
                lockout_until = NULL,
                last_login_at = %s
            WHERE id = %s
            """,
            (_utcnow(), str(user_id)),
        )
        conn.commit()
    except Exception as exc:
        logger.warning("mark_login_success failed: %s", exc)
    finally:
        conn.close()


def mark_login_failure(user_id: str, max_attempts: int, lock_minutes: int) -> None:
    conn = _get_connection()
    if conn is None:
        return
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT failed_login_attempts FROM users WHERE id = %s", (str(user_id),))
        row = cur.fetchone() or {"failed_login_attempts": 0}
        attempts = int(row.get("failed_login_attempts", 0)) + 1
        lockout_until = _utcnow() + timedelta(minutes=max(1, lock_minutes)) if attempts >= max_attempts else None

        update_cur = conn.cursor()
        update_cur.execute(
            """
            UPDATE users
            SET failed_login_attempts = %s,
                lockout_until = %s
            WHERE id = %s
            """,
            (attempts, lockout_until, str(user_id)),
        )
        conn.commit()
    except Exception as exc:
        logger.warning("mark_login_failure failed: %s", exc)
    finally:
        conn.close()


def create_password_setup_token(user_id: str, expires_hours: int = 24) -> Optional[str]:
    """Create and persist a one-time password setup token; returns the raw token."""
    conn = _get_connection()
    if conn is None:
        return None
    raw_token = secrets.token_urlsafe(48)
    token_hash = _hash_token(raw_token)
    expiry = _utcnow() + timedelta(hours=max(1, expires_hours))
    try:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE users
            SET password_setup_token_hash = %s,
                password_setup_token_expiry = %s,
                must_change_password = TRUE
            WHERE id = %s
            """,
            (token_hash, expiry, str(user_id)),
        )
        conn.commit()
        if cur.rowcount == 0:
            return None
        return raw_token
    except Exception as exc:
        logger.error("create_password_setup_token failed: %s", exc)
        return None
    finally:
        conn.close()


def get_user_by_setup_token(raw_token: str) -> Optional[Dict[str, Any]]:
    conn = _get_connection()
    if conn is None:
        return None
    token_hash = _hash_token(raw_token)
    now_ts = _utcnow()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """
            SELECT *
            FROM users
            WHERE password_setup_token_hash = %s
              AND password_setup_token_expiry IS NOT NULL
              AND password_setup_token_expiry >= %s
              AND is_active = TRUE
            """,
            (token_hash, now_ts),
        )
        user = cur.fetchone()
        if user:
            user["role"] = normalize_role(user.get("role", "Viewer"))
        return user
    finally:
        conn.close()


def set_user_password(user_id: str, password_hash: str) -> bool:
    conn = _get_connection()
    if conn is None:
        return False
    try:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE users
            SET password_hash = %s,
                password_setup_token_hash = NULL,
                password_setup_token_expiry = NULL,
                must_change_password = FALSE,
                password_changed_at = %s,
                failed_login_attempts = 0,
                lockout_until = NULL
            WHERE id = %s
            """,
            (password_hash, _utcnow(), str(user_id)),
        )
        conn.commit()
        return cur.rowcount > 0
    except Exception as exc:
        logger.error("set_user_password failed: %s", exc)
        return False
    finally:
        conn.close()


def create_user(username: str, password_hash: str, role: str = "Viewer") -> bool:
    """Backwards-compatible helper for tests/legacy call sites."""
    conn = _get_connection()
    if conn is None:
        return False
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (id, username, password_hash, role, is_active) VALUES (%s, %s, %s, %s, TRUE)",
            (str(uuid.uuid4()), username, password_hash, normalize_role(role)),
        )
        conn.commit()
        return True
    except Exception as exc:
        logger.error("MySQL create_user error: %s", exc)
        return False
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# API Key Management
# ---------------------------------------------------------------------------

_API_KEY_PREFIX = "qss_"


def generate_api_key(user_id: str) -> Optional[str]:
    """Generate a new API key for *user_id*.

    Creates a random ``qss_<48-byte-hex>`` raw key, stores the SHA-256 hash
    in ``users.api_key_hash``, and returns the raw key once (it is NOT stored
    in plaintext).  Returns ``None`` on failure.
    """
    conn = _get_connection()
    if conn is None:
        return None
    raw_key = _API_KEY_PREFIX + secrets.token_hex(48)
    key_hash = _hash_token(raw_key)
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET api_key_hash = %s WHERE id = %s",
            (key_hash, str(user_id)),
        )
        conn.commit()
        if cur.rowcount == 0:
            logger.warning("generate_api_key: no user updated (id=%s)", user_id)
            return None
        return raw_key
    except Exception as exc:
        logger.error("generate_api_key failed: %s", exc)
        return None
    finally:
        conn.close()


def get_user_by_api_key(raw_key: str) -> Optional[Dict[str, Any]]:
    """Return an active user whose hashed API key matches *raw_key*.

    Returns ``None`` if the key is invalid, the user is inactive, or the
    database is unavailable.
    """
    if not raw_key or not raw_key.startswith(_API_KEY_PREFIX):
        return None
    conn = _get_connection()
    if conn is None:
        return None
    key_hash = _hash_token(raw_key)
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT * FROM users WHERE api_key_hash = %s AND is_active = TRUE",
            (key_hash,),
        )
        user = cur.fetchone()
        if user:
            user["role"] = normalize_role(user.get("role", "Viewer"))
        return user
    except Exception as exc:
        logger.error("get_user_by_api_key failed: %s", exc)
        return None
    finally:
        conn.close()


def revoke_api_key(user_id: str) -> bool:
    """Clear the API key hash for *user_id* (key is revoked immediately)."""
    conn = _get_connection()
    if conn is None:
        return False
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET api_key_hash = NULL WHERE id = %s",
            (str(user_id),),
        )
        conn.commit()
        return cur.rowcount > 0
    except Exception as exc:
        logger.error("revoke_api_key failed: %s", exc)
        return False
    finally:
        conn.close()


def has_api_key(user_id: str) -> bool:
    """Return True if the user already has an API key issued."""
    conn = _get_connection()
    if conn is None:
        return False
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT api_key_hash IS NOT NULL FROM users WHERE id = %s",
            (str(user_id),),
        )
        row = cur.fetchone()
        return bool(row and row[0])
    except Exception as exc:
        logger.error("has_api_key failed: %s", exc)
        return False
    finally:
        conn.close()


def append_audit_log(
    event_category: str,
    event_type: str,
    status: str,
    actor_user_id: Optional[str] = None,
    actor_username: Optional[str] = None,
    target_user_id: Optional[str] = None,
    target_scan_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_method: Optional[str] = None,
    request_path: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> bool:
    """Append a tamper-evident audit event to the audit chain."""
    conn = _get_connection()
    if conn is None:
        return False
    details = details or {}
    try:
        chain_cur = conn.cursor(dictionary=True)
        chain_cur.execute("SELECT last_entry_id, last_hash FROM audit_log_chain WHERE id = 1 FOR UPDATE")
        chain_state = chain_cur.fetchone() or {"last_entry_id": None, "last_hash": "0" * 64}
        prev_hash = chain_state.get("last_hash") or "0" * 64
        # Standardize timestamp to seconds for tamper-evident chain consistency
        created_at = _utcnow().replace(microsecond=0)

        payload = {
            "actor_user_id": actor_user_id,
            "actor_username": actor_username,
            "event_category": event_category,
            "event_type": event_type,
            "target_user_id": target_user_id,
            "target_scan_id": target_scan_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "request_method": request_method,
            "request_path": request_path,
            "status": status,
            "details": details,
            "created_at": created_at.isoformat(timespec="seconds"),
        }
        entry_hash = _compute_audit_hash(payload, prev_hash)

        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO audit_logs
                (actor_user_id, actor_username, event_category, event_type,
                 target_user_id, target_scan_id, ip_address, user_agent,
                 request_method, request_path, status, details_json,
                 previous_hash, entry_hash, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                actor_user_id,
                actor_username,
                event_category,
                event_type,
                target_user_id,
                target_scan_id,
                ip_address,
                user_agent,
                request_method,
                request_path,
                status,
                _canonical_json(details),
                prev_hash,
                entry_hash,
                created_at,
            ),
        )
        new_entry_id = cur.lastrowid
        cur.execute(
            "UPDATE audit_log_chain SET last_entry_id = %s, last_hash = %s WHERE id = 1",
            (new_entry_id, entry_hash),
        )
        conn.commit()
        return True
    except Exception as exc:
        logger.error("append_audit_log failed: %s", exc)
        return False
    finally:
        conn.close()


def list_audit_logs(limit: int = 100) -> List[Dict[str, Any]]:
    conn = _get_connection()
    if conn is None:
        return []
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """
            SELECT id, actor_user_id, actor_username, event_category, event_type,
                   target_user_id, target_scan_id, ip_address, user_agent,
                   request_method, request_path, status, details_json,
                   previous_hash, entry_hash, created_at
            FROM audit_logs
            ORDER BY id DESC
            LIMIT %s
            """,
            (limit,),
        )
        rows = cur.fetchall() or []
        for row in rows:
            if isinstance(row.get("details_json"), str):
                try:
                    row["details"] = json.loads(row["details_json"])
                except json.JSONDecodeError:
                    row["details"] = {"raw": row["details_json"]}
            else:
                row["details"] = row.get("details_json") or {}
        return rows
    finally:
        conn.close()


def verify_audit_log_chain(limit: int = 500) -> Tuple[bool, List[str]]:
    conn = _get_connection()
    if conn is None:
        return False, ["Database unavailable"]
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """
            SELECT id, actor_user_id, actor_username, event_category, event_type,
                   target_user_id, target_scan_id, ip_address, user_agent,
                   request_method, request_path, status, details_json,
                   previous_hash, entry_hash, created_at
            FROM audit_logs
            ORDER BY id ASC
            LIMIT %s
            """,
            (limit,),
        )
        issues: List[str] = []
        prev_hash = "0" * 64
        for row in cur.fetchall() or []:
            details = {}
            raw_details = row.get("details_json")
            if isinstance(raw_details, str):
                try:
                    details = json.loads(raw_details)
                except json.JSONDecodeError:
                    details = {"raw": raw_details}
            payload = {
                "actor_user_id": row.get("actor_user_id"),
                "actor_username": row.get("actor_username"),
                "event_category": row.get("event_category"),
                "event_type": row.get("event_type"),
                "target_user_id": row.get("target_user_id"),
                "target_scan_id": row.get("target_scan_id"),
                "ip_address": row.get("ip_address"),
                "user_agent": row.get("user_agent"),
                "request_method": row.get("request_method"),
                "request_path": row.get("request_path"),
                "status": row.get("status"),
                "details": details,
                "created_at": row.get("created_at").replace(microsecond=0).isoformat(timespec="seconds") if row.get("created_at") else None,
            }
            if row.get("previous_hash") != prev_hash:
                issues.append(f"Chain break at audit log {row.get('id')}")
            expected_hash = _compute_audit_hash(payload, row.get("previous_hash") or "0" * 64)
            if row.get("entry_hash") != expected_hash:
                issues.append(f"Hash mismatch at audit log {row.get('id')}")
            prev_hash = row.get("entry_hash") or prev_hash
        return len(issues) == 0, issues
    except Exception as exc:
        logger.error("verify_audit_log_chain failed: %s", exc)
        return False, [f"Verification process error: {exc}"]
    finally:
        conn.close()
