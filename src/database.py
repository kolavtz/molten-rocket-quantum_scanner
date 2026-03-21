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
import pymysql.cursors
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

_CONNECT_RETRIES = int(os.environ.get("QSS_DB_CONNECT_RETRIES", "1"))
_CONNECT_RETRY_DELAY = float(os.environ.get("QSS_DB_CONNECT_RETRY_DELAY_SECONDS", "0.25"))
_CONNECT_TIMEOUT = int(float(os.environ.get("QSS_DB_CONNECT_TIMEOUT_SECONDS", "2")))

def _get_connection():
    """Return a MySQL connection with retry logic, or *None* on failure.

    Retries up to _CONNECT_RETRIES times with a short back-off to survive
    transient 'too many connections' or network hiccups.
    """
    import time as _time
    try:
        import pymysql
    except ImportError:
        logger.error("pymysql not installed.")
        return None

    last_exc: Optional[Exception] = None
    for attempt in range(1, _CONNECT_RETRIES + 1):
        try:
            conn = pymysql.connect(
                host=MYSQL_HOST,
                port=MYSQL_PORT,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                database=MYSQL_DATABASE,
                connect_timeout=_CONNECT_TIMEOUT,
            )
            # Verify the connection is alive (avoids stale-conn bugs)
            conn.ping(reconnect=True)
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
        import pymysql
    except ImportError:
        logger.error("pymysql not installed.")
        return None

    last_exc: Optional[Exception] = None
    for attempt in range(1, _CONNECT_RETRIES + 1):
        try:
            conn = pymysql.connect(
                host=MYSQL_HOST,
                port=MYSQL_PORT,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                connect_timeout=_CONNECT_TIMEOUT,
            )
            conn.ping(reconnect=True)
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
        try:
            cur.execute(create_sql)
        except Exception as e:
            logger.warning("Trigger '%s' setup warning: %s", trigger_name, e)



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


def _ensure_scans_id_column(cur) -> None:
    """Ensure a legacy scans table has an integer id primary key for ORM compatibility."""
    try:
        cur.execute(
            """
            SELECT COLUMN_KEY, EXTRA
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = %s
              AND TABLE_NAME = 'scans'
              AND COLUMN_NAME = 'id'
            """,
            (MYSQL_DATABASE,),
        )
        if cur.fetchone():
            return
    except Exception as e:
        logger.warning("Could not query scans.id metadata: %s", e)
        return

    logger.info("Legacy scans table detected without id column; applying migration.")

    # Detect whether scan_id currently serves as primary key or unique key.
    scan_id_primary = False
    try:
        cur.execute(
            """
            SELECT COLUMN_KEY
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = %s
              AND TABLE_NAME = 'scans'
              AND COLUMN_NAME = 'scan_id'
            """,
            (MYSQL_DATABASE,),
        )
        row = cur.fetchone()
        if row and row[0] == 'PRI':
            scan_id_primary = True
    except Exception:
        pass

    try:
        # First attempt: add an auto-increment id primary key column.
        cur.execute(
            "ALTER TABLE scans ADD COLUMN id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY FIRST"
        )
        logger.info("Added scans.id AUTO_INCREMENT PRIMARY KEY")
    except Exception as e:
        logger.warning("Failed to add scans.id as primary key: %s", e)
        try:
            if scan_id_primary:
                cur.execute("ALTER TABLE scans DROP PRIMARY KEY")
            cur.execute(
                "ALTER TABLE scans ADD COLUMN id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY FIRST"
            )
            if scan_id_primary:
                cur.execute(
                    "ALTER TABLE scans ADD UNIQUE INDEX uq_scans_scan_id (scan_id)"
                )
            logger.info("Migrated legacy scan_id PK by adding scans.id PK and preserving scan_id uniqueness")
        except Exception as e2:
            logger.warning("Failed to migrate scans.id legacy PK: %s", e2)


def _ensure_assets_name_and_target_columns(cur) -> None:
    """Ensure assets has both target and name columns for mixed compatibility."""
    try:
        cur.execute(
            """
            SELECT COLUMN_NAME
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = %s
              AND TABLE_NAME = 'assets'
              AND COLUMN_NAME IN ('target', 'name')
            """,
            (MYSQL_DATABASE,),
        )
        existing = {row[0] for row in cur.fetchall()}

        if 'target' not in existing:
            cur.execute("ALTER TABLE assets ADD COLUMN target VARCHAR(512) NULL")
            logger.info("Added assets.target column for legacy compatibility")
            if 'name' in existing:
                cur.execute("UPDATE assets SET target = name WHERE target IS NULL OR target = ''")

        if 'name' not in existing:
            cur.execute("ALTER TABLE assets ADD COLUMN name VARCHAR(255) NULL")
            logger.info("Added assets.name column for legacy compatibility")
            if 'target' in existing or 'target' in existing:
                cur.execute("UPDATE assets SET name = target WHERE name IS NULL OR name = ''")

    except Exception as e:
        logger.warning("Could not ensure assets target/name compatibility columns: %s", e)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def init_db() -> bool:
    """Create the database and tables if they don't exist.

    Returns ``True`` on success, ``False`` if MySQL is unreachable.
    """
    try:
        import pymysql
    except ImportError:
        logger.error("pymysql not installed.")
        return False
    
    # Connect to MySQL server WITHOUT selecting a database
    last_exc = None
    for attempt in range(1, _CONNECT_RETRIES + 1):
        try:
            conn = pymysql.connect(
                host=MYSQL_HOST,
                port=MYSQL_PORT,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                connect_timeout=_CONNECT_TIMEOUT,
                read_timeout=60,  # Very generous timeout for DDL operations (CREATE DATABASE, etc.)
                write_timeout=60,
                autocommit=False,  # IMPORTANT: explicit transaction control
            )
            break
        except Exception as exc:
            last_exc = exc
            if attempt < _CONNECT_RETRIES:
                import time as _time
                _time.sleep(_CONNECT_RETRY_DELAY * attempt)
    else:
        logger.info("MySQL unavailable — running in JSON-only mode. (Connection failed: %s)", last_exc)
        return False

    migration_lock_name = f"{MYSQL_DATABASE}__init_db"
    migration_lock_acquired = False

    try:
        cur = conn.cursor()
        
        # Try to select the database directly (it may already exist)
        try:
            cur.execute(f"USE `{MYSQL_DATABASE}`")
            conn.commit()
            logger.info("Database '%s' already exists, selected successfully", MYSQL_DATABASE)
        except Exception as e:
            # Database doesn't exist, try to create it
            logger.info("Database '%s' doesn't exist yet, attempting to create...", MYSQL_DATABASE)
            try:
                cur.execute(
                    f"CREATE DATABASE IF NOT EXISTS `{MYSQL_DATABASE}` "
                    "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
                )
                conn.commit()
                logger.info("Database '%s' created successfully", MYSQL_DATABASE)
                # Now select it
                cur.execute(f"USE `{MYSQL_DATABASE}`")
                conn.commit()
            except Exception as create_exc:
                logger.warning("Could not create database: %s. Trying to use existing...", create_exc)
                try:
                    cur.execute(f"USE `{MYSQL_DATABASE}`")
                    conn.commit()
                    logger.info("Successfully selected existing database '%s'", MYSQL_DATABASE)
                except Exception as use_exc:
                    raise use_exc

        # Keep metadata-lock waits reasonable (avoid long hangs while still allowing migration completion).
        try:
            cur.execute("SET SESSION lock_wait_timeout = 10")
            cur.execute("SET SESSION innodb_lock_wait_timeout = 10")
        except Exception:
            pass

        # Prevent concurrent multi-process startup migrations (e.g., Flask debug reloader).
        try:
            cur.execute("SELECT GET_LOCK(%s, 10)", (migration_lock_name,))
            _lock_row = cur.fetchone()
            migration_lock_acquired = bool(_lock_row and _lock_row[0] == 1)
        except Exception:
            migration_lock_acquired = False

        if not migration_lock_acquired:
            logger.info("Another process is initializing MySQL schema; skipping migrations for this cycle.")
            return True

        try:
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
        except Exception as e:
            logger.warning("Table 'users' setup warning: %s", e)

        try:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
                    scan_id         VARCHAR(36) UNIQUE,
                    target          VARCHAR(512) NOT NULL,
                    asset_class     VARCHAR(64),
                    status          VARCHAR(32),
                    started_at      DATETIME,
                    completed_at    DATETIME,
                    scanned_at      DATETIME,
                    total_assets    INT          DEFAULT 0,
                    compliance_score INT         DEFAULT 0,
                    overall_pqc_score DOUBLE,
                    quantum_safe    INT          DEFAULT 0,
                    quantum_vuln    INT          DEFAULT 0,
                    cbom_path       VARCHAR(500),
                    report_json     LONGTEXT     NOT NULL,
                    is_encrypted    BOOLEAN      DEFAULT FALSE,
                    created_at      DATETIME     DEFAULT CURRENT_TIMESTAMP,
                    is_deleted      BOOLEAN      DEFAULT FALSE,
                    deleted_at      DATETIME,
                    deleted_by_user_id VARCHAR(36),
                    INDEX idx_scans_status (status),
                    INDEX idx_scans_started_at (started_at)
                ) ENGINE=InnoDB
            """)
            _ensure_scans_id_column(cur)
        except Exception as e:
            logger.warning("Table 'scans' setup warning: %s", e)

        # Commit core tables to persist state
        try:
            conn.commit()
            logger.debug("Core tables (users, scans) committed")
        except Exception as e:
            # Transient connection/lock issues with DDL may occur under reloader races.
            logger.warning("Commit after base table setup failed: %s", e)
            try:
                conn.rollback()
            except Exception:
                pass
            raise

        try:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS asset_dns_records (
                    id            BIGINT AUTO_INCREMENT PRIMARY KEY,
                    scan_id       VARCHAR(36) NOT NULL,
                    hostname      VARCHAR(255) NOT NULL,
                    record_type   VARCHAR(16) NOT NULL,
                    record_value  VARCHAR(1024) NOT NULL,
                    ttl           INT DEFAULT 300,
                    resolved_at   DATETIME,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                        ON DELETE CASCADE,
                    INDEX idx_dns_scan_id (scan_id),
                    INDEX idx_dns_hostname (hostname)
                ) ENGINE=InnoDB
            """)
        except Exception as e:
            logger.warning("Table 'asset_dns_records' setup warning: %s", e)

        try:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cbom_reports (
                    scan_id      VARCHAR(36) PRIMARY KEY,
                    cbom_json    LONGTEXT NOT NULL,
                    is_encrypted BOOLEAN  DEFAULT FALSE,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                        ON DELETE CASCADE
                ) ENGINE=InnoDB
            """)
        except Exception as e:
            logger.warning("Table 'cbom_reports' setup warning: %s", e)

        try:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS audit_log_chain (
                    id             TINYINT PRIMARY KEY,
                    last_entry_id  BIGINT,
                    last_hash      CHAR(64),
                    updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP
                        ON UPDATE CURRENT_TIMESTAMP
                ) ENGINE=InnoDB
            """)
        except Exception as e:
            logger.warning("Table 'audit_log_chain' setup warning: %s", e)

        user_id_column_type = _get_users_id_column_type(cur)

        try:
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
        except Exception as e:
            logger.warning("Table 'audit_logs' setup warning: %s", e)

        try:
            cur.execute(f"""
                CREATE TABLE IF NOT EXISTS report_schedules (
                    schedule_id     VARCHAR(36) PRIMARY KEY,
                    created_by_id   {user_id_column_type},
                    created_by_name VARCHAR(150),
                    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    enabled         BOOLEAN DEFAULT TRUE,
                    report_type     VARCHAR(120) NOT NULL,
                    frequency       VARCHAR(32) NOT NULL,
                    assets          VARCHAR(256),
                    sections_json   LONGTEXT,
                    schedule_date   VARCHAR(20),
                    schedule_time   VARCHAR(10),
                    timezone_name   VARCHAR(64),
                    email_list      VARCHAR(512),
                    save_path       VARCHAR(512),
                    download_link   BOOLEAN DEFAULT FALSE,
                    status          VARCHAR(32) DEFAULT 'scheduled',
                    FOREIGN KEY (created_by_id) REFERENCES users(id)
                        ON DELETE SET NULL,
                    INDEX idx_report_schedules_created_at (created_at),
                    INDEX idx_report_schedules_status (status)
                ) ENGINE=InnoDB
            """)
        except Exception as e:
            logger.warning("Table 'report_schedules' setup warning: %s", e)

        try:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS assets (
                    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
                    target      VARCHAR(512) UNIQUE NOT NULL,
                    type        VARCHAR(64),
                    owner       VARCHAR(150),
                    risk_level  VARCHAR(32),
                    notes       TEXT,
                    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                ) ENGINE=InnoDB
            """)
        except Exception as e:
            logger.warning("Table 'assets' setup warning: %s", e)

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
            "ALTER TABLE cbom_reports ADD COLUMN is_encrypted BOOLEAN DEFAULT FALSE",
            "ALTER TABLE cbom_reports MODIFY COLUMN cbom_json LONGTEXT NOT NULL",
            # API key column — graceful; ignored if already present
            "ALTER TABLE users ADD COLUMN api_key_hash CHAR(64) UNIQUE",
            "ALTER TABLE report_schedules ADD COLUMN created_by_id VARCHAR(36)",
            "ALTER TABLE report_schedules ADD COLUMN created_by_name VARCHAR(150)",
            "ALTER TABLE report_schedules ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP",
            "ALTER TABLE report_schedules ADD COLUMN enabled BOOLEAN DEFAULT TRUE",
            "ALTER TABLE report_schedules ADD COLUMN report_type VARCHAR(120) NOT NULL",
            "ALTER TABLE report_schedules ADD COLUMN frequency VARCHAR(32) NOT NULL",
            "ALTER TABLE report_schedules ADD COLUMN assets VARCHAR(256)",
            "ALTER TABLE report_schedules ADD COLUMN sections_json LONGTEXT",
            "ALTER TABLE report_schedules ADD COLUMN schedule_date VARCHAR(20)",
            "ALTER TABLE report_schedules ADD COLUMN schedule_time VARCHAR(10)",
            "ALTER TABLE report_schedules ADD COLUMN timezone_name VARCHAR(64)",
            "ALTER TABLE report_schedules ADD COLUMN email_list VARCHAR(512)",
            "ALTER TABLE report_schedules ADD COLUMN save_path VARCHAR(512)",
            "ALTER TABLE report_schedules ADD COLUMN download_link BOOLEAN DEFAULT FALSE",
            "ALTER TABLE report_schedules ADD COLUMN status VARCHAR(32) DEFAULT 'scheduled'",
            "ALTER TABLE report_schedules ADD CONSTRAINT fk_report_schedules_created_by FOREIGN KEY (created_by_id) REFERENCES users(id) ON DELETE SET NULL",
            "ALTER TABLE asset_dns_records ADD COLUMN ttl INT DEFAULT 300",
            "ALTER TABLE asset_dns_records ADD COLUMN resolved_at DATETIME",
            "ALTER TABLE scans ADD COLUMN IF NOT EXISTS started_at DATETIME",
            "ALTER TABLE scans ADD COLUMN IF NOT EXISTS completed_at DATETIME",
            "ALTER TABLE scans ADD COLUMN IF NOT EXISTS asset_class VARCHAR(64)",
            "ALTER TABLE scans ADD COLUMN IF NOT EXISTS cbom_path VARCHAR(500)",
            "ALTER TABLE scans ADD COLUMN IF NOT EXISTS is_encrypted BOOLEAN DEFAULT FALSE",
            "ALTER TABLE scans ADD COLUMN IF NOT EXISTS created_at DATETIME DEFAULT CURRENT_TIMESTAMP",
            "ALTER TABLE assets ADD COLUMN IF NOT EXISTS target VARCHAR(512) UNIQUE",
            "ALTER TABLE assets ADD COLUMN IF NOT EXISTS name VARCHAR(255)",
        ]:
            try:
                cur.execute(alter_cmd)
            except Exception:
                pass # Column likely already exists

        # Normalize legacy scans tables that were created by older ORM metadata.
        try:
            cur.execute("UPDATE scans SET scan_id = UUID() WHERE scan_id IS NULL OR scan_id = ''")
        except Exception:
            pass
        try:
            cur.execute("ALTER TABLE scans MODIFY COLUMN scan_id VARCHAR(36) NOT NULL")
        except Exception:
            pass
        try:
            cur.execute("CREATE UNIQUE INDEX uq_scans_scan_id ON scans(scan_id)")
        except Exception:
            pass

        # Backfill/repair legacy scans schema for SQLAlchemy compatibility.
        try:
            _ensure_scans_id_column(cur)
        except Exception as e:
            logger.warning("Failed to enforce scans.id compatibility: %s", e)

        # Backfill/repair legacy assets schema for SQLAlchemy compatibility.
        try:
            _ensure_assets_name_and_target_columns(cur)
        except Exception as e:
            logger.warning("Failed to enforce assets target/name compatibility: %s", e)

        # Align report_schedules FK type with users.id type for mixed legacy installs.
        try:
            cur.execute(f"ALTER TABLE report_schedules MODIFY COLUMN created_by_id {user_id_column_type}")
        except Exception:
            pass

        # Initialize audit_log_chain (non-fatal if fails)
        try:
            cur.execute(
                "INSERT IGNORE INTO audit_log_chain (id, last_entry_id, last_hash) VALUES (1, NULL, %s)",
                ("0" * 64,),
            )
            conn.commit()
        except Exception as e:
            logger.warning("Could not initialize audit_log_chain: %s", e)
            try:
                conn.rollback()
            except Exception as rollback_error:
                logger.debug("Rollback after audit_log_chain failure failed: %s", rollback_error)

        # Create triggers (non-fatal if fail)
        try:
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
            conn.commit()
        except Exception as e:
            logger.warning("Could not create triggers: %s", e)
            try:
                conn.rollback()
            except Exception as rollback_error:
                logger.debug("Rollback after trigger creation failure failed: %s", rollback_error)

        # Seed default admin if no users exist (non-fatal if fails)
        try:
            cur.execute("SELECT COUNT(*) FROM users")
            _users_count_row = cur.fetchone()
            users_count = int(_users_count_row[0]) if _users_count_row and _users_count_row[0] is not None else 0
            if users_count == 0:
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
        except Exception as e:
            logger.warning("Could not seed default admin user: %s", e)
            conn.rollback()

        conn.commit()
        logger.info("MySQL database '%s' initialised successfully.", MYSQL_DATABASE)
        return True
    except Exception as exc:
        logger.error("MySQL init_db error: %s | Type: %s | Details: %r", exc, type(exc).__name__, exc.args)
        import traceback
        logger.error("Traceback: %s", traceback.format_exc())
        return False
    finally:
        if 'conn' in locals() and conn:
            try:
                if migration_lock_acquired:
                    _cur = conn.cursor()
                    _cur.execute("DO RELEASE_LOCK(%s)", (migration_lock_name,))
            except Exception:
                pass
        conn.close()
    return False


def save_asset(asset: Dict[str, Any]) -> bool:
    """Saves or Updates asset metadata in MySQL."""
    conn = _get_connection()
    if conn is None: return False
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO assets (target, name, type, owner, risk_level, notes)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                target = VALUES(target),
                name = VALUES(name),
                type = VALUES(type),
                owner = VALUES(owner),
                risk_level = VALUES(risk_level),
                notes = VALUES(notes)
        """, (
            asset.get("target"),
            asset.get("name") or asset.get("target"),
            asset.get("type"),
            asset.get("owner"),
            asset.get("risk_level"),
            asset.get("notes")
        ))
        conn.commit()
        return True
    except Exception as e:
        if logger: logger.error(f"save_asset error: {e}")
        return False
    finally: conn.close()
    return False

def delete_asset(target: str) -> bool:
    """Deletes an asset from MySQL by target hostname or IP."""
    conn = _get_connection()
    if conn is None: return False
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM assets WHERE target = %s", (target,))
        conn.commit()
        return True
    except Exception as e:
        if logger: logger.error(f"delete_asset error: {e}")
        return False
    finally: conn.close()
    return False

def list_assets() -> List[Dict[str, Any]]:
    """Lists all stored assets with metadata."""
    conn = _get_connection()
    if conn is None: return []
    try:
        cur = conn.cursor(pymysql.cursors.DictCursor)
        # Using dictionary=True depends on driver support; fallback standard cursor if fails
        cur.execute("SELECT * FROM assets ORDER BY created_at DESC")
        columns = [desc[0] for desc in cur.description]
        return [dict(zip(columns, row)) for row in cur.fetchall()]
    except Exception as e:
        if logger: logger.error(f"list_assets error: {e}")
        return []
    finally: conn.close()


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

        # Preserve compatibility with reports that use started_at in queries.
        started_at = report.get("started_at") or scanned_at
        if isinstance(started_at, str):
            try:
                started_at = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
            except Exception:
                started_at = scanned_at

        cur.execute(
            """
            INSERT INTO scans
                (scan_id, target, asset_class, status, compliance_score,
                 total_assets, quantum_safe, quantum_vuln,
                 scanned_at, report_json, is_encrypted, started_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                asset_class      = VALUES(asset_class),
                status           = VALUES(status),
                compliance_score = VALUES(compliance_score),
                total_assets     = VALUES(total_assets),
                quantum_safe     = VALUES(quantum_safe),
                quantum_vuln     = VALUES(quantum_vuln),
                scanned_at       = VALUES(scanned_at),
                report_json      = VALUES(report_json),
                is_encrypted     = VALUES(is_encrypted),
                started_at       = VALUES(started_at)
            """,
            (
                report.get("scan_id", ""),
                report.get("target", ""),
                report.get("asset_class", "Other"),
                report.get("status", ""),
                overview.get("average_compliance_score", 0),
                overview.get("total_assets", 0),
                overview.get("quantum_safe", 0),
                overview.get("quantum_vulnerable", 0),
                scanned_at,
                json_str,
                is_encrypted,
                started_at,
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


def get_enterprise_metrics() -> Dict[str, Any]:
    """Retrieve aggregated enterprise metrics directly via MySQL queries for O(1) dashboard loading."""
    conn = _get_connection()
    metrics = {
        "total_assets": 0,
        "quantum_safe": 0,
        "quantum_vulnerable": 0,
        "total_score": 0,
        "scan_count": 0,
        "avg_score": 0,
        "critical_findings": 0,
        "api_services": 0,
        "asset_class_distribution": {},
        "risk_distribution": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
        "ssl_expiry": {"0-30": 0, "30-60": 0, "60-90": 0, ">90": 0},
        "ssl_expiry_extended": {"Expired": 0, "0-7": 0, "8-30": 0, "31-90": 0, ">90": 0},
        "ip_breakdown": {"IPv4": 0, "IPv6": 0},
        "crypto_overview": [],
        "certificate_inventory": [],
        "dns_records_total": 0,
        "latest_scan": "",
    }
    if conn is None:
        return metrics

    try:
        cur = conn.cursor(pymysql.cursors.DictCursor)
        # 1. Base Aggregates
        cur.execute("""
            SELECT 
                COUNT(*) as scan_count,
                SUM(total_assets) as total_assets,
                SUM(quantum_safe) as quantum_safe,
                SUM(quantum_vuln) as quantum_vulnerable,
                AVG(compliance_score) as avg_score,
                MAX(scanned_at) as latest_scan
            FROM scans 
            WHERE status = 'complete'
        """)
        row = cur.fetchone()
        if row and row.get("scan_count", 0) > 0:
            metrics["scan_count"] = row.get("scan_count") or 0
            metrics["total_assets"] = int(row.get("total_assets") or 0)
            metrics["quantum_safe"] = int(row.get("quantum_safe") or 0)
            metrics["quantum_vulnerable"] = int(row.get("quantum_vulnerable") or 0)
            metrics["avg_score"] = int(row.get("avg_score") or 0)
            if row.get("latest_scan"):
                metrics["latest_scan"] = row["latest_scan"].isoformat()

        # 2. Asset Class Distribution
        cur.execute("""
            SELECT asset_class, COUNT(*) as cnt 
            FROM scans 
            WHERE status = 'complete' 
            GROUP BY asset_class
        """)
        for r in cur.fetchall():
            cls = r.get("asset_class") or "Other"
            metrics["asset_class_distribution"][cls] = r.get("cnt", 0)

        # 3. DNS Records Total
        cur.execute("SELECT COUNT(*) as cnt FROM asset_dns_records")
        metrics["dns_records_total"] = cur.fetchone().get("cnt", 0)

        # 4. Critical Findings and Complex Metrics via latest scan payloads
        # Since full report_json traversal is heavy for 1000s records, we aggregate from the top 50 recent complete scans.
        cur.execute("""
            SELECT report_json, is_encrypted 
            FROM scans 
            WHERE status = 'complete' 
            ORDER BY scanned_at DESC 
            LIMIT 20
        """)
        scans_data = cur.fetchall()
        
        class_counter = {}
        for r in scans_data:
            data = r.get("report_json")
            if r.get("is_encrypted") and isinstance(data, str):
                data = _decrypt_data(data)
            try:
                scan = json.loads(data) if isinstance(data, str) else data
            except (TypeError, json.JSONDecodeError):
                continue

            # Count critical findings
            for finding in scan.get("findings", []):
                if isinstance(finding, dict) and finding.get("severity", "").upper() == "CRITICAL":
                    metrics["critical_findings"] += 1

            # Discovered services & IP breakdown
            for svc in scan.get("discovered_services", []):
                if "api" in str(svc.get("service") or "").lower():
                    metrics["api_services"] += 1
                host = str(svc.get("host") or "")
                if ":" in host:
                    metrics["ip_breakdown"]["IPv6"] += 1
                elif host and host[0].isdigit():
                    metrics["ip_breakdown"]["IPv4"] += 1

            # Risk Distribution
            score_val = float(scan.get("overview", {}).get("average_compliance_score") or 0)
            # Define risk range local to avoid circle
            if score_val >= 90: risk = "Low"
            elif score_val >= 70: risk = "Medium"
            elif score_val >= 50: risk = "High"
            else: risk = "Critical"
            
            if risk in metrics["risk_distribution"]:
                metrics["risk_distribution"][risk] += 1

            # TLS & Crypto Overview
            for tr_raw in scan.get("tls_results", []):
                tr = tr_raw if isinstance(tr_raw, dict) else {}
                days = tr.get("cert_days_remaining")
                if isinstance(days, (int, float)):
                    if days <= 30: metrics["ssl_expiry"]["0-30"] += 1
                    elif days <= 60: metrics["ssl_expiry"]["30-60"] += 1
                    elif days <= 90: metrics["ssl_expiry"]["60-90"] += 1
                    else: metrics["ssl_expiry"][">90"] += 1

                    if days < 0: metrics["ssl_expiry_extended"]["Expired"] += 1
                    elif days <= 7: metrics["ssl_expiry_extended"]["0-7"] += 1
                    elif days <= 30: metrics["ssl_expiry_extended"]["8-30"] += 1
                    elif days <= 90: metrics["ssl_expiry_extended"]["31-90"] += 1
                    else: metrics["ssl_expiry_extended"][">90"] += 1

                issuer = tr.get("issuer") if isinstance(tr.get("issuer"), dict) else {}
                subject = tr.get("subject") if isinstance(tr.get("subject"), dict) else {}
                
                metrics["crypto_overview"].append({
                    "asset": scan.get("target", ""),
                    "key_length": tr.get("key_size") or tr.get("key_length") or 0,
                    "cipher_suite": (tr.get("cipher_suites") or ["Unknown"])[0],
                    "tls_version": tr.get("tls_version") or "Unknown",
                    "ca": issuer.get("O") or issuer.get("CN") or "Unknown",
                })

                metrics["certificate_inventory"].append({
                    "asset": scan.get("target", ""),
                    "common_name": subject.get("CN") or subject.get("commonName") or scan.get("target", ""),
                    "issuer": issuer.get("O") or issuer.get("CN") or "Unknown",
                    "signature_algorithm": tr.get("signature_algorithm") or "Unknown",
                    "key_length": tr.get("key_size") or tr.get("key_length") or 0,
                    "tls_version": tr.get("tls_version") or "Unknown",
                    "valid_to": tr.get("valid_to") or "",
                    "days_remaining": days if isinstance(days, (int, float)) else None,
                    "status": tr.get("cert_status") or "Unknown",
                })

        metrics["crypto_overview"] = metrics["crypto_overview"][:20]
        metrics["certificate_inventory"] = sorted(
            metrics["certificate_inventory"],
            key=lambda row: 10**9 if row.get("days_remaining") is None else int(row.get("days_remaining")),
        )[:30]

        return metrics

    except Exception as exc:
        logger.error("get_enterprise_metrics SQL error: %s", exc)
        return metrics
    finally:
        conn.close()



def save_dns_records(scan_id: str, records: List[Dict[str, Any]]) -> bool:
    """Persist DNS records discovered during a scan."""
    conn = _get_connection()
    if conn is None:
        return False
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM asset_dns_records WHERE scan_id = %s", (scan_id,))
        for record in records:
            resolved = record.get("resolved_at")
            resolved_at = None
            if isinstance(resolved, str) and resolved:
                try:
                    resolved_at = datetime.fromisoformat(resolved.replace("Z", "+00:00")).replace(tzinfo=None)
                except ValueError:
                    resolved_at = _utcnow()
            cur.execute(
                """
                INSERT INTO asset_dns_records
                    (scan_id, hostname, record_type, record_value, ttl, resolved_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    scan_id,
                    str(record.get("hostname") or ""),
                    str(record.get("record_type") or "A"),
                    str(record.get("record_value") or ""),
                    int(record.get("ttl") or 300),
                    resolved_at,
                ),
            )
        conn.commit()
        return True
    except Exception as exc:
        logger.error("save_dns_records failed: %s", exc)
        return False
    finally:
        conn.close()


def list_dns_records(scan_id: Optional[str] = None, limit: int = 500) -> List[Dict[str, Any]]:
    """Return DNS records, optionally filtered by scan_id."""
    conn = _get_connection()
    if conn is None:
        return []
    try:
        cur = conn.cursor(pymysql.cursors.DictCursor)
        if scan_id:
            cur.execute(
                """
                SELECT scan_id, hostname, record_type, record_value, ttl, resolved_at
                FROM asset_dns_records
                WHERE scan_id = %s
                ORDER BY id DESC
                LIMIT %s
                """,
                (scan_id, limit),
            )
        else:
            cur.execute(
                """
                SELECT scan_id, hostname, record_type, record_value, ttl, resolved_at
                FROM asset_dns_records
                ORDER BY id DESC
                LIMIT %s
                """,
                (limit,),
            )
        rows = cur.fetchall() or []
        out = []
        for row in rows:
            ttl_raw = row.get("ttl")
            try:
                ttl_value = int(ttl_raw) if ttl_raw is not None else 300
            except (TypeError, ValueError):
                ttl_value = 300
            out.append(
                {
                    "scan_id": row.get("scan_id"),
                    "hostname": row.get("hostname"),
                    "record_type": row.get("record_type"),
                    "record_value": row.get("record_value"),
                    "ttl": ttl_value,
                    "resolved_at": row.get("resolved_at").isoformat() if row.get("resolved_at") else "",
                }
            )
        return out
    except Exception as exc:
        logger.error("list_dns_records failed: %s", exc)
        return []
    finally:
        conn.close()


def save_report_schedule(schedule: Dict[str, Any]) -> bool:
    """Persist one report schedule in MySQL."""
    conn = _get_connection()
    if conn is None:
        return False
    try:
        cur = conn.cursor()
        sections = schedule.get("sections")
        sections_json = json.dumps(sections if isinstance(sections, list) else [], ensure_ascii=False)
        cur.execute(
            """
            INSERT INTO report_schedules
                (schedule_id, created_by_id, created_by_name, created_at, enabled,
                 report_type, frequency, assets, sections_json, schedule_date,
                 schedule_time, timezone_name, email_list, save_path, download_link, status)
            VALUES
                (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                enabled = VALUES(enabled),
                report_type = VALUES(report_type),
                frequency = VALUES(frequency),
                assets = VALUES(assets),
                sections_json = VALUES(sections_json),
                schedule_date = VALUES(schedule_date),
                schedule_time = VALUES(schedule_time),
                timezone_name = VALUES(timezone_name),
                email_list = VALUES(email_list),
                save_path = VALUES(save_path),
                download_link = VALUES(download_link),
                status = VALUES(status)
            """,
            (
                schedule.get("id"),
                schedule.get("created_by_id"),
                schedule.get("created_by"),
                _utcnow(),
                bool(schedule.get("enabled", True)),
                schedule.get("report_type", "Executive Summary Report"),
                schedule.get("frequency", "Weekly"),
                schedule.get("assets", "All Assets"),
                sections_json,
                schedule.get("schedule_date", ""),
                schedule.get("schedule_time", ""),
                schedule.get("timezone", "UTC"),
                schedule.get("email_list", ""),
                schedule.get("save_path", ""),
                bool(schedule.get("download_link", False)),
                schedule.get("status", "scheduled"),
            ),
        )
        conn.commit()
        return True
    except Exception as exc:
        logger.error("save_report_schedule failed: %s", exc)
        return False
    finally:
        conn.close()


def list_report_schedules(limit: int = 500) -> List[Dict[str, Any]]:
    """Return report schedules ordered by created_at descending."""
    conn = _get_connection()
    if conn is None:
        return []
    try:
        cur = conn.cursor(pymysql.cursors.DictCursor)
        cur.execute(
            """
            SELECT schedule_id, created_by_id, created_by_name, created_at, enabled,
                   report_type, frequency, assets, sections_json, schedule_date,
                   schedule_time, timezone_name, email_list, save_path, download_link, status
            FROM report_schedules
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (limit,),
        )
        rows = cur.fetchall() or []
        out = []
        for row in rows:
            sections = []
            raw_sections = row.get("sections_json")
            if isinstance(raw_sections, str) and raw_sections:
                try:
                    sections = json.loads(raw_sections)
                except json.JSONDecodeError:
                    sections = []
            out.append(
                {
                    "id": row.get("schedule_id"),
                    "created_by_id": row.get("created_by_id"),
                    "created_by": row.get("created_by_name"),
                    "created_at": row.get("created_at").isoformat() if row.get("created_at") else "",
                    "enabled": bool(row.get("enabled")),
                    "report_type": row.get("report_type"),
                    "frequency": row.get("frequency"),
                    "assets": row.get("assets"),
                    "sections": sections,
                    "schedule_date": row.get("schedule_date"),
                    "schedule_time": row.get("schedule_time"),
                    "timezone": row.get("timezone_name"),
                    "email_list": row.get("email_list"),
                    "save_path": row.get("save_path"),
                    "download_link": bool(row.get("download_link")),
                    "status": row.get("status"),
                }
            )
        return out
    except Exception as exc:
        logger.error("list_report_schedules failed: %s", exc)
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
        cur = conn.cursor(pymysql.cursors.DictCursor)
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
        cur = conn.cursor(pymysql.cursors.DictCursor)
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
        cur = conn.cursor(pymysql.cursors.DictCursor)
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
        cur = conn.cursor(pymysql.cursors.DictCursor)
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
        return list(users)
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
        cur = conn.cursor(pymysql.cursors.DictCursor)
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
        cur = conn.cursor(pymysql.cursors.DictCursor)
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
        cur = conn.cursor(pymysql.cursors.DictCursor)
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
        chain_cur = conn.cursor(pymysql.cursors.DictCursor)
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
        cur = conn.cursor(pymysql.cursors.DictCursor)
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
        return list(rows)
    finally:
        conn.close()


def verify_audit_log_chain(limit: int = 500) -> Tuple[bool, List[str]]:
    conn = _get_connection()
    if conn is None:
        return False, ["Database unavailable"]
    try:
        cur = conn.cursor(pymysql.cursors.DictCursor)
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
