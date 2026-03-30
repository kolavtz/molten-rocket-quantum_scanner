-- QuantumShield — Production MySQL Schema
-- Initial Setup for Quantum-Safe TLS Scanner

CREATE DATABASE IF NOT EXISTS `quantumshield` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `quantumshield`;

-- 1. Users Table (RBAC / Auth)
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
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- 2. Scans Table (Results Metadata)
CREATE TABLE IF NOT EXISTS scans (
    scan_id          VARCHAR(36)  PRIMARY KEY,
    target           VARCHAR(512) NOT NULL,
    asset_class      VARCHAR(64),
    status           VARCHAR(32),
    compliance_score INT          DEFAULT 0,
    total_assets     INT          DEFAULT 0,
    quantum_safe     INT          DEFAULT 0,
    quantum_vuln     INT          DEFAULT 0,
    scanned_at       DATETIME,
    report_json      LONGTEXT     NOT NULL,
    is_encrypted     BOOLEAN      DEFAULT FALSE
) ENGINE=InnoDB;

-- 3. DNS Records Table
CREATE TABLE IF NOT EXISTS asset_dns_records (
    id            BIGINT AUTO_INCREMENT PRIMARY KEY,
    scan_id       VARCHAR(36) NOT NULL,
    hostname      VARCHAR(255) NOT NULL,
    record_type   VARCHAR(16) NOT NULL,
    record_value  VARCHAR(1024) NOT NULL,
    ttl           INT DEFAULT 300,
    resolved_at   DATETIME,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
    INDEX idx_dns_scan_id (scan_id),
    INDEX idx_dns_hostname (hostname)
) ENGINE=InnoDB;

-- 4. CBOM Reports Table
CREATE TABLE IF NOT EXISTS cbom_reports (
    scan_id      VARCHAR(36) PRIMARY KEY,
    cbom_json    LONGTEXT NOT NULL,
    is_encrypted BOOLEAN  DEFAULT FALSE,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 5. Audit Log Chain (Consistency Check)
CREATE TABLE IF NOT EXISTS audit_log_chain (
    id             TINYINT PRIMARY KEY,
    last_entry_id  BIGINT,
    last_hash      CHAR(64),
    updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 6. Audit Logs Table (Immutable Event History)
CREATE TABLE IF NOT EXISTS audit_logs (
    id               BIGINT AUTO_INCREMENT PRIMARY KEY,
    actor_user_id    VARCHAR(36),
    actor_username   VARCHAR(150),
    event_category   VARCHAR(64) NOT NULL,
    event_type       VARCHAR(128) NOT NULL,
    target_user_id   VARCHAR(36),
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
    FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (target_user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (target_scan_id) REFERENCES scans(scan_id) ON DELETE SET NULL,
    INDEX idx_audit_created_at (created_at),
    INDEX idx_audit_category (event_category),
    INDEX idx_audit_actor (actor_user_id)
) ENGINE=InnoDB;

-- 7. Report Schedules (Executive / Scheduled Reporting)
CREATE TABLE IF NOT EXISTS report_schedules (
    schedule_id     VARCHAR(36) PRIMARY KEY,
    created_by_id   VARCHAR(36),
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
    FOREIGN KEY (created_by_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_report_schedules_created_at (created_at),
    INDEX idx_report_schedules_status (status)
) ENGINE=InnoDB;

-- 8. Assets Table (Inventory source of truth + soft delete support)
CREATE TABLE IF NOT EXISTS assets (
    id                 BIGINT AUTO_INCREMENT PRIMARY KEY,
    target             VARCHAR(512) NOT NULL UNIQUE,
    name               VARCHAR(255),
    url                VARCHAR(255),
    ipv4               VARCHAR(50),
    ipv6               VARCHAR(50),
    asset_type         VARCHAR(50) DEFAULT 'Web App',
    type               VARCHAR(64),
    owner              VARCHAR(150),
    risk_level         VARCHAR(32),
    notes              TEXT,
    last_scan_id       BIGINT,
    is_deleted         BOOLEAN DEFAULT FALSE,
    deleted_at         DATETIME,
    deleted_by_user_id BIGINT,
    created_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_assets_is_deleted (is_deleted)
) ENGINE=InnoDB;

-- 9. Immutability Triggers
-- Prevent updates to audit logs
DELIMITER //
CREATE TRIGGER audit_logs_no_update
BEFORE UPDATE ON audit_logs
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_logs is append-only';
END;
//

-- Prevent deletions from audit logs
CREATE TRIGGER audit_logs_no_delete
BEFORE DELETE ON audit_logs
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_logs cannot be deleted';
END;
//

-- Prevent deletions from audit log chain
CREATE TRIGGER audit_log_chain_no_delete
BEFORE DELETE ON audit_log_chain
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log_chain cannot be deleted';
END;
//
DELIMITER ;

-- 10. Initial Seed Data
INSERT IGNORE INTO audit_log_chain (id, last_entry_id, last_hash) 
VALUES (1, NULL, '0000000000000000000000000000000000000000000000000000000000000000');

-- 11. Compatibility migrations for legacy installs
-- Some historical builds created `scans` with `id` and without `scan_id`/`report_json`.
ALTER TABLE scans ADD COLUMN IF NOT EXISTS scan_id VARCHAR(36);
ALTER TABLE scans ADD COLUMN IF NOT EXISTS report_json LONGTEXT NOT NULL;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS scanned_at DATETIME;
UPDATE scans SET scan_id = UUID() WHERE scan_id IS NULL OR scan_id = '';
ALTER TABLE scans MODIFY COLUMN scan_id VARCHAR(36) NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_scans_scan_id ON scans(scan_id);

-- Soft-delete compatibility for legacy `assets` table definitions.
ALTER TABLE assets ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN DEFAULT FALSE;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS deleted_at DATETIME;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS deleted_by_user_id BIGINT;
CREATE INDEX IF NOT EXISTS idx_assets_is_deleted ON assets(is_deleted);

-- Note: Admin user will be auto-generated by the application on first cold start
-- using the QSS_ADMIN_* environment variables in .env file.
