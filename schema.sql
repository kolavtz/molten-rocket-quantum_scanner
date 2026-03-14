-- QuantumShield Production Schema
-- Compatible with MySQL 8.0+

CREATE DATABASE IF NOT EXISTS quantumshield
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
USE quantumshield;

-- ------------------------------------------------------------------
-- Users / RBAC / Credentials
-- Roles supported by app: Admin, Manager, SingleScan, Viewer
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id                          VARCHAR(36) PRIMARY KEY,
    employee_id                 VARCHAR(64) UNIQUE,
    username                    VARCHAR(150) NOT NULL UNIQUE,
    email                       VARCHAR(255) UNIQUE,
    password_hash               VARCHAR(255) NOT NULL,
    role                        VARCHAR(50) NOT NULL,
    created_by                  VARCHAR(36),
    is_active                   BOOLEAN NOT NULL DEFAULT TRUE,
    password_setup_token_hash   CHAR(64) UNIQUE,
    password_setup_token_expiry DATETIME,
    must_change_password        BOOLEAN NOT NULL DEFAULT TRUE,
    failed_login_attempts       INT NOT NULL DEFAULT 0,
    lockout_until               DATETIME,
    last_login_at               DATETIME,
    password_changed_at         DATETIME,
    created_at                  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_users_created_by
      FOREIGN KEY (created_by) REFERENCES users(id)
      ON DELETE SET NULL,
    CONSTRAINT chk_users_role
      CHECK (role IN ('Admin', 'Manager', 'SingleScan', 'Viewer'))
) ENGINE=InnoDB;

CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_active_role ON users(is_active, role);
CREATE INDEX idx_users_email ON users(email);

-- ------------------------------------------------------------------
-- Scan reports (encrypted at rest if app key is configured)
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scans (
    scan_id          VARCHAR(36) PRIMARY KEY,
    target           VARCHAR(512) NOT NULL,
    status           VARCHAR(32),
    compliance_score INT          DEFAULT 0,
    total_assets     INT          DEFAULT 0,
    quantum_safe     INT          DEFAULT 0,
    quantum_vuln     INT          DEFAULT 0,
    scanned_at       DATETIME,
    report_json      LONGTEXT     NOT NULL,
    is_encrypted     BOOLEAN      DEFAULT FALSE,
    INDEX idx_scans_target (target),
    INDEX idx_scans_scanned_at (scanned_at),
    INDEX idx_scans_status (status)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS cbom_reports (
    scan_id      VARCHAR(36) PRIMARY KEY,
    cbom_json    LONGTEXT NOT NULL,
    is_encrypted BOOLEAN  DEFAULT FALSE,
    CONSTRAINT fk_cbom_scan
      FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
      ON DELETE CASCADE
) ENGINE=InnoDB;

-- ------------------------------------------------------------------
-- Bootstrap admin account
-- IMPORTANT: replace the password hash before production use.
-- Hash below corresponds to temporary password: admin123
-- ------------------------------------------------------------------
INSERT IGNORE INTO users
    (id, employee_id, username, email, password_hash, role, is_active, must_change_password)
VALUES
    (
        UUID(),
        'ADMIN-001',
        'admin',
        'admin@localhost',
        'scrypt:32768:8:1$6R9Qh0qv4u4xrL7T$30be14ad96e6ce5ecc50e08621f2baf9b5b0f2e295f36ed1917fd9fa4a727dfdd5b6d4f9f96d07f8534cce14e4290af04076eb7e8228c6544c17d9d4c1804f58',
        'Admin',
        TRUE,
        TRUE
    );
