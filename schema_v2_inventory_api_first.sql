-- QuantumShield GLOBAL_APP_REFACTOR_V2
-- Inventory-centric, API-first, MySQL-only source of truth
-- No seed/demo rows included by design.

CREATE DATABASE IF NOT EXISTS `quantumshield`
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
USE `quantumshield`;

-- Full canonical reset for deterministic restores on legacy/drifted databases.
-- WARNING: This removes existing schema objects (structure + data) listed below.
SET FOREIGN_KEY_CHECKS = 0;
DROP VIEW IF EXISTS v_inventory_cyber_rating;
DROP VIEW IF EXISTS v_inventory_compliance;
DROP VIEW IF EXISTS v_inventory_cbom_entries;
DROP VIEW IF EXISTS v_inventory_pqc;
DROP VIEW IF EXISTS v_inventory_certificates;
DROP VIEW IF EXISTS v_inventory_assets;

DROP TABLE IF EXISTS report_request_assets;
DROP TABLE IF EXISTS report_schedule_assets;
DROP TABLE IF EXISTS report_requests;
DROP TABLE IF EXISTS report_schedule;
DROP TABLE IF EXISTS report_schedules;
DROP TABLE IF EXISTS cyber_rating;
DROP TABLE IF EXISTS compliance_scores;
DROP TABLE IF EXISTS cbom_entries;
DROP TABLE IF EXISTS cbom_summary;
DROP TABLE IF EXISTS cbom_reports;
DROP TABLE IF EXISTS pqc_classification;
DROP TABLE IF EXISTS certificates;
DROP TABLE IF EXISTS discovery_items;
DROP TABLE IF EXISTS discovery_software;
DROP TABLE IF EXISTS discovery_ips;
DROP TABLE IF EXISTS discovery_ssl;
DROP TABLE IF EXISTS discovery_domains;
DROP TABLE IF EXISTS asset_dns_records;
DROP TABLE IF EXISTS audit_log_chain;
DROP TABLE IF EXISTS scans;
DROP TABLE IF EXISTS assets;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS users;
SET FOREIGN_KEY_CHECKS = 1;

-- ------------------------------------------------------------
-- Core identity and auditing
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS users (
    id                          VARCHAR(36) PRIMARY KEY,
    employee_id                 VARCHAR(64) UNIQUE,
    username                    VARCHAR(150) UNIQUE NOT NULL,
    email                       VARCHAR(255) UNIQUE,
    password_hash               VARCHAR(255) NOT NULL,
    role                        ENUM('Admin','Manager','SingleScan','Viewer') NOT NULL DEFAULT 'Viewer',
    created_by                  VARCHAR(36) NULL,
    is_active                   BOOLEAN NOT NULL DEFAULT TRUE,
    api_key_hash                CHAR(64) UNIQUE,
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
      ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_logs (
    id               BIGINT AUTO_INCREMENT PRIMARY KEY,
    actor_user_id    VARCHAR(36) NULL,
    actor_username   VARCHAR(150),
    event_category   VARCHAR(64) NOT NULL,
    event_type       VARCHAR(128) NOT NULL,
    target_user_id   VARCHAR(36) NULL,
    target_asset_id  BIGINT NULL,
    target_scan_id   BIGINT NULL,
    ip_address       VARCHAR(64),
    user_agent       VARCHAR(512),
    request_method   VARCHAR(16),
    request_path     VARCHAR(255),
    status           VARCHAR(32) NOT NULL,
    details_json     LONGTEXT,
    previous_hash    CHAR(64),
    entry_hash       CHAR(64),
    created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_audit_created_at (created_at),
    INDEX idx_audit_category (event_category),
    INDEX idx_audit_actor (actor_user_id),
    INDEX idx_audit_asset (target_asset_id),
    INDEX idx_audit_scan (target_scan_id),
    CONSTRAINT fk_audit_actor_user
      FOREIGN KEY (actor_user_id) REFERENCES users(id)
      ON DELETE SET NULL,
    CONSTRAINT fk_audit_target_user
      FOREIGN KEY (target_user_id) REFERENCES users(id)
      ON DELETE SET NULL
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Inventory source of truth
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS assets (
    id                 BIGINT AUTO_INCREMENT PRIMARY KEY,
    asset_key          VARCHAR(255) NOT NULL UNIQUE,
    target             VARCHAR(512) NOT NULL,
    name               VARCHAR(255),
    url                VARCHAR(512),
    ipv4               VARCHAR(50),
    ipv6               VARCHAR(50),
    asset_type         VARCHAR(64) NOT NULL,
    owner              VARCHAR(150),
    risk_level         ENUM('Critical','High','Medium','Low','Unknown') DEFAULT 'Unknown',
    tags_json          LONGTEXT,
    notes              TEXT,
    source             ENUM('manual','scan_promoted','imported') NOT NULL DEFAULT 'manual',
    last_scan_id       BIGINT NULL,
    is_deleted         BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at         DATETIME,
    deleted_by         VARCHAR(36),
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_assets_active (is_deleted, asset_type, risk_level),
    INDEX idx_assets_owner (owner),
    CONSTRAINT fk_assets_deleted_by
      FOREIGN KEY (deleted_by) REFERENCES users(id)
      ON DELETE SET NULL
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Scan lifecycle + raw discovery
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS scans (
    id                 BIGINT AUTO_INCREMENT PRIMARY KEY,
    scan_uid           VARCHAR(36) NOT NULL UNIQUE,
    requested_target   VARCHAR(512) NOT NULL,
    normalized_target  VARCHAR(512),
    status             ENUM('queued','running','complete','failed','partial') NOT NULL DEFAULT 'queued',
    scan_kind          ENUM('manual','bulk','scheduled','api') NOT NULL DEFAULT 'manual',
    initiated_by       VARCHAR(36),
    started_at         DATETIME,
    completed_at       DATETIME,
    scanned_at         DATETIME,
    error_message      TEXT,
    report_json        LONGTEXT,
    cbom_path          VARCHAR(600),
    total_discovered   INT NOT NULL DEFAULT 0,
    total_promoted     INT NOT NULL DEFAULT 0,
    is_deleted         BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at         DATETIME,
    deleted_by         VARCHAR(36),
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_scans_status (status, scanned_at),
    INDEX idx_scans_target (normalized_target),
    CONSTRAINT fk_scans_initiated_by
      FOREIGN KEY (initiated_by) REFERENCES users(id)
      ON DELETE SET NULL,
    CONSTRAINT fk_scans_deleted_by
      FOREIGN KEY (deleted_by) REFERENCES users(id)
      ON DELETE SET NULL
) ENGINE=InnoDB;

-- Discovery tables retain scan evidence regardless of inventory promotion.
-- They become in-scope for dashboards only when promoted to assets and linked via asset_id.

CREATE TABLE IF NOT EXISTS discovery_domains (
    id                 BIGINT AUTO_INCREMENT PRIMARY KEY,
    scan_id            BIGINT NOT NULL,
    asset_id           BIGINT NULL,
    domain             VARCHAR(512) NOT NULL,
    registrar          VARCHAR(255),
    registration_date  DATE,
    status             ENUM('new','confirmed','ignored','false_positive') NOT NULL DEFAULT 'new',
    promoted_to_inventory BOOLEAN NOT NULL DEFAULT FALSE,
    promoted_at        DATETIME,
    promoted_by        VARCHAR(36),
    is_deleted         BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at         DATETIME,
    deleted_by         VARCHAR(36),
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_discovery_domains_scan (scan_id),
    INDEX idx_discovery_domains_asset (asset_id, promoted_to_inventory),
    INDEX idx_discovery_domains_domain (domain),
    CONSTRAINT fk_discovery_domains_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    CONSTRAINT fk_discovery_domains_asset FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE SET NULL,
    CONSTRAINT fk_discovery_domains_promoted_by FOREIGN KEY (promoted_by) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT fk_discovery_domains_deleted_by FOREIGN KEY (deleted_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS discovery_ssl (
    id                 BIGINT AUTO_INCREMENT PRIMARY KEY,
    scan_id            BIGINT NOT NULL,
    asset_id           BIGINT NULL,
    endpoint           VARCHAR(512) NOT NULL,
    tls_version        VARCHAR(50),
    cipher_suite       VARCHAR(255),
    key_exchange       VARCHAR(120),
    key_length         INT,
    subject_cn         VARCHAR(255),
    issuer             VARCHAR(255),
    valid_until        DATETIME,
    status             ENUM('new','confirmed','ignored','false_positive') NOT NULL DEFAULT 'new',
    promoted_to_inventory BOOLEAN NOT NULL DEFAULT FALSE,
    promoted_at        DATETIME,
    promoted_by        VARCHAR(36),
    is_deleted         BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at         DATETIME,
    deleted_by         VARCHAR(36),
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_discovery_ssl_scan (scan_id),
    INDEX idx_discovery_ssl_asset (asset_id, promoted_to_inventory),
    INDEX idx_discovery_ssl_endpoint (endpoint),
    CONSTRAINT fk_discovery_ssl_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    CONSTRAINT fk_discovery_ssl_asset FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE SET NULL,
    CONSTRAINT fk_discovery_ssl_promoted_by FOREIGN KEY (promoted_by) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT fk_discovery_ssl_deleted_by FOREIGN KEY (deleted_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS discovery_ips (
    id                 BIGINT AUTO_INCREMENT PRIMARY KEY,
    scan_id            BIGINT NOT NULL,
    asset_id           BIGINT NULL,
    ip_address         VARCHAR(80) NOT NULL,
    subnet             VARCHAR(80),
    asn                VARCHAR(80),
    netname            VARCHAR(255),
    location           VARCHAR(255),
    status             ENUM('new','confirmed','ignored','false_positive') NOT NULL DEFAULT 'new',
    promoted_to_inventory BOOLEAN NOT NULL DEFAULT FALSE,
    promoted_at        DATETIME,
    promoted_by        VARCHAR(36),
    is_deleted         BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at         DATETIME,
    deleted_by         VARCHAR(36),
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_discovery_ips_scan (scan_id),
    INDEX idx_discovery_ips_asset (asset_id, promoted_to_inventory),
    INDEX idx_discovery_ips_ip (ip_address),
    CONSTRAINT fk_discovery_ips_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    CONSTRAINT fk_discovery_ips_asset FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE SET NULL,
    CONSTRAINT fk_discovery_ips_promoted_by FOREIGN KEY (promoted_by) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT fk_discovery_ips_deleted_by FOREIGN KEY (deleted_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS discovery_software (
    id                 BIGINT AUTO_INCREMENT PRIMARY KEY,
    scan_id            BIGINT NOT NULL,
    asset_id           BIGINT NULL,
    product            VARCHAR(255) NOT NULL,
    version            VARCHAR(120),
    category           VARCHAR(80),
    cpe                VARCHAR(255),
    status             ENUM('new','confirmed','ignored','false_positive') NOT NULL DEFAULT 'new',
    promoted_to_inventory BOOLEAN NOT NULL DEFAULT FALSE,
    promoted_at        DATETIME,
    promoted_by        VARCHAR(36),
    is_deleted         BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at         DATETIME,
    deleted_by         VARCHAR(36),
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_discovery_software_scan (scan_id),
    INDEX idx_discovery_software_asset (asset_id, promoted_to_inventory),
    INDEX idx_discovery_software_product (product),
    CONSTRAINT fk_discovery_software_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    CONSTRAINT fk_discovery_software_asset FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE SET NULL,
    CONSTRAINT fk_discovery_software_promoted_by FOREIGN KEY (promoted_by) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT fk_discovery_software_deleted_by FOREIGN KEY (deleted_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Inventory-linked telemetry used in all KPIs/dashboarding
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS certificates (
    id                 BIGINT AUTO_INCREMENT PRIMARY KEY,
    asset_id           BIGINT NOT NULL,
    scan_id            BIGINT NULL,
    issuer             VARCHAR(500),
    subject            VARCHAR(500),
    subject_cn         VARCHAR(255),
    serial             VARCHAR(255),
    valid_from         DATETIME,
    valid_until        DATETIME,
    expiry_days        INT,
    fingerprint_sha256 CHAR(64),
    tls_version        VARCHAR(50),
    key_length         INT,
    key_algorithm      VARCHAR(100),
    cipher_suite       VARCHAR(255),
    signature_algorithm VARCHAR(100),
    ca                 VARCHAR(255),
    is_self_signed     BOOLEAN NOT NULL DEFAULT FALSE,
    is_expired         BOOLEAN NOT NULL DEFAULT FALSE,
    is_deleted         BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at         DATETIME,
    deleted_by         VARCHAR(36),
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_cert_asset_active (asset_id, is_deleted, valid_until),
    INDEX idx_cert_scan (scan_id),
    INDEX idx_cert_tls (tls_version, key_length),
    CONSTRAINT fk_cert_asset FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    CONSTRAINT fk_cert_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL,
    CONSTRAINT fk_cert_deleted_by FOREIGN KEY (deleted_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS pqc_classification (
    id                 BIGINT AUTO_INCREMENT PRIMARY KEY,
    asset_id           BIGINT NOT NULL,
    scan_id            BIGINT NULL,
    certificate_id     BIGINT NULL,
    algorithm_name     VARCHAR(120),
    algorithm_type     VARCHAR(80),
    quantum_safe_status ENUM('safe','hybrid','unsafe','migration_advised','unknown') NOT NULL DEFAULT 'unknown',
    nist_category      VARCHAR(64),
    pqc_score          DOUBLE,
    is_deleted         BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at         DATETIME,
    deleted_by         VARCHAR(36),
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_pqc_asset_active (asset_id, is_deleted, quantum_safe_status),
    INDEX idx_pqc_scan (scan_id),
    CONSTRAINT fk_pqc_asset FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    CONSTRAINT fk_pqc_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL,
    CONSTRAINT fk_pqc_cert FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE SET NULL,
    CONSTRAINT fk_pqc_deleted_by FOREIGN KEY (deleted_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS cbom_summary (
    id                 BIGINT AUTO_INCREMENT PRIMARY KEY,
    asset_id           BIGINT NOT NULL,
    scan_id            BIGINT NULL,
    total_components   INT NOT NULL DEFAULT 0,
    weak_crypto_count  INT NOT NULL DEFAULT 0,
    cert_issues_count  INT NOT NULL DEFAULT 0,
    json_path          VARCHAR(600),
    is_deleted         BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at         DATETIME,
    deleted_by         VARCHAR(36),
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_cbom_summary_asset_scan (asset_id, scan_id),
    INDEX idx_cbom_summary_asset_active (asset_id, is_deleted),
    CONSTRAINT fk_cbom_summary_asset FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    CONSTRAINT fk_cbom_summary_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL,
    CONSTRAINT fk_cbom_summary_deleted_by FOREIGN KEY (deleted_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS cbom_entries (
    id                 BIGINT AUTO_INCREMENT PRIMARY KEY,
    asset_id           BIGINT NOT NULL,
    scan_id            BIGINT NULL,
    cbom_summary_id    BIGINT NULL,
    algorithm_name     VARCHAR(120),
    category           VARCHAR(80),
    key_length         INT,
    protocol_version   VARCHAR(50),
    nist_status        VARCHAR(80),
    quantum_safe_flag  BOOLEAN NOT NULL DEFAULT FALSE,
    hndl_level         ENUM('critical','high','medium','low','unknown') DEFAULT 'unknown',
    is_deleted         BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at         DATETIME,
    deleted_by         VARCHAR(36),
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_cbom_entries_asset_active (asset_id, is_deleted, quantum_safe_flag),
    INDEX idx_cbom_entries_scan (scan_id),
    CONSTRAINT fk_cbom_entries_asset FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    CONSTRAINT fk_cbom_entries_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL,
    CONSTRAINT fk_cbom_entries_summary FOREIGN KEY (cbom_summary_id) REFERENCES cbom_summary(id) ON DELETE SET NULL,
    CONSTRAINT fk_cbom_entries_deleted_by FOREIGN KEY (deleted_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS compliance_scores (
    id                 BIGINT AUTO_INCREMENT PRIMARY KEY,
    asset_id           BIGINT NOT NULL,
    scan_id            BIGINT NULL,
    score_type         ENUM('pqc','tls','overall') NOT NULL,
    score_value        DOUBLE NOT NULL,
    tier               ENUM('elite','standard','legacy','critical','unknown') DEFAULT 'unknown',
    is_deleted         BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at         DATETIME,
    deleted_by         VARCHAR(36),
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_compliance_asset_active (asset_id, is_deleted, score_type),
    INDEX idx_compliance_scan (scan_id),
    CONSTRAINT fk_compliance_asset FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    CONSTRAINT fk_compliance_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL,
    CONSTRAINT fk_compliance_deleted_by FOREIGN KEY (deleted_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS cyber_rating (
    id                 BIGINT AUTO_INCREMENT PRIMARY KEY,
    asset_id           BIGINT NOT NULL,
    scan_id            BIGINT NULL,
    enterprise_score   DOUBLE NOT NULL,
    rating_tier        VARCHAR(50),
    generated_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_deleted         BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at         DATETIME,
    deleted_by         VARCHAR(36),
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_cyber_asset_active (asset_id, is_deleted, generated_at),
    INDEX idx_cyber_scan (scan_id),
    CONSTRAINT fk_cyber_asset FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    CONSTRAINT fk_cyber_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL,
    CONSTRAINT fk_cyber_deleted_by FOREIGN KEY (deleted_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Reporting workflows
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS report_schedule (
    id                 BIGINT AUTO_INCREMENT PRIMARY KEY,
    schedule_uid       VARCHAR(36) NOT NULL UNIQUE,
    created_by         VARCHAR(36),
    report_type        VARCHAR(120) NOT NULL,
    frequency          ENUM('daily','weekly','monthly','quarterly','onetime') NOT NULL,
    timezone_name      VARCHAR(64) NOT NULL DEFAULT 'UTC',
    schedule_date      DATE,
    schedule_time      TIME,
    email_list         VARCHAR(1024),
    save_path          VARCHAR(600),
    include_download_link BOOLEAN NOT NULL DEFAULT FALSE,
    enabled            BOOLEAN NOT NULL DEFAULT TRUE,
    status             ENUM('scheduled','paused','completed','failed') NOT NULL DEFAULT 'scheduled',
    is_deleted         BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at         DATETIME,
    deleted_by         VARCHAR(36),
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_report_schedule_active (enabled, is_deleted, status),
    CONSTRAINT fk_report_schedule_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT fk_report_schedule_deleted_by FOREIGN KEY (deleted_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS report_requests (
    id                 BIGINT AUTO_INCREMENT PRIMARY KEY,
    request_uid        VARCHAR(36) NOT NULL UNIQUE,
    schedule_id        BIGINT NULL,
    requested_by       VARCHAR(36),
    report_type        VARCHAR(120) NOT NULL,
    status             ENUM('queued','running','completed','failed','cancelled') NOT NULL DEFAULT 'queued',
    period_start       DATETIME,
    period_end         DATETIME,
    filters_json       LONGTEXT,
    output_path        VARCHAR(600),
    output_format      ENUM('pdf','json','csv') NOT NULL DEFAULT 'pdf',
    error_message      TEXT,
    is_deleted         BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at         DATETIME,
    deleted_by         VARCHAR(36),
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at         DATETIME,
    completed_at       DATETIME,
    INDEX idx_report_requests_status (status, created_at),
    INDEX idx_report_requests_schedule (schedule_id),
    CONSTRAINT fk_report_requests_schedule FOREIGN KEY (schedule_id) REFERENCES report_schedule(id) ON DELETE SET NULL,
    CONSTRAINT fk_report_requests_user FOREIGN KEY (requested_by) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT fk_report_requests_deleted_by FOREIGN KEY (deleted_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS report_request_assets (
    report_request_id  BIGINT NOT NULL,
    asset_id           BIGINT NOT NULL,
    PRIMARY KEY (report_request_id, asset_id),
    INDEX idx_report_request_assets_asset (asset_id),
    CONSTRAINT fk_rra_request FOREIGN KEY (report_request_id) REFERENCES report_requests(id) ON DELETE CASCADE,
    CONSTRAINT fk_rra_asset FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS report_schedule_assets (
    report_schedule_id BIGINT NOT NULL,
    asset_id           BIGINT NOT NULL,
    PRIMARY KEY (report_schedule_id, asset_id),
    INDEX idx_report_schedule_assets_asset (asset_id),
    CONSTRAINT fk_rsa_schedule FOREIGN KEY (report_schedule_id) REFERENCES report_schedule(id) ON DELETE CASCADE,
    CONSTRAINT fk_rsa_asset FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Canonical in-scope view used by all dashboard SQL
-- ------------------------------------------------------------

CREATE OR REPLACE VIEW v_inventory_assets AS
SELECT *
FROM assets
WHERE is_deleted = FALSE;

-- Optional convenience views to reduce query mistakes in dashboards.
CREATE OR REPLACE VIEW v_inventory_certificates AS
SELECT c.*
FROM certificates c
JOIN v_inventory_assets a ON a.id = c.asset_id
WHERE c.is_deleted = FALSE;

CREATE OR REPLACE VIEW v_inventory_pqc AS
SELECT p.*
FROM pqc_classification p
JOIN v_inventory_assets a ON a.id = p.asset_id
WHERE p.is_deleted = FALSE;

CREATE OR REPLACE VIEW v_inventory_cbom_entries AS
SELECT e.*
FROM cbom_entries e
JOIN v_inventory_assets a ON a.id = e.asset_id
WHERE e.is_deleted = FALSE;

CREATE OR REPLACE VIEW v_inventory_compliance AS
SELECT s.*
FROM compliance_scores s
JOIN v_inventory_assets a ON a.id = s.asset_id
WHERE s.is_deleted = FALSE;

CREATE OR REPLACE VIEW v_inventory_cyber_rating AS
SELECT r.*
FROM cyber_rating r
JOIN v_inventory_assets a ON a.id = r.asset_id
WHERE r.is_deleted = FALSE;
