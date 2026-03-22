-- QuantumShield — Complete Production MySQL Schema
-- Comprehensive Asset → Certificate → PQC relationships with proper foreign keys and indexes

CREATE DATABASE IF NOT EXISTS `quantumshield` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `quantumshield`;

-- ===============================================
-- 1. Core Tables
-- ===============================================

-- Users Table (RBAC / Auth)
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
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_username (username),
    INDEX idx_role (role),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Scans Table (Results Metadata)
CREATE TABLE IF NOT EXISTS scans (
    id                      BIGINT AUTO_INCREMENT PRIMARY KEY,
    scan_id                 VARCHAR(36) NOT NULL UNIQUE,
    target                  VARCHAR(512) NOT NULL,
    asset_class             VARCHAR(64),
    status                  VARCHAR(32),
    started_at              DATETIME,
    completed_at            DATETIME,
    scanned_at              DATETIME,
    compliance_score        INT DEFAULT 0,
    total_assets            INT DEFAULT 0,
    quantum_safe            INT DEFAULT 0,
    quantum_vuln            INT DEFAULT 0,
    overall_pqc_score       FLOAT,
    cbom_path               VARCHAR(500),
    report_json             LONGTEXT NOT NULL,
    is_encrypted            BOOLEAN DEFAULT FALSE,
    is_deleted              BOOLEAN DEFAULT FALSE,
    deleted_at              DATETIME,
    deleted_by_user_id      VARCHAR(36),
    created_at              DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (deleted_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_scan_id (scan_id),
    INDEX idx_status (status),
    INDEX idx_target (target),
    INDEX idx_scanned_at (scanned_at),
    INDEX idx_is_deleted (is_deleted),
    FULLTEXT INDEX ft_target (target)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Assets Table (Inventory Source of Truth)
CREATE TABLE IF NOT EXISTS assets (
    id                      BIGINT AUTO_INCREMENT PRIMARY KEY,
    target                  VARCHAR(512) NOT NULL UNIQUE,
    name                    VARCHAR(255),
    url                     VARCHAR(255),
    asset_name              VARCHAR(255),
    asset_class             VARCHAR(64),
    asset_type              VARCHAR(50) DEFAULT 'Web App',
    type                    VARCHAR(64),
    ipv4                    VARCHAR(50),
    ipv6                    VARCHAR(128),
    owner                   VARCHAR(150),
    risk_level              VARCHAR(32),
    notes                   TEXT,
    last_scan_id            BIGINT,
    is_deleted              BOOLEAN DEFAULT FALSE,
    deleted_at              DATETIME,
    deleted_by_user_id      VARCHAR(36),
    created_at              DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (last_scan_id) REFERENCES scans(id) ON DELETE SET NULL,
    FOREIGN KEY (deleted_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_target (target),
    INDEX idx_is_deleted (is_deleted),
    INDEX idx_asset_type (asset_type),
    INDEX idx_risk_level (risk_level),
    INDEX idx_owner (owner),
    INDEX idx_updated_at (updated_at),
    FULLTEXT INDEX ft_target (target)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===============================================
-- 2. Certificate Management
-- ===============================================

-- Certificates Table (TLS Certificate Details with full metadata)
CREATE TABLE IF NOT EXISTS certificates (
    id                      BIGINT AUTO_INCREMENT PRIMARY KEY,
    asset_id                BIGINT NOT NULL,
    scan_id                 BIGINT NOT NULL,
    
    -- Certificate Identification
    issuer                  VARCHAR(500),
    issuer_cn               VARCHAR(255),
    ca_name                 VARCHAR(255),
    subject                 VARCHAR(500),
    subject_cn              VARCHAR(255),
    company_name            VARCHAR(255),
    serial                  VARCHAR(255) UNIQUE,
    fingerprint_sha256      VARCHAR(64) UNIQUE,
    
    -- Validity Period
    valid_from              DATETIME,
    valid_until             DATETIME,
    expiry_days             INT,
    
    -- Technical Details
    tls_version             VARCHAR(50),
    key_algorithm           VARCHAR(100),
    key_length              INT,
    cipher_suite            VARCHAR(255),
    signature_algorithm     VARCHAR(100),
    ca                      VARCHAR(255),
    
    -- Status Tracking
    is_self_signed          BOOLEAN DEFAULT FALSE,
    is_expired              BOOLEAN DEFAULT FALSE,
    
    -- Soft Delete Support
    is_deleted              BOOLEAN DEFAULT FALSE,
    deleted_at              DATETIME,
    deleted_by_user_id      VARCHAR(36),
    created_at              DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (deleted_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    
    -- Indexes for filtering and queries
    INDEX idx_asset_id (asset_id),
    INDEX idx_scan_id (scan_id),
    INDEX idx_subject_cn (subject_cn),
    INDEX idx_issuer (issuer),
    INDEX idx_company_name (company_name),
    INDEX idx_ca_name (ca_name),
    INDEX idx_valid_until (valid_until),
    INDEX idx_tls_version (tls_version),
    INDEX idx_is_expired (is_expired),
    INDEX idx_is_deleted (is_deleted),
    INDEX idx_fingerprint_sha256 (fingerprint_sha256)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===============================================
-- 3. Post-Quantum Cryptography Classification
-- ===============================================

-- PQC Classification Table (Quantum-Safe Status per Algorithm/Certificate)
CREATE TABLE IF NOT EXISTS pqc_classification (
    id                      BIGINT AUTO_INCREMENT PRIMARY KEY,
    certificate_id          BIGINT,
    asset_id                BIGINT NOT NULL,
    scan_id                 BIGINT NOT NULL,
    
    -- Algorithm Classification
    algorithm_name          VARCHAR(100),
    algorithm_type          VARCHAR(100),
    quantum_safe_status     VARCHAR(50),
    nist_category           VARCHAR(50),
    pqc_score               FLOAT,
    
    -- Soft Delete Support
    is_deleted              BOOLEAN DEFAULT FALSE,
    deleted_at              DATETIME,
    deleted_by_user_id      VARCHAR(36),
    created_at              DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (deleted_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    
    -- Indexes for filtering and joins
    INDEX idx_certificate_id (certificate_id),
    INDEX idx_asset_id (asset_id),
    INDEX idx_scan_id (scan_id),
    INDEX idx_algorithm_name (algorithm_name),
    INDEX idx_quantum_safe_status (quantum_safe_status),
    INDEX idx_is_deleted (is_deleted),
    INDEX idx_pqc_score (pqc_score)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===============================================
-- 4. Compliance & Scoring
-- ===============================================

-- Compliance Scores Table (PQC, TLS, Overall Metrics per Asset/Scan)
CREATE TABLE IF NOT EXISTS compliance_scores (
    id                      BIGINT AUTO_INCREMENT PRIMARY KEY,
    asset_id                BIGINT NOT NULL,
    scan_id                 BIGINT NOT NULL,
    
    -- Score Details
    type                    VARCHAR(50),
    score_type              VARCHAR(50),
    score_value             FLOAT,
    tier                    VARCHAR(50),
    
    -- Soft Delete Support
    is_deleted              BOOLEAN DEFAULT FALSE,
    deleted_at              DATETIME,
    deleted_by_user_id      VARCHAR(36),
    created_at              DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (deleted_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    
    INDEX idx_asset_id (asset_id),
    INDEX idx_scan_id (scan_id),
    INDEX idx_type (type),
    INDEX idx_tier (tier),
    INDEX idx_is_deleted (is_deleted),
    UNIQUE INDEX uq_asset_scan_type (asset_id, scan_id, type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===============================================
-- 5. Discovery & Inventory Management
-- ===============================================

-- Discovery Items Table (Discovered Assets/Services During Scans)
CREATE TABLE IF NOT EXISTS discovery_items (
    id                      BIGINT AUTO_INCREMENT PRIMARY KEY,
    scan_id                 BIGINT NOT NULL,
    asset_id                BIGINT,
    
    -- Discovery Details
    type                    VARCHAR(50),
    status                  VARCHAR(50),
    detection_date          DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    -- Soft Delete Support
    is_deleted              BOOLEAN DEFAULT FALSE,
    deleted_at              DATETIME,
    deleted_by_user_id      VARCHAR(36),
    created_at              DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY (deleted_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    
    INDEX idx_scan_id (scan_id),
    INDEX idx_asset_id (asset_id),
    INDEX idx_type (type),
    INDEX idx_status (status),
    INDEX idx_is_deleted (is_deleted)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===============================================
-- 6. CBOM (Cryptographic Bill of Materials)
-- ===============================================

-- CBOM Summary Table (High-level CBOM Metadata per Scan)
CREATE TABLE IF NOT EXISTS cbom_summary (
    id                      BIGINT AUTO_INCREMENT PRIMARY KEY,
    scan_id                 BIGINT NOT NULL UNIQUE,
    
    -- Summary Counts
    total_components        INT DEFAULT 0,
    weak_crypto_count       INT DEFAULT 0,
    cert_issues_count       INT DEFAULT 0,
    json_path               VARCHAR(500),
    
    -- Soft Delete Support
    is_deleted              BOOLEAN DEFAULT FALSE,
    deleted_at              DATETIME,
    deleted_by_user_id      VARCHAR(36),
    created_at              DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (deleted_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    
    INDEX idx_scan_id (scan_id),
    INDEX idx_is_deleted (is_deleted)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- CBOM Entries Table (Individual Cryptographic Components)
CREATE TABLE IF NOT EXISTS cbom_entries (
    id                      BIGINT AUTO_INCREMENT PRIMARY KEY,
    scan_id                 BIGINT NOT NULL,
    asset_id                BIGINT,
    
    -- Component Details
    algorithm_name          VARCHAR(100),
    category                VARCHAR(50),
    key_length              INT,
    protocol_version        VARCHAR(50),
    nist_status             VARCHAR(50),
    quantum_safe_flag       BOOLEAN DEFAULT FALSE,
    hndl_level              VARCHAR(50),
    
    -- Soft Delete Support
    is_deleted              BOOLEAN DEFAULT FALSE,
    deleted_at              DATETIME,
    deleted_by_user_id      VARCHAR(36),
    created_at              DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY (deleted_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    
    INDEX idx_scan_id (scan_id),
    INDEX idx_asset_id (asset_id),
    INDEX idx_algorithm_name (algorithm_name),
    INDEX idx_nist_status (nist_status),
    INDEX idx_quantum_safe_flag (quantum_safe_flag),
    INDEX idx_is_deleted (is_deleted)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===============================================
-- 7. Enterprise Ratings & Reporting
-- ===============================================

-- Cyber Rating Table (Enterprise-Level Security Rating)
CREATE TABLE IF NOT EXISTS cyber_rating (
    id                      BIGINT AUTO_INCREMENT PRIMARY KEY,
    organization_id         VARCHAR(100),
    scan_id                 BIGINT NOT NULL,
    
    -- Rating Details
    enterprise_score        FLOAT,
    rating_tier             VARCHAR(50),
    generated_at            DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    -- Soft Delete Support
    is_deleted              BOOLEAN DEFAULT FALSE,
    deleted_at              DATETIME,
    deleted_by_user_id      VARCHAR(36),
    created_at              DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (deleted_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    
    INDEX idx_scan_id (scan_id),
    INDEX idx_organization_id (organization_id),
    INDEX idx_is_deleted (is_deleted)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===============================================
-- 8. DNS Records & Network Discovery
-- ===============================================

-- DNS Records Table (DNS A/AAAA Records Discovered)
CREATE TABLE IF NOT EXISTS asset_dns_records (
    id                      BIGINT AUTO_INCREMENT PRIMARY KEY,
    scan_id                 VARCHAR(36) NOT NULL,
    hostname                VARCHAR(255) NOT NULL,
    record_type             VARCHAR(16) NOT NULL,
    record_value            VARCHAR(1024) NOT NULL,
    ttl                     INT DEFAULT 300,
    resolved_at             DATETIME,
    
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
    
    INDEX idx_scan_id (scan_id),
    INDEX idx_hostname (hostname),
    INDEX idx_record_type (record_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===============================================
-- 9. CBOM Reports & Audit Infrastructure
-- ===============================================

-- CBOM Reports Table (Full CBOM JSON Storage)
CREATE TABLE IF NOT EXISTS cbom_reports (
    scan_id                 VARCHAR(36) PRIMARY KEY,
    cbom_json               LONGTEXT NOT NULL,
    is_encrypted            BOOLEAN DEFAULT FALSE,
    
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Audit Log Chain (Hash Chain for Integrity)
CREATE TABLE IF NOT EXISTS audit_log_chain (
    id                      TINYINT PRIMARY KEY,
    last_entry_id           BIGINT,
    last_hash               CHAR(64),
    updated_at              DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Audit Logs Table (Immutable Event History)
CREATE TABLE IF NOT EXISTS audit_logs (
    id                      BIGINT AUTO_INCREMENT PRIMARY KEY,
    actor_user_id           VARCHAR(36),
    actor_username          VARCHAR(150),
    event_category          VARCHAR(64) NOT NULL,
    event_type              VARCHAR(128) NOT NULL,
    target_user_id          VARCHAR(36),
    target_scan_id          VARCHAR(36),
    ip_address              VARCHAR(64),
    user_agent              VARCHAR(512),
    request_method          VARCHAR(16),
    request_path            VARCHAR(255),
    status                  VARCHAR(32) NOT NULL,
    details_json            LONGTEXT,
    previous_hash           CHAR(64) NOT NULL,
    entry_hash              CHAR(64) NOT NULL UNIQUE,
    created_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (target_user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (target_scan_id) REFERENCES scans(scan_id) ON DELETE SET NULL,
    
    INDEX idx_created_at (created_at),
    INDEX idx_category (event_category),
    INDEX idx_actor (actor_user_id),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Report Schedules Table (Scheduled Reporting)
CREATE TABLE IF NOT EXISTS report_schedules (
    schedule_id             VARCHAR(36) PRIMARY KEY,
    created_by_id           VARCHAR(36),
    created_by_name         VARCHAR(150),
    created_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    enabled                 BOOLEAN DEFAULT TRUE,
    report_type             VARCHAR(120) NOT NULL,
    frequency               VARCHAR(32) NOT NULL,
    assets                  VARCHAR(256),
    sections_json           LONGTEXT,
    schedule_date           VARCHAR(20),
    schedule_time           VARCHAR(10),
    timezone_name           VARCHAR(64),
    email_list              VARCHAR(512),
    save_path               VARCHAR(512),
    download_link           BOOLEAN DEFAULT FALSE,
    status                  VARCHAR(32) DEFAULT 'scheduled',
    
    FOREIGN KEY (created_by_id) REFERENCES users(id) ON DELETE SET NULL,
    
    INDEX idx_created_at (created_at),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===============================================
-- 10. Immutability Triggers
-- ===============================================

-- Prevent updates to audit logs
DELIMITER //
CREATE TRIGGER IF NOT EXISTS audit_logs_no_update
BEFORE UPDATE ON audit_logs
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_logs is append-only';
END //

-- Prevent deletions from audit logs
CREATE TRIGGER IF NOT EXISTS audit_logs_no_delete
BEFORE DELETE ON audit_logs
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_logs cannot be deleted';
END //

-- Prevent deletions from audit log chain
CREATE TRIGGER IF NOT EXISTS audit_log_chain_no_delete
BEFORE DELETE ON audit_log_chain
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log_chain cannot be deleted';
END //

DELIMITER ;

-- ===============================================
-- 11. Initial Seed Data
-- ===============================================

INSERT IGNORE INTO audit_log_chain (id, last_entry_id, last_hash) 
VALUES (1, NULL, '0000000000000000000000000000000000000000000000000000000000000000');

-- ===============================================
-- 12. Key Relationships Overview
-- ===============================================

-- Main Data Flow:
-- Scan → Assets → Certificates → PQC Classification
--              ↓
--         Compliance Scores
--              ↓
--         CBOM Entries
--
-- Deletion Cascade:
-- DELETE Asset → CASCADE to Certificates → CASCADE to PQC Classification → DELETE from Compliance Scores
--
-- All tables support soft deletes via is_deleted + deleted_at + deleted_by_user_id
-- All timestamps: created_at (immutable) + updated_at (on mutations)
-- All changes tracked in audit_logs (append-only, immutable hash chain)
