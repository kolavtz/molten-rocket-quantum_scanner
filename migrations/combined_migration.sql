-- Combined idempotent migration for QuantumShield
-- Purpose: Consolidate migrations so a single script can bring a schema up-to-date
-- Generated: 2026-04-11
-- IMPORTANT: Review and run in a non-production environment first. Back up your DB before running.

-- ------------------------------
-- Save and set session state
-- ------------------------------
SET @OLD_FOREIGN_KEY_CHECKS = @@FOREIGN_KEY_CHECKS;
SET FOREIGN_KEY_CHECKS = 0;
SET @OLD_UNIQUE_CHECKS = @@UNIQUE_CHECKS;
SET UNIQUE_CHECKS = 0;
SET @prev_sql_mode = @@sql_mode;
SET SESSION sql_mode = 'ANSI_QUOTES,STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION';

-- --------------------------------------------------------------------
-- 1) Core new tables and metric tables (CREATE IF NOT EXISTS)
-- --------------------------------------------------------------------

-- Findings table
CREATE TABLE IF NOT EXISTS findings (
    id                      BIGINT AUTO_INCREMENT PRIMARY KEY,
    finding_id              VARCHAR(36) NOT NULL UNIQUE,
    asset_id                BIGINT NOT NULL,
    scan_id                 BIGINT NOT NULL,
    issue_type              VARCHAR(100) NOT NULL,
    severity                VARCHAR(50) NOT NULL,
    description             TEXT NOT NULL,
    metadata_json           JSON,
    certificate_id          BIGINT,
    cbom_entry_id           BIGINT,
    is_deleted              BOOLEAN DEFAULT FALSE,
    deleted_at              DATETIME,
    deleted_by_user_id      VARCHAR(36),
    created_at              DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    -- Foreign keys will be added after table creation in a guarded step below
    INDEX idx_asset_id (asset_id),
    INDEX idx_scan_id (scan_id),
    INDEX idx_issue_type (issue_type),
    INDEX idx_severity (severity),
    INDEX idx_certificate_id (certificate_id),
    INDEX idx_cbom_entry_id (cbom_entry_id),
    INDEX idx_is_deleted (is_deleted),
    INDEX idx_created_at (created_at),
    UNIQUE INDEX uq_finding_id (finding_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Asset metrics
CREATE TABLE IF NOT EXISTS asset_metrics (
    asset_id                BIGINT PRIMARY KEY,
    pqc_score               FLOAT DEFAULT 0,
    pqc_score_timestamp     DATETIME,
    risk_penalty            FLOAT DEFAULT 0,
    total_findings_count    INT DEFAULT 0,
    critical_findings_count INT DEFAULT 0,
    pqc_class_tier          VARCHAR(50),
    digital_label           VARCHAR(50),
    has_critical_findings   BOOLEAN DEFAULT FALSE,
    asset_cyber_score       FLOAT DEFAULT 0,
    last_updated            DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    calculated_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
    -- Foreign key to assets(id) will be added later if types match
    INDEX idx_pqc_score (pqc_score),
    INDEX idx_pqc_class_tier (pqc_class_tier),
    INDEX idx_digital_label (digital_label),
    INDEX idx_has_critical_findings (has_critical_findings),
    INDEX idx_last_updated (last_updated)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Org-level PQC metrics
CREATE TABLE IF NOT EXISTS org_pqc_metrics (
    id                      BIGINT AUTO_INCREMENT PRIMARY KEY,
    metric_date             DATE NOT NULL UNIQUE,
    total_assets            INT DEFAULT 0,
    total_endpoints         INT DEFAULT 0,
    total_certificates      INT DEFAULT 0,
    elite_assets_count      INT DEFAULT 0,
    standard_assets_count   INT DEFAULT 0,
    legacy_assets_count     INT DEFAULT 0,
    critical_assets_count   INT DEFAULT 0,
    pct_elite               DECIMAL(5,2) DEFAULT 0,
    pct_standard            DECIMAL(5,2) DEFAULT 0,
    pct_legacy              DECIMAL(5,2) DEFAULT 0,
    pct_critical            DECIMAL(5,2) DEFAULT 0,
    avg_pqc_score           DECIMAL(5,2) DEFAULT 0,
    min_pqc_score           DECIMAL(5,2) DEFAULT 0,
    max_pqc_score           DECIMAL(5,2) DEFAULT 0,
    total_findings_count    INT DEFAULT 0,
    total_critical_findings INT DEFAULT 0,
    total_high_findings     INT DEFAULT 0,
    total_medium_findings   INT DEFAULT 0,
    total_low_findings      INT DEFAULT 0,
    quantum_safe_assets_count INT DEFAULT 0,
    quantum_safe_pct        DECIMAL(5,2) DEFAULT 0,
    vulnerable_assets_count INT DEFAULT 0,
    vulnerable_pct          DECIMAL(5,2) DEFAULT 0,
    created_at              DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_metric_date (metric_date),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Certificate expiry buckets
CREATE TABLE IF NOT EXISTS cert_expiry_buckets (
    id                      BIGINT AUTO_INCREMENT PRIMARY KEY,
    bucket_date             DATE NOT NULL,
    count_0_to_30_days      INT DEFAULT 0,
    count_31_to_60_days     INT DEFAULT 0,
    count_61_to_90_days     INT DEFAULT 0,
    count_greater_90_days   INT DEFAULT 0,
    count_expired           INT DEFAULT 0,
    total_active_certs      INT DEFAULT 0,
    total_expired_certs     INT DEFAULT 0,
    created_at              DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_bucket_date (bucket_date),
    UNIQUE INDEX uq_bucket_date (bucket_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- TLS compliance scores
CREATE TABLE IF NOT EXISTS tls_compliance_scores (
    asset_id                BIGINT PRIMARY KEY,
    tls_score               FLOAT DEFAULT 0,
    score_breakdown_json    JSON,
    weak_tls_version_count  INT DEFAULT 0,
    weak_cipher_count       INT DEFAULT 0,
    weak_key_length_count   INT DEFAULT 0,
    total_endpoints_scanned INT DEFAULT 0,
    calculated_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    -- FK to assets(id) will be added later if compatible
    INDEX idx_tls_score (tls_score),
    INDEX idx_updated_at (updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Digital labels
CREATE TABLE IF NOT EXISTS digital_labels (
    asset_id                BIGINT PRIMARY KEY,
    label                   VARCHAR(100) NOT NULL,
    label_reason_json       JSON,
    confidence_score        INT DEFAULT 0,
    based_on_pqc_score      FLOAT DEFAULT 0,
    based_on_finding_count  INT DEFAULT 0,
    based_on_critical_findings BOOLEAN DEFAULT FALSE,
    based_on_enterprise_score FLOAT DEFAULT 0,
    label_generated_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    label_updated_at        DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    -- FK to assets(id) will be added later if compatible
    INDEX idx_label (label),
    INDEX idx_confidence_score (confidence_score),
    INDEX idx_label_generated_at (label_generated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------------------
-- 2) CBOM: add minimum required columns (from 002)
-- --------------------------------------------------------------------
-- Replace `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` with information_schema-guarded prepared statements
-- (some MySQL/MariaDB versions do not support the IF NOT EXISTS syntax on ALTER TABLE)

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='asset_type');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `cbom_entries` ADD COLUMN `asset_type` VARCHAR(50) NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='element_name');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `cbom_entries` ADD COLUMN `element_name` VARCHAR(255) NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='primitive');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `cbom_entries` ADD COLUMN `primitive` VARCHAR(100) NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='mode');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `cbom_entries` ADD COLUMN `mode` VARCHAR(100) NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='crypto_functions');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `cbom_entries` ADD COLUMN `crypto_functions` LONGTEXT NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='classical_security_level');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `cbom_entries` ADD COLUMN `classical_security_level` INT NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='oid');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `cbom_entries` ADD COLUMN `oid` VARCHAR(255) NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='element_list');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `cbom_entries` ADD COLUMN `element_list` LONGTEXT NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='key_id');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `cbom_entries` ADD COLUMN `key_id` VARCHAR(255) NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='key_state');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `cbom_entries` ADD COLUMN `key_state` VARCHAR(50) NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='key_size');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `cbom_entries` ADD COLUMN `key_size` INT NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='key_creation_date');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `cbom_entries` ADD COLUMN `key_creation_date` DATETIME NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='key_activation_date');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `cbom_entries` ADD COLUMN `key_activation_date` DATETIME NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='protocol_name');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `cbom_entries` ADD COLUMN `protocol_name` VARCHAR(100) NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='protocol_version_name');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `cbom_entries` ADD COLUMN `protocol_version_name` VARCHAR(50) NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='cipher_suites');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `cbom_entries` ADD COLUMN `cipher_suites` LONGTEXT NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='subject_name');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `cbom_entries` ADD COLUMN `subject_name` VARCHAR(500) NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='issuer_name');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `cbom_entries` ADD COLUMN `issuer_name` VARCHAR(500) NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='not_valid_before');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `cbom_entries` ADD COLUMN `not_valid_before` DATETIME NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='not_valid_after');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `cbom_entries` ADD COLUMN `not_valid_after` DATETIME NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='signature_algorithm_reference');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `cbom_entries` ADD COLUMN `signature_algorithm_reference` VARCHAR(255) NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='subject_public_key_reference');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `cbom_entries` ADD COLUMN `subject_public_key_reference` VARCHAR(255) NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='certificate_format');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `cbom_entries` ADD COLUMN `certificate_format` VARCHAR(100) NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='certificate_extension');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `cbom_entries` ADD COLUMN `certificate_extension` VARCHAR(32) NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='superseded_at');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `cbom_entries` ADD COLUMN `superseded_at` DATETIME NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Create indexes safely using information_schema checks (some MySQL builds do not support CREATE INDEX IF NOT EXISTS)
SET @exists = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND INDEX_NAME='idx_cbom_asset_type');
SET @sql = IF(@exists = 0, 'CREATE INDEX idx_cbom_asset_type ON cbom_entries (asset_type)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @exists = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND INDEX_NAME='idx_cbom_oid');
SET @sql = IF(@exists = 0, 'CREATE INDEX idx_cbom_oid ON cbom_entries (oid)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- --------------------------------------------------------------------
-- 3) Certificates: details, fingerprints, dedup helpers, and indexes
-- --------------------------------------------------------------------

-- certificate details JSON
SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND COLUMN_NAME='certificate_details');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `certificates` ADD COLUMN `certificate_details` LONGTEXT NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- extra certificate fields
-- extra certificate fields (guarded per-column for compatibility)
SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND COLUMN_NAME='public_key_fingerprint_sha256');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `certificates` ADD COLUMN `public_key_fingerprint_sha256` VARCHAR(64) NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND COLUMN_NAME='certificate_version');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `certificates` ADD COLUMN `certificate_version` VARCHAR(50) NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND COLUMN_NAME='certificate_format');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `certificates` ADD COLUMN `certificate_format` VARCHAR(50) NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- alternate fingerprints and dedup metadata
SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND COLUMN_NAME='fingerprint_sha1');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `certificates` ADD COLUMN `fingerprint_sha1` VARCHAR(40) NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND COLUMN_NAME='fingerprint_md5');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `certificates` ADD COLUMN `fingerprint_md5` VARCHAR(32) NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND COLUMN_NAME='dedup_algorithm');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `certificates` ADD COLUMN `dedup_algorithm` VARCHAR(20) NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND COLUMN_NAME='dedup_value');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `certificates` ADD COLUMN `dedup_value` VARCHAR(128) NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND COLUMN_NAME='dedup_hash');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `certificates` ADD COLUMN `dedup_hash` VARCHAR(64) NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @exists = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND INDEX_NAME='idx_cert_pubkey_fp');
SET @sql = IF(@exists = 0, 'CREATE INDEX idx_cert_pubkey_fp ON certificates (public_key_fingerprint_sha256)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @exists = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND INDEX_NAME='idx_cert_fp_sha1');
SET @sql = IF(@exists = 0, 'CREATE INDEX idx_cert_fp_sha1 ON certificates (fingerprint_sha1)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @exists = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND INDEX_NAME='idx_cert_fp_md5');
SET @sql = IF(@exists = 0, 'CREATE INDEX idx_cert_fp_md5 ON certificates (fingerprint_md5)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @exists = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND INDEX_NAME='idx_cert_dedup_value');
SET @sql = IF(@exists = 0, 'CREATE INDEX idx_cert_dedup_value ON certificates (dedup_value)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @exists = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND INDEX_NAME='idx_cert_dedup_hash');
SET @sql = IF(@exists = 0, 'CREATE INDEX idx_cert_dedup_hash ON certificates (dedup_hash)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Apply CBOM hardening modifications from add_cbom_hardening_v2
-- Guarded MODIFY COLUMN: only run MODIFY if the column already exists (avoid errors on older dumps)
SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND COLUMN_NAME='serial');
SET @sql = IF(@col_exists > 0, 'ALTER TABLE `certificates` MODIFY COLUMN `serial` VARCHAR(255) NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND COLUMN_NAME='fingerprint_sha256');
SET @sql = IF(@col_exists > 0, 'ALTER TABLE `certificates` MODIFY COLUMN `fingerprint_sha256` VARCHAR(64) NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Drop legacy unique indexes if they exist (safe conditional drop)
SET @exists_serial_unique = (
  SELECT COUNT(*) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'certificates'
    AND INDEX_NAME = 'uq_certificates_serial'
    AND NON_UNIQUE = 0
);
SET @sql = IF(@exists_serial_unique > 0,
  'ALTER TABLE certificates DROP INDEX uq_certificates_serial',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @exists_fp_unique = (
  SELECT COUNT(*) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'certificates'
    AND INDEX_NAME = 'uq_certificates_fingerprint_sha256'
    AND NON_UNIQUE = 0
);
SET @sql2 = IF(@exists_fp_unique > 0,
  'ALTER TABLE certificates DROP INDEX uq_certificates_fingerprint_sha256',
  'SELECT 1'
);
PREPARE stmt2 FROM @sql2; EXECUTE stmt2; DEALLOCATE PREPARE stmt2;

-- is_current and first/last seen
-- Guarded additions: is_current, first_seen_at, last_seen_at
SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND COLUMN_NAME='is_current');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `certificates` ADD COLUMN `is_current` TINYINT(1) NOT NULL DEFAULT 0', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND COLUMN_NAME='first_seen_at');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `certificates` ADD COLUMN `first_seen_at` DATETIME NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND COLUMN_NAME='last_seen_at');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `certificates` ADD COLUMN `last_seen_at` DATETIME NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @exists = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND INDEX_NAME='idx_cert_asset_current');
SET @sql = IF(@exists = 0, 'CREATE INDEX idx_cert_asset_current ON certificates (asset_id, is_current)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @exists = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND INDEX_NAME='idx_cert_asset_created');
SET @sql = IF(@exists = 0, 'CREATE INDEX idx_cert_asset_created ON certificates (asset_id, created_at)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- --------------------------------------------------------------------
-- 4) Scans: correlation_id and scanner_version
-- --------------------------------------------------------------------
-- Guarded addition of scan columns
SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='scans' AND COLUMN_NAME='correlation_id');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `scans` ADD COLUMN `correlation_id` VARCHAR(36) NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='scans' AND COLUMN_NAME='scanner_version');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `scans` ADD COLUMN `scanner_version` VARCHAR(50) NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- --------------------------------------------------------------------
-- 5) New helper tables introduced in later migrations
-- --------------------------------------------------------------------

-- domain_current_state
CREATE TABLE IF NOT EXISTS domain_current_state (
  asset_id                  INT           NOT NULL,
  latest_scan_id            INT           NULL,
  current_ssl_certificate_id INT          NULL,
  current_risk_score        FLOAT         NOT NULL DEFAULT 0,
  current_risk_level        VARCHAR(50)   NULL,
  last_successful_scan_at   DATETIME      NULL,
  last_failed_scan_at       DATETIME      NULL,
  last_rendered_at          DATETIME      NULL,
  freshness_status          VARCHAR(20)   NOT NULL DEFAULT 'fresh',
  render_status             VARCHAR(20)   NULL,
  render_error_message      TEXT          NULL,
  updated_at                DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (asset_id),
  -- Foreign keys to assets/scans/certificates will be added after creation if compatible
  INDEX idx_dcs_freshness (freshness_status),
  INDEX idx_dcs_updated   (updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- asset_ssl_profiles
CREATE TABLE IF NOT EXISTS asset_ssl_profiles (
  id                      INT           NOT NULL AUTO_INCREMENT,
  asset_id                INT           NOT NULL,
  scan_id                 INT           NOT NULL,
  supports_tls_1_0        TINYINT(1)    NOT NULL DEFAULT 0,
  supports_tls_1_1        TINYINT(1)    NOT NULL DEFAULT 0,
  supports_tls_1_2        TINYINT(1)    NOT NULL DEFAULT 1,
  supports_tls_1_3        TINYINT(1)    NOT NULL DEFAULT 0,
  preferred_cipher        VARCHAR(255)  NULL,
  cipher_list_json        TEXT          NULL,
  weak_cipher_count       INT           NOT NULL DEFAULT 0,
  insecure_protocol_count INT           NOT NULL DEFAULT 0,
  hsts_enabled            TINYINT(1)    NOT NULL DEFAULT 0,
  hsts_max_age            INT           NULL,
  is_current              TINYINT(1)    NOT NULL DEFAULT 0,
  first_seen_at           DATETIME      NULL,
  last_seen_at            DATETIME      NULL,
  created_at              DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  is_deleted              TINYINT(1)    NOT NULL DEFAULT 0,
  deleted_at              DATETIME      NULL,
  deleted_by_user_id      VARCHAR(36)   NULL,
  PRIMARY KEY (id),
  -- Foreign keys to assets/scans will be added after creation if compatible
  INDEX idx_asp_asset_id    (asset_id),
  INDEX idx_asp_scan_id     (scan_id),
  INDEX idx_asp_is_current  (is_current),
  INDEX idx_asp_asset_curr  (asset_id, is_current)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- domain_events
CREATE TABLE IF NOT EXISTS domain_events (
  id                INT          NOT NULL AUTO_INCREMENT,
  asset_id          INT          NOT NULL,
  scan_id           INT          NULL,
  event_type        VARCHAR(80)  NOT NULL,
  event_title       VARCHAR(255) NOT NULL,
  event_description TEXT         NULL,
  old_value_json    TEXT         NULL,
  new_value_json    TEXT         NULL,
  severity          VARCHAR(20)  NULL,
  correlation_id    VARCHAR(36)  NULL,
  created_at        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  -- Foreign keys to assets/scans will be added after creation if compatible
  INDEX idx_de_asset_id      (asset_id),
  INDEX idx_de_event_type    (event_type),
  INDEX idx_de_severity      (severity),
  INDEX idx_de_created_at    (created_at),
  INDEX idx_de_correlation   (correlation_id),
  INDEX idx_de_asset_created (asset_id, created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- subdomains
CREATE TABLE IF NOT EXISTS subdomains (
    id            BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    parent_asset_id BIGINT     NOT NULL,
    subdomain     VARCHAR(512) NOT NULL,
    record_type   VARCHAR(20)  NOT NULL DEFAULT 'A',
    ip            VARCHAR(80)  NULL,
    is_inventoried TINYINT(1)  NOT NULL DEFAULT 0,
    is_deleted    TINYINT(1)   NOT NULL DEFAULT 0,
    discovered_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_sub_parent (parent_asset_id),
    INDEX idx_sub_subdomain (subdomain(191)),
    INDEX idx_sub_deleted (is_deleted)
    -- Foreign key to assets (parent_asset_id) will be added later if compatible
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- vulnerability_cache
CREATE TABLE IF NOT EXISTS vulnerability_cache (
    id          BIGINT        NOT NULL AUTO_INCREMENT PRIMARY KEY,
    asset_id    BIGINT        NOT NULL,
    cve_id      VARCHAR(30)   NOT NULL,
    severity    VARCHAR(20)   NOT NULL DEFAULT 'unknown',
    cvss        FLOAT         NULL,
    description TEXT          NULL,
    mitigation  TEXT          NULL,
    published_at DATETIME     NULL,
    source      VARCHAR(50)   NOT NULL DEFAULT 'nvd',
    fetched_at  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_vc_asset (asset_id),
    INDEX idx_vc_cve (cve_id),
    INDEX idx_vc_severity (severity),
    INDEX idx_vc_fetched (fetched_at),
    UNIQUE KEY uq_vc_asset_cve (asset_id, cve_id)
    -- Foreign key to assets (asset_id) will be added later if compatible
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ai_audit_log
CREATE TABLE IF NOT EXISTS ai_audit_log (
    id           BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id      VARCHAR(36)  NULL,
    ip_address   VARCHAR(80)  NULL,
    message_hash VARCHAR(64)  NOT NULL,
    model_used   VARCHAR(100) NULL,
    rag_enabled  TINYINT(1)   NOT NULL DEFAULT 0,
    token_count  INT          NULL,
    created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ai_user (user_id),
    INDEX idx_ai_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------------------
-- 6) HNDL, users 2FA, TLS resilience and other ALTERs (from 008)
-- --------------------------------------------------------------------

-- Guarded additions for asset_metrics and tls_compliance_scores
SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='asset_metrics' AND COLUMN_NAME='hndl_risk_score');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `asset_metrics` ADD COLUMN `hndl_risk_score` FLOAT NULL COMMENT ''Harvest-Now-Decrypt-Later composite risk score 0-100''', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='asset_metrics' AND COLUMN_NAME='hndl_flags');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `asset_metrics` ADD COLUMN `hndl_flags` JSON NULL COMMENT ''JSON array of detected HNDL risk flags''', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='tls_compliance_scores' AND COLUMN_NAME='resilience_tier');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `tls_compliance_scores` ADD COLUMN `resilience_tier` ENUM(''critical'',''medium'',''low'') NULL COMMENT ''TLS resilience tier''', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Guarded additions for users 2FA columns
SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='two_factor_enabled');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `users` ADD COLUMN `two_factor_enabled` TINYINT(1) NOT NULL DEFAULT 0 COMMENT ''1 = TOTP 2FA enabled for this user''', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='two_factor_secret');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `users` ADD COLUMN `two_factor_secret` VARCHAR(64) NULL COMMENT ''Fernet-encrypted TOTP base32 secret''', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='backup_codes');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE `users` ADD COLUMN `backup_codes` JSON NULL COMMENT ''JSON array of hashed single-use backup codes''', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- --------------------------------------------------------------------
-- 7) Normalize BIGINT columns (from 004) -- idempotent, preserves AUTO_INCREMENT
-- --------------------------------------------------------------------

-- This block runs a series of conditional ALTERs that only change types when necessary.
-- Keep it as-is because it is safe to re-run.

-- assets.id
SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='assets' AND COLUMN_NAME='id';
-- Do not attempt to modify the parent PK if there are incompatible child foreign keys
SELECT COUNT(*) INTO @incomp_refs FROM information_schema.KEY_COLUMN_USAGE k
 JOIN information_schema.COLUMNS c ON k.TABLE_SCHEMA = c.TABLE_SCHEMA AND k.TABLE_NAME = c.TABLE_NAME AND k.COLUMN_NAME = c.COLUMN_NAME
 WHERE k.TABLE_SCHEMA = DATABASE() AND k.REFERENCED_TABLE_NAME='assets' AND k.REFERENCED_COLUMN_NAME='id' AND c.DATA_TYPE <> 'bigint';

SELECT IF(@dt <> 'bigint' AND @incomp_refs = 0,
  CONCAT('ALTER TABLE `assets` MODIFY COLUMN `id` BIGINT ',
    (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='assets' AND COLUMN_NAME='id'),
    (SELECT IF(EXTRA LIKE '%auto_increment%',' AUTO_INCREMENT','') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='assets' AND COLUMN_NAME='id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- [Truncated in combined file for readability: the original 004 script contains many similar blocks
-- for scans, discovery_domains, discovery_ssl, discovery_ips, discovery_software, certificates,
-- pqc_classification, cbom_summary, cbom_entries, compliance_scores, cyber_rating, findings,
-- asset_metrics, org_pqc_metrics, cert_expiry_buckets, tls_compliance_scores, digital_labels,
-- domain_current_state, asset_ssl_profiles, domain_events.]

-- If you need the full column-by-column normalization, run 004_normalize_bigint_columns.sql separately or
-- copy its full content into this combined migration before running.

-- --------------------------------------------------------------------
-- 8) Backfill dedup values (from 007) -- transactional and idempotent
-- --------------------------------------------------------------------

START TRANSACTION;

-- 1) Populate dedup_algorithm where missing
UPDATE certificates
SET dedup_algorithm = CASE
  WHEN TRIM(COALESCE(fingerprint_sha256, '')) <> '' THEN 'sha256'
  WHEN TRIM(COALESCE(public_key_fingerprint_sha256, '')) <> '' THEN 'sha256'
  WHEN TRIM(COALESCE(fingerprint_sha1, '')) <> '' THEN 'sha1'
  WHEN TRIM(COALESCE(fingerprint_md5, '')) <> '' THEN 'md5'
  ELSE dedup_algorithm
END
WHERE (dedup_algorithm IS NULL OR TRIM(dedup_algorithm) = '');

-- 2) Populate dedup_value based on dedup_algorithm (do not overwrite existing non-empty values)
UPDATE certificates
SET dedup_value = CASE
  WHEN (TRIM(COALESCE(dedup_value, '')) = '') AND (dedup_algorithm = 'sha256')
    THEN COALESCE(NULLIF(TRIM(fingerprint_sha256), ''), NULLIF(TRIM(public_key_fingerprint_sha256), ''))
  WHEN (TRIM(COALESCE(dedup_value, '')) = '') AND (dedup_algorithm = 'sha1')
    THEN CONCAT('sha1:', TRIM(fingerprint_sha1))
  WHEN (TRIM(COALESCE(dedup_value, '')) = '') AND (dedup_algorithm = 'md5')
    THEN CONCAT('md5:', TRIM(fingerprint_md5))
  ELSE dedup_value
END
WHERE (dedup_value IS NULL OR TRIM(dedup_value) = '');

-- 3) Compute dedup_hash from asset_id + ':' + dedup_value where missing
UPDATE certificates
SET dedup_hash = LOWER(SHA2(CONCAT(COALESCE(CAST(asset_id AS CHAR), ''), ':', COALESCE(dedup_value, '')), 256))
WHERE (dedup_hash IS NULL OR TRIM(dedup_hash) = '') AND (dedup_value IS NOT NULL AND TRIM(dedup_value) <> '');

COMMIT;

-- --------------------------------------------------------------------
-- 9) New indexes and helper indexes (create safely if missing)
-- --------------------------------------------------------------------

-- Helper to create an index if it's missing using information_schema
SET @idx_exists = NULL;

SET @idx_exists = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND INDEX_NAME='idx_cbom_asset_type');
SET @sql = IF(@idx_exists = 0, 'CREATE INDEX idx_cbom_asset_type ON cbom_entries (asset_type)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @idx_exists = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND INDEX_NAME='idx_cbom_oid');
SET @sql = IF(@idx_exists = 0, 'CREATE INDEX idx_cbom_oid ON cbom_entries (oid)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @idx_exists = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND INDEX_NAME='idx_cert_pubkey_fp');
SET @sql = IF(@idx_exists = 0, 'CREATE INDEX idx_cert_pubkey_fp ON certificates (public_key_fingerprint_sha256)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @idx_exists = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND INDEX_NAME='idx_cert_fp_sha1');
SET @sql = IF(@idx_exists = 0, 'CREATE INDEX idx_cert_fp_sha1 ON certificates (fingerprint_sha1)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @idx_exists = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND INDEX_NAME='idx_cert_fp_md5');
SET @sql = IF(@idx_exists = 0, 'CREATE INDEX idx_cert_fp_md5 ON certificates (fingerprint_md5)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @idx_exists = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND INDEX_NAME='idx_cert_dedup_value');
SET @sql = IF(@idx_exists = 0, 'CREATE INDEX idx_cert_dedup_value ON certificates (dedup_value)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @idx_exists = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND INDEX_NAME='idx_cert_dedup_hash');
SET @sql = IF(@idx_exists = 0, 'CREATE INDEX idx_cert_dedup_hash ON certificates (dedup_hash)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @idx_exists = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND INDEX_NAME='idx_cert_asset_current');
SET @sql = IF(@idx_exists = 0, 'CREATE INDEX idx_cert_asset_current ON certificates (asset_id, is_current)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @idx_exists = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND INDEX_NAME='idx_cert_asset_created');
SET @sql = IF(@idx_exists = 0, 'CREATE INDEX idx_cert_asset_created ON certificates (asset_id, created_at)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Findings and dashboard indexes
SET @idx_exists = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='findings' AND INDEX_NAME='idx_findings_severity_date');
SET @sql = IF(@idx_exists = 0, 'CREATE INDEX idx_findings_severity_date ON findings (severity, created_at)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @idx_exists = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='findings' AND INDEX_NAME='idx_asset_finding_severity');
SET @sql = IF(@idx_exists = 0, 'CREATE INDEX idx_asset_finding_severity ON findings (asset_id, severity)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @idx_exists = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='org_pqc_metrics' AND INDEX_NAME='idx_org_metrics_date');
SET @sql = IF(@idx_exists = 0, 'CREATE INDEX idx_org_metrics_date ON org_pqc_metrics (metric_date)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- --------------------------------------------------------------------
-- 10) Add foreign key constraints conditionally if column types match
-- --------------------------------------------------------------------

-- Helper: add FK only when both columns exist, types match, and no existing FK

-- asset_metrics.asset_id -> assets.id
SELECT COUNT(*) INTO @c1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='asset_metrics' AND COLUMN_NAME='asset_id';
SELECT COUNT(*) INTO @c2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='assets' AND COLUMN_NAME='id';
SELECT COLUMN_TYPE INTO @t1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='asset_metrics' AND COLUMN_NAME='asset_id';
SELECT COLUMN_TYPE INTO @t2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='assets' AND COLUMN_NAME='id';
SELECT COUNT(*) INTO @fk_exists FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='asset_metrics' AND COLUMN_NAME='asset_id' AND REFERENCED_TABLE_NAME='assets' AND REFERENCED_COLUMN_NAME='id';
SET @do = IF(@c1>0 AND @c2>0 AND @fk_exists=0 AND @t1 = @t2, 1, 0);
SET @sql = IF(@do=1, 'ALTER TABLE `asset_metrics` ADD CONSTRAINT `fk_asset_metrics_asset` FOREIGN KEY (`asset_id`) REFERENCES `assets`(`id`) ON DELETE CASCADE', 'SELECT 1');
PREPARE stmt_fk FROM @sql; EXECUTE stmt_fk; DEALLOCATE PREPARE stmt_fk;

-- findings.asset_id -> assets.id
SELECT COUNT(*) INTO @c1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='findings' AND COLUMN_NAME='asset_id';
SELECT COUNT(*) INTO @c2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='assets' AND COLUMN_NAME='id';
SELECT COLUMN_TYPE INTO @t1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='findings' AND COLUMN_NAME='asset_id';
SELECT COLUMN_TYPE INTO @t2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='assets' AND COLUMN_NAME='id';
SELECT COUNT(*) INTO @fk_exists FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='findings' AND COLUMN_NAME='asset_id' AND REFERENCED_TABLE_NAME='assets' AND REFERENCED_COLUMN_NAME='id';
SET @do = IF(@c1>0 AND @c2>0 AND @fk_exists=0 AND @t1 = @t2, 1, 0);
SET @sql = IF(@do=1, 'ALTER TABLE `findings` ADD CONSTRAINT `fk_findings_asset` FOREIGN KEY (`asset_id`) REFERENCES `assets`(`id`) ON DELETE CASCADE', 'SELECT 1');
PREPARE stmt_fk FROM @sql; EXECUTE stmt_fk; DEALLOCATE PREPARE stmt_fk;

-- findings.scan_id -> scans.id
SELECT COUNT(*) INTO @c1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='findings' AND COLUMN_NAME='scan_id';
SELECT COUNT(*) INTO @c2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='scans' AND COLUMN_NAME='id';
SELECT COLUMN_TYPE INTO @t1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='findings' AND COLUMN_NAME='scan_id';
SELECT COLUMN_TYPE INTO @t2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='scans' AND COLUMN_NAME='id';
SELECT COUNT(*) INTO @fk_exists FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='findings' AND COLUMN_NAME='scan_id' AND REFERENCED_TABLE_NAME='scans' AND REFERENCED_COLUMN_NAME='id';
SET @do = IF(@c1>0 AND @c2>0 AND @fk_exists=0 AND @t1 = @t2, 1, 0);
SET @sql = IF(@do=1, 'ALTER TABLE `findings` ADD CONSTRAINT `fk_findings_scan` FOREIGN KEY (`scan_id`) REFERENCES `scans`(`id`) ON DELETE CASCADE', 'SELECT 1');
PREPARE stmt_fk FROM @sql; EXECUTE stmt_fk; DEALLOCATE PREPARE stmt_fk;

-- findings.certificate_id -> certificates.id
SELECT COUNT(*) INTO @c1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='findings' AND COLUMN_NAME='certificate_id';
SELECT COUNT(*) INTO @c2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='certificates' AND COLUMN_NAME='id';
SELECT COLUMN_TYPE INTO @t1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='findings' AND COLUMN_NAME='certificate_id';
SELECT COLUMN_TYPE INTO @t2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='certificates' AND COLUMN_NAME='id';
SELECT COUNT(*) INTO @fk_exists FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='findings' AND COLUMN_NAME='certificate_id' AND REFERENCED_TABLE_NAME='certificates' AND REFERENCED_COLUMN_NAME='id';
SET @do = IF(@c1>0 AND @c2>0 AND @fk_exists=0 AND @t1 = @t2, 1, 0);
SET @sql = IF(@do=1, 'ALTER TABLE `findings` ADD CONSTRAINT `fk_findings_certificate` FOREIGN KEY (`certificate_id`) REFERENCES `certificates`(`id`) ON DELETE SET NULL', 'SELECT 1');
PREPARE stmt_fk FROM @sql; EXECUTE stmt_fk; DEALLOCATE PREPARE stmt_fk;

-- findings.cbom_entry_id -> cbom_entries.id
SELECT COUNT(*) INTO @c1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='findings' AND COLUMN_NAME='cbom_entry_id';
SELECT COUNT(*) INTO @c2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='id';
SELECT COLUMN_TYPE INTO @t1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='findings' AND COLUMN_NAME='cbom_entry_id';
SELECT COLUMN_TYPE INTO @t2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='id';
SELECT COUNT(*) INTO @fk_exists FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='findings' AND COLUMN_NAME='cbom_entry_id' AND REFERENCED_TABLE_NAME='cbom_entries' AND REFERENCED_COLUMN_NAME='id';
SET @do = IF(@c1>0 AND @c2>0 AND @fk_exists=0 AND @t1 = @t2, 1, 0);
SET @sql = IF(@do=1, 'ALTER TABLE `findings` ADD CONSTRAINT `fk_findings_cbom_entry` FOREIGN KEY (`cbom_entry_id`) REFERENCES `cbom_entries`(`id`) ON DELETE SET NULL', 'SELECT 1');
PREPARE stmt_fk FROM @sql; EXECUTE stmt_fk; DEALLOCATE PREPARE stmt_fk;

-- findings.deleted_by_user_id -> users.id
SELECT COUNT(*) INTO @c1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='findings' AND COLUMN_NAME='deleted_by_user_id';
SELECT COUNT(*) INTO @c2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='id';
SELECT COLUMN_TYPE INTO @t1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='findings' AND COLUMN_NAME='deleted_by_user_id';
SELECT COLUMN_TYPE INTO @t2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='id';
SELECT COUNT(*) INTO @fk_exists FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='findings' AND COLUMN_NAME='deleted_by_user_id' AND REFERENCED_TABLE_NAME='users' AND REFERENCED_COLUMN_NAME='id';
SET @do = IF(@c1>0 AND @c2>0 AND @fk_exists=0 AND @t1 = @t2, 1, 0);
SET @sql = IF(@do=1, 'ALTER TABLE `findings` ADD CONSTRAINT `fk_findings_deleted_by_user` FOREIGN KEY (`deleted_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL', 'SELECT 1');
PREPARE stmt_fk FROM @sql; EXECUTE stmt_fk; DEALLOCATE PREPARE stmt_fk;

-- tls_compliance_scores.asset_id -> assets.id
SELECT COUNT(*) INTO @c1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tls_compliance_scores' AND COLUMN_NAME='asset_id';
SELECT COUNT(*) INTO @c2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='assets' AND COLUMN_NAME='id';
SELECT COLUMN_TYPE INTO @t1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tls_compliance_scores' AND COLUMN_NAME='asset_id';
SELECT COLUMN_TYPE INTO @t2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='assets' AND COLUMN_NAME='id';
SELECT COUNT(*) INTO @fk_exists FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tls_compliance_scores' AND COLUMN_NAME='asset_id' AND REFERENCED_TABLE_NAME='assets' AND REFERENCED_COLUMN_NAME='id';
SET @do = IF(@c1>0 AND @c2>0 AND @fk_exists=0 AND @t1 = @t2, 1, 0);
SET @sql = IF(@do=1, 'ALTER TABLE `tls_compliance_scores` ADD CONSTRAINT `fk_tls_compliance_asset` FOREIGN KEY (`asset_id`) REFERENCES `assets`(`id`) ON DELETE CASCADE', 'SELECT 1');
PREPARE stmt_fk FROM @sql; EXECUTE stmt_fk; DEALLOCATE PREPARE stmt_fk;

-- digital_labels.asset_id -> assets.id
SELECT COUNT(*) INTO @c1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='digital_labels' AND COLUMN_NAME='asset_id';
SELECT COUNT(*) INTO @c2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='assets' AND COLUMN_NAME='id';
SELECT COLUMN_TYPE INTO @t1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='digital_labels' AND COLUMN_NAME='asset_id';
SELECT COLUMN_TYPE INTO @t2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='assets' AND COLUMN_NAME='id';
SELECT COUNT(*) INTO @fk_exists FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='digital_labels' AND COLUMN_NAME='asset_id' AND REFERENCED_TABLE_NAME='assets' AND REFERENCED_COLUMN_NAME='id';
SET @do = IF(@c1>0 AND @c2>0 AND @fk_exists=0 AND @t1 = @t2, 1, 0);
SET @sql = IF(@do=1, 'ALTER TABLE `digital_labels` ADD CONSTRAINT `fk_digital_labels_asset` FOREIGN KEY (`asset_id`) REFERENCES `assets`(`id`) ON DELETE CASCADE', 'SELECT 1');
PREPARE stmt_fk FROM @sql; EXECUTE stmt_fk; DEALLOCATE PREPARE stmt_fk;

-- domain_current_state.asset_id -> assets.id
SELECT COUNT(*) INTO @c1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='domain_current_state' AND COLUMN_NAME='asset_id';
SELECT COUNT(*) INTO @c2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='assets' AND COLUMN_NAME='id';
SELECT COLUMN_TYPE INTO @t1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='domain_current_state' AND COLUMN_NAME='asset_id';
SELECT COLUMN_TYPE INTO @t2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='assets' AND COLUMN_NAME='id';
SELECT COUNT(*) INTO @fk_exists FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='domain_current_state' AND COLUMN_NAME='asset_id' AND REFERENCED_TABLE_NAME='assets' AND REFERENCED_COLUMN_NAME='id';
SET @do = IF(@c1>0 AND @c2>0 AND @fk_exists=0 AND @t1 = @t2, 1, 0);
SET @sql = IF(@do=1, 'ALTER TABLE `domain_current_state` ADD CONSTRAINT `fk_dcs_asset` FOREIGN KEY (`asset_id`) REFERENCES `assets`(`id`) ON DELETE CASCADE', 'SELECT 1');
PREPARE stmt_fk FROM @sql; EXECUTE stmt_fk; DEALLOCATE PREPARE stmt_fk;

-- domain_current_state.latest_scan_id -> scans.id
SELECT COUNT(*) INTO @c1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='domain_current_state' AND COLUMN_NAME='latest_scan_id';
SELECT COUNT(*) INTO @c2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='scans' AND COLUMN_NAME='id';
SELECT COLUMN_TYPE INTO @t1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='domain_current_state' AND COLUMN_NAME='latest_scan_id';
SELECT COLUMN_TYPE INTO @t2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='scans' AND COLUMN_NAME='id';
SELECT COUNT(*) INTO @fk_exists FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='domain_current_state' AND COLUMN_NAME='latest_scan_id' AND REFERENCED_TABLE_NAME='scans' AND REFERENCED_COLUMN_NAME='id';
SET @do = IF(@c1>0 AND @c2>0 AND @fk_exists=0 AND @t1 = @t2, 1, 0);
SET @sql = IF(@do=1, 'ALTER TABLE `domain_current_state` ADD CONSTRAINT `fk_dcs_scan` FOREIGN KEY (`latest_scan_id`) REFERENCES `scans`(`id`) ON DELETE SET NULL', 'SELECT 1');
PREPARE stmt_fk FROM @sql; EXECUTE stmt_fk; DEALLOCATE PREPARE stmt_fk;

-- domain_current_state.current_ssl_certificate_id -> certificates.id
SELECT COUNT(*) INTO @c1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='domain_current_state' AND COLUMN_NAME='current_ssl_certificate_id';
SELECT COUNT(*) INTO @c2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='certificates' AND COLUMN_NAME='id';
SELECT COLUMN_TYPE INTO @t1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='domain_current_state' AND COLUMN_NAME='current_ssl_certificate_id';
SELECT COLUMN_TYPE INTO @t2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='certificates' AND COLUMN_NAME='id';
SELECT COUNT(*) INTO @fk_exists FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='domain_current_state' AND COLUMN_NAME='current_ssl_certificate_id' AND REFERENCED_TABLE_NAME='certificates' AND REFERENCED_COLUMN_NAME='id';
SET @do = IF(@c1>0 AND @c2>0 AND @fk_exists=0 AND @t1 = @t2, 1, 0);
SET @sql = IF(@do=1, 'ALTER TABLE `domain_current_state` ADD CONSTRAINT `fk_dcs_cert` FOREIGN KEY (`current_ssl_certificate_id`) REFERENCES `certificates`(`id`) ON DELETE SET NULL', 'SELECT 1');
PREPARE stmt_fk FROM @sql; EXECUTE stmt_fk; DEALLOCATE PREPARE stmt_fk;

-- asset_ssl_profiles.asset_id -> assets.id
SELECT COUNT(*) INTO @c1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='asset_ssl_profiles' AND COLUMN_NAME='asset_id';
SELECT COUNT(*) INTO @c2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='assets' AND COLUMN_NAME='id';
SELECT COLUMN_TYPE INTO @t1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='asset_ssl_profiles' AND COLUMN_NAME='asset_id';
SELECT COLUMN_TYPE INTO @t2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='assets' AND COLUMN_NAME='id';
SELECT COUNT(*) INTO @fk_exists FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='asset_ssl_profiles' AND COLUMN_NAME='asset_id' AND REFERENCED_TABLE_NAME='assets' AND REFERENCED_COLUMN_NAME='id';
SET @do = IF(@c1>0 AND @c2>0 AND @fk_exists=0 AND @t1 = @t2, 1, 0);
SET @sql = IF(@do=1, 'ALTER TABLE `asset_ssl_profiles` ADD CONSTRAINT `fk_asp_asset` FOREIGN KEY (`asset_id`) REFERENCES `assets`(`id`) ON DELETE CASCADE', 'SELECT 1');
PREPARE stmt_fk FROM @sql; EXECUTE stmt_fk; DEALLOCATE PREPARE stmt_fk;

-- asset_ssl_profiles.scan_id -> scans.id
SELECT COUNT(*) INTO @c1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='asset_ssl_profiles' AND COLUMN_NAME='scan_id';
SELECT COUNT(*) INTO @c2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='scans' AND COLUMN_NAME='id';
SELECT COLUMN_TYPE INTO @t1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='asset_ssl_profiles' AND COLUMN_NAME='scan_id';
SELECT COLUMN_TYPE INTO @t2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='scans' AND COLUMN_NAME='id';
SELECT COUNT(*) INTO @fk_exists FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='asset_ssl_profiles' AND COLUMN_NAME='scan_id' AND REFERENCED_TABLE_NAME='scans' AND REFERENCED_COLUMN_NAME='id';
SET @do = IF(@c1>0 AND @c2>0 AND @fk_exists=0 AND @t1 = @t2, 1, 0);
SET @sql = IF(@do=1, 'ALTER TABLE `asset_ssl_profiles` ADD CONSTRAINT `fk_asp_scan` FOREIGN KEY (`scan_id`) REFERENCES `scans`(`id`) ON DELETE CASCADE', 'SELECT 1');
PREPARE stmt_fk FROM @sql; EXECUTE stmt_fk; DEALLOCATE PREPARE stmt_fk;

-- domain_events.asset_id -> assets.id
SELECT COUNT(*) INTO @c1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='domain_events' AND COLUMN_NAME='asset_id';
SELECT COUNT(*) INTO @c2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='assets' AND COLUMN_NAME='id';
SELECT COLUMN_TYPE INTO @t1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='domain_events' AND COLUMN_NAME='asset_id';
SELECT COLUMN_TYPE INTO @t2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='assets' AND COLUMN_NAME='id';
SELECT COUNT(*) INTO @fk_exists FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='domain_events' AND COLUMN_NAME='asset_id' AND REFERENCED_TABLE_NAME='assets' AND REFERENCED_COLUMN_NAME='id';
SET @do = IF(@c1>0 AND @c2>0 AND @fk_exists=0 AND @t1 = @t2, 1, 0);
SET @sql = IF(@do=1, 'ALTER TABLE `domain_events` ADD CONSTRAINT `fk_de_asset` FOREIGN KEY (`asset_id`) REFERENCES `assets`(`id`) ON DELETE CASCADE', 'SELECT 1');
PREPARE stmt_fk FROM @sql; EXECUTE stmt_fk; DEALLOCATE PREPARE stmt_fk;

-- domain_events.scan_id -> scans.id
SELECT COUNT(*) INTO @c1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='domain_events' AND COLUMN_NAME='scan_id';
SELECT COUNT(*) INTO @c2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='scans' AND COLUMN_NAME='id';
SELECT COLUMN_TYPE INTO @t1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='domain_events' AND COLUMN_NAME='scan_id';
SELECT COLUMN_TYPE INTO @t2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='scans' AND COLUMN_NAME='id';
SELECT COUNT(*) INTO @fk_exists FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='domain_events' AND COLUMN_NAME='scan_id' AND REFERENCED_TABLE_NAME='scans' AND REFERENCED_COLUMN_NAME='id';
SET @do = IF(@c1>0 AND @c2>0 AND @fk_exists=0 AND @t1 = @t2, 1, 0);
SET @sql = IF(@do=1, 'ALTER TABLE `domain_events` ADD CONSTRAINT `fk_de_scan` FOREIGN KEY (`scan_id`) REFERENCES `scans`(`id`) ON DELETE SET NULL', 'SELECT 1');
PREPARE stmt_fk FROM @sql; EXECUTE stmt_fk; DEALLOCATE PREPARE stmt_fk;

-- subdomains.parent_asset_id -> assets.id
SELECT COUNT(*) INTO @c1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='subdomains' AND COLUMN_NAME='parent_asset_id';
SELECT COUNT(*) INTO @c2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='assets' AND COLUMN_NAME='id';
SELECT COLUMN_TYPE INTO @t1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='subdomains' AND COLUMN_NAME='parent_asset_id';
SELECT COLUMN_TYPE INTO @t2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='assets' AND COLUMN_NAME='id';
SELECT COUNT(*) INTO @fk_exists FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='subdomains' AND COLUMN_NAME='parent_asset_id' AND REFERENCED_TABLE_NAME='assets' AND REFERENCED_COLUMN_NAME='id';
SET @do = IF(@c1>0 AND @c2>0 AND @fk_exists=0 AND @t1 = @t2, 1, 0);
SET @sql = IF(@do=1, 'ALTER TABLE `subdomains` ADD CONSTRAINT `fk_sub_asset` FOREIGN KEY (`parent_asset_id`) REFERENCES `assets`(`id`) ON DELETE CASCADE', 'SELECT 1');
PREPARE stmt_fk FROM @sql; EXECUTE stmt_fk; DEALLOCATE PREPARE stmt_fk;

-- vulnerability_cache.asset_id -> assets.id
SELECT COUNT(*) INTO @c1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='vulnerability_cache' AND COLUMN_NAME='asset_id';
SELECT COUNT(*) INTO @c2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='assets' AND COLUMN_NAME='id';
SELECT COLUMN_TYPE INTO @t1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='vulnerability_cache' AND COLUMN_NAME='asset_id';
SELECT COLUMN_TYPE INTO @t2 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='assets' AND COLUMN_NAME='id';
SELECT COUNT(*) INTO @fk_exists FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='vulnerability_cache' AND COLUMN_NAME='asset_id' AND REFERENCED_TABLE_NAME='assets' AND REFERENCED_COLUMN_NAME='id';
SET @do = IF(@c1>0 AND @c2>0 AND @fk_exists=0 AND @t1 = @t2, 1, 0);
SET @sql = IF(@do=1, 'ALTER TABLE `vulnerability_cache` ADD CONSTRAINT `fk_vc_asset` FOREIGN KEY (`asset_id`) REFERENCES `assets`(`id`) ON DELETE CASCADE', 'SELECT 1');
PREPARE stmt_fk FROM @sql; EXECUTE stmt_fk; DEALLOCATE PREPARE stmt_fk;


-- --------------------------------------------------------------------
-- 10) Restore session state
-- --------------------------------------------------------------------
SET SESSION sql_mode = @prev_sql_mode;
SET UNIQUE_CHECKS = @OLD_UNIQUE_CHECKS;
SET FOREIGN_KEY_CHECKS = @OLD_FOREIGN_KEY_CHECKS;

-- --------------------------------------------------------------------
-- Final notes:
-- - This combined migration collects the latest schema changes through 2026-04-08.
-- - The bigint-normalization section is intentionally abbreviated; if you expect many
--   integer-to-bigint conversions, include the full `004_normalize_bigint_columns.sql` content
--   or run that migration separately after verifying backups.
-- - If your MySQL server rejects `CREATE INDEX IF NOT EXISTS` or `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`,
--   run the individual original migration files included in the repo (migrations/00*.sql)
--   which include dynamic checks using information_schema.
-- - Always test in staging and take DB backups before running on production.
