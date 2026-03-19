-- MySQL DDL for QuantumShield Refactor
-- Supports Soft Deletes (is_deleted, deleted_at, deleted_by_user_id)
-- Supports Hard Deletes via ON DELETE CASCADE

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    role VARCHAR(50) DEFAULT 'Viewer'
);

CREATE TABLE scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL,
    started_at DATETIME,
    completed_at DATETIME,
    total_assets INT DEFAULT 0,
    overall_pqc_score FLOAT,
    cbom_path VARCHAR(500),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at DATETIME,
    deleted_by_user_id INT,
    FOREIGN KEY (deleted_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_scans_target (target),
    INDEX idx_scans_deleted (is_deleted)
);

CREATE TABLE assets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    url VARCHAR(255),
    ipv4 VARCHAR(50),
    ipv6 VARCHAR(50),
    asset_type VARCHAR(50) NOT NULL,
    owner VARCHAR(100),
    risk_level VARCHAR(50),
    last_scan_id INT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at DATETIME,
    deleted_by_user_id INT,
    FOREIGN KEY (last_scan_id) REFERENCES scans(id) ON DELETE SET NULL,
    FOREIGN KEY (deleted_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_assets_name (name),
    INDEX idx_assets_deleted (is_deleted)
);

CREATE TABLE discovery_items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    asset_id INT,
    type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    detection_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at DATETIME,
    deleted_by_user_id INT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY (deleted_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_discovery_scan_asset (scan_id, asset_id),
    INDEX idx_discovery_deleted (is_deleted)
);

CREATE TABLE certificates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    asset_id INT NOT NULL,
    scan_id INT NOT NULL,
    issuer TEXT,
    subject TEXT,
    serial VARCHAR(255),
    valid_from DATETIME,
    valid_until DATETIME,
    fingerprint_sha256 VARCHAR(64),
    tls_version VARCHAR(50),
    key_length INT,
    cipher_suite VARCHAR(255),
    ca VARCHAR(255),
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at DATETIME,
    deleted_by_user_id INT,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (deleted_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_certificates_deleted (is_deleted)
);

CREATE TABLE pqc_classification (
    id INT AUTO_INCREMENT PRIMARY KEY,
    certificate_id INT,
    asset_id INT NOT NULL,
    scan_id INT NOT NULL,
    algorithm_name VARCHAR(100),
    algorithm_type VARCHAR(100),
    quantum_safe_status VARCHAR(50),
    nist_category VARCHAR(50),
    pqc_score FLOAT,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at DATETIME,
    deleted_by_user_id INT,
    FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (deleted_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_pqc_deleted (is_deleted)
);

CREATE TABLE cbom_summary (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL UNIQUE,
    total_components INT DEFAULT 0,
    weak_crypto_count INT DEFAULT 0,
    cert_issues_count INT DEFAULT 0,
    json_path VARCHAR(500),
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at DATETIME,
    deleted_by_user_id INT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (deleted_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_cbom_summary_deleted (is_deleted)
);

CREATE TABLE cbom_entries (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    asset_id INT,
    algorithm_name VARCHAR(100),
    category VARCHAR(50),
    key_length INT,
    protocol_version VARCHAR(50),
    nist_status VARCHAR(50),
    quantum_safe_flag BOOLEAN DEFAULT FALSE,
    hndl_level VARCHAR(50),
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at DATETIME,
    deleted_by_user_id INT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY (deleted_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_cbom_entries_deleted (is_deleted)
);

CREATE TABLE compliance_scores (
    id INT AUTO_INCREMENT PRIMARY KEY,
    asset_id INT NOT NULL,
    scan_id INT NOT NULL,
    type VARCHAR(50),
    score_value FLOAT,
    tier VARCHAR(50),
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at DATETIME,
    deleted_by_user_id INT,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (deleted_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_compliance_scores_deleted (is_deleted)
);

CREATE TABLE cyber_rating (
    id INT AUTO_INCREMENT PRIMARY KEY,
    organization_id VARCHAR(100),
    scan_id INT NOT NULL,
    enterprise_score FLOAT,
    rating_tier VARCHAR(50),
    generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at DATETIME,
    deleted_by_user_id INT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (deleted_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_cyber_rating_deleted (is_deleted)
);
