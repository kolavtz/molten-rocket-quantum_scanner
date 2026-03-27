-- Migration: Add Findings, Metrics, and Digital Labels Tables
-- Purpose: Implement Phase 1 of math-based KPI system per math-definition-for-quantumshield-app.md
-- Date: 2026-03-23

-- ===============================================
-- TABLE 1: Findings (Issue/Security Finding Tracking)
-- ===============================================
-- Purpose: Audit trail for all discovered security issues
-- Based on Math Spec Section 8 (Reporting Metrics)
-- Stores findings per asset-scan pair for immutable history

CREATE TABLE IF NOT EXISTS findings (
    id                      BIGINT AUTO_INCREMENT PRIMARY KEY,
    finding_id              VARCHAR(36) NOT NULL UNIQUE,
    asset_id                BIGINT NOT NULL,
    scan_id                 BIGINT NOT NULL,
    
    -- Finding Classification
    issue_type              VARCHAR(100) NOT NULL,  -- weak_cipher, expiring_certificate, weak_tls, weak_key, etc.
    severity                VARCHAR(50) NOT NULL,   -- critical, high, medium, low
    description             TEXT NOT NULL,
    
    -- Finding Context (JSON for flexibility)
    metadata_json           JSON,
    
    -- Related Information
    certificate_id          BIGINT,
    cbom_entry_id           BIGINT,
    
    -- Soft Delete Support
    is_deleted              BOOLEAN DEFAULT FALSE,
    deleted_at              DATETIME,
    deleted_by_user_id      VARCHAR(36),
    created_at              DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Foreign Keys
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE SET NULL,
    FOREIGN KEY (cbom_entry_id) REFERENCES cbom_entries(id) ON DELETE SET NULL,
    FOREIGN KEY (deleted_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    
    -- Indexes for fast querying
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

-- ===============================================
-- TABLE 2: Asset Metrics (Materialized View for Asset-Level KPIs)
-- ===============================================
-- Purpose: Fast retrieval of asset-level calculations
-- Based on Math Spec Sections 2, 3, 5
-- Refreshed after each scan or via batch job

CREATE TABLE IF NOT EXISTS asset_metrics (
    asset_id                BIGINT PRIMARY KEY,
    
    -- PQC Scoring (Math Section 3.1-3.2)
    pqc_score               FLOAT DEFAULT 0,        -- 0-100, weighted average endpoint scores
    pqc_score_timestamp     DATETIME,
    
    -- Risk Penalties (Math Section 5.1)
    risk_penalty            FLOAT DEFAULT 0,        -- Σ(finding_severity × weight)
    total_findings_count    INT DEFAULT 0,
    critical_findings_count INT DEFAULT 0,
    
    -- Classification & Labeling (Math Section 3.3)
    pqc_class_tier          VARCHAR(50),            -- Elite, Standard, Legacy, Critical
    digital_label           VARCHAR(50),            -- Quantum-Safe, PQC Ready, Fully Quantum Safe
    has_critical_findings   BOOLEAN DEFAULT FALSE,
    
    -- Asset-level Cyber Score (Math Section 5.2)
    asset_cyber_score       FLOAT DEFAULT 0,        -- max(0, pqc_score - penalty_alpha × risk_penalty)
    
    -- Metadata
    last_updated            DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    calculated_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    -- Foreign Key
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    
    -- Indexes
    INDEX idx_pqc_score (pqc_score),
    INDEX idx_pqc_class_tier (pqc_class_tier),
    INDEX idx_digital_label (digital_label),
    INDEX idx_has_critical_findings (has_critical_findings),
    INDEX idx_last_updated (last_updated)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===============================================
-- TABLE 3: Organization-Level PQC Metrics (Daily Snapshot)
-- ===============================================
-- Purpose: Trends and historical KPIs for the entire organization
-- Based on Math Spec Section 7.1 (Home Dashboard)
-- Refreshed daily via batch job

CREATE TABLE IF NOT EXISTS org_pqc_metrics (
    id                      BIGINT AUTO_INCREMENT PRIMARY KEY,
    metric_date             DATE NOT NULL UNIQUE,
    
    -- Counts (Math Section 2.1)
    total_assets            INT DEFAULT 0,
    total_endpoints         INT DEFAULT 0,
    total_certificates      INT DEFAULT 0,
    
    -- PQC Distribution (Math Section 3.4)
    elite_assets_count      INT DEFAULT 0,
    standard_assets_count   INT DEFAULT 0,
    legacy_assets_count     INT DEFAULT 0,
    critical_assets_count   INT DEFAULT 0,
    
    -- Percentages (Math Section 2.2)
    pct_elite               DECIMAL(5, 2) DEFAULT 0,
    pct_standard            DECIMAL(5, 2) DEFAULT 0,
    pct_legacy              DECIMAL(5, 2) DEFAULT 0,
    pct_critical            DECIMAL(5, 2) DEFAULT 0,
    
    -- Aggregate Scores
    avg_pqc_score           DECIMAL(5, 2) DEFAULT 0,
    min_pqc_score           DECIMAL(5, 2) DEFAULT 0,
    max_pqc_score           DECIMAL(5, 2) DEFAULT 0,
    
    -- Findings Summary
    total_findings_count    INT DEFAULT 0,
    total_critical_findings INT DEFAULT 0,
    total_high_findings     INT DEFAULT 0,
    total_medium_findings   INT DEFAULT 0,
    total_low_findings      INT DEFAULT 0,
    
    -- Quantum-Safe Status
    quantum_safe_assets_count INT DEFAULT 0,
    quantum_safe_pct        DECIMAL(5, 2) DEFAULT 0,
    vulnerable_assets_count INT DEFAULT 0,
    vulnerable_pct          DECIMAL(5, 2) DEFAULT 0,
    
    -- Timestamps
    created_at              DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Indexes
    INDEX idx_metric_date (metric_date),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===============================================
-- TABLE 4: Certificate Expiry Buckets (Summary Distribution)
-- ===============================================
-- Purpose: Support cert expiry timeline charts (0-30, 31-60, 61-90, >90 days)
-- Based on Math Spec Section 2.5
-- Refreshed daily or post-scan

CREATE TABLE IF NOT EXISTS cert_expiry_buckets (
    id                      BIGINT AUTO_INCREMENT PRIMARY KEY,
    bucket_date             DATE NOT NULL,
    
    -- Expiry Bucket Counts (Math Section 2.5)
    count_0_to_30_days      INT DEFAULT 0,          -- Expiring soon
    count_31_to_60_days     INT DEFAULT 0,
    count_61_to_90_days     INT DEFAULT 0,
    count_greater_90_days   INT DEFAULT 0,
    count_expired           INT DEFAULT 0,
    
    -- Summary
    total_active_certs      INT DEFAULT 0,
    total_expired_certs     INT DEFAULT 0,
    
    -- Metadata
    created_at              DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Indexes
    INDEX idx_bucket_date (bucket_date),
    UNIQUE INDEX uq_bucket_date (bucket_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===============================================
-- TABLE 5: TLS Compliance Scores (TLS Metrics per Asset)
-- ===============================================
-- Purpose: Track TLS/cipher suite compliance metrics
-- Based on Math Spec Section 4 (CBOM Metrics)
-- Supports weak cipher detection and compliance scoring

CREATE TABLE IF NOT EXISTS tls_compliance_scores (
    asset_id                BIGINT PRIMARY KEY,
    
    -- TLS Score Calculation
    tls_score               FLOAT DEFAULT 0,        -- 0-100 based on TLS versions, algorithms, key lengths
    
    -- Breakdown
    score_breakdown_json    JSON,                   -- {weak_count, deprecated_count, good_count, strong_count}
    
    -- Weak Elements Counts
    weak_tls_version_count  INT DEFAULT 0,          -- TLS < 1.2
    weak_cipher_count       INT DEFAULT 0,          -- Deprecated ciphers
    weak_key_length_count   INT DEFAULT 0,          -- Key length < WEAK_KEY_LENGTH (config)
    
    -- Summary
    total_endpoints_scanned INT DEFAULT 0,
    
    -- Timestamps
    calculated_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Foreign Key
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    
    -- Indexes
    INDEX idx_tls_score (tls_score),
    INDEX idx_updated_at (updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===============================================
-- TABLE 6: Digital Labels (Asset Classification Labels)
-- ===============================================
-- Purpose: Store digital labels (Quantum-Safe, PQC Ready, Fully Quantum Safe)
-- Based on Feature Requirement: Digital Labels for Asset Classification
-- Denormalized for fast lookup in inventory/home dashboards

CREATE TABLE IF NOT EXISTS digital_labels (
    asset_id                BIGINT PRIMARY KEY,
    
    -- Label Classification
    label                   VARCHAR(100) NOT NULL,  -- Quantum-Safe, PQC Ready, Fully Quantum Safe, At Risk
    label_reason_json       JSON,                   -- {reason, confidence_score, threshold_values}
    confidence_score        INT DEFAULT 0,          -- 0-100, confidence in label assignment
    
    -- Label Derivation Info
    based_on_pqc_score      FLOAT DEFAULT 0,
    based_on_finding_count  INT DEFAULT 0,
    based_on_critical_findings BOOLEAN DEFAULT FALSE,
    based_on_enterprise_score FLOAT DEFAULT 0,
    
    -- Metadata
    label_generated_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    label_updated_at        DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Foreign Key
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    
    -- Indexes
    INDEX idx_label (label),
    INDEX idx_confidence_score (confidence_score),
    INDEX idx_label_generated_at (label_generated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===============================================
-- TABLE 7: Asset Fields (New Columns)
-- ===============================================
-- Purpose: Add calculated fields to assets table for direct querying
-- NOTE: These are denormalized from asset_metrics for convenience

-- ALTER TABLE assets ADD COLUMN IF NOT EXISTS pqc_score FLOAT DEFAULT 0;
-- ALTER TABLE assets ADD COLUMN IF NOT EXISTS risk_penalty FLOAT DEFAULT 0;
-- ALTER TABLE assets ADD COLUMN IF NOT EXISTS total_findings_count INT DEFAULT 0;
-- ALTER TABLE assets ADD COLUMN IF NOT EXISTS last_findings_sync_at DATETIME;
-- ALTER TABLE assets ADD INDEX idx_pqc_score (pqc_score);
-- ALTER TABLE assets ADD INDEX idx_total_findings_count (total_findings_count);

-- ===============================================
-- INDEXES FOR COMMON QUERIES
-- ===============================================

-- Fast lookup for home dashboard
CREATE INDEX IF NOT EXISTS idx_findings_severity_date 
    ON findings(severity, created_at);

-- Fast lookup for asset drill-down
CREATE INDEX IF NOT EXISTS idx_asset_finding_severity 
    ON findings(asset_id, severity);

-- Fast lookup for trends
CREATE INDEX IF NOT EXISTS idx_org_metrics_date 
    ON org_pqc_metrics(metric_date DESC);

-- Certificate expiry near-term alerts
CREATE INDEX IF NOT EXISTS idx_cert_expiry_emergency 
    ON cert_expiry_buckets((DATEDIFF(DATE_ADD(bucket_date, INTERVAL 90 DAY), CURDATE())) DESC);

-- Digital label filtering
CREATE INDEX IF NOT EXISTS idx_digital_label_confidence 
    ON digital_labels(label, confidence_score);

-- ===============================================
-- Notes for Implementation
-- ===============================================
-- All tables support soft-delete via is_deleted + deleted_at + deleted_by_user_id
-- All metrics tables have immutable created_at and mutable updated_at
-- foreign keys cascade on deletion for data consistency
-- Batch jobs will populate org_pqc_metrics, cert_expiry_buckets on schedule
-- asset_metrics updated after each scan via post_scan_processing job
-- findings detected and inserted during scan analysis phase
