-- ===========================================================================
-- CBOM HARDENING V2 MIGRATION
-- Sprint 1: Schema extensions for hardened CBOM dashboard
-- Safe to re-run: uses IF NOT EXISTS / COLUMN checks
-- ===========================================================================

-- ─── 1. Certificates – add new columns ─────────────────────────────────────

ALTER TABLE certificates
  MODIFY COLUMN serial VARCHAR(255) NULL,
  MODIFY COLUMN fingerprint_sha256 VARCHAR(64) NULL;

-- Drop old unique constraints that will block wildcard cert sharing
SET @exists_serial_unique = (
  SELECT COUNT(*) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'certificates'
    AND INDEX_NAME = 'uq_certificates_serial'
    AND NON_UNIQUE = 0
);

-- Remove old unique key on serial if still present (replaced by composite)
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

-- is_current flag
ALTER TABLE certificates
  ADD COLUMN IF NOT EXISTS is_current TINYINT(1) NOT NULL DEFAULT 0
    COMMENT 'TRUE = this is the latest certificate for the asset. At most one per asset.',
  ADD COLUMN IF NOT EXISTS first_seen_at DATETIME NULL
    COMMENT 'When this certificate fingerprint was first captured.',
  ADD COLUMN IF NOT EXISTS last_seen_at DATETIME NULL
    COMMENT 'Updated each time the same fingerprint is re-observed in a new scan.',
  ADD COLUMN IF NOT EXISTS dedup_hash VARCHAR(64) NULL
    COMMENT 'SHA-256 of CONCAT(asset_id, fingerprint_sha256) for idempotent insert detection.';

-- ─── 2. Scans – add correlation_id and scanner_version ────────────────────

ALTER TABLE scans
  ADD COLUMN IF NOT EXISTS correlation_id VARCHAR(36) NULL
    COMMENT 'Trace ID propagated from frontend → API → worker for end-to-end observability.',
  ADD COLUMN IF NOT EXISTS scanner_version VARCHAR(50) NULL
    COMMENT 'Version string of the scanner module that produced this scan.';

-- ─── 3. Table: domain_current_state ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS domain_current_state (
  asset_id                  INT           NOT NULL,
  latest_scan_id            INT           NULL,
  current_ssl_certificate_id INT          NULL,
  current_risk_score        FLOAT         NOT NULL DEFAULT 0,
  current_risk_level        VARCHAR(50)   NULL,
  last_successful_scan_at   DATETIME      NULL,
  last_failed_scan_at       DATETIME      NULL,
  last_rendered_at          DATETIME      NULL,
  -- 'fresh' | 'stale' | 'degraded'
  freshness_status          VARCHAR(20)   NOT NULL DEFAULT 'fresh',
  render_status             VARCHAR(20)   NULL,
  render_error_message      TEXT          NULL,
  updated_at                DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

  PRIMARY KEY (asset_id),
  CONSTRAINT fk_dcs_asset     FOREIGN KEY (asset_id)                   REFERENCES assets(id)       ON DELETE CASCADE,
  CONSTRAINT fk_dcs_scan      FOREIGN KEY (latest_scan_id)             REFERENCES scans(id)        ON DELETE SET NULL,
  CONSTRAINT fk_dcs_cert      FOREIGN KEY (current_ssl_certificate_id) REFERENCES certificates(id) ON DELETE SET NULL,

  INDEX idx_dcs_freshness (freshness_status),
  INDEX idx_dcs_updated   (updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Canonical current-state pointer per monitored asset. One row per asset. Never deleted.';

-- ─── 4. Table: asset_ssl_profiles ────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS asset_ssl_profiles (
  id                      INT           NOT NULL AUTO_INCREMENT,
  asset_id                INT           NOT NULL,
  scan_id                 INT           NOT NULL,
  supports_tls_1_0        TINYINT(1)    NOT NULL DEFAULT 0,
  supports_tls_1_1        TINYINT(1)    NOT NULL DEFAULT 0,
  supports_tls_1_2        TINYINT(1)    NOT NULL DEFAULT 1,
  supports_tls_1_3        TINYINT(1)    NOT NULL DEFAULT 0,
  preferred_cipher        VARCHAR(255)  NULL,
  cipher_list_json        TEXT          NULL COMMENT 'JSON array of observed cipher suites',
  weak_cipher_count       INT           NOT NULL DEFAULT 0,
  insecure_protocol_count INT           NOT NULL DEFAULT 0 COMMENT 'Count of TLS < 1.2 versions',
  hsts_enabled            TINYINT(1)    NOT NULL DEFAULT 0,
  hsts_max_age            INT           NULL,
  is_current              TINYINT(1)    NOT NULL DEFAULT 0 COMMENT 'At most one per asset should be 1',
  first_seen_at           DATETIME      NULL,
  last_seen_at            DATETIME      NULL,
  created_at              DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  is_deleted              TINYINT(1)    NOT NULL DEFAULT 0,
  deleted_at              DATETIME      NULL,
  deleted_by_user_id      VARCHAR(36)   NULL,

  PRIMARY KEY (id),
  CONSTRAINT fk_asp_asset FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
  CONSTRAINT fk_asp_scan  FOREIGN KEY (scan_id)  REFERENCES scans(id)  ON DELETE CASCADE,

  INDEX idx_asp_asset_id    (asset_id),
  INDEX idx_asp_scan_id     (scan_id),
  INDEX idx_asp_is_current  (is_current),
  INDEX idx_asp_asset_curr  (asset_id, is_current)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Historical TLS profile snapshots per scan. is_current=1 is the latest for that asset.';

-- ─── 5. Table: domain_events ──────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS domain_events (
  id                INT          NOT NULL AUTO_INCREMENT,
  asset_id          INT          NOT NULL,
  scan_id           INT          NULL,
  event_type        VARCHAR(80)  NOT NULL COMMENT 'cert_renewed|cert_expired|issuer_changed|tls_version_added|etc.',
  event_title       VARCHAR(255) NOT NULL,
  event_description TEXT         NULL,
  old_value_json    TEXT         NULL COMMENT 'JSON snapshot of previous state',
  new_value_json    TEXT         NULL COMMENT 'JSON snapshot of new state',
  severity          VARCHAR(20)  NULL COMMENT 'info|warning|critical',
  correlation_id    VARCHAR(36)  NULL,
  created_at        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,

  PRIMARY KEY (id),
  CONSTRAINT fk_de_asset FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
  CONSTRAINT fk_de_scan  FOREIGN KEY (scan_id)  REFERENCES scans(id)  ON DELETE SET NULL,

  INDEX idx_de_asset_id      (asset_id),
  INDEX idx_de_event_type    (event_type),
  INDEX idx_de_severity      (severity),
  INDEX idx_de_created_at    (created_at),
  INDEX idx_de_correlation   (correlation_id),
  INDEX idx_de_asset_created (asset_id, created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Immutable append-only audit log of security events per domain. Never updated or deleted.';

-- ─── 6. Composite indexes on certificates ─────────────────────────────────────

-- (asset_id, is_current) for fast "get current cert for asset" lookup
CREATE INDEX IF NOT EXISTS idx_cert_asset_current
  ON certificates (asset_id, is_current);

-- (asset_id, created_at DESC) for history ordered queries
CREATE INDEX IF NOT EXISTS idx_cert_asset_created
  ON certificates (asset_id, created_at DESC);

-- dedup_hash index for idempotent insert detection
CREATE INDEX IF NOT EXISTS idx_cert_dedup_hash
  ON certificates (dedup_hash);

-- ─── 7. Final verification query (run to confirm migration) ──────────────────
-- SELECT
--   (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='certificates' AND COLUMN_NAME='is_current') AS cert_is_current_exists,
--   (SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='domain_current_state') AS dcs_exists,
--   (SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='asset_ssl_profiles') AS asp_exists,
--   (SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='domain_events') AS de_exists;
