-- Migration 009: New tables for vulnerabilities cache, subdomain discovery, AI audit log
-- Idempotent: all statements use CREATE TABLE IF NOT EXISTS

-- ─────────────────────────────────────────────
-- subdomains: discovered subdomains per asset
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS subdomains (
    id            BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    parent_asset_id BIGINT     NOT NULL,
    subdomain     VARCHAR(512) NOT NULL,
    record_type   VARCHAR(20)  NOT NULL DEFAULT 'A'
                  COMMENT 'DNS record type: A, CNAME, MX, NS, TXT, CT',
    ip            VARCHAR(80)  NULL,
    is_inventoried TINYINT(1)  NOT NULL DEFAULT 0
                  COMMENT '1 = promoted to assets table',
    is_deleted    TINYINT(1)   NOT NULL DEFAULT 0,
    discovered_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_sub_parent (parent_asset_id),
    INDEX idx_sub_subdomain (subdomain(191)),
    INDEX idx_sub_deleted (is_deleted),
    CONSTRAINT fk_sub_asset FOREIGN KEY (parent_asset_id)
        REFERENCES assets(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─────────────────────────────────────────────
-- vulnerability_cache: CVE data per asset (24h TTL)
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS vulnerability_cache (
    id          BIGINT        NOT NULL AUTO_INCREMENT PRIMARY KEY,
    asset_id    BIGINT        NOT NULL,
    cve_id      VARCHAR(30)   NOT NULL COMMENT 'e.g. CVE-2024-12345',
    severity    VARCHAR(20)   NOT NULL DEFAULT 'unknown'
                COMMENT 'critical, high, medium, low, unknown',
    cvss        FLOAT         NULL     COMMENT 'CVSS base score 0-10',
    description TEXT          NULL,
    mitigation  TEXT          NULL,
    published_at DATETIME     NULL,
    source      VARCHAR(50)   NOT NULL DEFAULT 'nvd'
                COMMENT 'circl | nvd',
    fetched_at  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_vc_asset (asset_id),
    INDEX idx_vc_cve (cve_id),
    INDEX idx_vc_severity (severity),
    INDEX idx_vc_fetched (fetched_at),
    UNIQUE KEY uq_vc_asset_cve (asset_id, cve_id),
    CONSTRAINT fk_vc_asset FOREIGN KEY (asset_id)
        REFERENCES assets(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─────────────────────────────────────────────
-- ai_audit_log: every AI assistant request logged
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ai_audit_log (
    id           BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id      VARCHAR(36)  NULL     COMMENT 'FK to users.id (nullable for anonymous)',
    ip_address   VARCHAR(80)  NULL,
    message_hash VARCHAR(64)  NOT NULL COMMENT 'SHA-256 of sanitized user message',
    model_used   VARCHAR(100) NULL,
    rag_enabled  TINYINT(1)   NOT NULL DEFAULT 0,
    token_count  INT          NULL,
    created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ai_user (user_id),
    INDEX idx_ai_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
