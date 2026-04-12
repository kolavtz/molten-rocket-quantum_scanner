-- Migration 008: HNDL risk columns, TLS resilience tier, 2FA columns, CBOM superseded_at
-- Idempotent: all statements use IF NOT EXISTS / safe ALTER patterns
-- Run order: after 007_backfill_dedup_values.sql

-- ─────────────────────────────────────────────
-- asset_metrics: HNDL detection fields
-- ─────────────────────────────────────────────
ALTER TABLE asset_metrics
    ADD COLUMN IF NOT EXISTS hndl_risk_score FLOAT NULL COMMENT 'Harvest-Now-Decrypt-Later composite risk score 0-100',
    ADD COLUMN IF NOT EXISTS hndl_flags JSON NULL COMMENT 'JSON array of detected HNDL risk flags';

-- ─────────────────────────────────────────────
-- tls_compliance_scores: resilience tier
-- ─────────────────────────────────────────────
ALTER TABLE tls_compliance_scores
    ADD COLUMN IF NOT EXISTS resilience_tier ENUM('critical','medium','low') NULL
        COMMENT 'TLS resilience tier: critical=TLS<1.2/RC4, medium=TLS1.2-only/SHA1, low=TLS1.3+strong';

-- ─────────────────────────────────────────────
-- users: two-factor authentication fields
-- ─────────────────────────────────────────────
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS two_factor_enabled TINYINT(1) NOT NULL DEFAULT 0
        COMMENT '1 = TOTP 2FA enabled for this user',
    ADD COLUMN IF NOT EXISTS two_factor_secret VARCHAR(64) NULL
        COMMENT 'Fernet-encrypted TOTP base32 secret',
    ADD COLUMN IF NOT EXISTS backup_codes JSON NULL
        COMMENT 'JSON array of hashed single-use backup codes';

-- ─────────────────────────────────────────────
-- cbom_entries: superseded tracking for history
-- ─────────────────────────────────────────────
ALTER TABLE cbom_entries
    ADD COLUMN IF NOT EXISTS superseded_at DATETIME NULL
        COMMENT 'Set to NOW() when a newer scan replaces this CBOM entry for the same asset';
