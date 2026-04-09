-- Migration: Add extra certificate fields for enhanced telemetry
-- Date: 2026-04-08

ALTER TABLE certificates
  ADD COLUMN IF NOT EXISTS public_key_fingerprint_sha256 VARCHAR(64) NULL,
  ADD COLUMN IF NOT EXISTS certificate_version VARCHAR(50) NULL,
  ADD COLUMN IF NOT EXISTS certificate_format VARCHAR(50) NULL;

CREATE INDEX IF NOT EXISTS idx_cert_pubkey_fp ON certificates(public_key_fingerprint_sha256);

-- End migration
