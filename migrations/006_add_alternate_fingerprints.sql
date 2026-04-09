-- Migration: Add alternate fingerprint columns and dedup metadata
-- Date: 2026-04-08

ALTER TABLE certificates
  ADD COLUMN IF NOT EXISTS fingerprint_sha1 VARCHAR(40) NULL,
  ADD COLUMN IF NOT EXISTS fingerprint_md5 VARCHAR(32) NULL,
  ADD COLUMN IF NOT EXISTS dedup_algorithm VARCHAR(20) NULL,
  ADD COLUMN IF NOT EXISTS dedup_value VARCHAR(128) NULL;

CREATE INDEX IF NOT EXISTS idx_cert_fp_sha1 ON certificates(fingerprint_sha1);
CREATE INDEX IF NOT EXISTS idx_cert_fp_md5 ON certificates(fingerprint_md5);
CREATE INDEX IF NOT EXISTS idx_cert_dedup_value ON certificates(dedup_value);

-- End migration
