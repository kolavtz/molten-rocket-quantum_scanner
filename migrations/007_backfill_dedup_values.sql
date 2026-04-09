-- Backfill dedup_algorithm, dedup_value and dedup_hash from existing fingerprint columns
-- Safe to run idempotently; will not overwrite existing dedup_* values unless empty/null
-- Run as: mysql -u <user> -p<pass> <db> < 007_backfill_dedup_values.sql

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

-- Verification queries (run after migration):
-- SELECT COUNT(*) AS total, SUM(dedup_hash IS NOT NULL) AS with_dedup_hash, SUM(dedup_value IS NOT NULL) AS with_dedup_value FROM certificates;
-- SELECT id, asset_id, dedup_algorithm, dedup_value, dedup_hash FROM certificates WHERE dedup_hash IS NULL LIMIT 20;

-- End backfill
