-- Migration: Normalize integer PK/FK columns to BIGINT to match ORM
-- Date: 2026-04-08
-- This script is safe to run multiple times. Each block checks the current
-- column DATA_TYPE in information_schema and only runs the ALTER if it's
-- not already 'bigint'. It preserves NULL/NOT NULL and AUTO_INCREMENT.

SET @prev_sql_mode = @@sql_mode;
SET SESSION sql_mode = 'ANSI_QUOTES,STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION';

-- Helper pattern (reused per-column):
-- 1) read DATA_TYPE into @dt
-- 2) build ALTER statement dynamically preserving NULL/NOT NULL and AUTO_INCREMENT
-- 3) PREPARE/EXECUTE the statement (or SELECT 1 no-op)

-- assets.id
SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='assets' AND COLUMN_NAME='id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `assets` MODIFY COLUMN `id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='assets' AND COLUMN_NAME='id'),
         (SELECT IF(EXTRA LIKE '%auto_increment%',' AUTO_INCREMENT','') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='assets' AND COLUMN_NAME='id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- assets.last_scan_id
SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='assets' AND COLUMN_NAME='last_scan_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `assets` MODIFY COLUMN `last_scan_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='assets' AND COLUMN_NAME='last_scan_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- scans.id
SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='scans' AND COLUMN_NAME='id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `scans` MODIFY COLUMN `id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='scans' AND COLUMN_NAME='id'),
         (SELECT IF(EXTRA LIKE '%auto_increment%',' AUTO_INCREMENT','') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='scans' AND COLUMN_NAME='id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- discovery_domains: id, scan_id, asset_id
SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='discovery_domains' AND COLUMN_NAME='id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `discovery_domains` MODIFY COLUMN `id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='discovery_domains' AND COLUMN_NAME='id'),
         (SELECT IF(EXTRA LIKE '%auto_increment%',' AUTO_INCREMENT','') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='discovery_domains' AND COLUMN_NAME='id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='discovery_domains' AND COLUMN_NAME='scan_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `discovery_domains` MODIFY COLUMN `scan_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='discovery_domains' AND COLUMN_NAME='scan_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='discovery_domains' AND COLUMN_NAME='asset_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `discovery_domains` MODIFY COLUMN `asset_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='discovery_domains' AND COLUMN_NAME='asset_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- discovery_ssl
SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='discovery_ssl' AND COLUMN_NAME='id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `discovery_ssl` MODIFY COLUMN `id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='discovery_ssl' AND COLUMN_NAME='id'),
         (SELECT IF(EXTRA LIKE '%auto_increment%',' AUTO_INCREMENT','') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='discovery_ssl' AND COLUMN_NAME='id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='discovery_ssl' AND COLUMN_NAME='scan_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `discovery_ssl` MODIFY COLUMN `scan_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='discovery_ssl' AND COLUMN_NAME='scan_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='discovery_ssl' AND COLUMN_NAME='asset_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `discovery_ssl` MODIFY COLUMN `asset_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='discovery_ssl' AND COLUMN_NAME='asset_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- discovery_ips
SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='discovery_ips' AND COLUMN_NAME='id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `discovery_ips` MODIFY COLUMN `id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='discovery_ips' AND COLUMN_NAME='id'),
         (SELECT IF(EXTRA LIKE '%auto_increment%',' AUTO_INCREMENT','') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='discovery_ips' AND COLUMN_NAME='id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='discovery_ips' AND COLUMN_NAME='scan_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `discovery_ips` MODIFY COLUMN `scan_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='discovery_ips' AND COLUMN_NAME='scan_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='discovery_ips' AND COLUMN_NAME='asset_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `discovery_ips` MODIFY COLUMN `asset_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='discovery_ips' AND COLUMN_NAME='asset_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- discovery_software
SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='discovery_software' AND COLUMN_NAME='id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `discovery_software` MODIFY COLUMN `id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='discovery_software' AND COLUMN_NAME='id'),
         (SELECT IF(EXTRA LIKE '%auto_increment%',' AUTO_INCREMENT','') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='discovery_software' AND COLUMN_NAME='id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='discovery_software' AND COLUMN_NAME='scan_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `discovery_software` MODIFY COLUMN `scan_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='discovery_software' AND COLUMN_NAME='scan_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='discovery_software' AND COLUMN_NAME='asset_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `discovery_software` MODIFY COLUMN `asset_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='discovery_software' AND COLUMN_NAME='asset_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- certificates
SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND COLUMN_NAME='id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `certificates` MODIFY COLUMN `id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='certificates' AND COLUMN_NAME='id'),
         (SELECT IF(EXTRA LIKE '%auto_increment%',' AUTO_INCREMENT','') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='certificates' AND COLUMN_NAME='id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND COLUMN_NAME='asset_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `certificates` MODIFY COLUMN `asset_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='certificates' AND COLUMN_NAME='asset_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='certificates' AND COLUMN_NAME='scan_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `certificates` MODIFY COLUMN `scan_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='certificates' AND COLUMN_NAME='scan_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- pqc_classification
SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='pqc_classification' AND COLUMN_NAME='id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `pqc_classification` MODIFY COLUMN `id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='pqc_classification' AND COLUMN_NAME='id'),
         (SELECT IF(EXTRA LIKE '%auto_increment%',' AUTO_INCREMENT','') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='pqc_classification' AND COLUMN_NAME='id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='pqc_classification' AND COLUMN_NAME='certificate_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `pqc_classification` MODIFY COLUMN `certificate_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='pqc_classification' AND COLUMN_NAME='certificate_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='pqc_classification' AND COLUMN_NAME='asset_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `pqc_classification` MODIFY COLUMN `asset_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='pqc_classification' AND COLUMN_NAME='asset_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='pqc_classification' AND COLUMN_NAME='scan_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `pqc_classification` MODIFY COLUMN `scan_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='pqc_classification' AND COLUMN_NAME='scan_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- cbom_summary
SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_summary' AND COLUMN_NAME='id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `cbom_summary` MODIFY COLUMN `id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='cbom_summary' AND COLUMN_NAME='id'),
         (SELECT IF(EXTRA LIKE '%auto_increment%',' AUTO_INCREMENT','') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='cbom_summary' AND COLUMN_NAME='id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_summary' AND COLUMN_NAME='asset_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `cbom_summary` MODIFY COLUMN `asset_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='cbom_summary' AND COLUMN_NAME='asset_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- cbom_entries
SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `cbom_entries` MODIFY COLUMN `id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='id'),
         (SELECT IF(EXTRA LIKE '%auto_increment%',' AUTO_INCREMENT','') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='asset_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `cbom_entries` MODIFY COLUMN `asset_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='cbom_entries' AND COLUMN_NAME='asset_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- compliance_scores
SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='compliance_scores' AND COLUMN_NAME='id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `compliance_scores` MODIFY COLUMN `id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='compliance_scores' AND COLUMN_NAME='id'),
         (SELECT IF(EXTRA LIKE '%auto_increment%',' AUTO_INCREMENT','') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='compliance_scores' AND COLUMN_NAME='id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='compliance_scores' AND COLUMN_NAME='asset_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `compliance_scores` MODIFY COLUMN `asset_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='compliance_scores' AND COLUMN_NAME='asset_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- cyber_rating
SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cyber_rating' AND COLUMN_NAME='id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `cyber_rating` MODIFY COLUMN `id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='cyber_rating' AND COLUMN_NAME='id'),
         (SELECT IF(EXTRA LIKE '%auto_increment%',' AUTO_INCREMENT','') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='cyber_rating' AND COLUMN_NAME='id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- findings
SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='findings' AND COLUMN_NAME='id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `findings` MODIFY COLUMN `id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='findings' AND COLUMN_NAME='id'),
         (SELECT IF(EXTRA LIKE '%auto_increment%',' AUTO_INCREMENT','') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='findings' AND COLUMN_NAME='id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='findings' AND COLUMN_NAME='asset_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `findings` MODIFY COLUMN `asset_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='findings' AND COLUMN_NAME='asset_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- findings.scan_id, findings.certificate_id, findings.cbom_entry_id
SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='findings' AND COLUMN_NAME='scan_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `findings` MODIFY COLUMN `scan_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='findings' AND COLUMN_NAME='scan_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='findings' AND COLUMN_NAME='certificate_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `findings` MODIFY COLUMN `certificate_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='findings' AND COLUMN_NAME='certificate_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='findings' AND COLUMN_NAME='cbom_entry_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `findings` MODIFY COLUMN `cbom_entry_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='findings' AND COLUMN_NAME='cbom_entry_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- asset_metrics.asset_id
SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='asset_metrics' AND COLUMN_NAME='asset_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `asset_metrics` MODIFY COLUMN `asset_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='asset_metrics' AND COLUMN_NAME='asset_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- org_pqc_metrics.id
SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='org_pqc_metrics' AND COLUMN_NAME='id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `org_pqc_metrics` MODIFY COLUMN `id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='org_pqc_metrics' AND COLUMN_NAME='id'),
         (SELECT IF(EXTRA LIKE '%auto_increment%',' AUTO_INCREMENT','') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='org_pqc_metrics' AND COLUMN_NAME='id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- cert_expiry_buckets.id
SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='cert_expiry_buckets' AND COLUMN_NAME='id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `cert_expiry_buckets` MODIFY COLUMN `id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='cert_expiry_buckets' AND COLUMN_NAME='id'),
         (SELECT IF(EXTRA LIKE '%auto_increment%',' AUTO_INCREMENT','') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='cert_expiry_buckets' AND COLUMN_NAME='id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- tls_compliance_scores.asset_id
SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='tls_compliance_scores' AND COLUMN_NAME='asset_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `tls_compliance_scores` MODIFY COLUMN `asset_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tls_compliance_scores' AND COLUMN_NAME='asset_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- digital_labels.asset_id
SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='digital_labels' AND COLUMN_NAME='asset_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `digital_labels` MODIFY COLUMN `asset_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='digital_labels' AND COLUMN_NAME='asset_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- domain_current_state
SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='domain_current_state' AND COLUMN_NAME='asset_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `domain_current_state` MODIFY COLUMN `asset_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='domain_current_state' AND COLUMN_NAME='asset_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='domain_current_state' AND COLUMN_NAME='latest_scan_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `domain_current_state` MODIFY COLUMN `latest_scan_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='domain_current_state' AND COLUMN_NAME='latest_scan_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='domain_current_state' AND COLUMN_NAME='current_ssl_certificate_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `domain_current_state` MODIFY COLUMN `current_ssl_certificate_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='domain_current_state' AND COLUMN_NAME='current_ssl_certificate_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- asset_ssl_profiles
SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='asset_ssl_profiles' AND COLUMN_NAME='id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `asset_ssl_profiles` MODIFY COLUMN `id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='asset_ssl_profiles' AND COLUMN_NAME='id'),
         (SELECT IF(EXTRA LIKE '%auto_increment%',' AUTO_INCREMENT','') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='asset_ssl_profiles' AND COLUMN_NAME='id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='asset_ssl_profiles' AND COLUMN_NAME='asset_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `asset_ssl_profiles` MODIFY COLUMN `asset_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='asset_ssl_profiles' AND COLUMN_NAME='asset_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='asset_ssl_profiles' AND COLUMN_NAME='scan_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `asset_ssl_profiles` MODIFY COLUMN `scan_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='asset_ssl_profiles' AND COLUMN_NAME='scan_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- domain_events
SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='domain_events' AND COLUMN_NAME='id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `domain_events` MODIFY COLUMN `id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='domain_events' AND COLUMN_NAME='id'),
         (SELECT IF(EXTRA LIKE '%auto_increment%',' AUTO_INCREMENT','') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='domain_events' AND COLUMN_NAME='id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='domain_events' AND COLUMN_NAME='asset_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `domain_events` MODIFY COLUMN `asset_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='domain_events' AND COLUMN_NAME='asset_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT DATA_TYPE INTO @dt FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='domain_events' AND COLUMN_NAME='scan_id';
SELECT IF(@dt <> 'bigint',
  CONCAT('ALTER TABLE `domain_events` MODIFY COLUMN `scan_id` BIGINT ',
         (SELECT IF(IS_NULLABLE='NO','NOT NULL','NULL') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='domain_events' AND COLUMN_NAME='scan_id')
  ), 'SELECT 1') INTO @sql;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Final: restore sql_mode
SET SESSION sql_mode = @prev_sql_mode;

-- End of migration
