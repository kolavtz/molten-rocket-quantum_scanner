-- Schema-only backup
--
-- Table: asset_dns_records
--
CREATE TABLE `asset_dns_records` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `scan_id` varchar(36) COLLATE utf8mb4_unicode_ci NOT NULL,
  `hostname` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `record_type` varchar(16) COLLATE utf8mb4_unicode_ci NOT NULL,
  `record_value` varchar(1024) COLLATE utf8mb4_unicode_ci NOT NULL,
  `ttl` int DEFAULT '300',
  `resolved_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_dns_scan_id` (`scan_id`),
  KEY `idx_dns_hostname` (`hostname`),
  CONSTRAINT `asset_dns_records_ibfk_1` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`scan_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table: asset_metrics
--
CREATE TABLE `asset_metrics` (
  `asset_id` bigint NOT NULL,
  `pqc_score` float DEFAULT '0',
  `pqc_score_timestamp` datetime DEFAULT NULL,
  `risk_penalty` float DEFAULT '0',
  `total_findings_count` int DEFAULT '0',
  `critical_findings_count` int DEFAULT '0',
  `pqc_class_tier` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `digital_label` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `has_critical_findings` tinyint(1) DEFAULT '0',
  `asset_cyber_score` float DEFAULT '0',
  `last_updated` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `calculated_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`asset_id`),
  KEY `idx_pqc_score` (`pqc_score`),
  KEY `idx_pqc_class_tier` (`pqc_class_tier`),
  KEY `idx_digital_label` (`digital_label`),
  KEY `idx_has_critical_findings` (`has_critical_findings`),
  KEY `idx_last_updated` (`last_updated`),
  CONSTRAINT `asset_metrics_ibfk_1` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table: assets
--
CREATE TABLE `assets` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `asset_key` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `target` varchar(512) COLLATE utf8mb4_unicode_ci NOT NULL,
  `name` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `url` varchar(512) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `ipv4` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `ipv6` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `asset_type` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL,
  `owner` varchar(150) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `risk_level` enum('Critical','High','Medium','Low','Unknown') COLLATE utf8mb4_unicode_ci DEFAULT 'Unknown',
  `tags_json` longtext COLLATE utf8mb4_unicode_ci,
  `notes` text COLLATE utf8mb4_unicode_ci,
  `source` enum('manual','scan_promoted','imported') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'manual',
  `last_scan_id` bigint DEFAULT NULL,
  `is_deleted` tinyint(1) NOT NULL DEFAULT '0',
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by` varchar(36) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `deleted_by_user_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `asset_key` (`asset_key`),
  KEY `idx_assets_active` (`is_deleted`,`asset_type`,`risk_level`),
  KEY `idx_assets_owner` (`owner`),
  KEY `fk_assets_deleted_by` (`deleted_by`),
  KEY `idx_assets_is_deleted` (`is_deleted`),
  CONSTRAINT `fk_assets_deleted_by` FOREIGN KEY (`deleted_by`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=1116 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table: audit_log_chain
--
CREATE TABLE `audit_log_chain` (
  `id` tinyint NOT NULL,
  `last_entry_id` bigint DEFAULT NULL,
  `last_hash` char(64) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table: audit_logs
--
CREATE TABLE `audit_logs` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `actor_user_id` varchar(36) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `actor_username` varchar(150) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `event_category` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL,
  `event_type` varchar(128) COLLATE utf8mb4_unicode_ci NOT NULL,
  `target_user_id` varchar(36) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `target_asset_id` bigint DEFAULT NULL,
  `target_scan_id` bigint DEFAULT NULL,
  `ip_address` varchar(64) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `user_agent` varchar(512) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `request_method` varchar(16) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `request_path` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `status` varchar(32) COLLATE utf8mb4_unicode_ci NOT NULL,
  `details_json` longtext COLLATE utf8mb4_unicode_ci,
  `previous_hash` char(64) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `entry_hash` char(64) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_audit_created_at` (`created_at`),
  KEY `idx_audit_category` (`event_category`),
  KEY `idx_audit_actor` (`actor_user_id`),
  KEY `idx_audit_asset` (`target_asset_id`),
  KEY `idx_audit_scan` (`target_scan_id`),
  KEY `fk_audit_target_user` (`target_user_id`),
  CONSTRAINT `fk_audit_actor_user` FOREIGN KEY (`actor_user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_audit_target_user` FOREIGN KEY (`target_user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=175 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table: cbom_entries
--
CREATE TABLE `cbom_entries` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `asset_id` bigint NOT NULL,
  `scan_id` bigint DEFAULT NULL,
  `cbom_summary_id` bigint DEFAULT NULL,
  `algorithm_name` varchar(120) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `category` varchar(80) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `key_length` int DEFAULT NULL,
  `protocol_version` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `nist_status` varchar(80) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `quantum_safe_flag` tinyint(1) NOT NULL DEFAULT '0',
  `hndl_level` enum('critical','high','medium','low','unknown') COLLATE utf8mb4_unicode_ci DEFAULT 'unknown',
  `is_deleted` tinyint(1) NOT NULL DEFAULT '0',
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by` varchar(36) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `deleted_by_user_id` bigint DEFAULT NULL,
  `asset_type` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `element_name` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `primitive` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `mode` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `crypto_functions` longtext COLLATE utf8mb4_unicode_ci,
  `classical_security_level` int DEFAULT NULL,
  `oid` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `element_list` longtext COLLATE utf8mb4_unicode_ci,
  `key_id` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `key_state` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `key_size` int DEFAULT NULL,
  `key_creation_date` datetime DEFAULT NULL,
  `key_activation_date` datetime DEFAULT NULL,
  `protocol_name` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `protocol_version_name` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `cipher_suites` longtext COLLATE utf8mb4_unicode_ci,
  `subject_name` varchar(500) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `issuer_name` varchar(500) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `not_valid_before` datetime DEFAULT NULL,
  `not_valid_after` datetime DEFAULT NULL,
  `signature_algorithm_reference` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `subject_public_key_reference` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `certificate_format` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `certificate_extension` varchar(32) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_cbom_entries_asset_active` (`asset_id`,`is_deleted`,`quantum_safe_flag`),
  KEY `idx_cbom_entries_scan` (`scan_id`),
  KEY `fk_cbom_entries_summary` (`cbom_summary_id`),
  KEY `fk_cbom_entries_deleted_by` (`deleted_by`),
  CONSTRAINT `fk_cbom_entries_asset` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_cbom_entries_deleted_by` FOREIGN KEY (`deleted_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_cbom_entries_scan` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_cbom_entries_summary` FOREIGN KEY (`cbom_summary_id`) REFERENCES `cbom_summary` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=54 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table: cbom_reports
--
CREATE TABLE `cbom_reports` (
  `scan_id` varchar(36) COLLATE utf8mb4_unicode_ci NOT NULL,
  `cbom_json` longtext COLLATE utf8mb4_unicode_ci NOT NULL,
  `is_encrypted` tinyint(1) DEFAULT '0',
  PRIMARY KEY (`scan_id`),
  CONSTRAINT `cbom_reports_ibfk_1` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`scan_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table: cbom_summary
--
CREATE TABLE `cbom_summary` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `asset_id` bigint NOT NULL,
  `scan_id` bigint DEFAULT NULL,
  `total_components` int NOT NULL DEFAULT '0',
  `weak_crypto_count` int NOT NULL DEFAULT '0',
  `cert_issues_count` int NOT NULL DEFAULT '0',
  `json_path` varchar(600) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `is_deleted` tinyint(1) NOT NULL DEFAULT '0',
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by` varchar(36) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `deleted_by_user_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_cbom_summary_asset_scan` (`asset_id`,`scan_id`),
  KEY `idx_cbom_summary_asset_active` (`asset_id`,`is_deleted`),
  KEY `fk_cbom_summary_scan` (`scan_id`),
  KEY `fk_cbom_summary_deleted_by` (`deleted_by`),
  CONSTRAINT `fk_cbom_summary_asset` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_cbom_summary_deleted_by` FOREIGN KEY (`deleted_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_cbom_summary_scan` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=57 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table: cert_expiry_buckets
--
CREATE TABLE `cert_expiry_buckets` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `bucket_date` date NOT NULL,
  `count_0_to_30_days` int DEFAULT '0',
  `count_31_to_60_days` int DEFAULT '0',
  `count_61_to_90_days` int DEFAULT '0',
  `count_greater_90_days` int DEFAULT '0',
  `count_expired` int DEFAULT '0',
  `total_active_certs` int DEFAULT '0',
  `total_expired_certs` int DEFAULT '0',
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_bucket_date` (`bucket_date`),
  KEY `idx_bucket_date` (`bucket_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table: certificates
--
CREATE TABLE `certificates` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `asset_id` bigint NOT NULL,
  `scan_id` bigint DEFAULT NULL,
  `issuer` varchar(500) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `subject` varchar(500) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `subject_cn` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `serial` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `valid_from` datetime DEFAULT NULL,
  `valid_until` datetime DEFAULT NULL,
  `expiry_days` int DEFAULT NULL,
  `fingerprint_sha256` char(64) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `tls_version` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `key_length` int DEFAULT NULL,
  `key_algorithm` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `cipher_suite` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `signature_algorithm` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `ca` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `is_self_signed` tinyint(1) NOT NULL DEFAULT '0',
  `is_expired` tinyint(1) NOT NULL DEFAULT '0',
  `is_deleted` tinyint(1) NOT NULL DEFAULT '0',
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by` varchar(36) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `company_name` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `ca_name` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `deleted_by_user_id` bigint DEFAULT NULL,
  `endpoint` varchar(512) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `port` int DEFAULT NULL,
  `subject_o` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `subject_ou` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `issuer_cn` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `issuer_o` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `issuer_ou` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `public_key_type` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `public_key_pem` longtext COLLATE utf8mb4_unicode_ci,
  `san_domains` longtext COLLATE utf8mb4_unicode_ci,
  `cert_chain_length` int DEFAULT NULL,
  `certificate_details` longtext COLLATE utf8mb4_unicode_ci,
  PRIMARY KEY (`id`),
  KEY `idx_cert_asset_active` (`asset_id`,`is_deleted`,`valid_until`),
  KEY `idx_cert_scan` (`scan_id`),
  KEY `idx_cert_tls` (`tls_version`,`key_length`),
  KEY `fk_cert_deleted_by` (`deleted_by`),
  CONSTRAINT `fk_cert_asset` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_cert_deleted_by` FOREIGN KEY (`deleted_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_cert_scan` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=77 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table: compliance_scores
--
CREATE TABLE `compliance_scores` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `asset_id` bigint NOT NULL,
  `scan_id` bigint DEFAULT NULL,
  `score_type` enum('pqc','tls','overall') COLLATE utf8mb4_unicode_ci NOT NULL,
  `score_value` double NOT NULL,
  `tier` enum('elite','standard','legacy','critical','unknown') COLLATE utf8mb4_unicode_ci DEFAULT 'unknown',
  `is_deleted` tinyint(1) NOT NULL DEFAULT '0',
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by` varchar(36) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `deleted_by_user_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_compliance_asset_active` (`asset_id`,`is_deleted`,`score_type`),
  KEY `idx_compliance_scan` (`scan_id`),
  KEY `fk_compliance_deleted_by` (`deleted_by`),
  CONSTRAINT `fk_compliance_asset` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_compliance_deleted_by` FOREIGN KEY (`deleted_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_compliance_scan` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table: cyber_rating
--
CREATE TABLE `cyber_rating` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `asset_id` bigint NOT NULL,
  `scan_id` bigint DEFAULT NULL,
  `enterprise_score` double NOT NULL,
  `rating_tier` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `generated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `is_deleted` tinyint(1) NOT NULL DEFAULT '0',
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by` varchar(36) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `deleted_by_user_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_cyber_asset_active` (`asset_id`,`is_deleted`,`generated_at`),
  KEY `idx_cyber_scan` (`scan_id`),
  KEY `fk_cyber_deleted_by` (`deleted_by`),
  CONSTRAINT `fk_cyber_asset` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_cyber_deleted_by` FOREIGN KEY (`deleted_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_cyber_scan` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table: digital_labels
--
CREATE TABLE `digital_labels` (
  `asset_id` bigint NOT NULL,
  `label` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `label_reason_json` json DEFAULT NULL,
  `confidence_score` int DEFAULT '0',
  `based_on_pqc_score` float DEFAULT '0',
  `based_on_finding_count` int DEFAULT '0',
  `based_on_critical_findings` tinyint(1) DEFAULT '0',
  `based_on_enterprise_score` float DEFAULT '0',
  `label_generated_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `label_updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`asset_id`),
  KEY `idx_label` (`label`),
  KEY `idx_confidence_score` (`confidence_score`),
  KEY `idx_label_generated_at` (`label_generated_at`),
  CONSTRAINT `digital_labels_ibfk_1` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table: discovery_domains
--
CREATE TABLE `discovery_domains` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `scan_id` bigint NOT NULL,
  `asset_id` bigint DEFAULT NULL,
  `domain` varchar(512) COLLATE utf8mb4_unicode_ci NOT NULL,
  `registrar` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `registration_date` date DEFAULT NULL,
  `status` enum('new','confirmed','ignored','false_positive') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'new',
  `promoted_to_inventory` tinyint(1) NOT NULL DEFAULT '0',
  `promoted_at` datetime DEFAULT NULL,
  `promoted_by` varchar(36) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `is_deleted` tinyint(1) NOT NULL DEFAULT '0',
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by` varchar(36) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `deleted_by_user_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_discovery_domains_scan` (`scan_id`),
  KEY `idx_discovery_domains_asset` (`asset_id`,`promoted_to_inventory`),
  KEY `idx_discovery_domains_domain` (`domain`),
  KEY `fk_discovery_domains_promoted_by` (`promoted_by`),
  KEY `fk_discovery_domains_deleted_by` (`deleted_by`),
  CONSTRAINT `fk_discovery_domains_asset` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_discovery_domains_deleted_by` FOREIGN KEY (`deleted_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_discovery_domains_promoted_by` FOREIGN KEY (`promoted_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_discovery_domains_scan` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=94 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table: discovery_ips
--
CREATE TABLE `discovery_ips` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `scan_id` bigint NOT NULL,
  `asset_id` bigint DEFAULT NULL,
  `ip_address` varchar(80) COLLATE utf8mb4_unicode_ci NOT NULL,
  `subnet` varchar(80) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `asn` varchar(80) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `netname` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `location` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `status` enum('new','confirmed','ignored','false_positive') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'new',
  `promoted_to_inventory` tinyint(1) NOT NULL DEFAULT '0',
  `promoted_at` datetime DEFAULT NULL,
  `promoted_by` varchar(36) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `is_deleted` tinyint(1) NOT NULL DEFAULT '0',
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by` varchar(36) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `deleted_by_user_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_discovery_ips_scan` (`scan_id`),
  KEY `idx_discovery_ips_asset` (`asset_id`,`promoted_to_inventory`),
  KEY `idx_discovery_ips_ip` (`ip_address`),
  KEY `fk_discovery_ips_promoted_by` (`promoted_by`),
  KEY `fk_discovery_ips_deleted_by` (`deleted_by`),
  CONSTRAINT `fk_discovery_ips_asset` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_discovery_ips_deleted_by` FOREIGN KEY (`deleted_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_discovery_ips_promoted_by` FOREIGN KEY (`promoted_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_discovery_ips_scan` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=67 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table: discovery_items
--
CREATE TABLE `discovery_items` (
  `id` int NOT NULL AUTO_INCREMENT,
  `scan_id` bigint NOT NULL,
  `asset_id` bigint DEFAULT NULL,
  `type` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL,
  `status` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL,
  `detection_date` datetime DEFAULT NULL,
  `is_deleted` tinyint(1) NOT NULL,
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by_user_id` varchar(128) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `scan_id` (`scan_id`),
  KEY `asset_id` (`asset_id`),
  KEY `deleted_by_user_id` (`deleted_by_user_id`),
  KEY `ix_discovery_items_is_deleted` (`is_deleted`),
  CONSTRAINT `discovery_items_ibfk_1` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE,
  CONSTRAINT `discovery_items_ibfk_2` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `discovery_items_ibfk_3` FOREIGN KEY (`deleted_by_user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table: discovery_software
--
CREATE TABLE `discovery_software` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `scan_id` bigint NOT NULL,
  `asset_id` bigint DEFAULT NULL,
  `product` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `version` varchar(120) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `category` varchar(80) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `cpe` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `status` enum('new','confirmed','ignored','false_positive') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'new',
  `promoted_to_inventory` tinyint(1) NOT NULL DEFAULT '0',
  `promoted_at` datetime DEFAULT NULL,
  `promoted_by` varchar(36) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `is_deleted` tinyint(1) NOT NULL DEFAULT '0',
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by` varchar(36) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `deleted_by_user_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_discovery_software_scan` (`scan_id`),
  KEY `idx_discovery_software_asset` (`asset_id`,`promoted_to_inventory`),
  KEY `idx_discovery_software_product` (`product`),
  KEY `fk_discovery_software_promoted_by` (`promoted_by`),
  KEY `fk_discovery_software_deleted_by` (`deleted_by`),
  CONSTRAINT `fk_discovery_software_asset` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_discovery_software_deleted_by` FOREIGN KEY (`deleted_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_discovery_software_promoted_by` FOREIGN KEY (`promoted_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_discovery_software_scan` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=100 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table: discovery_ssl
--
CREATE TABLE `discovery_ssl` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `scan_id` bigint NOT NULL,
  `asset_id` bigint DEFAULT NULL,
  `endpoint` varchar(512) COLLATE utf8mb4_unicode_ci NOT NULL,
  `tls_version` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `cipher_suite` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `key_exchange` varchar(120) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `key_length` int DEFAULT NULL,
  `subject_cn` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `issuer` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `valid_until` datetime DEFAULT NULL,
  `status` enum('new','confirmed','ignored','false_positive') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'new',
  `promoted_to_inventory` tinyint(1) NOT NULL DEFAULT '0',
  `promoted_at` datetime DEFAULT NULL,
  `promoted_by` varchar(36) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `is_deleted` tinyint(1) NOT NULL DEFAULT '0',
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by` varchar(36) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `deleted_by_user_id` bigint DEFAULT NULL,
  `pqc_score` double DEFAULT NULL,
  `pqc_assessment` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_discovery_ssl_scan` (`scan_id`),
  KEY `idx_discovery_ssl_asset` (`asset_id`,`promoted_to_inventory`),
  KEY `idx_discovery_ssl_endpoint` (`endpoint`),
  KEY `fk_discovery_ssl_promoted_by` (`promoted_by`),
  KEY `fk_discovery_ssl_deleted_by` (`deleted_by`),
  CONSTRAINT `fk_discovery_ssl_asset` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_discovery_ssl_deleted_by` FOREIGN KEY (`deleted_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_discovery_ssl_promoted_by` FOREIGN KEY (`promoted_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_discovery_ssl_scan` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=62 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table: findings
--
CREATE TABLE `findings` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `finding_id` varchar(36) COLLATE utf8mb4_unicode_ci NOT NULL,
  `asset_id` bigint NOT NULL,
  `scan_id` bigint NOT NULL,
  `issue_type` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `severity` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL,
  `description` text COLLATE utf8mb4_unicode_ci NOT NULL,
  `metadata_json` json DEFAULT NULL,
  `certificate_id` bigint DEFAULT NULL,
  `cbom_entry_id` bigint DEFAULT NULL,
  `is_deleted` tinyint(1) DEFAULT '0',
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by_user_id` varchar(36) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `finding_id` (`finding_id`),
  UNIQUE KEY `uq_finding_id` (`finding_id`),
  KEY `deleted_by_user_id` (`deleted_by_user_id`),
  KEY `idx_asset_id` (`asset_id`),
  KEY `idx_scan_id` (`scan_id`),
  KEY `idx_issue_type` (`issue_type`),
  KEY `idx_severity` (`severity`),
  KEY `idx_certificate_id` (`certificate_id`),
  KEY `idx_cbom_entry_id` (`cbom_entry_id`),
  KEY `idx_is_deleted` (`is_deleted`),
  KEY `idx_created_at` (`created_at`),
  CONSTRAINT `findings_ibfk_1` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `findings_ibfk_2` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE,
  CONSTRAINT `findings_ibfk_3` FOREIGN KEY (`certificate_id`) REFERENCES `certificates` (`id`) ON DELETE SET NULL,
  CONSTRAINT `findings_ibfk_4` FOREIGN KEY (`cbom_entry_id`) REFERENCES `cbom_entries` (`id`) ON DELETE SET NULL,
  CONSTRAINT `findings_ibfk_5` FOREIGN KEY (`deleted_by_user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=42 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table: org_pqc_metrics
--
CREATE TABLE `org_pqc_metrics` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `metric_date` date NOT NULL,
  `total_assets` int DEFAULT '0',
  `total_endpoints` int DEFAULT '0',
  `total_certificates` int DEFAULT '0',
  `elite_assets_count` int DEFAULT '0',
  `standard_assets_count` int DEFAULT '0',
  `legacy_assets_count` int DEFAULT '0',
  `critical_assets_count` int DEFAULT '0',
  `pct_elite` decimal(5,2) DEFAULT '0.00',
  `pct_standard` decimal(5,2) DEFAULT '0.00',
  `pct_legacy` decimal(5,2) DEFAULT '0.00',
  `pct_critical` decimal(5,2) DEFAULT '0.00',
  `avg_pqc_score` decimal(5,2) DEFAULT '0.00',
  `min_pqc_score` decimal(5,2) DEFAULT '0.00',
  `max_pqc_score` decimal(5,2) DEFAULT '0.00',
  `total_findings_count` int DEFAULT '0',
  `total_critical_findings` int DEFAULT '0',
  `total_high_findings` int DEFAULT '0',
  `total_medium_findings` int DEFAULT '0',
  `total_low_findings` int DEFAULT '0',
  `quantum_safe_assets_count` int DEFAULT '0',
  `quantum_safe_pct` decimal(5,2) DEFAULT '0.00',
  `vulnerable_assets_count` int DEFAULT '0',
  `vulnerable_pct` decimal(5,2) DEFAULT '0.00',
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `metric_date` (`metric_date`),
  KEY `idx_metric_date` (`metric_date`),
  KEY `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table: pqc_classification
--
CREATE TABLE `pqc_classification` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `asset_id` bigint NOT NULL,
  `scan_id` bigint DEFAULT NULL,
  `certificate_id` bigint DEFAULT NULL,
  `algorithm_name` varchar(120) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `algorithm_type` varchar(80) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `quantum_safe_status` enum('safe','hybrid','unsafe','migration_advised','unknown') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'unknown',
  `nist_category` varchar(64) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `pqc_score` double DEFAULT NULL,
  `is_deleted` tinyint(1) NOT NULL DEFAULT '0',
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by` varchar(36) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `deleted_by_user_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_pqc_asset_active` (`asset_id`,`is_deleted`,`quantum_safe_status`),
  KEY `idx_pqc_scan` (`scan_id`),
  KEY `fk_pqc_cert` (`certificate_id`),
  KEY `fk_pqc_deleted_by` (`deleted_by`),
  CONSTRAINT `fk_pqc_asset` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_pqc_cert` FOREIGN KEY (`certificate_id`) REFERENCES `certificates` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_pqc_deleted_by` FOREIGN KEY (`deleted_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_pqc_scan` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=59 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table: report_request_assets
--
CREATE TABLE `report_request_assets` (
  `report_request_id` bigint NOT NULL,
  `asset_id` bigint NOT NULL,
  PRIMARY KEY (`report_request_id`,`asset_id`),
  KEY `idx_report_request_assets_asset` (`asset_id`),
  CONSTRAINT `fk_rra_asset` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_rra_request` FOREIGN KEY (`report_request_id`) REFERENCES `report_requests` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table: report_requests
--
CREATE TABLE `report_requests` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `request_uid` varchar(36) COLLATE utf8mb4_unicode_ci NOT NULL,
  `schedule_id` bigint DEFAULT NULL,
  `requested_by` varchar(36) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `report_type` varchar(120) COLLATE utf8mb4_unicode_ci NOT NULL,
  `status` enum('queued','running','completed','failed','cancelled') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'queued',
  `period_start` datetime DEFAULT NULL,
  `period_end` datetime DEFAULT NULL,
  `filters_json` longtext COLLATE utf8mb4_unicode_ci,
  `output_path` varchar(600) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `output_format` enum('pdf','json','csv') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'pdf',
  `error_message` text COLLATE utf8mb4_unicode_ci,
  `is_deleted` tinyint(1) NOT NULL DEFAULT '0',
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by` varchar(36) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `started_at` datetime DEFAULT NULL,
  `completed_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `request_uid` (`request_uid`),
  KEY `idx_report_requests_status` (`status`,`created_at`),
  KEY `idx_report_requests_schedule` (`schedule_id`),
  KEY `fk_report_requests_user` (`requested_by`),
  KEY `fk_report_requests_deleted_by` (`deleted_by`),
  CONSTRAINT `fk_report_requests_deleted_by` FOREIGN KEY (`deleted_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_report_requests_schedule` FOREIGN KEY (`schedule_id`) REFERENCES `report_schedule` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_report_requests_user` FOREIGN KEY (`requested_by`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table: report_schedule
--
CREATE TABLE `report_schedule` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `schedule_uid` varchar(36) COLLATE utf8mb4_unicode_ci NOT NULL,
  `created_by` varchar(36) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `report_type` varchar(120) COLLATE utf8mb4_unicode_ci NOT NULL,
  `frequency` enum('daily','weekly','monthly','quarterly','onetime') COLLATE utf8mb4_unicode_ci NOT NULL,
  `timezone_name` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'UTC',
  `schedule_date` date DEFAULT NULL,
  `schedule_time` time DEFAULT NULL,
  `email_list` varchar(1024) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `save_path` varchar(600) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `include_download_link` tinyint(1) NOT NULL DEFAULT '0',
  `enabled` tinyint(1) NOT NULL DEFAULT '1',
  `status` enum('scheduled','paused','completed','failed') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'scheduled',
  `is_deleted` tinyint(1) NOT NULL DEFAULT '0',
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by` varchar(36) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `schedule_uid` (`schedule_uid`),
  KEY `idx_report_schedule_active` (`enabled`,`is_deleted`,`status`),
  KEY `fk_report_schedule_created_by` (`created_by`),
  KEY `fk_report_schedule_deleted_by` (`deleted_by`),
  CONSTRAINT `fk_report_schedule_created_by` FOREIGN KEY (`created_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_report_schedule_deleted_by` FOREIGN KEY (`deleted_by`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table: report_schedule_assets
--
CREATE TABLE `report_schedule_assets` (
  `report_schedule_id` bigint NOT NULL,
  `asset_id` bigint NOT NULL,
  PRIMARY KEY (`report_schedule_id`,`asset_id`),
  KEY `idx_report_schedule_assets_asset` (`asset_id`),
  CONSTRAINT `fk_rsa_asset` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_rsa_schedule` FOREIGN KEY (`report_schedule_id`) REFERENCES `report_schedule` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table: report_schedules
--
CREATE TABLE `report_schedules` (
  `schedule_id` varchar(36) COLLATE utf8mb4_unicode_ci NOT NULL,
  `created_by_id` varchar(36) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_by_name` varchar(150) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `enabled` tinyint(1) DEFAULT '1',
  `report_type` varchar(120) COLLATE utf8mb4_unicode_ci NOT NULL,
  `frequency` varchar(32) COLLATE utf8mb4_unicode_ci NOT NULL,
  `assets` varchar(256) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `sections_json` longtext COLLATE utf8mb4_unicode_ci,
  `schedule_date` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `schedule_time` varchar(10) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `timezone_name` varchar(64) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `email_list` varchar(512) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `pdf_password_enc` longtext COLLATE utf8mb4_unicode_ci,
  `save_path` varchar(512) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `download_link` tinyint(1) DEFAULT '0',
  `status` varchar(32) COLLATE utf8mb4_unicode_ci DEFAULT 'scheduled',
  PRIMARY KEY (`schedule_id`),
  KEY `idx_report_schedules_created_at` (`created_at`),
  KEY `idx_report_schedules_status` (`status`),
  KEY `fk_report_schedules_created_by` (`created_by_id`),
  CONSTRAINT `fk_report_schedules_created_by` FOREIGN KEY (`created_by_id`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `report_schedules_ibfk_1` FOREIGN KEY (`created_by_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table: scans
--
CREATE TABLE `scans` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `scan_uid` varchar(36) COLLATE utf8mb4_unicode_ci NOT NULL,
  `requested_target` varchar(512) COLLATE utf8mb4_unicode_ci NOT NULL,
  `normalized_target` varchar(512) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `status` enum('queued','running','complete','failed','partial') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'queued',
  `scan_kind` enum('manual','bulk','scheduled','api') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'manual',
  `initiated_by` varchar(36) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `started_at` datetime DEFAULT NULL,
  `completed_at` datetime DEFAULT NULL,
  `scanned_at` datetime DEFAULT NULL,
  `error_message` text COLLATE utf8mb4_unicode_ci,
  `report_json` longtext COLLATE utf8mb4_unicode_ci,
  `cbom_path` varchar(600) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `total_discovered` int NOT NULL DEFAULT '0',
  `total_promoted` int NOT NULL DEFAULT '0',
  `is_deleted` tinyint(1) NOT NULL DEFAULT '0',
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by` varchar(36) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `deleted_by_user_id` bigint DEFAULT NULL,
  `scan_id` varchar(36) COLLATE utf8mb4_unicode_ci NOT NULL,
  `target` varchar(512) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `asset_class` varchar(64) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `compliance_score` int DEFAULT '0',
  `overall_pqc_score` double DEFAULT NULL,
  `quantum_safe` int DEFAULT '0',
  `quantum_vuln` int DEFAULT '0',
  `is_encrypted` tinyint(1) DEFAULT '0',
  `total_assets` int DEFAULT '0',
  `add_to_inventory` tinyint(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `scan_uid` (`scan_uid`),
  UNIQUE KEY `uq_scans_scan_id` (`scan_id`),
  KEY `idx_scans_status` (`status`,`scanned_at`),
  KEY `idx_scans_target` (`normalized_target`),
  KEY `fk_scans_initiated_by` (`initiated_by`),
  KEY `fk_scans_deleted_by` (`deleted_by`),
  CONSTRAINT `fk_scans_deleted_by` FOREIGN KEY (`deleted_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_scans_initiated_by` FOREIGN KEY (`initiated_by`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=213 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table: tls_compliance_scores
--
CREATE TABLE `tls_compliance_scores` (
  `asset_id` bigint NOT NULL,
  `tls_score` float DEFAULT '0',
  `score_breakdown_json` json DEFAULT NULL,
  `weak_tls_version_count` int DEFAULT '0',
  `weak_cipher_count` int DEFAULT '0',
  `weak_key_length_count` int DEFAULT '0',
  `total_endpoints_scanned` int DEFAULT '0',
  `calculated_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`asset_id`),
  KEY `idx_tls_score` (`tls_score`),
  KEY `idx_updated_at` (`updated_at`),
  CONSTRAINT `tls_compliance_scores_ibfk_1` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Table: users
--
CREATE TABLE `users` (
  `id` varchar(36) COLLATE utf8mb4_unicode_ci NOT NULL,
  `employee_id` varchar(64) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `username` varchar(150) COLLATE utf8mb4_unicode_ci NOT NULL,
  `email` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `password_hash` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `role` enum('Admin','Manager','SingleScan','Viewer') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'Viewer',
  `created_by` varchar(36) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT '1',
  `api_key_hash` char(64) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `password_setup_token_hash` char(64) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `password_setup_token_expiry` datetime DEFAULT NULL,
  `must_change_password` tinyint(1) NOT NULL DEFAULT '1',
  `failed_login_attempts` int NOT NULL DEFAULT '0',
  `lockout_until` datetime DEFAULT NULL,
  `last_login_at` datetime DEFAULT NULL,
  `password_changed_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `reset_token` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `token_expiry` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`),
  UNIQUE KEY `employee_id` (`employee_id`),
  UNIQUE KEY `email` (`email`),
  UNIQUE KEY `api_key_hash` (`api_key_hash`),
  UNIQUE KEY `password_setup_token_hash` (`password_setup_token_hash`),
  UNIQUE KEY `reset_token` (`reset_token`),
  KEY `fk_users_created_by` (`created_by`),
  CONSTRAINT `fk_users_created_by` FOREIGN KEY (`created_by`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

