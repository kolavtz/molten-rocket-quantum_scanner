-- MySQL dump 10.13  Distrib 8.0.45, for Win64 (x86_64)
--
-- Host: localhost    Database: quantumshield_v2
-- ------------------------------------------------------
-- Server version	8.0.45

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `ai_audit_log`
--

DROP TABLE IF EXISTS `ai_audit_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ai_audit_log` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` varchar(36) DEFAULT NULL,
  `ip_address` varchar(80) DEFAULT NULL,
  `message_hash` varchar(64) NOT NULL,
  `model_used` varchar(100) DEFAULT NULL,
  `rag_enabled` tinyint(1) NOT NULL,
  `token_count` int DEFAULT NULL,
  `created_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_ai_audit_log_created_at` (`created_at`),
  KEY `ix_ai_audit_log_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `asset_dns_records`
--

DROP TABLE IF EXISTS `asset_dns_records`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `asset_dns_records` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `scan_id` varchar(36) NOT NULL,
  `hostname` varchar(255) NOT NULL,
  `record_type` varchar(16) NOT NULL,
  `record_value` varchar(1024) NOT NULL,
  `ttl` int DEFAULT '300',
  `resolved_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_dns_scan_id` (`scan_id`),
  KEY `idx_dns_hostname` (`hostname`),
  CONSTRAINT `asset_dns_records_ibfk_1` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`scan_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `asset_metrics`
--

DROP TABLE IF EXISTS `asset_metrics`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `asset_metrics` (
  `asset_id` bigint NOT NULL,
  `pqc_score` float NOT NULL,
  `pqc_score_timestamp` datetime DEFAULT NULL,
  `risk_penalty` float NOT NULL,
  `total_findings_count` int DEFAULT NULL,
  `critical_findings_count` int DEFAULT NULL,
  `pqc_class_tier` varchar(50) DEFAULT NULL,
  `digital_label` varchar(50) DEFAULT NULL,
  `has_critical_findings` tinyint(1) DEFAULT NULL,
  `asset_cyber_score` float DEFAULT NULL,
  `hndl_risk_score` float DEFAULT NULL,
  `hndl_flags` text,
  `calculated_at` datetime DEFAULT NULL,
  `last_updated` datetime DEFAULT NULL,
  PRIMARY KEY (`asset_id`),
  KEY `ix_asset_metrics_pqc_class_tier` (`pqc_class_tier`),
  KEY `ix_asset_metrics_digital_label` (`digital_label`),
  CONSTRAINT `asset_metrics_ibfk_1` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `asset_ssl_profiles`
--

DROP TABLE IF EXISTS `asset_ssl_profiles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `asset_ssl_profiles` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `asset_id` bigint NOT NULL,
  `scan_id` bigint NOT NULL,
  `supports_tls_1_0` tinyint(1) NOT NULL,
  `supports_tls_1_1` tinyint(1) NOT NULL,
  `supports_tls_1_2` tinyint(1) NOT NULL,
  `supports_tls_1_3` tinyint(1) NOT NULL,
  `preferred_cipher` varchar(255) DEFAULT NULL,
  `cipher_list_json` text,
  `weak_cipher_count` int DEFAULT NULL,
  `insecure_protocol_count` int DEFAULT NULL,
  `hsts_enabled` tinyint(1) NOT NULL,
  `hsts_max_age` int DEFAULT NULL,
  `is_current` tinyint(1) NOT NULL,
  `first_seen_at` datetime DEFAULT NULL,
  `last_seen_at` datetime DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  `is_deleted` tinyint(1) NOT NULL,
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by_user_id` varchar(36) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `deleted_by_user_id` (`deleted_by_user_id`),
  KEY `ix_asset_ssl_profiles_is_current` (`is_current`),
  KEY `ix_asset_ssl_profiles_is_deleted` (`is_deleted`),
  KEY `ix_asset_ssl_profiles_asset_id` (`asset_id`),
  KEY `ix_asset_ssl_profiles_scan_id` (`scan_id`),
  CONSTRAINT `asset_ssl_profiles_ibfk_1` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `asset_ssl_profiles_ibfk_2` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE,
  CONSTRAINT `asset_ssl_profiles_ibfk_3` FOREIGN KEY (`deleted_by_user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `assets`
--

DROP TABLE IF EXISTS `assets`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `assets` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `asset_key` varchar(255) DEFAULT NULL,
  `target` varchar(255) NOT NULL,
  `url` varchar(255) DEFAULT NULL,
  `ipv4` varchar(50) DEFAULT NULL,
  `ipv6` varchar(50) DEFAULT NULL,
  `asset_type` varchar(50) NOT NULL,
  `owner` varchar(100) DEFAULT NULL,
  `risk_level` varchar(50) DEFAULT NULL,
  `notes` text,
  `last_scan_id` bigint DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  `updated_at` datetime DEFAULT NULL,
  `is_deleted` tinyint(1) NOT NULL,
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by_user_id` varchar(36) DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_assets_target` (`target`),
  UNIQUE KEY `ix_assets_asset_key` (`asset_key`),
  KEY `last_scan_id` (`last_scan_id`),
  KEY `deleted_by_user_id` (`deleted_by_user_id`),
  KEY `ix_assets_is_deleted` (`is_deleted`),
  KEY `idx_assets_is_deleted` (`is_deleted`),
  CONSTRAINT `assets_ibfk_1` FOREIGN KEY (`last_scan_id`) REFERENCES `scans` (`id`) ON DELETE SET NULL,
  CONSTRAINT `assets_ibfk_2` FOREIGN KEY (`deleted_by_user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=921 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `audit_blocks`
--

DROP TABLE IF EXISTS `audit_blocks`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `audit_blocks` (
  `block_index` bigint NOT NULL,
  `audit_log_id` bigint NOT NULL,
  `previous_block_hash` char(64) NOT NULL,
  `payload_hash` char(64) NOT NULL,
  `nonce` bigint NOT NULL DEFAULT '0',
  `difficulty` int NOT NULL DEFAULT '0',
  `block_hash` char(64) NOT NULL,
  `block_signature` char(64) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`block_index`),
  UNIQUE KEY `audit_log_id` (`audit_log_id`),
  UNIQUE KEY `block_hash` (`block_hash`),
  KEY `idx_audit_blocks_created_at` (`created_at`),
  CONSTRAINT `audit_blocks_ibfk_1` FOREIGN KEY (`audit_log_id`) REFERENCES `audit_logs` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `audit_log_chain`
--

DROP TABLE IF EXISTS `audit_log_chain`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `audit_log_chain` (
  `id` tinyint NOT NULL,
  `last_entry_id` bigint DEFAULT NULL,
  `last_hash` char(64) DEFAULT NULL,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `audit_logs`
--

DROP TABLE IF EXISTS `audit_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `audit_logs` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `actor_user_id` varchar(36) DEFAULT NULL,
  `actor_username` varchar(150) DEFAULT NULL,
  `event_category` varchar(64) NOT NULL,
  `event_type` varchar(128) NOT NULL,
  `target_user_id` varchar(36) DEFAULT NULL,
  `target_scan_id` varchar(36) DEFAULT NULL,
  `ip_address` varchar(64) DEFAULT NULL,
  `user_agent` varchar(512) DEFAULT NULL,
  `request_method` varchar(16) DEFAULT NULL,
  `request_path` varchar(255) DEFAULT NULL,
  `status` varchar(32) NOT NULL,
  `details_json` longtext,
  `previous_hash` char(64) NOT NULL,
  `entry_hash` char(64) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `entry_hash` (`entry_hash`),
  KEY `idx_audit_created_at` (`created_at`),
  KEY `idx_audit_category` (`event_category`),
  KEY `idx_audit_actor` (`actor_user_id`),
  KEY `idx_audit_target_user` (`target_user_id`),
  KEY `idx_audit_target_scan` (`target_scan_id`),
  CONSTRAINT `audit_logs_ibfk_1` FOREIGN KEY (`actor_user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `audit_logs_ibfk_2` FOREIGN KEY (`target_user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `audit_logs_ibfk_3` FOREIGN KEY (`target_scan_id`) REFERENCES `scans` (`scan_id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=463 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `cbom_entries`
--

DROP TABLE IF EXISTS `cbom_entries`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cbom_entries` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `scan_id` bigint NOT NULL,
  `asset_id` bigint DEFAULT NULL,
  `algorithm_name` varchar(100) DEFAULT NULL,
  `category` varchar(50) DEFAULT NULL,
  `asset_type` varchar(50) DEFAULT NULL,
  `element_name` varchar(255) DEFAULT NULL,
  `primitive` varchar(100) DEFAULT NULL,
  `mode` varchar(100) DEFAULT NULL,
  `crypto_functions` text,
  `classical_security_level` int DEFAULT NULL,
  `oid` varchar(255) DEFAULT NULL,
  `element_list` text,
  `key_id` varchar(255) DEFAULT NULL,
  `key_state` varchar(50) DEFAULT NULL,
  `key_size` int DEFAULT NULL,
  `key_creation_date` datetime DEFAULT NULL,
  `key_activation_date` datetime DEFAULT NULL,
  `protocol_name` varchar(100) DEFAULT NULL,
  `protocol_version_name` varchar(50) DEFAULT NULL,
  `cipher_suites` text,
  `subject_name` varchar(500) DEFAULT NULL,
  `issuer_name` varchar(500) DEFAULT NULL,
  `not_valid_before` datetime DEFAULT NULL,
  `not_valid_after` datetime DEFAULT NULL,
  `signature_algorithm_reference` varchar(255) DEFAULT NULL,
  `subject_public_key_reference` varchar(255) DEFAULT NULL,
  `certificate_format` varchar(100) DEFAULT NULL,
  `certificate_extension` varchar(32) DEFAULT NULL,
  `key_length` int DEFAULT NULL,
  `protocol_version` varchar(50) DEFAULT NULL,
  `nist_status` varchar(50) DEFAULT NULL,
  `quantum_safe_flag` tinyint(1) DEFAULT NULL,
  `hndl_level` varchar(50) DEFAULT NULL,
  `superseded_at` datetime DEFAULT NULL,
  `is_deleted` tinyint(1) NOT NULL,
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by_user_id` varchar(36) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `scan_id` (`scan_id`),
  KEY `asset_id` (`asset_id`),
  KEY `deleted_by_user_id` (`deleted_by_user_id`),
  KEY `ix_cbom_entries_oid` (`oid`),
  KEY `ix_cbom_entries_is_deleted` (`is_deleted`),
  KEY `ix_cbom_entries_asset_type` (`asset_type`),
  CONSTRAINT `cbom_entries_ibfk_1` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE,
  CONSTRAINT `cbom_entries_ibfk_2` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `cbom_entries_ibfk_3` FOREIGN KEY (`deleted_by_user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=61 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `cbom_reports`
--

DROP TABLE IF EXISTS `cbom_reports`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cbom_reports` (
  `scan_id` varchar(36) NOT NULL,
  `cbom_json` longtext NOT NULL,
  `is_encrypted` tinyint(1) DEFAULT '0',
  PRIMARY KEY (`scan_id`),
  CONSTRAINT `cbom_reports_ibfk_1` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`scan_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `cbom_summary`
--

DROP TABLE IF EXISTS `cbom_summary`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cbom_summary` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `asset_id` bigint DEFAULT NULL,
  `scan_id` bigint NOT NULL,
  `total_components` int DEFAULT NULL,
  `weak_crypto_count` int DEFAULT NULL,
  `cert_issues_count` int DEFAULT NULL,
  `json_path` varchar(500) DEFAULT NULL,
  `is_deleted` tinyint(1) NOT NULL,
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by_user_id` varchar(36) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `scan_id` (`scan_id`),
  KEY `deleted_by_user_id` (`deleted_by_user_id`),
  KEY `ix_cbom_summary_is_deleted` (`is_deleted`),
  KEY `ix_cbom_summary_asset_id` (`asset_id`),
  CONSTRAINT `cbom_summary_ibfk_1` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `cbom_summary_ibfk_2` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE,
  CONSTRAINT `cbom_summary_ibfk_3` FOREIGN KEY (`deleted_by_user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=82 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `cert_expiry_buckets`
--

DROP TABLE IF EXISTS `cert_expiry_buckets`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cert_expiry_buckets` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `bucket_date` datetime NOT NULL,
  `count_0_to_30_days` int DEFAULT NULL,
  `count_31_to_60_days` int DEFAULT NULL,
  `count_61_to_90_days` int DEFAULT NULL,
  `count_greater_90_days` int DEFAULT NULL,
  `count_expired` int DEFAULT NULL,
  `total_active_certs` int DEFAULT NULL,
  `total_expired_certs` int DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  `updated_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_cert_expiry_buckets_bucket_date` (`bucket_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `certificates`
--

DROP TABLE IF EXISTS `certificates`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `certificates` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `asset_id` bigint NOT NULL,
  `scan_id` bigint NOT NULL,
  `endpoint` varchar(512) DEFAULT NULL,
  `port` int DEFAULT NULL,
  `issuer` varchar(500) DEFAULT NULL,
  `subject` varchar(500) DEFAULT NULL,
  `subject_cn` varchar(255) DEFAULT NULL,
  `subject_o` varchar(255) DEFAULT NULL,
  `subject_ou` varchar(255) DEFAULT NULL,
  `issuer_cn` varchar(255) DEFAULT NULL,
  `issuer_o` varchar(255) DEFAULT NULL,
  `issuer_ou` varchar(255) DEFAULT NULL,
  `serial` varchar(255) DEFAULT NULL,
  `company_name` varchar(255) DEFAULT NULL,
  `valid_from` datetime DEFAULT NULL,
  `valid_until` datetime DEFAULT NULL,
  `expiry_days` int DEFAULT NULL,
  `fingerprint_sha256` varchar(64) DEFAULT NULL,
  `fingerprint_sha1` varchar(40) DEFAULT NULL,
  `fingerprint_md5` varchar(32) DEFAULT NULL,
  `public_key_fingerprint_sha256` varchar(64) DEFAULT NULL,
  `certificate_version` varchar(50) DEFAULT NULL,
  `certificate_format` varchar(50) DEFAULT NULL,
  `dedup_algorithm` varchar(20) DEFAULT NULL,
  `dedup_value` varchar(128) DEFAULT NULL,
  `dedup_hash` varchar(64) DEFAULT NULL,
  `tls_version` varchar(50) DEFAULT NULL,
  `key_length` int DEFAULT NULL,
  `key_algorithm` varchar(100) DEFAULT NULL,
  `public_key_type` varchar(100) DEFAULT NULL,
  `public_key_pem` text,
  `cipher_suite` varchar(255) DEFAULT NULL,
  `signature_algorithm` varchar(100) DEFAULT NULL,
  `ca` varchar(255) DEFAULT NULL,
  `ca_name` varchar(255) DEFAULT NULL,
  `san_domains` text,
  `cert_chain_length` int DEFAULT NULL,
  `is_self_signed` tinyint(1) DEFAULT NULL,
  `is_expired` tinyint(1) DEFAULT NULL,
  `is_current` tinyint(1) NOT NULL,
  `first_seen_at` datetime DEFAULT NULL,
  `last_seen_at` datetime DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  `updated_at` datetime DEFAULT NULL,
  `certificate_details` text,
  `is_deleted` tinyint(1) NOT NULL,
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by_user_id` varchar(36) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `deleted_by_user_id` (`deleted_by_user_id`),
  KEY `ix_certificates_fingerprint_sha1` (`fingerprint_sha1`),
  KEY `ix_certificates_is_current` (`is_current`),
  KEY `ix_certificates_fingerprint_md5` (`fingerprint_md5`),
  KEY `ix_certificates_issuer_cn` (`issuer_cn`),
  KEY `ix_certificates_is_deleted` (`is_deleted`),
  KEY `ix_certificates_public_key_fingerprint_sha256` (`public_key_fingerprint_sha256`),
  KEY `ix_certificates_serial` (`serial`),
  KEY `ix_certificates_endpoint` (`endpoint`),
  KEY `ix_certificates_dedup_value` (`dedup_value`),
  KEY `ix_certificates_asset_id` (`asset_id`),
  KEY `ix_certificates_scan_id` (`scan_id`),
  KEY `ix_certificates_company_name` (`company_name`),
  KEY `ix_certificates_dedup_hash` (`dedup_hash`),
  KEY `ix_certificates_valid_until` (`valid_until`),
  KEY `ix_certificates_tls_version` (`tls_version`),
  KEY `ix_certificates_issuer` (`issuer`),
  KEY `ix_certificates_fingerprint_sha256` (`fingerprint_sha256`),
  KEY `ix_certificates_subject_cn` (`subject_cn`),
  KEY `ix_certificates_ca` (`ca`),
  CONSTRAINT `certificates_ibfk_1` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `certificates_ibfk_2` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE,
  CONSTRAINT `certificates_ibfk_3` FOREIGN KEY (`deleted_by_user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=67 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `compliance_scores`
--

DROP TABLE IF EXISTS `compliance_scores`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `compliance_scores` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `asset_id` bigint NOT NULL,
  `scan_id` bigint NOT NULL,
  `score_type` varchar(50) DEFAULT NULL,
  `score_value` float DEFAULT NULL,
  `tier` varchar(50) DEFAULT NULL,
  `is_deleted` tinyint(1) NOT NULL,
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by_user_id` varchar(36) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `asset_id` (`asset_id`),
  KEY `scan_id` (`scan_id`),
  KEY `deleted_by_user_id` (`deleted_by_user_id`),
  KEY `ix_compliance_scores_is_deleted` (`is_deleted`),
  CONSTRAINT `compliance_scores_ibfk_1` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `compliance_scores_ibfk_2` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE,
  CONSTRAINT `compliance_scores_ibfk_3` FOREIGN KEY (`deleted_by_user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `cyber_rating`
--

DROP TABLE IF EXISTS `cyber_rating`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cyber_rating` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `asset_id` bigint DEFAULT NULL,
  `scan_id` bigint NOT NULL,
  `enterprise_score` float DEFAULT NULL,
  `rating_tier` varchar(50) DEFAULT NULL,
  `generated_at` datetime DEFAULT NULL,
  `is_deleted` tinyint(1) NOT NULL,
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by_user_id` varchar(36) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `scan_id` (`scan_id`),
  KEY `deleted_by_user_id` (`deleted_by_user_id`),
  KEY `ix_cyber_rating_asset_id` (`asset_id`),
  KEY `ix_cyber_rating_is_deleted` (`is_deleted`),
  CONSTRAINT `cyber_rating_ibfk_1` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `cyber_rating_ibfk_2` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE,
  CONSTRAINT `cyber_rating_ibfk_3` FOREIGN KEY (`deleted_by_user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `digital_labels`
--

DROP TABLE IF EXISTS `digital_labels`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `digital_labels` (
  `asset_id` bigint NOT NULL,
  `label` varchar(100) NOT NULL,
  `label_reason_json` text,
  `confidence_score` int DEFAULT NULL,
  `based_on_pqc_score` float DEFAULT NULL,
  `based_on_finding_count` int DEFAULT NULL,
  `based_on_critical_findings` tinyint(1) DEFAULT NULL,
  `based_on_enterprise_score` float DEFAULT NULL,
  `label_generated_at` datetime DEFAULT NULL,
  `label_updated_at` datetime DEFAULT NULL,
  PRIMARY KEY (`asset_id`),
  KEY `ix_digital_labels_label` (`label`),
  CONSTRAINT `digital_labels_ibfk_1` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `discovery_domains`
--

DROP TABLE IF EXISTS `discovery_domains`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `discovery_domains` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `scan_id` bigint NOT NULL,
  `asset_id` bigint DEFAULT NULL,
  `domain` varchar(512) NOT NULL,
  `registrar` varchar(255) DEFAULT NULL,
  `registration_date` date DEFAULT NULL,
  `status` enum('new','confirmed','ignored','false_positive') DEFAULT NULL,
  `promoted_to_inventory` tinyint(1) DEFAULT NULL,
  `promoted_at` datetime DEFAULT NULL,
  `promoted_by` varchar(36) DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  `updated_at` datetime DEFAULT NULL,
  `is_deleted` tinyint(1) NOT NULL,
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by_user_id` varchar(36) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `scan_id` (`scan_id`),
  KEY `asset_id` (`asset_id`),
  KEY `promoted_by` (`promoted_by`),
  KEY `deleted_by_user_id` (`deleted_by_user_id`),
  KEY `ix_discovery_domains_is_deleted` (`is_deleted`),
  CONSTRAINT `discovery_domains_ibfk_1` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE,
  CONSTRAINT `discovery_domains_ibfk_2` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE SET NULL,
  CONSTRAINT `discovery_domains_ibfk_3` FOREIGN KEY (`promoted_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `discovery_domains_ibfk_4` FOREIGN KEY (`deleted_by_user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=640 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `discovery_ips`
--

DROP TABLE IF EXISTS `discovery_ips`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `discovery_ips` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `scan_id` bigint NOT NULL,
  `asset_id` bigint DEFAULT NULL,
  `ip_address` varchar(80) NOT NULL,
  `subnet` varchar(80) DEFAULT NULL,
  `asn` varchar(80) DEFAULT NULL,
  `netname` varchar(255) DEFAULT NULL,
  `location` varchar(255) DEFAULT NULL,
  `status` enum('new','confirmed','ignored','false_positive') DEFAULT NULL,
  `promoted_to_inventory` tinyint(1) DEFAULT NULL,
  `promoted_at` datetime DEFAULT NULL,
  `promoted_by` varchar(36) DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  `updated_at` datetime DEFAULT NULL,
  `is_deleted` tinyint(1) NOT NULL,
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by_user_id` varchar(36) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `scan_id` (`scan_id`),
  KEY `asset_id` (`asset_id`),
  KEY `promoted_by` (`promoted_by`),
  KEY `deleted_by_user_id` (`deleted_by_user_id`),
  KEY `ix_discovery_ips_is_deleted` (`is_deleted`),
  CONSTRAINT `discovery_ips_ibfk_1` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE,
  CONSTRAINT `discovery_ips_ibfk_2` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE SET NULL,
  CONSTRAINT `discovery_ips_ibfk_3` FOREIGN KEY (`promoted_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `discovery_ips_ibfk_4` FOREIGN KEY (`deleted_by_user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=97 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `discovery_software`
--

DROP TABLE IF EXISTS `discovery_software`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `discovery_software` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `scan_id` bigint NOT NULL,
  `asset_id` bigint DEFAULT NULL,
  `product` varchar(255) NOT NULL,
  `version` varchar(120) DEFAULT NULL,
  `category` varchar(80) DEFAULT NULL,
  `cpe` varchar(255) DEFAULT NULL,
  `status` enum('new','confirmed','ignored','false_positive') DEFAULT NULL,
  `promoted_to_inventory` tinyint(1) DEFAULT NULL,
  `promoted_at` datetime DEFAULT NULL,
  `promoted_by` varchar(36) DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  `updated_at` datetime DEFAULT NULL,
  `is_deleted` tinyint(1) NOT NULL,
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by_user_id` varchar(36) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `scan_id` (`scan_id`),
  KEY `asset_id` (`asset_id`),
  KEY `promoted_by` (`promoted_by`),
  KEY `deleted_by_user_id` (`deleted_by_user_id`),
  KEY `ix_discovery_software_is_deleted` (`is_deleted`),
  CONSTRAINT `discovery_software_ibfk_1` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE,
  CONSTRAINT `discovery_software_ibfk_2` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE SET NULL,
  CONSTRAINT `discovery_software_ibfk_3` FOREIGN KEY (`promoted_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `discovery_software_ibfk_4` FOREIGN KEY (`deleted_by_user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=134 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `discovery_ssl`
--

DROP TABLE IF EXISTS `discovery_ssl`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `discovery_ssl` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `scan_id` bigint NOT NULL,
  `asset_id` bigint DEFAULT NULL,
  `endpoint` varchar(512) NOT NULL,
  `tls_version` varchar(50) DEFAULT NULL,
  `cipher_suite` varchar(255) DEFAULT NULL,
  `key_exchange` varchar(120) DEFAULT NULL,
  `key_length` int DEFAULT NULL,
  `subject_cn` varchar(255) DEFAULT NULL,
  `issuer` varchar(255) DEFAULT NULL,
  `valid_until` datetime DEFAULT NULL,
  `pqc_score` float DEFAULT NULL,
  `pqc_assessment` varchar(50) DEFAULT NULL,
  `status` enum('new','confirmed','ignored','false_positive') DEFAULT NULL,
  `promoted_to_inventory` tinyint(1) DEFAULT NULL,
  `promoted_at` datetime DEFAULT NULL,
  `promoted_by` varchar(36) DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  `updated_at` datetime DEFAULT NULL,
  `is_deleted` tinyint(1) NOT NULL,
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by_user_id` varchar(36) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `scan_id` (`scan_id`),
  KEY `asset_id` (`asset_id`),
  KEY `promoted_by` (`promoted_by`),
  KEY `deleted_by_user_id` (`deleted_by_user_id`),
  KEY `ix_discovery_ssl_pqc_assessment` (`pqc_assessment`),
  KEY `ix_discovery_ssl_is_deleted` (`is_deleted`),
  CONSTRAINT `discovery_ssl_ibfk_1` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE,
  CONSTRAINT `discovery_ssl_ibfk_2` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE SET NULL,
  CONSTRAINT `discovery_ssl_ibfk_3` FOREIGN KEY (`promoted_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `discovery_ssl_ibfk_4` FOREIGN KEY (`deleted_by_user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=96 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `domain_current_state`
--

DROP TABLE IF EXISTS `domain_current_state`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `domain_current_state` (
  `asset_id` bigint NOT NULL,
  `latest_scan_id` bigint DEFAULT NULL,
  `current_ssl_certificate_id` bigint DEFAULT NULL,
  `current_risk_score` float NOT NULL,
  `current_risk_level` varchar(50) DEFAULT NULL,
  `last_successful_scan_at` datetime DEFAULT NULL,
  `last_failed_scan_at` datetime DEFAULT NULL,
  `last_rendered_at` datetime DEFAULT NULL,
  `freshness_status` varchar(20) NOT NULL,
  `render_status` varchar(20) DEFAULT NULL,
  `render_error_message` text,
  `updated_at` datetime DEFAULT NULL,
  PRIMARY KEY (`asset_id`),
  KEY `latest_scan_id` (`latest_scan_id`),
  KEY `current_ssl_certificate_id` (`current_ssl_certificate_id`),
  KEY `ix_domain_current_state_freshness_status` (`freshness_status`),
  CONSTRAINT `domain_current_state_ibfk_1` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `domain_current_state_ibfk_2` FOREIGN KEY (`latest_scan_id`) REFERENCES `scans` (`id`) ON DELETE SET NULL,
  CONSTRAINT `domain_current_state_ibfk_3` FOREIGN KEY (`current_ssl_certificate_id`) REFERENCES `certificates` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `domain_events`
--

DROP TABLE IF EXISTS `domain_events`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `domain_events` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `asset_id` bigint NOT NULL,
  `scan_id` bigint DEFAULT NULL,
  `event_type` varchar(80) NOT NULL,
  `event_title` varchar(255) NOT NULL,
  `event_description` text,
  `old_value_json` text,
  `new_value_json` text,
  `severity` varchar(20) DEFAULT NULL,
  `correlation_id` varchar(36) DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `scan_id` (`scan_id`),
  KEY `ix_domain_events_created_at` (`created_at`),
  KEY `ix_domain_events_event_type` (`event_type`),
  KEY `ix_domain_events_asset_id` (`asset_id`),
  KEY `ix_domain_events_correlation_id` (`correlation_id`),
  KEY `ix_domain_events_severity` (`severity`),
  CONSTRAINT `domain_events_ibfk_1` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `domain_events_ibfk_2` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `findings`
--

DROP TABLE IF EXISTS `findings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `findings` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `finding_id` varchar(36) NOT NULL,
  `asset_id` bigint NOT NULL,
  `scan_id` bigint NOT NULL,
  `issue_type` varchar(100) NOT NULL,
  `severity` varchar(50) NOT NULL,
  `description` text NOT NULL,
  `metadata_json` text,
  `certificate_id` bigint DEFAULT NULL,
  `cbom_entry_id` bigint DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  `updated_at` datetime DEFAULT NULL,
  `is_deleted` tinyint(1) NOT NULL,
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by_user_id` varchar(36) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_findings_finding_id` (`finding_id`),
  KEY `certificate_id` (`certificate_id`),
  KEY `cbom_entry_id` (`cbom_entry_id`),
  KEY `deleted_by_user_id` (`deleted_by_user_id`),
  KEY `ix_findings_asset_id` (`asset_id`),
  KEY `ix_findings_severity` (`severity`),
  KEY `ix_findings_is_deleted` (`is_deleted`),
  KEY `ix_findings_issue_type` (`issue_type`),
  KEY `ix_findings_scan_id` (`scan_id`),
  CONSTRAINT `findings_ibfk_1` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `findings_ibfk_2` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE,
  CONSTRAINT `findings_ibfk_3` FOREIGN KEY (`certificate_id`) REFERENCES `certificates` (`id`) ON DELETE SET NULL,
  CONSTRAINT `findings_ibfk_4` FOREIGN KEY (`cbom_entry_id`) REFERENCES `cbom_entries` (`id`) ON DELETE SET NULL,
  CONSTRAINT `findings_ibfk_5` FOREIGN KEY (`deleted_by_user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=66 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `org_pqc_metrics`
--

DROP TABLE IF EXISTS `org_pqc_metrics`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `org_pqc_metrics` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `metric_date` datetime NOT NULL,
  `total_assets` int DEFAULT NULL,
  `total_endpoints` int DEFAULT NULL,
  `total_certificates` int DEFAULT NULL,
  `elite_assets_count` int DEFAULT NULL,
  `standard_assets_count` int DEFAULT NULL,
  `legacy_assets_count` int DEFAULT NULL,
  `critical_assets_count` int DEFAULT NULL,
  `pct_elite` float DEFAULT NULL,
  `pct_standard` float DEFAULT NULL,
  `pct_legacy` float DEFAULT NULL,
  `pct_critical` float DEFAULT NULL,
  `avg_pqc_score` float DEFAULT NULL,
  `min_pqc_score` float DEFAULT NULL,
  `max_pqc_score` float DEFAULT NULL,
  `total_findings_count` int DEFAULT NULL,
  `total_critical_findings` int DEFAULT NULL,
  `total_high_findings` int DEFAULT NULL,
  `total_medium_findings` int DEFAULT NULL,
  `total_low_findings` int DEFAULT NULL,
  `quantum_safe_assets_count` int DEFAULT NULL,
  `quantum_safe_pct` float DEFAULT NULL,
  `vulnerable_assets_count` int DEFAULT NULL,
  `vulnerable_pct` float DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  `updated_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_org_pqc_metrics_metric_date` (`metric_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pqc_classification`
--

DROP TABLE IF EXISTS `pqc_classification`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `pqc_classification` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `certificate_id` bigint DEFAULT NULL,
  `asset_id` bigint NOT NULL,
  `scan_id` bigint NOT NULL,
  `algorithm_name` varchar(100) DEFAULT NULL,
  `algorithm_type` varchar(100) DEFAULT NULL,
  `quantum_safe_status` varchar(50) DEFAULT NULL,
  `nist_category` varchar(50) DEFAULT NULL,
  `pqc_score` float DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  `updated_at` datetime DEFAULT NULL,
  `is_deleted` tinyint(1) NOT NULL,
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by_user_id` varchar(36) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `deleted_by_user_id` (`deleted_by_user_id`),
  KEY `ix_pqc_classification_asset_id` (`asset_id`),
  KEY `ix_pqc_classification_certificate_id` (`certificate_id`),
  KEY `ix_pqc_classification_quantum_safe_status` (`quantum_safe_status`),
  KEY `ix_pqc_classification_is_deleted` (`is_deleted`),
  KEY `ix_pqc_classification_algorithm_name` (`algorithm_name`),
  KEY `ix_pqc_classification_scan_id` (`scan_id`),
  KEY `ix_pqc_classification_nist_category` (`nist_category`),
  CONSTRAINT `pqc_classification_ibfk_1` FOREIGN KEY (`certificate_id`) REFERENCES `certificates` (`id`) ON DELETE CASCADE,
  CONSTRAINT `pqc_classification_ibfk_2` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `pqc_classification_ibfk_3` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE,
  CONSTRAINT `pqc_classification_ibfk_4` FOREIGN KEY (`deleted_by_user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=93 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `report_schedules`
--

DROP TABLE IF EXISTS `report_schedules`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `report_schedules` (
  `schedule_id` varchar(36) NOT NULL,
  `created_by_id` varchar(36) DEFAULT NULL,
  `created_by_name` varchar(150) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `enabled` tinyint(1) DEFAULT '1',
  `report_type` varchar(120) NOT NULL,
  `frequency` varchar(32) NOT NULL,
  `assets` varchar(256) DEFAULT NULL,
  `sections_json` longtext,
  `schedule_date` varchar(20) DEFAULT NULL,
  `schedule_time` varchar(10) DEFAULT NULL,
  `timezone_name` varchar(64) DEFAULT NULL,
  `email_list` varchar(512) DEFAULT NULL,
  `pdf_password_enc` longtext,
  `save_path` varchar(512) DEFAULT NULL,
  `download_link` tinyint(1) DEFAULT '0',
  `status` varchar(32) DEFAULT 'scheduled',
  PRIMARY KEY (`schedule_id`),
  KEY `idx_report_schedules_created_at` (`created_at`),
  KEY `idx_report_schedules_status` (`status`),
  KEY `fk_report_schedules_created_by` (`created_by_id`),
  CONSTRAINT `fk_report_schedules_created_by` FOREIGN KEY (`created_by_id`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `report_schedules_ibfk_1` FOREIGN KEY (`created_by_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `scans`
--

DROP TABLE IF EXISTS `scans`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `scans` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `scan_uid` varchar(36) NOT NULL,
  `scan_id` varchar(36) NOT NULL,
  `requested_target` varchar(512) DEFAULT NULL,
  `normalized_target` varchar(512) DEFAULT NULL,
  `target` varchar(255) NOT NULL,
  `asset_class` varchar(64) DEFAULT NULL,
  `status` varchar(50) NOT NULL,
  `scan_kind` varchar(32) DEFAULT NULL,
  `initiated_by` varchar(36) DEFAULT NULL,
  `started_at` datetime DEFAULT NULL,
  `completed_at` datetime DEFAULT NULL,
  `scanned_at` datetime DEFAULT NULL,
  `total_assets` int DEFAULT NULL,
  `compliance_score` int DEFAULT NULL,
  `overall_pqc_score` float DEFAULT NULL,
  `quantum_safe` int DEFAULT NULL,
  `quantum_vuln` int DEFAULT NULL,
  `cbom_path` varchar(500) DEFAULT NULL,
  `add_to_inventory` tinyint(1) NOT NULL,
  `error_message` text,
  `report_json` text NOT NULL,
  `is_encrypted` tinyint(1) DEFAULT NULL,
  `total_discovered` int DEFAULT NULL,
  `total_promoted` int DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  `updated_at` datetime DEFAULT NULL,
  `deleted_by` varchar(36) DEFAULT NULL,
  `correlation_id` varchar(36) DEFAULT NULL,
  `scanner_version` varchar(50) DEFAULT NULL,
  `is_deleted` tinyint(1) NOT NULL,
  `deleted_at` datetime DEFAULT NULL,
  `deleted_by_user_id` varchar(36) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_scans_scan_id` (`scan_id`),
  UNIQUE KEY `uq_scans_scan_id` (`scan_id`),
  UNIQUE KEY `ix_scans_scan_uid` (`scan_uid`),
  UNIQUE KEY `uq_scans_scan_uid` (`scan_uid`),
  KEY `deleted_by_user_id` (`deleted_by_user_id`),
  KEY `ix_scans_is_deleted` (`is_deleted`),
  KEY `ix_scans_normalized_target` (`normalized_target`),
  KEY `ix_scans_target` (`target`),
  KEY `ix_scans_correlation_id` (`correlation_id`),
  CONSTRAINT `scans_ibfk_1` FOREIGN KEY (`deleted_by_user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=218 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `subdomains`
--

DROP TABLE IF EXISTS `subdomains`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `subdomains` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `parent_asset_id` bigint NOT NULL,
  `subdomain` varchar(512) NOT NULL,
  `record_type` varchar(20) NOT NULL,
  `ip` varchar(80) DEFAULT NULL,
  `is_inventoried` tinyint(1) NOT NULL,
  `is_deleted` tinyint(1) NOT NULL,
  `discovered_at` datetime DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_subdomains_subdomain` (`subdomain`),
  KEY `ix_subdomains_parent_asset_id` (`parent_asset_id`),
  KEY `ix_subdomains_is_deleted` (`is_deleted`),
  CONSTRAINT `subdomains_ibfk_1` FOREIGN KEY (`parent_asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=23 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tls_compliance_scores`
--

DROP TABLE IF EXISTS `tls_compliance_scores`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `tls_compliance_scores` (
  `asset_id` bigint NOT NULL,
  `tls_score` float NOT NULL,
  `score_breakdown_json` text,
  `weak_tls_version_count` int DEFAULT NULL,
  `weak_cipher_count` int DEFAULT NULL,
  `weak_key_length_count` int DEFAULT NULL,
  `resilience_tier` enum('critical','medium','low') DEFAULT NULL,
  `total_endpoints_scanned` int DEFAULT NULL,
  `calculated_at` datetime DEFAULT NULL,
  `updated_at` datetime DEFAULT NULL,
  PRIMARY KEY (`asset_id`),
  KEY `ix_tls_compliance_scores_resilience_tier` (`resilience_tier`),
  CONSTRAINT `tls_compliance_scores_ibfk_1` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` varchar(36) NOT NULL,
  `username` varchar(50) NOT NULL,
  `role` varchar(50) DEFAULT NULL,
  `password_hash` varchar(255) DEFAULT NULL,
  `two_factor_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `two_factor_secret` longtext,
  `backup_codes` longtext,
  `email` varchar(255) DEFAULT NULL,
  `reset_token` varchar(255) DEFAULT NULL,
  `token_expiry` datetime DEFAULT NULL,
  `employee_id` varchar(64) DEFAULT NULL,
  `created_by` varchar(36) DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT '1',
  `password_setup_token_hash` char(64) DEFAULT NULL,
  `password_setup_token_expiry` datetime DEFAULT NULL,
  `must_change_password` tinyint(1) DEFAULT '1',
  `failed_login_attempts` int DEFAULT '0',
  `lockout_until` datetime DEFAULT NULL,
  `last_login_at` datetime DEFAULT NULL,
  `password_changed_at` datetime DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `api_key_hash` char(64) DEFAULT NULL,
  `locked_until` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`),
  UNIQUE KEY `email` (`email`),
  UNIQUE KEY `reset_token` (`reset_token`),
  UNIQUE KEY `employee_id` (`employee_id`),
  UNIQUE KEY `password_setup_token_hash` (`password_setup_token_hash`),
  UNIQUE KEY `api_key_hash` (`api_key_hash`),
  KEY `fk_users_created_by` (`created_by`),
  CONSTRAINT `fk_users_created_by` FOREIGN KEY (`created_by`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vulnerability_cache`
--

DROP TABLE IF EXISTS `vulnerability_cache`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vulnerability_cache` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `asset_id` bigint NOT NULL,
  `cve_id` varchar(30) NOT NULL,
  `severity` varchar(20) NOT NULL,
  `cvss` float DEFAULT NULL,
  `description` text,
  `mitigation` text,
  `published_at` datetime DEFAULT NULL,
  `source` varchar(50) NOT NULL,
  `fetched_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_vulnerability_cache_cve_id` (`cve_id`),
  KEY `ix_vulnerability_cache_severity` (`severity`),
  KEY `ix_vulnerability_cache_asset_id` (`asset_id`),
  KEY `ix_vulnerability_cache_fetched_at` (`fetched_at`),
  CONSTRAINT `vulnerability_cache_ibfk_1` FOREIGN KEY (`asset_id`) REFERENCES `assets` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-08-12 18:06:38
