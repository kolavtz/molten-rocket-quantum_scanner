# TLS Scanner Schema Inventory (QuantumShield)

Generated: 2026-04-12
Source: `src/models.py` SQLAlchemy metadata (runtime introspection)

## Core scan pipeline tables

### `scans`
- `id`, `scan_uid`, `scan_id`
- `requested_target`, `normalized_target`, `target`, `asset_class`
- `status`, `scan_kind`, `initiated_by`
- `started_at`, `completed_at`, `scanned_at`
- `total_assets`, `total_discovered`, `total_promoted`
- `compliance_score`, `overall_pqc_score`, `quantum_safe`, `quantum_vuln`
- `cbom_path`, `add_to_inventory`, `error_message`, `report_json`, `is_encrypted`
- `correlation_id`, `scanner_version`
- soft delete/audit: `is_deleted`, `deleted_at`, `deleted_by`, `deleted_by_user_id`, `created_at`, `updated_at`

### `assets`
- Identity: `id`, `asset_key`, `target`, `url`, `asset_type`
- Network: `ipv4`, `ipv6`
- Ownership/risk: `owner`, `risk_level`, `notes`
- Linkage: `last_scan_id`
- soft delete/audit: `is_deleted`, `deleted_at`, `deleted_by_user_id`, `created_at`, `updated_at`

### `certificates`
- Keys: `id`, `asset_id`, `scan_id`
- Endpoint: `endpoint`, `port`
- Subject/issuer: `subject`, `subject_cn`, `subject_o`, `subject_ou`, `issuer`, `issuer_cn`, `issuer_o`, `issuer_ou`, `ca`, `ca_name`, `company_name`
- Validity: `valid_from`, `valid_until`, `expiry_days`
- Fingerprints/identity: `serial`, `fingerprint_sha256`, `fingerprint_sha1`, `fingerprint_md5`, `public_key_fingerprint_sha256`
- Crypto: `tls_version`, `cipher_suite`, `key_length`, `key_algorithm`, `public_key_type`, `public_key_pem`, `signature_algorithm`
- Cert metadata: `certificate_version`, `certificate_format`, `san_domains`, `cert_chain_length`, `certificate_details`
- Lifecycle: `is_self_signed`, `is_expired`, `is_current`, `first_seen_at`, `last_seen_at`
- Dedup helpers: `dedup_algorithm`, `dedup_value`, `dedup_hash`
- soft delete/audit: `is_deleted`, `deleted_at`, `deleted_by_user_id`, `created_at`, `updated_at`

## Discovery telemetry tables

### `discovery_ssl`
- `id`, `scan_id`, `asset_id`, `endpoint`
- `tls_version`, `cipher_suite`, `key_exchange`, `key_length`
- `subject_cn`, `issuer`, `valid_until`
- PQC: `pqc_score`, `pqc_assessment`
- Status/promotion: `status`, `promoted_to_inventory`, `promoted_at`, `promoted_by`
- soft delete/audit: `is_deleted`, `deleted_at`, `deleted_by_user_id`, `created_at`, `updated_at`

### `discovery_domains`
- `id`, `scan_id`, `asset_id`, `domain`, `registrar`, `registration_date`
- `status`, `promoted_to_inventory`, `promoted_at`, `promoted_by`
- soft delete/audit: `is_deleted`, `deleted_at`, `deleted_by_user_id`, `created_at`, `updated_at`

### `discovery_ips`
- `id`, `scan_id`, `asset_id`, `ip_address`, `subnet`, `asn`, `netname`, `location`
- `status`, `promoted_to_inventory`, `promoted_at`, `promoted_by`
- soft delete/audit: `is_deleted`, `deleted_at`, `deleted_by_user_id`, `created_at`, `updated_at`

### `discovery_software`
- `id`, `scan_id`, `asset_id`, `product`, `version`, `category`, `cpe`
- `status`, `promoted_to_inventory`, `promoted_at`, `promoted_by`
- soft delete/audit: `is_deleted`, `deleted_at`, `deleted_by_user_id`, `created_at`, `updated_at`

## CBOM tables

### `cbom_summary`
- `id`, `asset_id`, `scan_id`
- `total_components`, `weak_crypto_count`, `cert_issues_count`, `json_path`
- soft delete/audit: `is_deleted`, `deleted_at`, `deleted_by_user_id`

### `cbom_entries`
- Identity: `id`, `scan_id`, `asset_id`, `algorithm_name`, `category`, `asset_type`, `element_name`
- Crypto fields: `primitive`, `mode`, `crypto_functions`, `classical_security_level`, `oid`, `element_list`
- Key lifecycle: `key_id`, `key_state`, `key_size`, `key_creation_date`, `key_activation_date`
- Protocol/cipher: `protocol_name`, `protocol_version_name`, `cipher_suites`
- Cert linkage: `subject_name`, `issuer_name`, `not_valid_before`, `not_valid_after`, `signature_algorithm_reference`, `subject_public_key_reference`, `certificate_format`, `certificate_extension`
- Scoring flags: `key_length`, `protocol_version`, `nist_status`, `quantum_safe_flag`, `hndl_level`
- Replacement marker: `superseded_at`
- soft delete/audit: `is_deleted`, `deleted_at`, `deleted_by_user_id`

## PQC / risk / reporting support tables

- `pqc_classification`
- `compliance_scores`
- `cyber_rating`
- `findings`
- `asset_metrics`
- `org_pqc_metrics`
- `cert_expiry_buckets`
- `tls_compliance_scores`
- `digital_labels`
- `domain_current_state`
- `asset_ssl_profiles`
- `domain_events`
- `vulnerability_cache`

## Minimum required fields for CBOM SSL issuer visibility

For SSL issuer/TLS details to appear reliably in CBOM views, ensure these are present and populated:
- `scans`: `id`, `target`, `status`, `report_json`
- `certificates`: `asset_id`, `scan_id`, `subject_cn`, `issuer` / `issuer_cn` / `issuer_o`, `tls_version`, `cipher_suite`, `valid_until`, `certificate_details`, `is_current`
- `discovery_ssl`: `scan_id`, `asset_id`, `endpoint`, `subject_cn`, `issuer`, `tls_version`, `cipher_suite`, `valid_until`
- `cbom_entries`: `scan_id`, `asset_id`, `subject_name`, `issuer_name`, `protocol_name`, `protocol_version_name`, `cipher_suites`
