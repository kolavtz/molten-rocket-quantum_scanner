-- Add CERT-IN Table 9 minimum CBOM element columns to cbom_entries
-- Date: 2026-03-23

ALTER TABLE cbom_entries ADD COLUMN IF NOT EXISTS asset_type VARCHAR(50) NULL;
ALTER TABLE cbom_entries ADD COLUMN IF NOT EXISTS element_name VARCHAR(255) NULL;
ALTER TABLE cbom_entries ADD COLUMN IF NOT EXISTS primitive VARCHAR(100) NULL;
ALTER TABLE cbom_entries ADD COLUMN IF NOT EXISTS mode VARCHAR(100) NULL;
ALTER TABLE cbom_entries ADD COLUMN IF NOT EXISTS crypto_functions LONGTEXT NULL;
ALTER TABLE cbom_entries ADD COLUMN IF NOT EXISTS classical_security_level INT NULL;
ALTER TABLE cbom_entries ADD COLUMN IF NOT EXISTS oid VARCHAR(255) NULL;
ALTER TABLE cbom_entries ADD COLUMN IF NOT EXISTS element_list LONGTEXT NULL;

ALTER TABLE cbom_entries ADD COLUMN IF NOT EXISTS key_id VARCHAR(255) NULL;
ALTER TABLE cbom_entries ADD COLUMN IF NOT EXISTS key_state VARCHAR(50) NULL;
ALTER TABLE cbom_entries ADD COLUMN IF NOT EXISTS key_size INT NULL;
ALTER TABLE cbom_entries ADD COLUMN IF NOT EXISTS key_creation_date DATETIME NULL;
ALTER TABLE cbom_entries ADD COLUMN IF NOT EXISTS key_activation_date DATETIME NULL;

ALTER TABLE cbom_entries ADD COLUMN IF NOT EXISTS protocol_name VARCHAR(100) NULL;
ALTER TABLE cbom_entries ADD COLUMN IF NOT EXISTS protocol_version_name VARCHAR(50) NULL;
ALTER TABLE cbom_entries ADD COLUMN IF NOT EXISTS cipher_suites LONGTEXT NULL;

ALTER TABLE cbom_entries ADD COLUMN IF NOT EXISTS subject_name VARCHAR(500) NULL;
ALTER TABLE cbom_entries ADD COLUMN IF NOT EXISTS issuer_name VARCHAR(500) NULL;
ALTER TABLE cbom_entries ADD COLUMN IF NOT EXISTS not_valid_before DATETIME NULL;
ALTER TABLE cbom_entries ADD COLUMN IF NOT EXISTS not_valid_after DATETIME NULL;
ALTER TABLE cbom_entries ADD COLUMN IF NOT EXISTS signature_algorithm_reference VARCHAR(255) NULL;
ALTER TABLE cbom_entries ADD COLUMN IF NOT EXISTS subject_public_key_reference VARCHAR(255) NULL;
ALTER TABLE cbom_entries ADD COLUMN IF NOT EXISTS certificate_format VARCHAR(100) NULL;
ALTER TABLE cbom_entries ADD COLUMN IF NOT EXISTS certificate_extension VARCHAR(32) NULL;

CREATE INDEX idx_cbom_asset_type ON cbom_entries(asset_type);
CREATE INDEX idx_cbom_oid ON cbom_entries(oid);
