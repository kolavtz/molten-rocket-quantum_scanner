-- Migration: Add certificate_details column to certificates
-- Date: 2026-04-04

ALTER TABLE certificates ADD COLUMN IF NOT EXISTS certificate_details LONGTEXT NULL;

-- Notes:
-- This column stores serialized X.509 certificate details as JSON for richer UI telemetry
-- A conservative backfill script is provided at scripts/backfill_certificate_details.py
