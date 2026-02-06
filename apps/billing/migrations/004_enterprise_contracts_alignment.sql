-- FIX-077: Align enterprise_contracts schema with EnterpriseContractService
-- The service code expects column names that differ from the original migration.
-- This migration renames/adds columns to match the service interface.

BEGIN;

-- Rename existing columns to match service expectations
-- base_fee → base_price (service uses basePrice / base_price)
ALTER TABLE enterprise_contracts RENAME COLUMN base_fee TO base_price;

-- committed_volume JSONB → committed_volume_tiers (free up name for integer column)
ALTER TABLE enterprise_contracts RENAME COLUMN committed_volume TO committed_volume_tiers;

-- overage_rates JSONB → overage_rate_tiers (free up for scalar overage_rate)
ALTER TABLE enterprise_contracts RENAME COLUMN overage_rates TO overage_rate_tiers;

-- signer_name → signed_by (service uses signedBy / signed_by)
ALTER TABLE enterprise_contracts RENAME COLUMN signer_name TO signed_by;

-- payment_terms → payment_terms_legacy (service uses payment_terms_days integer)
ALTER TABLE enterprise_contracts RENAME COLUMN payment_terms TO payment_terms_legacy;

-- Add columns the service expects that were missing
ALTER TABLE enterprise_contracts
  ADD COLUMN IF NOT EXISTS name VARCHAR(255),
  ADD COLUMN IF NOT EXISTS auto_renew BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS committed_volume INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS overage_rate INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS annual_prepay_discount INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS additional_fees JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS payment_terms_days INTEGER NOT NULL DEFAULT 30,
  ADD COLUMN IF NOT EXISTS sla_credit_percentage INTEGER NOT NULL DEFAULT 10,
  ADD COLUMN IF NOT EXISTS custom_terms TEXT,
  ADD COLUMN IF NOT EXISTS purchase_order_number VARCHAR(100);

-- Backfill: migrate data from old columns to new where possible
-- Extract payment_terms_days from payment_terms_legacy (e.g. 'net30' → 30)
UPDATE enterprise_contracts
SET payment_terms_days = CASE
  WHEN payment_terms_legacy ~ '^\d+$' THEN payment_terms_legacy::integer
  WHEN payment_terms_legacy ~ 'net(\d+)' THEN (regexp_match(payment_terms_legacy, 'net(\d+)'))[1]::integer
  ELSE 30
END
WHERE payment_terms_legacy IS NOT NULL;

-- Use contract_number as name if name is null
UPDATE enterprise_contracts
SET name = contract_number
WHERE name IS NULL AND contract_number IS NOT NULL;

COMMIT;
