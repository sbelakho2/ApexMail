-- FIX-077: Align enterprise_contracts schema with EnterpriseContractService
-- The service code expects column names that differ from the original migration.
-- This migration renames/adds columns to match the service interface.

BEGIN;

-- Rename existing columns to match service expectations (guarded)
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'enterprise_contracts' AND column_name = 'base_fee')
     AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'enterprise_contracts' AND column_name = 'base_price') THEN
    EXECUTE 'ALTER TABLE enterprise_contracts RENAME COLUMN base_fee TO base_price';
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'enterprise_contracts' AND column_name = 'committed_volume')
     AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'enterprise_contracts' AND column_name = 'committed_volume_tiers') THEN
    EXECUTE 'ALTER TABLE enterprise_contracts RENAME COLUMN committed_volume TO committed_volume_tiers';
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'enterprise_contracts' AND column_name = 'overage_rates')
     AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'enterprise_contracts' AND column_name = 'overage_rate_tiers') THEN
    EXECUTE 'ALTER TABLE enterprise_contracts RENAME COLUMN overage_rates TO overage_rate_tiers';
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'enterprise_contracts' AND column_name = 'signer_name')
     AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'enterprise_contracts' AND column_name = 'signed_by') THEN
    EXECUTE 'ALTER TABLE enterprise_contracts RENAME COLUMN signer_name TO signed_by';
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'enterprise_contracts' AND column_name = 'payment_terms')
     AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'enterprise_contracts' AND column_name = 'payment_terms_legacy') THEN
    EXECUTE 'ALTER TABLE enterprise_contracts RENAME COLUMN payment_terms TO payment_terms_legacy';
  END IF;
END $$;

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
