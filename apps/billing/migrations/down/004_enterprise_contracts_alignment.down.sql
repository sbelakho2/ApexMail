BEGIN;

ALTER TABLE enterprise_contracts
  DROP COLUMN IF EXISTS name,
  DROP COLUMN IF EXISTS auto_renew,
  DROP COLUMN IF EXISTS committed_volume,
  DROP COLUMN IF EXISTS overage_rate,
  DROP COLUMN IF EXISTS annual_prepay_discount,
  DROP COLUMN IF EXISTS additional_fees,
  DROP COLUMN IF EXISTS payment_terms_days,
  DROP COLUMN IF EXISTS sla_credit_percentage,
  DROP COLUMN IF EXISTS custom_terms,
  DROP COLUMN IF EXISTS purchase_order_number;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'enterprise_contracts' AND column_name = 'base_price')
       AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'enterprise_contracts' AND column_name = 'base_fee') THEN
        EXECUTE 'ALTER TABLE enterprise_contracts RENAME COLUMN base_price TO base_fee';
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'enterprise_contracts' AND column_name = 'committed_volume_tiers')
       AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'enterprise_contracts' AND column_name = 'committed_volume') THEN
        EXECUTE 'ALTER TABLE enterprise_contracts RENAME COLUMN committed_volume_tiers TO committed_volume';
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'enterprise_contracts' AND column_name = 'overage_rate_tiers')
       AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'enterprise_contracts' AND column_name = 'overage_rates') THEN
        EXECUTE 'ALTER TABLE enterprise_contracts RENAME COLUMN overage_rate_tiers TO overage_rates';
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'enterprise_contracts' AND column_name = 'signed_by')
       AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'enterprise_contracts' AND column_name = 'signer_name') THEN
        EXECUTE 'ALTER TABLE enterprise_contracts RENAME COLUMN signed_by TO signer_name';
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'enterprise_contracts' AND column_name = 'payment_terms_legacy')
       AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'enterprise_contracts' AND column_name = 'payment_terms') THEN
        EXECUTE 'ALTER TABLE enterprise_contracts RENAME COLUMN payment_terms_legacy TO payment_terms';
    END IF;
END $$;

COMMIT;
