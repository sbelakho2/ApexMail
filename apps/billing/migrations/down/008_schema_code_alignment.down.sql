BEGIN;

DROP VIEW IF EXISTS usage_events;
DROP VIEW IF EXISTS subscriptions;

ALTER TABLE stripe_subscriptions
  DROP COLUMN IF EXISTS billing_cycle_start,
  DROP COLUMN IF EXISTS billing_cycle_end,
  DROP COLUMN IF EXISTS stripe_price_id,
  DROP COLUMN IF EXISTS cancel_at_period_end;

ALTER TABLE metering_events
  DROP COLUMN IF EXISTS timestamp;

ALTER TABLE wallet_transactions
  DROP COLUMN IF EXISTS balance,
  DROP COLUMN IF EXISTS metadata;

ALTER TABLE proration_records
  DROP COLUMN IF EXISTS stripe_subscription_id;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'proration_records'
          AND column_name = 'subscription_id'
          AND data_type = 'character varying'
    ) THEN
        ALTER TABLE proration_records
            ALTER COLUMN subscription_id TYPE UUID USING NULLIF(subscription_id, '')::uuid;
    END IF;
END $$;

COMMIT;
