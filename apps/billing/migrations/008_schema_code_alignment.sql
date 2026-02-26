-- Migration 008: Schema code alignment
-- Fixes column name mismatches between TypeScript code and database schema

-- ============================================
-- 1. stripe_subscriptions additional columns
-- ============================================

-- Add billing_cycle_start/end as aliases for current_period_start/end
ALTER TABLE stripe_subscriptions 
    ADD COLUMN IF NOT EXISTS billing_cycle_start TIMESTAMPTZ GENERATED ALWAYS AS (current_period_start) STORED,
    ADD COLUMN IF NOT EXISTS billing_cycle_end TIMESTAMPTZ GENERATED ALWAYS AS (current_period_end) STORED;

-- Add Stripe price ID for subscription syncing
ALTER TABLE stripe_subscriptions
    ADD COLUMN IF NOT EXISTS stripe_price_id VARCHAR(255);

-- Add cancel_at_period_end flag
ALTER TABLE stripe_subscriptions
    ADD COLUMN IF NOT EXISTS cancel_at_period_end BOOLEAN DEFAULT false;

-- Update existing rows based on cancel_at presence
UPDATE stripe_subscriptions
SET cancel_at_period_end = (cancel_at IS NOT NULL)
WHERE cancel_at_period_end IS NULL;

-- ============================================
-- 2. metering_events additional column alias
-- ============================================

-- Add timestamp column as alias for recorded_at
ALTER TABLE metering_events
    ADD COLUMN IF NOT EXISTS timestamp TIMESTAMPTZ GENERATED ALWAYS AS (recorded_at) STORED;

DROP TRIGGER IF EXISTS sync_metering_timestamps ON metering_events;
DROP FUNCTION IF EXISTS sync_metering_event_timestamps();

-- ============================================
-- 3. wallet_transactions fixes
-- ============================================

-- Add balance column as alias for balance_after
ALTER TABLE wallet_transactions
    ADD COLUMN IF NOT EXISTS balance INTEGER GENERATED ALWAYS AS (balance_after) STORED;

-- Add metadata column
ALTER TABLE wallet_transactions
    ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM wallet_transactions WHERE wallet_id IS NULL) THEN
        ALTER TABLE wallet_transactions
            ALTER COLUMN wallet_id SET NOT NULL;
    END IF;
END $$;

DROP TRIGGER IF EXISTS sync_wallet_balance_trigger ON wallet_transactions;
DROP FUNCTION IF EXISTS sync_wallet_balance();

-- ============================================
-- 4. plans table - add email_limit/api_call_limit
-- ============================================

-- Add columns that code expects (extracted from JSONB limits)
ALTER TABLE plans
    ADD COLUMN IF NOT EXISTS email_limit INTEGER,
    ADD COLUMN IF NOT EXISTS api_call_limit INTEGER;

-- Populate from existing JSONB limits
UPDATE plans
SET 
    email_limit = COALESCE((limits->>'emails_per_month')::INTEGER, 0),
    api_call_limit = COALESCE((limits->>'api_calls_per_month')::INTEGER, 0)
WHERE email_limit IS NULL OR api_call_limit IS NULL;

-- ============================================
-- 5. proration_records - fix subscription_id type
-- ============================================

-- Change from UUID to VARCHAR to accept Stripe subscription IDs
-- Drop the FK constraint first if it exists
ALTER TABLE proration_records 
    DROP CONSTRAINT IF EXISTS proration_records_subscription_id_fkey;

-- Change column type
ALTER TABLE proration_records
    ALTER COLUMN subscription_id TYPE VARCHAR(255);

-- Add a stripe_subscription_id column for Stripe IDs
ALTER TABLE proration_records
    ADD COLUMN IF NOT EXISTS stripe_subscription_id VARCHAR(255);

-- ============================================
-- 6. Update compatibility views
-- ============================================

-- Drop and recreate usage_events view with timestamp mapping
DROP VIEW IF EXISTS usage_events;
CREATE VIEW usage_events AS
SELECT 
    id,
    tenant_id,
    event_type,
    quantity,
    timestamp,
    recorded_at,
    metadata,
    idempotency_key,
    created_at
FROM metering_events;

-- Create or replace subscriptions view with all needed columns
DROP VIEW IF EXISTS subscriptions;
CREATE VIEW subscriptions AS
SELECT 
    id,
    tenant_id,
    stripe_subscription_id,
    stripe_customer_id,
    stripe_price_id,
    plan_id,
    status,
    current_period_start,
    current_period_end,
    billing_cycle_start,
    billing_cycle_end,
    cancel_at,
    cancel_at_period_end,
    canceled_at,
    created_at,
    updated_at
FROM stripe_subscriptions;

-- Create index on new columns
CREATE INDEX IF NOT EXISTS idx_metering_events_timestamp ON metering_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_ss_stripe_price_id ON stripe_subscriptions(stripe_price_id);
