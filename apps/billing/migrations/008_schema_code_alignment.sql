-- Migration 008: Schema code alignment
-- Fixes column name mismatches between TypeScript code and database schema

-- ============================================
-- 1. stripe_subscriptions additional columns
-- ============================================

-- Add billing_cycle_start/end as aliases for current_period_start/end
ALTER TABLE stripe_subscriptions 
    ADD COLUMN IF NOT EXISTS billing_cycle_start TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS billing_cycle_end TIMESTAMPTZ;

-- Keep them in sync with current_period columns
UPDATE stripe_subscriptions 
SET billing_cycle_start = current_period_start,
    billing_cycle_end = current_period_end
WHERE billing_cycle_start IS NULL;

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
    ADD COLUMN IF NOT EXISTS timestamp TIMESTAMPTZ;

-- Populate from recorded_at
UPDATE metering_events
SET timestamp = recorded_at
WHERE timestamp IS NULL;

-- Create trigger to keep columns in sync
CREATE OR REPLACE FUNCTION sync_metering_event_timestamps()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.timestamp IS NOT NULL AND NEW.recorded_at IS NULL THEN
            NEW.recorded_at := NEW.timestamp;
        ELSIF NEW.recorded_at IS NOT NULL AND NEW.timestamp IS NULL THEN
            NEW.timestamp := NEW.recorded_at;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS sync_metering_timestamps ON metering_events;
CREATE TRIGGER sync_metering_timestamps
    BEFORE INSERT ON metering_events
    FOR EACH ROW EXECUTE FUNCTION sync_metering_event_timestamps();

-- ============================================
-- 3. wallet_transactions fixes
-- ============================================

-- Add balance column as alias for balance_after
ALTER TABLE wallet_transactions
    ADD COLUMN IF NOT EXISTS balance INTEGER;

UPDATE wallet_transactions
SET balance = balance_after
WHERE balance IS NULL;

-- Add metadata column
ALTER TABLE wallet_transactions
    ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}';

-- wallet_id might need to be nullable for credit operations
-- where wallet is created in same transaction
ALTER TABLE wallet_transactions
    ALTER COLUMN wallet_id DROP NOT NULL;

-- Create trigger to sync balance columns
CREATE OR REPLACE FUNCTION sync_wallet_balance()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.balance IS NOT NULL AND NEW.balance_after IS NULL THEN
            NEW.balance_after := NEW.balance;
        ELSIF NEW.balance_after IS NOT NULL AND NEW.balance IS NULL THEN
            NEW.balance := NEW.balance_after;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS sync_wallet_balance_trigger ON wallet_transactions;
CREATE TRIGGER sync_wallet_balance_trigger
    BEFORE INSERT ON wallet_transactions
    FOR EACH ROW EXECUTE FUNCTION sync_wallet_balance();

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
