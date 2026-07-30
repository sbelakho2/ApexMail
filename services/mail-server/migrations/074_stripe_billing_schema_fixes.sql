-- =============================================================================
-- 074: Stripe billing schema fixes — critical gap remediation
-- =============================================================================
-- Fixes P0 issues identified in 2026-07-25 audit:
--   1. stripe_webhook_events table was referenced in code but never created
--   2. plans table missing stripe_price_id_monthly/stripe_price_id_yearly
--   3. stripe_customers table missing email/name/updated_at columns
--   4. stripe_subscriptions missing UNIQUE on stripe_subscription_id
-- =============================================================================

-- 1. STRIPE WEBHOOK EVENTS TABLE
-- Referenced by billing-service/src/stripe_webhooks.rs for idempotent event
-- processing. Without this table, every webhook event crashes with
-- "relation does not exist".
CREATE TABLE IF NOT EXISTS stripe_webhook_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stripe_event_id     VARCHAR(255) NOT NULL,
    event_type          VARCHAR(100) NOT NULL,
    status              VARCHAR(20)  NOT NULL DEFAULT 'pending',
    error               TEXT,
    processed_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_stripe_webhook_events_event_id
    ON stripe_webhook_events (stripe_event_id);
CREATE INDEX IF NOT EXISTS idx_stripe_webhook_events_status
    ON stripe_webhook_events (status);

-- 2. STRIPE PRICE ID COLUMNS ON PLANS TABLE
-- billing-service/src/stripe_webhooks.rs:703 resolves plan name from price ID.
-- plans.rs:487-501 (PlanRow) reads these but the columns never existed.
ALTER TABLE plans
    ADD COLUMN IF NOT EXISTS stripe_price_id_monthly VARCHAR(128),
    ADD COLUMN IF NOT EXISTS stripe_price_id_yearly  VARCHAR(128);

-- 3. STRIPE CUSTOMERS TABLE — ADD MISSING COLUMNS
-- billing.rs:1071-1078 INSERT includes email, name, updated_at but migration
-- 069 only created id, tenant_id, stripe_customer_id, created_at.
ALTER TABLE stripe_customers
    ADD COLUMN IF NOT EXISTS email      VARCHAR(320),
    ADD COLUMN IF NOT EXISTS name       VARCHAR(255),
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Also add UNIQUE constraint on stripe_customer_id (was missing in migration 069)
CREATE UNIQUE INDEX IF NOT EXISTS idx_stripe_customers_customer_id
    ON stripe_customers (stripe_customer_id);

-- 4. STRIPE SUBSCRIPTIONS — ADD UNIQUE CONSTRAINT
-- stripe_webhooks.rs uses ON CONFLICT (stripe_subscription_id) but no
-- unique constraint existed. This would silently insert duplicates.
CREATE UNIQUE INDEX IF NOT EXISTS idx_stripe_subscriptions_sub_id
    ON stripe_subscriptions (stripe_subscription_id);
