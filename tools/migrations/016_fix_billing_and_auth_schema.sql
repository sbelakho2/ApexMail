-- ApexMail Schema Fix Migration
-- Version:1.0.16
-- (plans limits), (invoices table), (subscriptions tenant_id type)
-- This migration resolves all schema-code drift found during deep scan.

-- =============================================================================
-- Add to_emails, cc_emails, bcc_emails to messages table
-- =============================================================================
-- Code in messages.rs uses to_emails/cc_emails/bcc_emails but schema only has
-- to_address (singular VARCHAR) and cc/bcc (JSONB). The code stores arrays.
-- Migration 003 renamed from_address→from_email but missed the recipient columns.

-- Add new array-type columns for the messages handler
ALTER TABLE messages ADD COLUMN IF NOT EXISTS to_emails JSONB;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS cc_emails JSONB;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS bcc_emails JSONB;

-- Backfill:convert existing to_address (VARCHAR) to to_emails (JSONB array)
UPDATE messages
SET to_emails = COALESCE(to_emails, jsonb_build_array(to_address))
WHERE to_emails IS NULL AND to_address IS NOT NULL;

-- Backfill:rename existing cc → cc_emails, bcc → bcc_emails only if the
-- original cc/bcc columns still exist and the new ones are empty.
-- Note:Since the original cc/bcc columns were already JSONB, we copy them.
UPDATE messages SET cc_emails = COALESCE(cc_emails, cc) WHERE cc_emails IS NULL AND cc IS NOT NULL;
UPDATE messages SET bcc_emails = COALESCE(bcc_emails, bcc) WHERE bcc_emails IS NULL AND bcc IS NOT NULL;

-- Add tags column as JSONB (auth.rs:281 writes tags to messages)
ALTER TABLE messages ADD COLUMN IF NOT EXISTS tags JSONB;

-- Add scheduled_at column if somehow missing (used by send_message for scheduling)
-- This already exists in the original schema, so IF NOT EXISTS is a safety net.

-- Add sent_at if missing
ALTER TABLE messages ADD COLUMN IF NOT EXISTS sent_at TIMESTAMPTZ;

-- The send handlers now store recipient arrays in to_emails. Keep the legacy
-- to_address column for compatibility, but allow it to be null and backfill
-- from the first JSON recipient when possible.
ALTER TABLE messages ALTER COLUMN to_address DROP NOT NULL;
UPDATE messages
SET to_address = COALESCE(to_address, to_emails->>0)
WHERE to_address IS NULL AND to_emails IS NOT NULL;

-- Message IDs remain VARCHAR(26) in the canonical schema; route code must
-- bind string identifiers rather than introducing a shadow UUID column.

-- Ensure a well-known internal tenant exists for system-generated emails such
-- as registration verification and password reset notifications.
INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at)
SELECT
    'system_internal_tenant01',
    'ApexMail System',
    'apexmail-system',
    'free',
    'active',
    '{}'::jsonb,
    '{"system": true}'::jsonb,
    NOW(),
    NOW()
WHERE NOT EXISTS (
    SELECT 1 FROM tenants WHERE id = 'system_internal_tenant01'
);

-- =============================================================================
-- Create sessions table
-- =============================================================================
-- auth.rs:693,862,1090 all execute DELETE FROM sessions WHERE user_id = $1

CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(26) PRIMARY KEY,
    user_id VARCHAR(26) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id VARCHAR(26) REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash VARCHAR(128) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_tenant ON sessions(tenant_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);
CREATE INDEX idx_sessions_token ON sessions(token_hash);

ALTER TABLE sessions ALTER COLUMN tenant_id DROP NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_global
    ON users (LOWER(email));

-- =============================================================================
-- Create metering_events table with meter_event_type enum
-- =============================================================================

-- Create enum type for metering events (used by billing usage.rs)
DO $$ BEGIN
    CREATE TYPE meter_event_type AS ENUM (
        'emails_sent',
        'emails_delivered',
        'api_calls',
        'webhooks_delivered',
        'dedicated_ip_hours',
        'storage_gb_hours',
        'bandwidth_gb'
    );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS metering_events (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    quantity BIGINT NOT NULL DEFAULT 1,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Unique constraint for idempotency (ON CONFLICT id DO NOTHING)
CREATE UNIQUE INDEX IF NOT EXISTS idx_metering_events_id ON metering_events(id);

CREATE INDEX idx_metering_events_tenant ON metering_events(tenant_id);
CREATE INDEX idx_metering_events_type ON metering_events(event_type);
CREATE INDEX idx_metering_events_timestamp ON metering_events(timestamp);
CREATE INDEX idx_metering_events_tenant_period ON metering_events(tenant_id, timestamp);

-- =============================================================================
-- Add email_limit and api_call_limit to plans table
-- =============================================================================
-- usage.rs queries:SELECT p.email_limit, p.api_call_limit FROM plans ...

CREATE TABLE IF NOT EXISTS plans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) NOT NULL UNIQUE,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    price_monthly BIGINT NOT NULL DEFAULT 0,
    price_yearly BIGINT NOT NULL DEFAULT 0,
    features JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_active BOOLEAN NOT NULL DEFAULT true,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE plans ADD COLUMN IF NOT EXISTS email_limit BIGINT NOT NULL DEFAULT 100;
ALTER TABLE plans ADD COLUMN IF NOT EXISTS api_call_limit BIGINT NOT NULL DEFAULT 1000;

-- Set sensible defaults for known plans
UPDATE plans SET email_limit = 100, api_call_limit = 1000 WHERE name = 'free' AND email_limit = 100;
UPDATE plans SET email_limit = 10000, api_call_limit = 50000 WHERE name = 'starter' AND email_limit = 100;
UPDATE plans SET email_limit = 100000, api_call_limit = 500000 WHERE name = 'pro' AND email_limit = 100;
UPDATE plans SET email_limit = -1, api_call_limit = -1 WHERE name = 'enterprise' AND email_limit = 100;
-- -1 means unlimited

-- =============================================================================
-- Create invoices table
-- =============================================================================

CREATE TABLE IF NOT EXISTS invoices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    amount_cents BIGINT NOT NULL DEFAULT 0,
    currency VARCHAR(3) NOT NULL DEFAULT 'USD',
    status VARCHAR(20) NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'open', 'paid', 'void', 'uncollectible')),
    invoice_number VARCHAR(50),
    stripe_invoice_id VARCHAR(255),
    period_start TIMESTAMPTZ,
    period_end TIMESTAMPTZ,
    due_date TIMESTAMPTZ,
    paid_at TIMESTAMPTZ,
    line_items JSONB NOT NULL DEFAULT '[]',
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_invoices_tenant ON invoices(tenant_id);
CREATE INDEX idx_invoices_status ON invoices(status);
CREATE INDEX idx_invoices_created ON invoices(created_at DESC);
CREATE INDEX idx_invoices_stripe ON invoices(stripe_invoice_id) WHERE stripe_invoice_id IS NOT NULL;

-- =============================================================================
-- Fix subscriptions.tenant_id type mismatch
-- =============================================================================
-- subscriptions.tenant_id is UUID but tenants.id is VARCHAR(26)
-- We change subscriptions.tenant_id to VARCHAR(26) to match

CREATE TABLE IF NOT EXISTS subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    plan_name VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'past_due', 'canceled', 'trialing', 'paused', 'incomplete')),
    billing_interval VARCHAR(20) NOT NULL DEFAULT 'monthly',
    current_period_start TIMESTAMPTZ,
    current_period_end TIMESTAMPTZ,
    stripe_subscription_id TEXT,
    stripe_customer_id TEXT,
    cancel_at_period_end BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'subscriptions'
          AND column_name = 'tenant_id'
          AND data_type = 'uuid'
    ) THEN
        ALTER TABLE subscriptions RENAME COLUMN tenant_id TO tenant_id_old;
        ALTER TABLE subscriptions ADD COLUMN tenant_id VARCHAR(26);

        UPDATE subscriptions
        SET tenant_id = tenant_id_old::text
        WHERE tenant_id IS NULL AND tenant_id_old IS NOT NULL;

        ALTER TABLE subscriptions DROP COLUMN tenant_id_old;
        ALTER TABLE subscriptions ALTER COLUMN tenant_id SET NOT NULL;
    END IF;
END $$;

DROP INDEX IF EXISTS idx_subscriptions_tenant;
CREATE INDEX IF NOT EXISTS idx_subscriptions_tenant ON subscriptions(tenant_id, status);

-- =============================================================================
-- SCHEMA VERSION
-- =============================================================================

INSERT INTO schema_migrations (version) VALUES ('1.0.16') ON CONFLICT DO NOTHING;