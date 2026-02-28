-- Dedicated IP management schema
-- Supports the full lifecycle: inventory → allocation → warmup → active → release
--
-- Two tables:
-- 1. ses_ip_inventory: AWS-provisioned IPs available for assignment
-- 2. dedicated_ips: Per-tenant IP assignments with SES pool tracking

-- =============================================================================
-- SES IP Inventory
-- Pre-provisioned dedicated IPs leased from AWS SES.
-- Managed by ApexMail ops; customers never interact with this table directly.
-- =============================================================================

CREATE TABLE IF NOT EXISTS ses_ip_inventory (
    ip_address    INET PRIMARY KEY,
    aws_region    TEXT NOT NULL DEFAULT 'us-east-1',

    -- Assignment tracking
    assignment_status TEXT NOT NULL DEFAULT 'available'
        CHECK (assignment_status IN ('available', 'assigned', 'releasing', 'decommissioned')),
    assigned_tenant_id UUID,
    assigned_at   TIMESTAMPTZ,
    last_released_at TIMESTAMPTZ,

    -- Metadata
    provisioned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    notes         TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ses_ip_inventory_status
    ON ses_ip_inventory(assignment_status, aws_region);
CREATE INDEX IF NOT EXISTS idx_ses_ip_inventory_tenant
    ON ses_ip_inventory(assigned_tenant_id) WHERE assigned_tenant_id IS NOT NULL;

-- =============================================================================
-- Dedicated IPs (per-tenant assignments)
-- Each row represents an IP allocated to a tenant with full lifecycle tracking.
-- =============================================================================

CREATE TABLE IF NOT EXISTS dedicated_ips (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID NOT NULL,
    ip_address        TEXT NOT NULL,
    region            TEXT NOT NULL DEFAULT 'us-east-1',

    -- SES integration
    ses_pool_name     TEXT,
    ptr_record        TEXT,  -- Reverse DNS (e.g. mail.customer.com)

    -- Lifecycle status
    status            TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'warming', 'active', 'suspended', 'releasing', 'retired')),

    -- Warmup tracking (synced from SES)
    warmup_progress   DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    warmup_started_at TIMESTAMPTZ,
    warmup_completed_at TIMESTAMPTZ,

    -- Billing integration
    billing_status    TEXT NOT NULL DEFAULT 'pending_charge'
        CHECK (billing_status IN ('included', 'pending_charge', 'active', 'pending_cancel', 'canceled')),
    stripe_subscription_item_id TEXT,
    billing_failure_count INT NOT NULL DEFAULT 0,
    billing_retry_after TIMESTAMPTZ,
    billing_started_at TIMESTAMPTZ,
    billing_ended_at   TIMESTAMPTZ,

    -- Timestamps
    allocated_at      TIMESTAMPTZ DEFAULT NOW(),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dedicated_ips_tenant
    ON dedicated_ips(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_dedicated_ips_billing
    ON dedicated_ips(billing_status) WHERE billing_status IN ('pending_charge', 'pending_cancel');
CREATE INDEX IF NOT EXISTS idx_dedicated_ips_warmup
    ON dedicated_ips(status) WHERE status = 'warming';
CREATE UNIQUE INDEX IF NOT EXISTS idx_dedicated_ips_ip_active
    ON dedicated_ips(ip_address) WHERE status NOT IN ('retired', 'releasing');

-- =============================================================================
-- Subscriptions + Plans (if not already present from billing service)
-- These are referenced by the plan-gating queries in the API server.
-- Using IF NOT EXISTS to avoid conflicts with billing service migrations.
-- =============================================================================

CREATE TABLE IF NOT EXISTS plans (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    display_name TEXT,
    features    JSONB NOT NULL DEFAULT '{}'::jsonb,
    price_cents INT NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS subscriptions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL,
    plan_name   TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'past_due', 'canceled', 'trialing')),
    stripe_subscription_id TEXT,
    current_period_start TIMESTAMPTZ,
    current_period_end   TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_subscriptions_tenant
    ON subscriptions(tenant_id, status);

-- =============================================================================
-- Trigger: auto-update updated_at
-- =============================================================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'trg_dedicated_ips_updated_at'
    ) THEN
        CREATE TRIGGER trg_dedicated_ips_updated_at
            BEFORE UPDATE ON dedicated_ips
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'trg_ses_ip_inventory_updated_at'
    ) THEN
        CREATE TRIGGER trg_ses_ip_inventory_updated_at
            BEFORE UPDATE ON ses_ip_inventory
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
END $$;
