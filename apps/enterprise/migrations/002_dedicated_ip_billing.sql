-- Migration: Add billing tracking columns to dedicated_ips
-- Required for automated Stripe subscription item management

-- Billing status for dedicated IP add-ons
CREATE TYPE dedicated_ip_billing_status AS ENUM (
  'included',         -- Covered by plan (no add-on charge)
  'pending_charge',   -- Needs Stripe subscription item creation
  'active',           -- Stripe subscription item active, being billed
  'pending_cancel',   -- Needs Stripe subscription item removal
  'canceled',         -- Billing stopped (IP is retired)
  'exempt'            -- Enterprise custom deal, billed separately
);

ALTER TABLE dedicated_ips
  ADD COLUMN IF NOT EXISTS billing_status dedicated_ip_billing_status NOT NULL DEFAULT 'pending_charge',
  ADD COLUMN IF NOT EXISTS stripe_subscription_item_id TEXT,
  ADD COLUMN IF NOT EXISTS billing_started_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS billing_ended_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS billing_failure_count INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS billing_retry_after TIMESTAMPTZ;

-- Index for the billing sync job to find IPs needing action
CREATE INDEX IF NOT EXISTS idx_dedicated_ips_billing_pending
  ON dedicated_ips (billing_status)
  WHERE billing_status IN ('pending_charge', 'pending_cancel');

-- Index for cost-circuit queries (replaces reference to non-existent allocated_at column)
CREATE INDEX IF NOT EXISTS idx_dedicated_ips_tenant_active
  ON dedicated_ips (tenant_id)
  WHERE status NOT IN ('retired');

COMMENT ON COLUMN dedicated_ips.billing_status IS 'Tracks Stripe subscription item lifecycle for add-on IPs';
COMMENT ON COLUMN dedicated_ips.stripe_subscription_item_id IS 'Stripe subscription item ID for this add-on IP (null for included IPs)';
