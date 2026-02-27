-- Billing Atomicity Fixes Migration
-- Adds tables required for BILL-002, BILL-004 fixes

BEGIN;

SELECT pg_advisory_xact_lock(hashtext('billing_atomicity_fixes_v003'));

-- Add status column to stripe_webhook_events if not exists
-- BILL-001/ATOM-003: Track webhook processing state
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'stripe_webhook_events' AND column_name = 'status'
    ) THEN
        ALTER TABLE stripe_webhook_events 
        ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'processed',
        ADD COLUMN error TEXT,
        ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
        
        -- Update existing records
        UPDATE stripe_webhook_events SET status = 'processed' WHERE status IS NULL;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_stripe_webhook_events_status ON stripe_webhook_events(status);

-- BILL-004: Track orphaned Stripe customers for cleanup
CREATE TABLE IF NOT EXISTS stripe_orphaned_customers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stripe_customer_id VARCHAR(255) UNIQUE NOT NULL,
    tenant_id VARCHAR(26) REFERENCES tenants(id) ON DELETE SET NULL,
    reason VARCHAR(100) NOT NULL,
    cleanup_attempted_at TIMESTAMPTZ,
    cleanup_error TEXT,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_stripe_orphaned_customers_unresolved 
    ON stripe_orphaned_customers(created_at) 
    WHERE resolved_at IS NULL;

COMMENT ON TABLE stripe_orphaned_customers IS 'Tracks Stripe customers created during race conditions that need manual cleanup';

-- BILL-002: Subscription change saga table for tracking multi-step operations
CREATE TABLE IF NOT EXISTS subscription_change_saga (
    id VARCHAR(100) PRIMARY KEY,
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subscription_id UUID NOT NULL,
    from_price_id VARCHAR(255),
    to_price_id VARCHAR(255) NOT NULL,
    from_interval VARCHAR(20),
    to_interval VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    stripe_response JSONB,
    proration_amount INTEGER,
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    
    CONSTRAINT valid_saga_status CHECK (status IN (
        'pending',           -- Intent recorded
        'stripe_completed',  -- Stripe updated successfully
        'completed',         -- Both Stripe and DB updated
        'failed',            -- Operation failed before Stripe update
        'db_failed',         -- Stripe succeeded but DB failed (needs reconciliation)
        'rolled_back'        -- Manual rollback performed
    ))
);

CREATE INDEX IF NOT EXISTS idx_subscription_saga_tenant ON subscription_change_saga(tenant_id);
CREATE INDEX IF NOT EXISTS idx_subscription_saga_status ON subscription_change_saga(status) 
    WHERE status NOT IN ('completed', 'rolled_back');
CREATE INDEX IF NOT EXISTS idx_subscription_saga_needs_attention 
    ON subscription_change_saga(created_at) 
    WHERE status IN ('db_failed', 'failed', 'pending');

COMMENT ON TABLE subscription_change_saga IS 'Saga pattern tracking for subscription changes - ensures atomicity across Stripe and DB';

-- Add helper view for operations team to see issues needing attention
CREATE OR REPLACE VIEW billing_issues_needing_attention AS
SELECT 
    'orphaned_customer' as issue_type,
    oc.id::text as issue_id,
    oc.tenant_id,
    oc.stripe_customer_id as external_id,
    oc.reason as description,
    oc.created_at,
    NULL::text as error_details
FROM stripe_orphaned_customers oc
WHERE oc.resolved_at IS NULL

UNION ALL

SELECT 
    'saga_' || ss.status as issue_type,
    ss.id as issue_id,
    ss.tenant_id,
    ss.subscription_id::text as external_id,
    'Subscription change from ' || COALESCE(ss.from_price_id, 'none') || ' to ' || ss.to_price_id as description,
    ss.created_at,
    ss.error as error_details
FROM subscription_change_saga ss
WHERE ss.status IN ('db_failed', 'failed')
  AND ss.created_at > NOW() - INTERVAL '30 days'

ORDER BY created_at DESC;

COMMENT ON VIEW billing_issues_needing_attention IS 'Operations view for billing issues requiring manual intervention';

COMMIT;
