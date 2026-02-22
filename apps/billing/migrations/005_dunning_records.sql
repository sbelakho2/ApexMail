-- Migration: Add dunning_records table
-- The DunningService code expects this table with specific columns.
-- Note: This is separate from dunning_states which has a different schema.

CREATE TABLE IF NOT EXISTS dunning_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    status VARCHAR(30) NOT NULL DEFAULT 'healthy',
    failed_payment_count INTEGER NOT NULL DEFAULT 0,
    first_failed_at TIMESTAMPTZ,
    last_failed_at TIMESTAMPTZ,
    next_retry_at TIMESTAMPTZ,
    suspended_at TIMESTAMPTZ,
    grace_period_ends_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_dunning_records_status ON dunning_records(status);
CREATE INDEX IF NOT EXISTS idx_dunning_records_next_retry ON dunning_records(next_retry_at);
CREATE INDEX IF NOT EXISTS idx_dunning_records_tenant ON dunning_records(tenant_id);

-- Dunning events table for audit trail
CREATE TABLE IF NOT EXISTS dunning_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    invoice_id TEXT,
    amount INTEGER,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dunning_events_tenant ON dunning_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_dunning_events_type ON dunning_events(event_type);

COMMENT ON TABLE dunning_records IS 'Tracks payment failure states per tenant for the DunningService';
COMMENT ON TABLE dunning_events IS 'Audit trail of dunning-related events';
