-- Migration: Provide dunning_records without duplicating dunning_states
-- The DunningService expects dunning_records; map it to dunning_states via a view.

CREATE OR REPLACE VIEW dunning_records AS
SELECT
    id,
    tenant_id,
    dunning_state AS status,
    retry_count AS failed_payment_count,
    NULL::timestamptz AS first_failed_at,
    last_retry_at AS last_failed_at,
    next_retry_at,
    hard_suspended_at AS suspended_at,
    grace_period_ends_at,
    created_at,
    updated_at
FROM dunning_states;

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
