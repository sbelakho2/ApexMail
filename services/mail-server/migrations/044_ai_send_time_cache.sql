-- Cache for API-server send-time optimization responses.

BEGIN;

CREATE TABLE IF NOT EXISTS ai_send_time_cache (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cache_key TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    recipient_email TEXT,
    recommended_hour INTEGER NOT NULL CHECK (recommended_hour BETWEEN 0 AND 23),
    confidence DOUBLE PRECISION NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_send_time_cache_tenant_expires
    ON ai_send_time_cache(tenant_id, expires_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_send_time_cache_expiry
    ON ai_send_time_cache(expires_at);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_proc
        WHERE proname = 'enterprise_billing_update_updated_at_column'
    )
    AND NOT EXISTS (
        SELECT 1
        FROM pg_trigger
        WHERE tgname = 'trg_ai_send_time_cache_updated_at'
    ) THEN
        CREATE TRIGGER trg_ai_send_time_cache_updated_at
            BEFORE UPDATE ON ai_send_time_cache
            FOR EACH ROW EXECUTE FUNCTION enterprise_billing_update_updated_at_column();
    END IF;
END;
$$;

COMMIT;