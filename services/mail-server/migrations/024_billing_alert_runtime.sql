-- Billing alert runtime tables required by the Rust API and maintenance jobs.

BEGIN;

CREATE TABLE IF NOT EXISTS notification_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_notification_queue_tenant ON notification_queue(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notification_queue_status ON notification_queue(status, created_at DESC);

CREATE TABLE IF NOT EXISTS usage_alert_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    metric_type VARCHAR(50) NOT NULL,
    threshold_percent INTEGER NOT NULL CHECK (threshold_percent BETWEEN 1 AND 100),
    notification_channel VARCHAR(20) NOT NULL DEFAULT 'email',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_triggered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, metric_type, threshold_percent)
);

CREATE INDEX IF NOT EXISTS idx_usage_alert_configs_tenant ON usage_alert_configs(tenant_id, enabled);

DROP TRIGGER IF EXISTS update_usage_alert_configs_updated_at ON usage_alert_configs;
CREATE TRIGGER update_usage_alert_configs_updated_at
    BEFORE UPDATE ON usage_alert_configs
    FOR EACH ROW
    EXECUTE FUNCTION enterprise_billing_update_updated_at_column();

COMMIT;