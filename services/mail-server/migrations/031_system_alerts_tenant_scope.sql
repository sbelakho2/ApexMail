-- Add tenant scoping metadata for system alerts.
-- Existing account-level alerts remain visible only to system administrators
-- because tenant-scoped queries filter on tenant_id.

ALTER TABLE system_alerts
    ADD COLUMN IF NOT EXISTS tenant_id TEXT,
    ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS idx_system_alerts_tenant_time
    ON system_alerts(tenant_id, created_at DESC)
    WHERE tenant_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_system_alerts_tenant_unack
    ON system_alerts(tenant_id, acknowledged, created_at DESC)
    WHERE tenant_id IS NOT NULL AND acknowledged = false;