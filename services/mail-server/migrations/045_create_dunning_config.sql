-- Create dunning_config table for dunning process configuration.
-- Previously created at runtime via ensure_dunning_config_table().
-- See: stripe_webhooks.rs ensure_dunning_config_table()

CREATE TABLE IF NOT EXISTS dunning_config (
    tenant_id VARCHAR(36) PRIMARY KEY,
    retry_schedule_days INTEGER[] NOT NULL,
    soft_suspend_after_days INTEGER NOT NULL,
    hard_suspend_after_days INTEGER NOT NULL,
    grace_period_days INTEGER NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
