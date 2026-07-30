-- =============================================================================
-- 065: Webhook dual-secret rotation support
-- =============================================================================
-- API-M-03: Preserve previous webhook signing secret during rotation so
-- receivers can verify both signatures within a bounded grace period.

ALTER TABLE webhooks
    ADD COLUMN IF NOT EXISTS previous_secret VARCHAR(255),
    ADD COLUMN IF NOT EXISTS previous_secret_expires_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_webhooks_previous_secret_expires_at
    ON webhooks (previous_secret_expires_at)
    WHERE previous_secret IS NOT NULL;
