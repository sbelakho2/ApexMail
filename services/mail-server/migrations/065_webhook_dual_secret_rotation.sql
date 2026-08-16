-- =============================================================================
-- 065: Webhook dual-secret rotation support
-- =============================================================================
-- API-M-03: Preserve previous webhook signing secret during rotation so
-- receivers can verify both signatures within a bounded grace period.

DO $$
BEGIN
    -- webhooks is created by migration 075; guard for fresh-DB ordering.
    IF to_regclass('public.webhooks') IS NOT NULL THEN
        ALTER TABLE webhooks
            ADD COLUMN IF NOT EXISTS previous_secret VARCHAR(255),
            ADD COLUMN IF NOT EXISTS previous_secret_expires_at TIMESTAMPTZ;
    END IF;
END
$$;

DO $$
BEGIN
    IF to_regclass('public.webhooks') IS NOT NULL THEN
        CREATE INDEX IF NOT EXISTS idx_webhooks_previous_secret_expires_at
            ON webhooks (previous_secret_expires_at);
    END IF;
END
$$;
