-- Migration 236: campaign send pipeline — audience, recipient tracking, sender.
--
-- Campaign send pipeline (FX-1 / dogfood DF-3).
--
-- Campaigns could be created and scheduled but NEVER sent: nothing consumed
-- `campaigns.scheduled_at` or `campaign_jobs`, and the documented audience
-- selectors (`listIds` / `excludeListIds`) were never stored. This migration
-- adds what the pipeline needs:
--
--   1. audience columns on `campaigns` (lists-based targeting),
--   2. a sender address column (the send ladder requires an explicit from),
--   3. the `template_id` type fix so a campaign can actually reference a row
--      of `templates` (whose `id` is VARCHAR(26), not UUID — a UUID column
--      could never hold a real template id),
--   4. a fresh `campaign_recipients` recipient-tracking table (the 069 shape
--      was repurposed for the sales/drip contract in 093 and dropped in 200,
--      so the name is free again) with a per-contact status machine and a
--      message back-reference for per-campaign delivery/engagement queries.

-- ── 1+2+3. campaigns: audience, sender, template reference ──────────────
ALTER TABLE campaigns
    ADD COLUMN IF NOT EXISTS list_ids JSONB NOT NULL DEFAULT '[]',
    ADD COLUMN IF NOT EXISTS exclude_list_ids JSONB NOT NULL DEFAULT '[]',
    ADD COLUMN IF NOT EXISTS from_email VARCHAR(320);

-- JSONB shape guards: both audience columns are arrays of list ids.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'campaigns_list_ids_shape_check') THEN
        ALTER TABLE campaigns
            ADD CONSTRAINT campaigns_list_ids_shape_check
            CHECK (jsonb_typeof(list_ids) = 'array');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'campaigns_exclude_list_ids_shape_check') THEN
        ALTER TABLE campaigns
            ADD CONSTRAINT campaigns_exclude_list_ids_shape_check
            CHECK (jsonb_typeof(exclude_list_ids) = 'array');
    END IF;
END $$;

-- templates.id is VARCHAR(26) (migrations 064/075; apexmail-db audit F6):
-- campaigns.template_id as UUID could store values that never match a real
-- template. Recast so the reference is usable; no FK (075 declares none and
-- legacy UUID values may not resolve).
ALTER TABLE campaigns
    ALTER COLUMN template_id TYPE VARCHAR(26) USING template_id::text;

-- Claim planning: the worker polls due scheduled campaigns.
CREATE INDEX IF NOT EXISTS idx_campaigns_scheduled_due
    ON campaigns (scheduled_at)
    WHERE status = 'scheduled';

-- ── 4. campaign_recipients: per-contact send tracking ───────────────────
-- Status machine: 'queued' (audience resolved, not yet enqueued) →
-- 'sending' (claimed under a lease) → 'sent' (message + queue row written)
-- | 'failed' (per-recipient error captured; resend requeues) |
-- 'suppressed' (dropped by the canonical suppression gate — terminal, a
-- resend MUST NOT retry it).
CREATE TABLE IF NOT EXISTS campaign_recipients (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   VARCHAR(26) NOT NULL,
    campaign_id UUID NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    contact_id  UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    email       VARCHAR(320) NOT NULL,
    status      VARCHAR(20) NOT NULL DEFAULT 'queued',
    message_id  UUID,
    error       TEXT,
    attempts    INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (campaign_id, contact_id)
);

CREATE INDEX IF NOT EXISTS idx_campaign_recipients_tenant
    ON campaign_recipients (tenant_id);
CREATE INDEX IF NOT EXISTS idx_campaign_recipients_campaign_status
    ON campaign_recipients (campaign_id, status);
-- Back-reference lookups: per-campaign delivery/engagement from
-- messages/events joined through message_id.
CREATE INDEX IF NOT EXISTS idx_campaign_recipients_message
    ON campaign_recipients (message_id)
    WHERE message_id IS NOT NULL;

COMMENT ON TABLE campaign_recipients IS
    'Per-contact campaign send tracking (FX-1): audience snapshot plus send state machine (queued/sending/sent/failed/suppressed) and the messages.id back-reference that powers per-campaign stats.';
