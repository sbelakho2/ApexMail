-- Migration 238: campaigns full-fidelity content/audience/AB + segments
--
-- Restores the customer-facing campaign capabilities the API documents but
-- the wire never had (preview text, display name, reply-to, raw html/text,
-- global variables, segments, per-campaign tracking toggles, UTM params,
-- send settings, A/B template testing) — implemented, not documented away.
--
-- * campaigns: content/audience/settings columns.
-- * segments: named saved audiences (lists + tag/status match rules) that
--   campaigns can target via segment_id.
-- * campaign_recipients: arm_index/phase for A/B test-phase routing.
-- * campaign_ab_arms / campaign_ab_outcomes: customer-owned A/B state
--   (Beta-Bernoulli shape mirroring the sales engine's proven schema, but
--   FK-bound to the customer `campaigns` table — the sales `campaign_arms`
--   table is keyed to `sales_campaigns` and stays owner/CP-only).

CREATE TABLE IF NOT EXISTS segments (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          VARCHAR(26) NOT NULL,
    name               VARCHAR(255) NOT NULL,
    description        TEXT,
    list_ids           JSONB NOT NULL DEFAULT '[]'::jsonb,
    exclude_list_ids   JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- {"tags_all": ["vip"], "tags_any": ["beta"], "statuses": ["active"]}
    match              JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_segments_tenant ON segments (tenant_id);

ALTER TABLE campaigns
    ADD COLUMN IF NOT EXISTS preview_text  TEXT,
    ADD COLUMN IF NOT EXISTS from_name     TEXT,
    ADD COLUMN IF NOT EXISTS reply_to      TEXT,
    ADD COLUMN IF NOT EXISTS html_body     TEXT,
    ADD COLUMN IF NOT EXISTS text_body     TEXT,
    ADD COLUMN IF NOT EXISTS variables     JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS segment_id    UUID,
    ADD COLUMN IF NOT EXISTS track_opens   BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS track_clicks  BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS utm_params    JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS settings      JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS ab_config     JSONB;

DO $$
BEGIN
    ALTER TABLE campaigns
        ADD CONSTRAINT campaigns_segment_id_fkey
        FOREIGN KEY (segment_id) REFERENCES segments(id) ON DELETE SET NULL;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

ALTER TABLE campaign_recipients
    ADD COLUMN IF NOT EXISTS arm_index INTEGER,
    ADD COLUMN IF NOT EXISTS phase     TEXT;

CREATE INDEX IF NOT EXISTS idx_campaign_recipients_campaign_phase
    ON campaign_recipients (campaign_id, phase)
    WHERE phase IS NOT NULL;

CREATE TABLE IF NOT EXISTS campaign_ab_arms (
    campaign_id UUID NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    arm_index   INTEGER NOT NULL CHECK (arm_index >= 0),
    template_id TEXT NOT NULL,
    subject     TEXT,
    trials      BIGINT NOT NULL DEFAULT 0,
    successes   BIGINT NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (campaign_id, arm_index)
);

CREATE TABLE IF NOT EXISTS campaign_ab_outcomes (
    outcome_key TEXT PRIMARY KEY,
    campaign_id UUID NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    arm_index   INTEGER NOT NULL,
    success     BOOLEAN NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_campaign_ab_outcomes_campaign
    ON campaign_ab_outcomes (campaign_id, arm_index);

COMMENT ON TABLE segments IS
    'Named saved audiences: list membership plus tag/status match rules; '
    'campaigns target them via campaigns.segment_id.';
COMMENT ON TABLE campaign_ab_arms IS
    'Customer-campaign A/B state (one row per template arm). The sales '
    'campaign_arms table is keyed to sales_campaigns and is owner/CP-only.';
