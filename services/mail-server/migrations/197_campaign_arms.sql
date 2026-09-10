-- 197_campaign_arms.sql
--
-- =============================================================================
-- F85: canonical schema for the campaign autopilot's Thompson-sampling arm
-- store. analytics/campaign_autopilot.rs reads/updates campaign_arms
-- (SELECT template_id, alpha, beta, trials, successes, arm_index ... ORDER
-- BY arm_index; UPDATE ... SET alpha = alpha + $1, beta = beta + $2,
-- trials = trials + 1, successes = successes + $3) — but no migration or
-- initializer ever created the table, so every optimization read/write
-- failed with 42P01.
--
-- FK note: sales_campaigns is runtime-initialized by the sales-autopilot
-- service (routes bootstrap, CREATE TABLE IF NOT EXISTS). It is folded
-- here FIRST with the identical shape so the arm table can carry a real
-- foreign key to the campaign model in the canonical chain; the runtime
-- bootstrap's IF NOT EXISTS makes the two orders compatible. template_id
-- is TEXT (no FK to canonical templates.id VARCHAR(26)): the sales-campaign
-- model carries TEXT template identifiers and accepts ids outside the
-- canonical templates domain.
--
-- Validation: alpha/beta must be positive and finite. PostgreSQL treats
-- NaN as greater than every non-NaN value (including 'Infinity'), so
-- `alpha < 'Infinity'` rejects +Inf AND NaN in one comparison; combined
-- with `alpha > 0` this admits exactly the finite positives the Beta
-- sampler requires (sample_beta rejects everything else).
--
-- Counters are bounded non-negative with successes <= trials — one success
-- per trial is the Beta-Bernoulli observation contract.
--
-- campaign_arm_outcomes: idempotent outcome-event ledger. The outcome_key
-- is the caller's stable logical identity (e.g. "<message-id>:<outcome>")
-- — replaying the same outcome collapses to the stored row and the arm
-- counters move at most once (see CampaignAutopilot::record_outcome).
-- =============================================================================

-- Campaign model (byte-compatible with the sales service's runtime
-- bootstrap, including its later guarded ALTERs).
CREATE TABLE IF NOT EXISTS sales_campaigns (
    id          UUID PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    name        TEXT NOT NULL,
    template_id TEXT NOT NULL,
    audience    TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'draft',
    sent        BIGINT NOT NULL DEFAULT 0,
    opened      BIGINT NOT NULL DEFAULT 0,
    clicked     BIGINT NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE sales_campaigns ADD COLUMN IF NOT EXISTS last_error TEXT;
CREATE INDEX IF NOT EXISTS idx_sales_campaigns_tenant_id ON sales_campaigns(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sales_campaigns_status ON sales_campaigns(status);

CREATE TABLE IF NOT EXISTS campaign_arms (
    campaign_id  UUID   NOT NULL REFERENCES sales_campaigns(id) ON DELETE CASCADE,
    arm_index    INTEGER NOT NULL CHECK (arm_index >= 0),
    template_id  TEXT   NOT NULL,
    alpha        DOUBLE PRECISION NOT NULL
        CHECK (alpha > 0 AND alpha < 'Infinity'),
    beta         DOUBLE PRECISION NOT NULL
        CHECK (beta > 0 AND beta < 'Infinity'),
    trials       BIGINT NOT NULL DEFAULT 0
        CHECK (trials >= 0 AND trials <= 1000000000),
    successes    BIGINT NOT NULL DEFAULT 0
        CHECK (successes >= 0 AND successes <= trials),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (campaign_id, arm_index)
);

CREATE INDEX IF NOT EXISTS idx_campaign_arms_campaign
    ON campaign_arms (campaign_id, arm_index);

CREATE TABLE IF NOT EXISTS campaign_arm_outcomes (
    outcome_key TEXT       PRIMARY KEY,
    campaign_id UUID       NOT NULL,
    arm_index   INTEGER    NOT NULL,
    success     BOOLEAN    NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_campaign_arm_outcomes_campaign
    ON campaign_arm_outcomes (campaign_id, arm_index);
