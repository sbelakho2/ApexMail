-- Sales Autopilot — Funnel, Bandits, Safety & Cadence Tables
-- Migration 003 — depends on 001_drip_campaigns.sql

BEGIN;

-- ────────────────────────────────────────────────────────────────────
-- Funnel events — one row per contact × funnel stage transition
-- ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS funnel_events (
    id           BIGSERIAL PRIMARY KEY,
    campaign_id  VARCHAR(64) NOT NULL REFERENCES drip_campaigns(id) ON DELETE CASCADE,
    enrollment_id VARCHAR(64) NOT NULL REFERENCES campaign_enrollments(id) ON DELETE CASCADE,
    contact_id   VARCHAR(64) NOT NULL,
    stage        VARCHAR(32) NOT NULL, -- delivered, opened, clicked, replied, booked, activated, retained
    step_id      VARCHAR(64),
    metadata     JSONB NOT NULL DEFAULT '{}',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_funnel_campaign     ON funnel_events(campaign_id);
CREATE INDEX idx_funnel_contact      ON funnel_events(contact_id);
CREATE INDEX idx_funnel_stage        ON funnel_events(stage);
CREATE INDEX idx_funnel_created      ON funnel_events(created_at);
CREATE INDEX idx_funnel_enrollment   ON funnel_events(enrollment_id);

-- Prevent duplicate stage transitions for the same contact in the same enrollment
CREATE UNIQUE INDEX idx_funnel_dedup ON funnel_events(enrollment_id, contact_id, stage);

-- ────────────────────────────────────────────────────────────────────
-- Control group assignments — stable per contact per campaign
-- ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS control_group_assignments (
    campaign_id  VARCHAR(64) NOT NULL REFERENCES drip_campaigns(id) ON DELETE CASCADE,
    contact_id   VARCHAR(64) NOT NULL,
    is_control   BOOLEAN NOT NULL DEFAULT FALSE,
    assigned_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (campaign_id, contact_id)
);

-- ────────────────────────────────────────────────────────────────────
-- Bandit pools — one pool per (campaign stage × ICP segment)
-- ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS bandit_pools (
    id          VARCHAR(64) PRIMARY KEY,
    pool_key    VARCHAR(255) NOT NULL UNIQUE, -- e.g. "cold_outreach:saas:step_1"
    stage       VARCHAR(64) NOT NULL,
    icp_segment VARCHAR(128) NOT NULL,
    frozen      BOOLEAN NOT NULL DEFAULT FALSE,
    frozen_at   TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_bandit_pools_stage ON bandit_pools(stage);

-- ────────────────────────────────────────────────────────────────────
-- Bandit arms — one arm per subject/template variant per pool
-- ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS bandit_arms (
    id         VARCHAR(64) PRIMARY KEY,
    pool_id    VARCHAR(64) NOT NULL REFERENCES bandit_pools(id) ON DELETE CASCADE,
    arm_key    VARCHAR(255) NOT NULL,
    alpha      DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    beta       DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    trials     INTEGER NOT NULL DEFAULT 0,
    successes  INTEGER NOT NULL DEFAULT 0,
    failures   INTEGER NOT NULL DEFAULT 0,
    frozen     BOOLEAN NOT NULL DEFAULT FALSE,
    frozen_at  TIMESTAMPTZ,
    metadata   JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_bandit_arms_pool ON bandit_arms(pool_id);
CREATE UNIQUE INDEX idx_bandit_arms_unique ON bandit_arms(pool_id, arm_key);

-- ────────────────────────────────────────────────────────────────────
-- Decision traces — audit trail for every bandit + safety decision
-- ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS decision_traces (
    id           BIGSERIAL PRIMARY KEY,
    trace_type   VARCHAR(32) NOT NULL, -- bandit_select, safety_block, rollback, cadence_skip, copy_lint
    campaign_id  VARCHAR(64) REFERENCES drip_campaigns(id) ON DELETE SET NULL,
    contact_id   VARCHAR(64),
    pool_id      VARCHAR(64),
    arm_id       VARCHAR(64),
    decision     VARCHAR(64) NOT NULL,
    reason       TEXT,
    context      JSONB NOT NULL DEFAULT '{}',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_decision_traces_type    ON decision_traces(trace_type);
CREATE INDEX idx_decision_traces_created ON decision_traces(created_at);
CREATE INDEX idx_decision_traces_campaign ON decision_traces(campaign_id);

-- Partition-friendly: only keep 90 days of decision traces
-- (application layer handles cleanup via CRON)

-- ────────────────────────────────────────────────────────────────────
-- Safety health reports — daily roll-up
-- ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS health_reports (
    id              BIGSERIAL PRIMARY KEY,
    report_date     DATE NOT NULL,
    campaign_id     VARCHAR(64) REFERENCES drip_campaigns(id) ON DELETE CASCADE,
    activation_rate DOUBLE PRECISION,
    reply_rate      DOUBLE PRECISION,
    negative_rate   DOUBLE PRECISION,
    bounce_rate     DOUBLE PRECISION,
    unsub_rate      DOUBLE PRECISION,
    arm_entropy     DOUBLE PRECISION,
    kpi_flags       JSONB NOT NULL DEFAULT '{}',
    rollback_triggered BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_health_reports_date_campaign ON health_reports(report_date, campaign_id);

-- ────────────────────────────────────────────────────────────────────
-- Contact cadence tracking — per-contact send history for governor
-- ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS contact_cadence (
    id           BIGSERIAL PRIMARY KEY,
    contact_id   VARCHAR(64) NOT NULL,
    campaign_id  VARCHAR(64) NOT NULL REFERENCES drip_campaigns(id) ON DELETE CASCADE,
    step_id      VARCHAR(64),
    channel      VARCHAR(32) NOT NULL DEFAULT 'email',
    sent_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    local_hour   INTEGER,
    timezone     VARCHAR(64)
);

CREATE INDEX idx_cadence_contact  ON contact_cadence(contact_id);
CREATE INDEX idx_cadence_sent     ON contact_cadence(sent_at);
CREATE INDEX idx_cadence_contact_window ON contact_cadence(contact_id, sent_at);

-- ────────────────────────────────────────────────────────────────────
-- Contact stop signals — cadence governor stop events
-- ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS contact_stop_signals (
    contact_id  VARCHAR(64) NOT NULL,
    campaign_id VARCHAR(64) NOT NULL REFERENCES drip_campaigns(id) ON DELETE CASCADE,
    reason      VARCHAR(64) NOT NULL, -- reply, bounce, complaint, unsubscribe, manual
    stopped_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (contact_id, campaign_id, reason)
);

-- ────────────────────────────────────────────────────────────────────
-- Lead validation results — cached validation for list hygiene
-- ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lead_validation_results (
    lead_id       VARCHAR(64) PRIMARY KEY,
    is_valid      BOOLEAN NOT NULL,
    issues        JSONB NOT NULL DEFAULT '[]',
    validated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ────────────────────────────────────────────────────────────────────
-- Apply updated_at triggers
-- ────────────────────────────────────────────────────────────────────
CREATE TRIGGER update_bandit_pools_timestamp
    BEFORE UPDATE ON bandit_pools
    FOR EACH ROW EXECUTE FUNCTION sales_update_timestamp();

CREATE TRIGGER update_bandit_arms_timestamp
    BEFORE UPDATE ON bandit_arms
    FOR EACH ROW EXECUTE FUNCTION sales_update_timestamp();

COMMIT;
