-- Migration 030: Bounce analytics
-- Bounce analytics aggregation tables. Schema previously created at runtime
-- via `Aggregator::initialize_schema`; centralized here so deploys go through
-- migration history. Idempotent.

-- Aggregated bounce metrics per tenant per day
CREATE TABLE IF NOT EXISTS bounce_analytics_daily (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   VARCHAR(64) NOT NULL,
    date        DATE NOT NULL,
    total_bounces       BIGINT NOT NULL DEFAULT 0,
    hard_bounces        BIGINT NOT NULL DEFAULT 0,
    soft_bounces        BIGINT NOT NULL DEFAULT 0,
    transient_bounces   BIGINT NOT NULL DEFAULT 0,
    top_subtypes        JSONB,
    top_domains         JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, date)
);

-- Domain reputation tracking
CREATE TABLE IF NOT EXISTS bounce_domain_reputation (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain          VARCHAR(255) NOT NULL,
    tenant_id       VARCHAR(64) NOT NULL,
    total_sent      BIGINT NOT NULL DEFAULT 0,
    total_bounces   BIGINT NOT NULL DEFAULT 0,
    hard_bounces    BIGINT NOT NULL DEFAULT 0,
    soft_bounces    BIGINT NOT NULL DEFAULT 0,
    risk_level      VARCHAR(16) NOT NULL DEFAULT 'normal',
    predominant_reason VARCHAR(128),
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_bounce     TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (domain, tenant_id)
);

-- Detected bounce bursts
CREATE TABLE IF NOT EXISTS bounce_bursts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain          VARCHAR(255) NOT NULL,
    tenant_id       VARCHAR(64),
    burst_start     TIMESTAMPTZ NOT NULL,
    burst_end       TIMESTAMPTZ NOT NULL,
    bounce_count    INT NOT NULL,
    expected_baseline   DOUBLE PRECISION,
    burst_factor    DOUBLE PRECISION,
    predominant_subtype VARCHAR(64),
    acknowledged    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_bounce_analytics_daily_tenant_date
    ON bounce_analytics_daily (tenant_id, date DESC);
CREATE INDEX IF NOT EXISTS idx_bounce_domain_reputation_tenant
    ON bounce_domain_reputation (tenant_id, risk_level);
CREATE INDEX IF NOT EXISTS idx_bounce_bursts_domain
    ON bounce_bursts (domain, burst_start DESC);
CREATE INDEX IF NOT EXISTS idx_bounce_bursts_unacknowledged
    ON bounce_bursts (acknowledged, created_at DESC)
    WHERE acknowledged = FALSE;
