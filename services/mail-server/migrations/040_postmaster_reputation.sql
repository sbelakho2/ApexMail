-- 040: Sender reputation tracking (Google Postmaster Tools v1 + Microsoft SNDS).
--
-- ApexMail polls Postmaster Tools and SNDS daily for every sending domain /
-- IP we operate.  The raw metrics land here so:
--   * Customer dashboards can surface domain reputation per ISP without us
--     having to re-call the upstream APIs.
--   * Outbound-queue throttling can degrade send rate when reputation drops.
--   * SOC 2 evidence collection has an auditable history of deliverability.
--
-- Schema is normalised on (provider, identity, observed_at) so a single row
-- represents one daily snapshot for one (provider, sending domain or IP).
--
-- See:
--   * https://developers.google.com/gmail/postmaster
--   * https://sendersupport.olc.protection.outlook.com/snds/

CREATE TABLE IF NOT EXISTS postmaster_credentials (
    id              TEXT        PRIMARY KEY,
    provider        TEXT        NOT NULL,           -- 'google' | 'microsoft'
    label           TEXT        NOT NULL,           -- human label
    -- For google: OAuth refresh token (encrypted at rest by application).
    -- For microsoft: SNDS access key.
    secret_ref      TEXT        NOT NULL,           -- pointer into compliance.secrets
    enabled         BOOLEAN     NOT NULL DEFAULT TRUE,
    last_polled_at  TIMESTAMPTZ,
    last_error      TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider, label)
);

-- Google Postmaster Tools reputation (one row per domain per day).
CREATE TABLE IF NOT EXISTS postmaster_google_reputation (
    id                      BIGSERIAL   PRIMARY KEY,
    domain                  TEXT        NOT NULL,
    observed_at             DATE        NOT NULL,         -- traffic-stats date (UTC)
    -- Reputation buckets per the Postmaster Tools API.
    domain_reputation       TEXT,                         -- HIGH | MEDIUM | LOW | BAD | UNKNOWN
    ip_reputation           JSONB       NOT NULL DEFAULT '[]'::jsonb,
        -- [{ipAddress, reputation:HIGH|...}, ...]
    -- Spam ratios are floats in 0..=1, NULL when Google withholds data.
    user_reported_spam_ratio DOUBLE PRECISION,
    spammy_feedback_loops   JSONB,
    -- Authentication success rates (0..=1).
    spf_success_ratio       DOUBLE PRECISION,
    dkim_success_ratio      DOUBLE PRECISION,
    dmarc_success_ratio     DOUBLE PRECISION,
    -- Encryption (TLS) inbound success.
    inbound_encryption_ratio DOUBLE PRECISION,
    outbound_encryption_ratio DOUBLE PRECISION,
    -- Delivery error breakdown — JSONB list of {reason, ratio}.
    delivery_errors         JSONB       NOT NULL DEFAULT '[]'::jsonb,
    raw                     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    fetched_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (domain, observed_at)
);
CREATE INDEX IF NOT EXISTS idx_pm_google_domain_date
    ON postmaster_google_reputation (domain, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_pm_google_recent
    ON postmaster_google_reputation (fetched_at DESC);

-- Microsoft SNDS data (one row per IP per day).
CREATE TABLE IF NOT EXISTS postmaster_snds_reputation (
    id              BIGSERIAL   PRIMARY KEY,
    ip              INET        NOT NULL,
    observed_at     DATE        NOT NULL,
    activity_start  TIMESTAMPTZ,
    activity_end    TIMESTAMPTZ,
    rcpt_commands   BIGINT      NOT NULL DEFAULT 0,
    data_commands   BIGINT      NOT NULL DEFAULT 0,
    message_recipients BIGINT   NOT NULL DEFAULT 0,
    filter_result   TEXT,                                   -- GREEN | YELLOW | RED
    complaint_rate  DOUBLE PRECISION,                       -- 0..=1
    trap_hits       BIGINT      NOT NULL DEFAULT 0,
    sample_helo     TEXT,
    sample_from     TEXT,
    raw             JSONB       NOT NULL DEFAULT '{}'::jsonb,
    fetched_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (ip, observed_at)
);
CREATE INDEX IF NOT EXISTS idx_pm_snds_ip_date
    ON postmaster_snds_reputation (ip, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_pm_snds_red
    ON postmaster_snds_reputation (filter_result, observed_at DESC)
    WHERE filter_result = 'RED';

-- Aggregated reputation roll-up consumed by the outbound-queue throttler and
-- customer dashboards.  Recomputed by `postmaster::aggregator::recompute()`
-- after each ingest run.
CREATE TABLE IF NOT EXISTS postmaster_reputation_summary (
    id              BIGSERIAL   PRIMARY KEY,
    scope           TEXT        NOT NULL,        -- 'domain' | 'ip'
    identity        TEXT        NOT NULL,        -- domain string or IP
    provider        TEXT        NOT NULL,        -- 'google' | 'microsoft'
    -- Normalised score 0..=100; <40 = red, 40-69 = amber, 70-100 = green.
    reputation_score INTEGER    NOT NULL,
    band            TEXT        NOT NULL,        -- 'green' | 'amber' | 'red'
    -- Top three contributing factors for human reading.
    factors         JSONB       NOT NULL DEFAULT '[]'::jsonb,
    suggested_throttle_pct INTEGER NOT NULL DEFAULT 0,
        -- 0 = no throttle, 100 = full pause; queue treats >0 as RPM cut.
    window_days     INTEGER     NOT NULL DEFAULT 7,
    computed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (scope, identity, provider)
);
CREATE INDEX IF NOT EXISTS idx_pm_summary_band
    ON postmaster_reputation_summary (band, computed_at DESC);

-- Per-tenant alerting on reputation events; consumed by the alert-router.
CREATE TABLE IF NOT EXISTS postmaster_reputation_events (
    id              BIGSERIAL   PRIMARY KEY,
    tenant_id       TEXT,                                   -- nullable for unowned IPs
    scope           TEXT        NOT NULL,                   -- 'domain' | 'ip'
    identity        TEXT        NOT NULL,
    provider        TEXT        NOT NULL,
    severity        TEXT        NOT NULL,                   -- 'info'|'warn'|'critical'
    event_type      TEXT        NOT NULL,                   -- 'band_drop' | 'spam_spike' | 'auth_drop' | 'red_listed'
    from_band       TEXT,
    to_band         TEXT,
    payload         JSONB       NOT NULL DEFAULT '{}'::jsonb,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    notified_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_pm_events_tenant_ts
    ON postmaster_reputation_events (tenant_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_pm_events_unsent
    ON postmaster_reputation_events (occurred_at DESC) WHERE notified_at IS NULL;
