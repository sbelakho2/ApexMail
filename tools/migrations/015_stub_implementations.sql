-- =============================================================================
-- ApexMail Stub Implementations
-- Migration: 015_stub_implementations.sql
-- Date: 2026-02-23
-- Purpose: Create tables required for proper implementation of previously
--          stubbed functionality including SCIM groups, enriched companies,
--          IP pool allocation, export jobs, alert webhooks, and trust metrics.
-- =============================================================================

-- =============================================================================
-- SCIM GROUPS (for enterprise SSO group provisioning)
-- =============================================================================
CREATE TABLE IF NOT EXISTS scim_groups (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(26)  NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    display_name    VARCHAR(255) NOT NULL,
    external_id     VARCHAR(255),
    scim_id         VARCHAR(255) NOT NULL,  -- The SCIM-visible ID
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, display_name)
);

CREATE INDEX IF NOT EXISTS idx_scim_groups_tenant ON scim_groups(tenant_id);
CREATE INDEX IF NOT EXISTS idx_scim_groups_scim_id ON scim_groups(scim_id);

-- Group membership (many-to-many between scim_groups and users)
CREATE TABLE IF NOT EXISTS scim_group_members (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id        UUID         NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
    user_id         VARCHAR(26)  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id       VARCHAR(26)  NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    display         VARCHAR(255),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (group_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_scim_group_members_group ON scim_group_members(group_id);
CREATE INDEX IF NOT EXISTS idx_scim_group_members_user ON scim_group_members(user_id);

-- =============================================================================
-- ENRICHED COMPANIES (for sales autopilot company enrichment)
-- =============================================================================
CREATE TABLE IF NOT EXISTS enriched_companies (
    id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           VARCHAR(26)  NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain              VARCHAR(255) NOT NULL,
    company_name        VARCHAR(500),
    industry            VARCHAR(255),
    employee_count      VARCHAR(50),
    annual_revenue      VARCHAR(100),
    funding_stage       VARCHAR(100),
    funding_total       VARCHAR(100),
    headquarters        VARCHAR(255),
    founded_year        INTEGER,
    description         TEXT,
    linkedin_url        VARCHAR(500),
    twitter_handle      VARCHAR(100),
    technologies        JSONB        NOT NULL DEFAULT '[]',
    email_provider      VARCHAR(100),
    mx_records          JSONB        NOT NULL DEFAULT '[]',
    alexa_rank          INTEGER,
    confidence_score    DECIMAL(3,2) NOT NULL DEFAULT 0.0,
    last_enriched_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, domain)
);

CREATE INDEX IF NOT EXISTS idx_enriched_companies_tenant ON enriched_companies(tenant_id);
CREATE INDEX IF NOT EXISTS idx_enriched_companies_domain ON enriched_companies(domain);
CREATE INDEX IF NOT EXISTS idx_enriched_companies_industry ON enriched_companies(industry);

-- =============================================================================
-- IP POOL (for real dedicated IP allocation)
-- =============================================================================
CREATE TABLE IF NOT EXISTS ip_pool_available (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address      INET         NOT NULL UNIQUE,
    region          VARCHAR(50)  NOT NULL DEFAULT 'us-east-1',
    datacenter      VARCHAR(100),
    provider        VARCHAR(50)  NOT NULL DEFAULT 'hetzner',  -- hetzner, aws, gcp
    status          VARCHAR(20)  NOT NULL DEFAULT 'available', -- available, allocated, reserved, blacklisted
    is_warmed       BOOLEAN      NOT NULL DEFAULT false,
    reputation_score DECIMAL(3,2) NOT NULL DEFAULT 1.0,
    ptr_record      VARCHAR(255),
    allocated_to    UUID,        -- tenant_id when allocated
    allocated_at    TIMESTAMPTZ,
    last_used_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ip_pool_available_status ON ip_pool_available(status);
CREATE INDEX IF NOT EXISTS idx_ip_pool_available_region ON ip_pool_available(region);
CREATE INDEX IF NOT EXISTS idx_ip_pool_available_allocated ON ip_pool_available(allocated_to);

-- =============================================================================
-- EXPORT JOBS (for async analytics exports)
-- =============================================================================
CREATE TABLE IF NOT EXISTS export_jobs (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID         NOT NULL,
    job_type        VARCHAR(50)  NOT NULL,  -- analytics, contacts, campaigns, audit_logs
    status          VARCHAR(20)  NOT NULL DEFAULT 'pending', -- pending, processing, completed, failed
    format          VARCHAR(20)  NOT NULL DEFAULT 'csv',     -- csv, json, xlsx
    filters         JSONB        NOT NULL DEFAULT '{}',
    date_range_start TIMESTAMPTZ,
    date_range_end   TIMESTAMPTZ,
    total_rows      BIGINT,
    processed_rows  BIGINT       NOT NULL DEFAULT 0,
    file_size_bytes BIGINT,
    download_url    TEXT,
    download_expires_at TIMESTAMPTZ,
    error_message   TEXT,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_by      UUID
);

CREATE INDEX IF NOT EXISTS idx_export_jobs_tenant ON export_jobs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_export_jobs_status ON export_jobs(status);

-- =============================================================================
-- ALERT WEBHOOKS (for complaint rate alerts and other notifications)
-- =============================================================================
CREATE TABLE IF NOT EXISTS alert_webhooks (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(26)  NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    url             TEXT         NOT NULL,
    secret          VARCHAR(255),
    enabled         BOOLEAN      NOT NULL DEFAULT true,
    alert_types     JSONB        NOT NULL DEFAULT '["complaint_rate", "bounce_rate", "blacklist"]',
    headers         JSONB        NOT NULL DEFAULT '{}',
    retry_count     INTEGER      NOT NULL DEFAULT 3,
    timeout_ms      INTEGER      NOT NULL DEFAULT 5000,
    last_triggered_at TIMESTAMPTZ,
    last_success_at   TIMESTAMPTZ,
    last_failure_at   TIMESTAMPTZ,
    failure_count     INTEGER    NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alert_webhooks_tenant ON alert_webhooks(tenant_id);
CREATE INDEX IF NOT EXISTS idx_alert_webhooks_enabled ON alert_webhooks(enabled) WHERE enabled = true;

-- Alert webhook delivery log
CREATE TABLE IF NOT EXISTS alert_webhook_deliveries (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id      UUID         NOT NULL REFERENCES alert_webhooks(id) ON DELETE CASCADE,
    alert_type      VARCHAR(50)  NOT NULL,
    payload         JSONB        NOT NULL,
    response_status INTEGER,
    response_body   TEXT,
    latency_ms      INTEGER,
    success         BOOLEAN      NOT NULL DEFAULT false,
    attempt_number  INTEGER      NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alert_webhook_deliveries_webhook ON alert_webhook_deliveries(webhook_id, created_at DESC);

-- =============================================================================
-- TRUST METRICS (aggregated sender reputation data for trust scoring)
-- =============================================================================
CREATE TABLE IF NOT EXISTS trust_metrics (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID         NOT NULL UNIQUE,
    bounce_rate     DECIMAL(5,4) NOT NULL DEFAULT 0.0,
    complaint_rate  DECIMAL(5,4) NOT NULL DEFAULT 0.0,
    engagement_rate DECIMAL(5,4) NOT NULL DEFAULT 0.0,
    open_rate       DECIMAL(5,4) NOT NULL DEFAULT 0.0,
    click_rate      DECIMAL(5,4) NOT NULL DEFAULT 0.0,
    unsubscribe_rate DECIMAL(5,4) NOT NULL DEFAULT 0.0,
    spam_trap_hits  INTEGER      NOT NULL DEFAULT 0,
    blacklist_count INTEGER      NOT NULL DEFAULT 0,
    volume_30d      BIGINT       NOT NULL DEFAULT 0,
    age_days        INTEGER      NOT NULL DEFAULT 0,
    trust_score     DECIMAL(5,2) NOT NULL DEFAULT 50.0,
    tier            VARCHAR(20)  NOT NULL DEFAULT 'new', -- new, warming, standard, premium, trusted
    computed_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_trust_metrics_tenant ON trust_metrics(tenant_id);
CREATE INDEX IF NOT EXISTS idx_trust_metrics_tier ON trust_metrics(tier);

-- =============================================================================
-- AI INSIGHTS CACHE (for caching send-time optimization and subject analysis)
-- =============================================================================
CREATE TABLE IF NOT EXISTS ai_send_time_cache (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID         NOT NULL,
    audience_hash   VARCHAR(64)  NOT NULL,  -- Hash of audience criteria
    timezone        VARCHAR(50)  NOT NULL DEFAULT 'UTC',
    recommended_hour INTEGER     NOT NULL,
    confidence      DECIMAL(3,2) NOT NULL,
    reasoning       TEXT,
    sample_size     INTEGER      NOT NULL DEFAULT 0,
    computed_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW() + INTERVAL '7 days',
    UNIQUE (tenant_id, audience_hash, timezone)
);

CREATE INDEX IF NOT EXISTS idx_ai_send_time_cache_tenant ON ai_send_time_cache(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ai_send_time_cache_expires ON ai_send_time_cache(expires_at);

-- Subject line analysis history
CREATE TABLE IF NOT EXISTS ai_subject_analysis_log (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID         NOT NULL,
    subject         TEXT         NOT NULL,
    score           DECIMAL(3,2) NOT NULL,
    suggestions     JSONB        NOT NULL DEFAULT '[]',
    signals         JSONB        NOT NULL DEFAULT '[]',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_subject_analysis_tenant ON ai_subject_analysis_log(tenant_id, created_at DESC);

-- =============================================================================
-- SSO OIDC STATE (for secure OIDC login flow state management)
-- =============================================================================
CREATE TABLE IF NOT EXISTS sso_oidc_state (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    state           VARCHAR(255) NOT NULL UNIQUE,
    code_verifier   VARCHAR(255) NOT NULL,
    tenant_id       UUID         NOT NULL,
    redirect_uri    TEXT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW() + INTERVAL '10 minutes'
);

CREATE INDEX IF NOT EXISTS idx_sso_oidc_state_state ON sso_oidc_state(state);
CREATE INDEX IF NOT EXISTS idx_sso_oidc_state_expires ON sso_oidc_state(expires_at);

-- Cleanup old states automatically (via cron or application)
-- DELETE FROM sso_oidc_state WHERE expires_at < NOW();
