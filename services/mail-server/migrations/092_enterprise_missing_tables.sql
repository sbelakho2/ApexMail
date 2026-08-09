-- Enterprise service: missing backing tables.
-- The Rust enterprise-server crate (crates/enterprise) routes for compliance,
-- log streaming, whitelabel, sub-accounts, QBR and template approval query
-- these tables; they were never created by a migration, so every route that
-- touched them returned 500 ("relation does not exist").
--
-- Column types mirror the sqlx::FromRow structs in the enterprise crate:
--   * tenant_id VARCHAR(26)   — matches tenants.id (migration 064); the crate
--                               binds tenant ids as plain strings
--   * enabled_frameworks TEXT[]— Vec<String>
--   * *_value FLOAT8          — f64
--   * *_date DATE             — chrono::NaiveDate
--   * *_at TIMESTAMPTZ        — chrono::DateTime<Utc>
--   * *_config / *_details    — serde_json::Value
--   * ip_address TEXT         — audit INSERT casts the bound value with $9::inet
--                               (inet->text is an assignment cast) and the row
--                               struct decodes it back into Option<String>.

BEGIN;

-- ── Compliance (HIPAA/SOC2/GDPR/CCPA/ISO27001) ──────────────────────────

CREATE TABLE IF NOT EXISTS ent_compliance_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL UNIQUE,
    enabled_frameworks TEXT[] NOT NULL DEFAULT '{}',
    status VARCHAR(30) NOT NULL DEFAULT 'inactive',
    zero_retention_mode BOOLEAN NOT NULL DEFAULT FALSE,
    encryption_at_rest BOOLEAN NOT NULL DEFAULT FALSE,
    encryption_in_transit BOOLEAN NOT NULL DEFAULT FALSE,
    audit_log_retention_days INTEGER NOT NULL DEFAULT 2555 CHECK (audit_log_retention_days >= 0),
    data_retention_days INTEGER,
    require_mfa BOOLEAN NOT NULL DEFAULT FALSE,
    baa_signed BOOLEAN NOT NULL DEFAULT FALSE,
    baa_signed_at TIMESTAMPTZ,
    baa_signatory_name TEXT,
    baa_signatory_title TEXT,
    baa_signatory_email TEXT,
    dpa_signed BOOLEAN NOT NULL DEFAULT FALSE,
    dpa_signed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ent_compliance_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL,
    user_id TEXT,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id TEXT,
    old_value JSONB,
    new_value JSONB,
    ip_address TEXT,
    user_agent TEXT,
    session_id TEXT,
    request_id TEXT,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- L-01: composite index for the filtered tenant queries in get_audit_logs()
CREATE INDEX IF NOT EXISTS idx_ent_audit_logs_tenant_action
    ON ent_compliance_audit_logs (tenant_id, action, resource_type, created_at DESC);

CREATE TABLE IF NOT EXISTS ent_data_access_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL,
    type VARCHAR(30) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'pending',
    requester_id TEXT NOT NULL,
    requester_email VARCHAR(320) NOT NULL,
    resource_type VARCHAR(100),
    resource_id TEXT,
    scope TEXT,
    identifiers JSONB,
    justification TEXT,
    approved_by TEXT,
    approved_at TIMESTAMPTZ,
    access_token TEXT,
    expires_at TIMESTAMPTZ,
    duration_minutes INTEGER,
    completed_at TIMESTAMPTZ,
    completion_details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_data_access_requests_tenant
    ON ent_data_access_requests (tenant_id, created_at DESC);

-- ── Log streaming (S3/Webhook/Splunk/Datadog destinations) ──────────────

CREATE TABLE IF NOT EXISTS ent_log_streams (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    destination_type VARCHAR(50) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'paused', 'error')),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    destination_config JSONB,
    credentials_encrypted TEXT,
    log_categories TEXT[],
    filter_rules JSONB,
    batch_size INTEGER,
    batch_interval_seconds INTEGER,
    compression_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    format VARCHAR(20) NOT NULL DEFAULT 'json',
    total_events_delivered BIGINT NOT NULL DEFAULT 0,
    total_bytes_delivered BIGINT NOT NULL DEFAULT 0,
    delivery_failures_count INTEGER NOT NULL DEFAULT 0,
    last_delivery_at TIMESTAMPTZ,
    last_error TEXT,
    last_error_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_log_streams_tenant
    ON ent_log_streams (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ent_log_streams_active
    ON ent_log_streams (status, enabled);

CREATE TABLE IF NOT EXISTS ent_stream_batches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stream_id UUID NOT NULL REFERENCES ent_log_streams(id) ON DELETE CASCADE,
    batch_id VARCHAR(100) NOT NULL,
    event_count INTEGER NOT NULL DEFAULT 0,
    bytes_delivered BIGINT NOT NULL DEFAULT 0,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    success BOOLEAN NOT NULL DEFAULT TRUE,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_stream_batches_stream_created
    ON ent_stream_batches (stream_id, created_at);

-- ── White-labeling ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ent_whitelabel_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL UNIQUE,
    company_name TEXT,
    logo_url TEXT,
    primary_color TEXT,
    secondary_color TEXT,
    accent_color TEXT,
    font_family TEXT,
    custom_css TEXT,
    favicon_url TEXT,
    footer_text TEXT,
    support_email TEXT,
    support_url TEXT,
    privacy_url TEXT,
    terms_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ent_whitelabel_domains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL,
    domain VARCHAR(255) NOT NULL,
    domain_type VARCHAR(30) NOT NULL,
    verification_status VARCHAR(30) NOT NULL DEFAULT 'pending'
        CHECK (verification_status IN ('pending', 'verified', 'failed')),
    verification_token TEXT,
    dns_records JSONB,
    verified_at TIMESTAMPTZ,
    ssl_status VARCHAR(30),
    ssl_certificate_id TEXT,
    ssl_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, domain)
);

CREATE INDEX IF NOT EXISTS idx_ent_whitelabel_domains_tenant
    ON ent_whitelabel_domains (tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS ent_whitelabel_email_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL,
    template_type VARCHAR(50) NOT NULL,
    subject_template TEXT,
    html_template TEXT,
    text_template TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, template_type)
);

-- ── Sub-accounts (agency/reseller) ──────────────────────────────────────

CREATE TABLE IF NOT EXISTS ent_sub_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_id VARCHAR(26) NOT NULL,
    name VARCHAR(255) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended')),
    email VARCHAR(320),
    domain VARCHAR(255),
    plan VARCHAR(50),
    volume_limit BIGINT,
    volume_used BIGINT NOT NULL DEFAULT 0,
    inherit_parent_settings BOOLEAN NOT NULL DEFAULT TRUE,
    settings JSONB,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_sub_accounts_parent
    ON ent_sub_accounts (parent_id, created_at DESC);

CREATE TABLE IF NOT EXISTS ent_sub_account_api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sub_account_id UUID NOT NULL REFERENCES ent_sub_accounts(id) ON DELETE CASCADE,
    key_hash VARCHAR(64) NOT NULL,
    key_prefix VARCHAR(16) NOT NULL,
    name VARCHAR(255) NOT NULL,
    permissions TEXT[],
    rate_limit INTEGER,
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_sub_account_api_keys_sub_account
    ON ent_sub_account_api_keys (sub_account_id);

-- ── Quarterly Business Reviews ──────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ent_qbrs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL,
    quarter INTEGER NOT NULL CHECK (quarter BETWEEN 1 AND 4),
    year INTEGER NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'scheduled'
        CHECK (status IN ('scheduled', 'generating', 'delivered', 'feedback_received')),
    scheduled_date DATE,
    delivered_date TIMESTAMPTZ,
    attendees JSONB,
    metrics JSONB,
    insights JSONB,
    recommendations JSONB,
    highlights JSONB,
    concerns JSONB,
    goals JSONB,
    previous_qbr_id UUID,
    quarter_over_quarter_change JSONB,
    presentation_url TEXT,
    report_url TEXT,
    recording_url TEXT,
    feedback JSONB,
    action_items JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, quarter, year)
);

CREATE INDEX IF NOT EXISTS idx_ent_qbrs_tenant_year
    ON ent_qbrs (tenant_id, year DESC, quarter DESC);

CREATE TABLE IF NOT EXISTS ent_qbr_goals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    qbr_id UUID NOT NULL REFERENCES ent_qbrs(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    category VARCHAR(100),
    target_metric VARCHAR(100),
    target_value FLOAT8,
    current_value FLOAT8,
    baseline_value FLOAT8,
    unit VARCHAR(30),
    due_date DATE,
    status VARCHAR(30) NOT NULL DEFAULT 'not_started'
        CHECK (status IN ('not_started', 'in_progress', 'completed', 'missed')),
    progress_percent FLOAT8,
    owner VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_qbr_goals_qbr ON ent_qbr_goals (qbr_id);

CREATE TABLE IF NOT EXISTS ent_industry_benchmarks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    industry VARCHAR(100) NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    metric_value FLOAT8 NOT NULL,
    percentile_25 FLOAT8,
    percentile_50 FLOAT8,
    percentile_75 FLOAT8,
    percentile_90 FLOAT8,
    unit VARCHAR(30),
    period VARCHAR(30),
    source VARCHAR(255),
    valid_from DATE,
    valid_until DATE,
    UNIQUE (industry, metric_name)
);

-- Read by QBR metric gathering: aggregate sending stats per quarter
CREATE TABLE IF NOT EXISTS ent_sending_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id VARCHAR(26) NOT NULL,
    period_start TIMESTAMPTZ NOT NULL,
    sent BIGINT NOT NULL DEFAULT 0,
    delivered BIGINT NOT NULL DEFAULT 0,
    bounced BIGINT NOT NULL DEFAULT 0,
    opened BIGINT NOT NULL DEFAULT 0,
    clicked BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_ent_sending_metrics_account_period
    ON ent_sending_metrics (account_id, period_start);

-- ── Template approval workflow ──────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ent_template_submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    html_content TEXT NOT NULL,
    text_content TEXT,
    subject VARCHAR(500) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected', 'changes_requested')),
    submitted_by VARCHAR(255) NOT NULL,
    reviewed_by VARCHAR(255),
    review_notes TEXT,
    spam_score FLOAT8,
    spam_details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_template_submissions_tenant_status
    ON ent_template_submissions (tenant_id, status, created_at DESC);

COMMIT;
