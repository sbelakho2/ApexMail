-- ApexMail Database Schema
-- Version:1.0.0
-- This file contains all database tables required for the ApexMail platform

-- =============================================================================
-- EXTENSIONS
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================================
-- TENANTS & USERS
-- =============================================================================

CREATE TABLE IF NOT EXISTS tenants (
    id VARCHAR(26) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    plan VARCHAR(50) NOT NULL DEFAULT 'free',
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    settings JSONB NOT NULL DEFAULT '{}',
    metadata JSONB NOT NULL DEFAULT '{}',
    legal_hold BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tenants_slug ON tenants(slug);
CREATE INDEX idx_tenants_status ON tenants(status);

CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(26) PRIMARY KEY,
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255),
    name VARCHAR(255),
    role VARCHAR(50) NOT NULL DEFAULT 'member',
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    email_verified BOOLEAN NOT NULL DEFAULT false,
    mfa_enabled BOOLEAN NOT NULL DEFAULT false,
    mfa_secret VARCHAR(255),
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, email)
);

CREATE INDEX idx_users_tenant ON users(tenant_id);
CREATE INDEX idx_users_email ON users(email);

-- =============================================================================
-- API KEYS
-- =============================================================================

CREATE TABLE IF NOT EXISTS api_keys (
    id VARCHAR(26) PRIMARY KEY,
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id VARCHAR(26) REFERENCES users(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(10) NOT NULL,
    key_hash VARCHAR(255) NOT NULL,
    scopes JSONB NOT NULL DEFAULT '["*"]',
    rate_limit INTEGER,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_tenant ON api_keys(tenant_id);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);

-- =============================================================================
-- DOMAINS
-- =============================================================================

CREATE TABLE IF NOT EXISTS domains (
    id VARCHAR(26) PRIMARY KEY,
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    verification_token VARCHAR(100),
    is_verified BOOLEAN NOT NULL DEFAULT false,
    verified_at TIMESTAMPTZ,
    accepts_inbound BOOLEAN NOT NULL DEFAULT false,
    dkim_selector VARCHAR(100),
    dkim_public_key TEXT,
    dkim_private_key_encrypted TEXT,
    spf_configured BOOLEAN NOT NULL DEFAULT false,
    dmarc_configured BOOLEAN NOT NULL DEFAULT false,
    dns_last_checked_at TIMESTAMPTZ,
    warmup_enabled BOOLEAN NOT NULL DEFAULT false,
    warmup_started_at TIMESTAMPTZ,
    warmup_daily_limit INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, name)
);

CREATE INDEX idx_domains_tenant ON domains(tenant_id);
CREATE INDEX idx_domains_name ON domains(name);
CREATE INDEX idx_domains_verified ON domains(is_verified);

-- =============================================================================
-- TEMPLATES
-- =============================================================================

CREATE TABLE IF NOT EXISTS templates (
    id VARCHAR(26) PRIMARY KEY,
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL,
    description TEXT,
    subject VARCHAR(255),
    html_body TEXT,
    text_body TEXT,
    mjml_source TEXT,
    variables_schema JSONB,
    parent_template_id VARCHAR(26) REFERENCES templates(id) ON DELETE SET NULL,
    version INTEGER NOT NULL DEFAULT 1,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, slug, version)
);

CREATE INDEX idx_templates_tenant ON templates(tenant_id);
CREATE INDEX idx_templates_slug ON templates(tenant_id, slug);
CREATE INDEX idx_templates_active ON templates(tenant_id, is_active);

CREATE TABLE IF NOT EXISTS template_versions (
    id VARCHAR(26) PRIMARY KEY,
    template_id VARCHAR(26) NOT NULL REFERENCES templates(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    subject VARCHAR(255),
    html_body TEXT,
    text_body TEXT,
    mjml_source TEXT,
    variables_schema JSONB,
    created_by VARCHAR(26),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(template_id, version)
);

CREATE INDEX idx_template_versions_template ON template_versions(template_id);

-- =============================================================================
-- MESSAGES
-- =============================================================================

CREATE TABLE IF NOT EXISTS messages (
    id VARCHAR(26) PRIMARY KEY,
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain_id VARCHAR(26) REFERENCES domains(id) ON DELETE SET NULL,
    template_id VARCHAR(26) REFERENCES templates(id) ON DELETE SET NULL,
    idempotency_key VARCHAR(255),
    message_id_header VARCHAR(255),
    message_type VARCHAR(20) NOT NULL DEFAULT 'transactional',
    from_address VARCHAR(255) NOT NULL,
    from_name VARCHAR(255),
    reply_to VARCHAR(255),
    to_address VARCHAR(255) NOT NULL,
    to_name VARCHAR(255),
    cc JSONB,
    bcc JSONB,
    subject VARCHAR(255) NOT NULL,
    html_body TEXT,
    text_body TEXT,
    headers JSONB,
    attachments JSONB,
    metadata JSONB,
    tags JSONB,
    status VARCHAR(20) NOT NULL DEFAULT 'queued',
    priority INTEGER NOT NULL DEFAULT 5,
    scheduled_at TIMESTAMPTZ,
    sent_at TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    first_opened_at TIMESTAMPTZ,
    first_clicked_at TIMESTAMPTZ,
    open_count INTEGER NOT NULL DEFAULT 0,
    click_count INTEGER NOT NULL DEFAULT 0,
    unsubscribe_count INTEGER NOT NULL DEFAULT 0,
    recipient_count INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, idempotency_key)
);

CREATE INDEX idx_messages_tenant ON messages(tenant_id);
CREATE INDEX idx_messages_status ON messages(status);
CREATE INDEX idx_messages_created ON messages(created_at);
CREATE INDEX idx_messages_scheduled ON messages(scheduled_at) WHERE scheduled_at IS NOT NULL;
CREATE INDEX idx_messages_recipient ON messages(to_address);
CREATE INDEX idx_messages_message_id ON messages(message_id_header);

-- =============================================================================
-- MESSAGE QUEUE
-- =============================================================================

CREATE TABLE IF NOT EXISTS message_queue (
    id VARCHAR(26) PRIMARY KEY,
    message_id VARCHAR(26) NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    priority INTEGER NOT NULL DEFAULT 5,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    attempt INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    next_attempt_at TIMESTAMPTZ,
    locked_at TIMESTAMPTZ,
    locked_by VARCHAR(100),
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_queue_pending ON message_queue(status, priority DESC, next_attempt_at) 
    WHERE status = 'pending';
CREATE INDEX idx_queue_tenant ON message_queue(tenant_id);
CREATE INDEX idx_queue_locked ON message_queue(locked_at) WHERE locked_at IS NOT NULL;

-- =============================================================================
-- EMAIL QUEUE (Denormalized for worker performance)
-- =============================================================================

CREATE TABLE IF NOT EXISTS email_queue (
    id VARCHAR(26) PRIMARY KEY,
    message_id VARCHAR(26) NOT NULL,
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain_id VARCHAR(26) REFERENCES domains(id) ON DELETE SET NULL,
    "from" VARCHAR(255) NOT NULL,
    "to" VARCHAR(255) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    html TEXT,
    text TEXT,
    headers JSONB,
    attachments JSONB,
    campaign_id VARCHAR(26),
    tags JSONB,
    metadata JSONB,
    scheduled_at TIMESTAMPTZ,
    priority INTEGER NOT NULL DEFAULT 5,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    attempt INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    locked_until TIMESTAMPTZ,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_email_queue_processing ON email_queue(status, priority DESC, created_at) 
    WHERE status = 'pending';
CREATE INDEX idx_email_queue_tenant ON email_queue(tenant_id);
CREATE INDEX idx_email_queue_scheduled ON email_queue(scheduled_at) WHERE scheduled_at IS NOT NULL;
CREATE INDEX idx_email_queue_locked ON email_queue(locked_until) WHERE locked_until IS NOT NULL;

-- =============================================================================
-- EVENTS
-- =============================================================================

CREATE TABLE IF NOT EXISTS events (
    id VARCHAR(26) PRIMARY KEY,
    tenant_id VARCHAR(26) NOT NULL,
    message_id VARCHAR(26),
    event_type VARCHAR(50) NOT NULL,
    recipient VARCHAR(255),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_agent TEXT,
    ip_address VARCHAR(45),
    link_id VARCHAR(50),
    link_url TEXT,
    bounce_type VARCHAR(20),
    bounce_subtype VARCHAR(50),
    diagnostic_code TEXT,
    complaint_type VARCHAR(50),
    complaint_user_agent TEXT,
    raw_data JSONB
);

CREATE INDEX idx_events_tenant ON events(tenant_id);
CREATE INDEX idx_events_message ON events(message_id);
CREATE INDEX idx_events_type ON events(event_type);
CREATE INDEX idx_events_timestamp ON events(timestamp);
CREATE INDEX idx_events_recipient ON events(recipient);

-- =============================================================================
-- SUPPRESSIONS
-- =============================================================================

CREATE TABLE IF NOT EXISTS suppressions (
    id VARCHAR(26) PRIMARY KEY,
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    reason VARCHAR(50) NOT NULL,
    subtype VARCHAR(100),
    source VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ,
    UNIQUE(tenant_id, email)
);

CREATE INDEX idx_suppressions_tenant ON suppressions(tenant_id);
CREATE INDEX idx_suppressions_email ON suppressions(email);
CREATE INDEX idx_suppressions_reason ON suppressions(reason);

-- =============================================================================
-- SUBSCRIPTION PREFERENCES
-- =============================================================================

CREATE TABLE IF NOT EXISTS subscription_preferences (
    id VARCHAR(26) PRIMARY KEY,
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    category VARCHAR(100) NOT NULL,
    subscribed BOOLEAN NOT NULL DEFAULT true,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, email, category)
);

CREATE INDEX idx_sub_prefs_tenant_email ON subscription_preferences(tenant_id, email);

CREATE TABLE IF NOT EXISTS email_categories (
    id VARCHAR(26) PRIMARY KEY,
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    active BOOLEAN NOT NULL DEFAULT true,
    display_order INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, name)
);

-- =============================================================================
-- WEBHOOKS
-- =============================================================================

CREATE TABLE IF NOT EXISTS webhooks (
    id VARCHAR(26) PRIMARY KEY,
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    url VARCHAR(2048) NOT NULL,
    secret VARCHAR(255) NOT NULL,
    events JSONB NOT NULL DEFAULT '["*"]',
    enabled BOOLEAN NOT NULL DEFAULT true,
    headers JSONB,
    failure_count INTEGER NOT NULL DEFAULT 0,
    last_triggered_at TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,
    last_failure_at TIMESTAMPTZ,
    disabled_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webhooks_tenant ON webhooks(tenant_id);
CREATE INDEX idx_webhooks_enabled ON webhooks(enabled);

CREATE TABLE IF NOT EXISTS webhook_queue (
    id VARCHAR(26) PRIMARY KEY,
    webhook_id VARCHAR(26) NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    tenant_id VARCHAR(26) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    payload JSONB NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    attempt INTEGER NOT NULL DEFAULT 1,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    next_attempt_at TIMESTAMPTZ,
    response_status INTEGER,
    response_body TEXT,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX idx_webhook_queue_pending ON webhook_queue(status, next_attempt_at) 
    WHERE status = 'pending';
CREATE INDEX idx_webhook_queue_webhook ON webhook_queue(webhook_id);

-- =============================================================================
-- INBOUND MESSAGES
-- =============================================================================

CREATE TABLE IF NOT EXISTS inbound_messages (
    id VARCHAR(26) PRIMARY KEY,
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain_id VARCHAR(26) REFERENCES domains(id) ON DELETE SET NULL,
    message_id_header VARCHAR(255),
    from_address VARCHAR(255) NOT NULL,
    to_address VARCHAR(255) NOT NULL,
    subject VARCHAR(255),
    text_body TEXT,
    html_body TEXT,
    raw_message BYTEA,
    headers JSONB,
    attachments JSONB,
    spam_score DECIMAL(5,2),
    spam_status VARCHAR(20),
    virus_status VARCHAR(20),
    spf_result VARCHAR(20),
    dkim_result VARCHAR(20),
    dmarc_result VARCHAR(20),
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    client_ip VARCHAR(45),
    session_id VARCHAR(50)
);

CREATE INDEX idx_inbound_tenant ON inbound_messages(tenant_id);
CREATE INDEX idx_inbound_received ON inbound_messages(received_at);
CREATE INDEX idx_inbound_from ON inbound_messages(from_address);

-- =============================================================================
-- BOUNCE & COMPLAINT TRACKING
-- =============================================================================

CREATE TABLE IF NOT EXISTS unmatched_bounces (
    id VARCHAR(26) PRIMARY KEY,
    recipient VARCHAR(255),
    from_address VARCHAR(255),
    bounce_type VARCHAR(20),
    bounce_subtype VARCHAR(100),
    diagnostic_code TEXT,
    original_message_id VARCHAR(255),
    raw_message BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_unmatched_bounces_created ON unmatched_bounces(created_at);

CREATE TABLE IF NOT EXISTS unmatched_complaints (
    id VARCHAR(26) PRIMARY KEY,
    recipient VARCHAR(255),
    from_address VARCHAR(255),
    feedback_type VARCHAR(50),
    user_agent VARCHAR(255),
    original_message_id VARCHAR(255),
    original_recipient VARCHAR(255),
    raw_message BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_unmatched_complaints_created ON unmatched_complaints(created_at);

-- =============================================================================
-- SMTP CREDENTIALS
-- =============================================================================

CREATE TABLE IF NOT EXISTS smtp_credentials (
    id VARCHAR(26) PRIMARY KEY,
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    username VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_smtp_creds_username ON smtp_credentials(username);

-- =============================================================================
-- REPUTATION & ANALYTICS
-- =============================================================================

CREATE TABLE IF NOT EXISTS reputation_stats (
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    date DATE NOT NULL,
    sent INTEGER NOT NULL DEFAULT 0,
    delivered INTEGER NOT NULL DEFAULT 0,
    bounces INTEGER NOT NULL DEFAULT 0,
    complaints INTEGER NOT NULL DEFAULT 0,
    opens INTEGER NOT NULL DEFAULT 0,
    clicks INTEGER NOT NULL DEFAULT 0,
    unsubscribes INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, date)
);

CREATE TABLE IF NOT EXISTS reputation_alerts (
    id VARCHAR(26) PRIMARY KEY,
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    alert_type VARCHAR(50) NOT NULL,
    value DECIMAL(10,6),
    threshold DECIMAL(10,6),
    acknowledged BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rep_alerts_tenant ON reputation_alerts(tenant_id);

-- =============================================================================
-- IDEMPOTENCY
-- =============================================================================

CREATE TABLE IF NOT EXISTS idempotency_keys (
    id VARCHAR(26) PRIMARY KEY,
    tenant_id VARCHAR(26) NOT NULL,
    idempotency_key VARCHAR(255) NOT NULL,
    request_hash VARCHAR(64) NOT NULL,
    response_status INTEGER NOT NULL,
    response_body JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    UNIQUE(tenant_id, idempotency_key)
);

CREATE INDEX idx_idempotency_expires ON idempotency_keys(expires_at);

-- =============================================================================
-- AUDIT LOGS
-- =============================================================================

CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(26) PRIMARY KEY,
    tenant_id VARCHAR(26),
    user_id VARCHAR(26),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(26),
    metadata JSONB,
    ip_address VARCHAR(45),
    user_agent TEXT,
    prev_hash VARCHAR(64),
    hash VARCHAR(64) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_tenant ON audit_logs(tenant_id);
CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_action ON audit_logs(action);

-- =============================================================================
-- COMPACTION & RECONCILIATION
-- =============================================================================

CREATE TABLE IF NOT EXISTS compaction_log (
    date DATE PRIMARY KEY,
    status VARCHAR(20) NOT NULL,
    event_count INTEGER NOT NULL DEFAULT 0,
    completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS reconciliation_log (
    id VARCHAR(26) PRIMARY KEY,
    date DATE UNIQUE NOT NULL,
    status VARCHAR(20) NOT NULL,
    messages_sent INTEGER NOT NULL DEFAULT 0,
    events_expected INTEGER NOT NULL DEFAULT 0,
    events_found INTEGER NOT NULL DEFAULT 0,
    discrepancy_count INTEGER NOT NULL DEFAULT 0,
    discrepancy_details JSONB,
    duration_ms INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ
);

-- =============================================================================
-- SYSTEM ALERTS
-- =============================================================================

CREATE TABLE IF NOT EXISTS system_alerts (
    id VARCHAR(26) PRIMARY KEY,
    alert_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'info',
    title VARCHAR(255) NOT NULL,
    message TEXT,
    metadata JSONB,
    acknowledged BOOLEAN NOT NULL DEFAULT false,
    acknowledged_by VARCHAR(26),
    acknowledged_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_system_alerts_type ON system_alerts(alert_type);
CREATE INDEX idx_system_alerts_unack ON system_alerts(acknowledged) WHERE acknowledged = false;

-- =============================================================================
-- SCHEMA VERSION
-- =============================================================================

CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(50) PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO schema_migrations (version) VALUES ('1.0.0') ON CONFLICT DO NOTHING;
