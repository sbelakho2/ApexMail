-- Migration 075: Create tables referenced by api-server routes and worker processors
-- that have no prior CREATE TABLE migration. Each uses CREATE TABLE IF NOT EXISTS
-- so re-running is safe even if the table was manually created earlier.
--
-- Tables covered: templates, events, contacts, automations,
--    support_tickets, campaigns, webhook_queue, webhooks, export_jobs

-- =============================================================================
-- TEMPLATES
-- =============================================================================
CREATE TABLE IF NOT EXISTS templates (
    id          VARCHAR(26) PRIMARY KEY,
    tenant_id   VARCHAR(26) NOT NULL,
    name        VARCHAR(255) NOT NULL,
    slug        VARCHAR(100),
    subject     VARCHAR(255) NOT NULL,
    html_body   TEXT NOT NULL,
    text_body   TEXT,
    version     INTEGER NOT NULL DEFAULT 1,
    status      VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_templates_tenant ON templates(tenant_id);
CREATE INDEX IF NOT EXISTS idx_templates_tenant_name ON templates(tenant_id, name);

-- =============================================================================
-- EVENTS
-- =============================================================================
CREATE TABLE IF NOT EXISTS events (
    id              VARCHAR(64) PRIMARY KEY,
    tenant_id       VARCHAR(26) NOT NULL,
    message_id      VARCHAR(64),
    domain_id       VARCHAR(26),
    campaign_id     VARCHAR(64),
    event_type      VARCHAR(50) NOT NULL,
    recipient       VARCHAR(255),
    link_id         VARCHAR(64),
    link_url        TEXT,
    user_agent      TEXT,
    ip_address      VARCHAR(45),
    bounce_type     VARCHAR(20),
    bounce_subtype  VARCHAR(50),
    diagnostic_code TEXT,
    complaint_type  VARCHAR(50),
    metadata        JSONB DEFAULT '{}',
    raw_data        JSONB,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_events_tenant ON events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_events_message ON events(message_id);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_recipient ON events(recipient);

-- =============================================================================
-- CONTACTS
-- =============================================================================
CREATE TABLE IF NOT EXISTS contacts (
    id              VARCHAR(26) PRIMARY KEY,
    tenant_id       VARCHAR(26) NOT NULL,
    email           VARCHAR(320) NOT NULL,
    name            VARCHAR(512),
    tags            JSONB DEFAULT '[]',
    metadata        JSONB DEFAULT '{}',
    phone           VARCHAR(32),
    status          VARCHAR(20) NOT NULL DEFAULT 'subscribed',
    unsubscribed_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_contacts_tenant_email ON contacts(tenant_id, email);
CREATE INDEX IF NOT EXISTS idx_contacts_tenant ON contacts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_contacts_status ON contacts(tenant_id, status);

-- =============================================================================
-- AUTOMATIONS
-- =============================================================================
CREATE TABLE IF NOT EXISTS automations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(26) NOT NULL,
    name            VARCHAR(255) NOT NULL,
    trigger_config  JSONB DEFAULT '{}',
    actions         JSONB DEFAULT '[]',
    conditions      JSONB DEFAULT '{}',
    status          VARCHAR(20) NOT NULL DEFAULT 'disabled',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_automations_tenant ON automations(tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_automations_tenant_name ON automations(tenant_id, name);

-- =============================================================================
-- SUPPORT TICKETS
-- =============================================================================
CREATE TABLE IF NOT EXISTS support_tickets (
    id              VARCHAR(26) PRIMARY KEY,
    tenant_id       VARCHAR(26),
    subject         VARCHAR(500) NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    tenant_name     VARCHAR(255),
    tenant_email    VARCHAR(255),
    status          VARCHAR(30) NOT NULL DEFAULT 'open',
    priority        VARCHAR(20) NOT NULL DEFAULT 'normal',
    category        VARCHAR(50),
    assigned_to     VARCHAR(26),
    assignee        VARCHAR(255),
    resolved_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_support_tickets_tenant ON support_tickets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_support_tickets_status ON support_tickets(status);
CREATE INDEX IF NOT EXISTS idx_support_tickets_priority ON support_tickets(priority);

-- =============================================================================
-- CAMPAIGNS
-- =============================================================================
CREATE TABLE IF NOT EXISTS campaigns (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(26) NOT NULL,
    name            VARCHAR(255) NOT NULL,
    subject         VARCHAR(998),
    template_id     UUID,
    scheduled_at    TIMESTAMPTZ,
    status          VARCHAR(20) NOT NULL DEFAULT 'draft',
    sent_count      INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_campaigns_tenant ON campaigns(tenant_id);
CREATE INDEX IF NOT EXISTS idx_campaigns_status ON campaigns(tenant_id, status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_campaigns_tenant_name ON campaigns(tenant_id, name);

-- =============================================================================
-- WEBHOOKS
-- =============================================================================
CREATE TABLE IF NOT EXISTS webhooks (
    id                              VARCHAR(26) PRIMARY KEY,
    tenant_id                       VARCHAR(26) NOT NULL,
    name                            VARCHAR(255),
    url                             VARCHAR(2048) NOT NULL,
    secret                          VARCHAR(255) NOT NULL,
    previous_secret                 VARCHAR(255),
    previous_secret_expires_at      TIMESTAMPTZ,
    events                          JSONB NOT NULL DEFAULT '["*"]',
    enabled                         BOOLEAN NOT NULL DEFAULT true,
    headers                         JSONB,
    retry_policy                    JSONB DEFAULT '{"maxRetries":5,"retryDelay":1,"backoffMultiplier":2.0}',
    failure_count                   INTEGER NOT NULL DEFAULT 0,
    last_triggered_at               TIMESTAMPTZ,
    last_success_at                 TIMESTAMPTZ,
    last_failure_at                 TIMESTAMPTZ,
    disabled_reason                 TEXT,
    status                          VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_webhooks_tenant ON webhooks(tenant_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_enabled ON webhooks(enabled);

-- =============================================================================
-- WEBHOOK QUEUE
-- =============================================================================
CREATE TABLE IF NOT EXISTS webhook_queue (
    id              VARCHAR(64) PRIMARY KEY,
    webhook_id      VARCHAR(26) NOT NULL,
    tenant_id       VARCHAR(26) NOT NULL,
    event_type      VARCHAR(100) NOT NULL,
    payload         JSONB NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',
    attempt         INTEGER NOT NULL DEFAULT 1,
    max_attempts    INTEGER NOT NULL DEFAULT 5,
    next_attempt_at TIMESTAMPTZ,
    scheduled_at    TIMESTAMPTZ,
    locked_until    TIMESTAMPTZ,
    response_status INTEGER,
    response_body   TEXT,
    error_message   TEXT,
    updated_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_webhook_queue_pending ON webhook_queue(status, next_attempt_at) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_webhook_queue_webhook ON webhook_queue(webhook_id);
CREATE INDEX IF NOT EXISTS idx_webhook_queue_locked ON webhook_queue(status, locked_until) WHERE status IN ('pending', 'processing');

-- =============================================================================
-- EXPORT JOBS
-- =============================================================================
CREATE TABLE IF NOT EXISTS export_jobs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           VARCHAR(26) NOT NULL,
    job_type            VARCHAR(50) NOT NULL DEFAULT 'analytics',
    status              VARCHAR(20) NOT NULL DEFAULT 'pending',
    format              VARCHAR(20) NOT NULL DEFAULT 'csv',
    date_range_start    TIMESTAMPTZ,
    date_range_end      TIMESTAMPTZ,
    total_rows          BIGINT,
    processed_rows      BIGINT NOT NULL DEFAULT 0,
    file_size_bytes     BIGINT,
    download_url        TEXT,
    download_expires_at TIMESTAMPTZ,
    error_message       TEXT,
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by          VARCHAR(26)
);
CREATE INDEX IF NOT EXISTS idx_export_jobs_tenant ON export_jobs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_export_jobs_status ON export_jobs(status);
