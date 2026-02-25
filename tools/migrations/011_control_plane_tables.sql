-- =============================================================================
-- ApexMail Control Plane Tables
-- Migration: 011_control_plane_tables.sql
-- Date: 2026-02-07
-- Purpose: Create tables for secrets, feature flags, content, calendar,
--          support tickets, inbox messages, and sandbox stats so that
--          control-plane API routes query real data instead of demo arrays.
-- =============================================================================

-- =============================================================================
-- SECRETS / CREDENTIALS VAULT
-- =============================================================================
CREATE TABLE IF NOT EXISTS secrets (
    id              VARCHAR(64)  PRIMARY KEY DEFAULT 'secret-' || gen_random_uuid()::text,
    name            VARCHAR(255) NOT NULL UNIQUE,
    type            VARCHAR(50)  NOT NULL,  -- api_key, database, oauth, certificate, encryption
    description     TEXT         NOT NULL DEFAULT '',
    rotation_policy VARCHAR(20)  NOT NULL DEFAULT 'manual',  -- 90d, 60d, manual, never
    status          VARCHAR(20)  NOT NULL DEFAULT 'active',  -- active, expiring_soon, revoked
    access_count    BIGINT       NOT NULL DEFAULT 0,
    last_accessed   TIMESTAMPTZ,
    last_rotated    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_secrets_status ON secrets(status);

-- =============================================================================
-- FEATURE FLAGS
-- =============================================================================
CREATE TABLE IF NOT EXISTS feature_flags (
    id          VARCHAR(64)  PRIMARY KEY DEFAULT 'f-' || gen_random_uuid()::text,
    key         VARCHAR(255) NOT NULL UNIQUE,
    name        VARCHAR(255) NOT NULL,
    description TEXT         NOT NULL DEFAULT '',
    type        VARCHAR(20)  NOT NULL DEFAULT 'boolean',  -- boolean, percentage, allowlist
    enabled     BOOLEAN      NOT NULL DEFAULT false,
    percentage  INTEGER,            -- for percentage rollout (0-100)
    allowlist   JSONB,              -- for allowlist rollout (array of tenant ids)
    category    VARCHAR(50)  NOT NULL DEFAULT 'core',  -- core, beta, experimental, killswitch
    updated_by  VARCHAR(255),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_feature_flags_category ON feature_flags(category);
CREATE INDEX IF NOT EXISTS idx_feature_flags_key ON feature_flags(key);

CREATE TABLE IF NOT EXISTS feature_flag_overrides (
    id         VARCHAR(64)  PRIMARY KEY DEFAULT 'ffo-' || gen_random_uuid()::text,
    tenant_id  VARCHAR(64)  NOT NULL,
    tenant_name VARCHAR(255),
    flag_key   VARCHAR(255) NOT NULL REFERENCES feature_flags(key) ON DELETE CASCADE,
    value      BOOLEAN      NOT NULL,
    reason     TEXT,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, flag_key)
);

CREATE INDEX IF NOT EXISTS idx_feature_flag_overrides_flag ON feature_flag_overrides(flag_key);

-- =============================================================================
-- CONTENT / CMS
-- =============================================================================
CREATE TABLE IF NOT EXISTS content_items (
    id             VARCHAR(64)  PRIMARY KEY DEFAULT 'c-' || gen_random_uuid()::text,
    title          VARCHAR(500) NOT NULL,
    slug           VARCHAR(500) NOT NULL UNIQUE,
    type           VARCHAR(50)  NOT NULL DEFAULT 'blog',  -- blog, changelog, docs
    status         VARCHAR(20)  NOT NULL DEFAULT 'draft', -- draft, published, scheduled, archived
    excerpt        TEXT,
    content        TEXT,
    author         VARCHAR(255),
    category       VARCHAR(255),
    tags           JSONB        NOT NULL DEFAULT '[]',
    featured_image VARCHAR(500),
    scheduled_for  TIMESTAMPTZ,
    published_at   TIMESTAMPTZ,
    views          BIGINT       NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_content_items_type ON content_items(type);
CREATE INDEX IF NOT EXISTS idx_content_items_status ON content_items(status);
CREATE INDEX IF NOT EXISTS idx_content_items_slug ON content_items(slug);

-- =============================================================================
-- CALENDAR EVENTS (for sales / demos)
-- =============================================================================
CREATE TABLE IF NOT EXISTS calendar_events (
    id           VARCHAR(64)  PRIMARY KEY DEFAULT 'evt-' || gen_random_uuid()::text,
    title        VARCHAR(500) NOT NULL,
    lead_name    VARCHAR(255),
    lead_email   VARCHAR(255),
    lead_company VARCHAR(255),
    type         VARCHAR(50)  NOT NULL DEFAULT 'discovery',  -- discovery, demo, follow_up
    status       VARCHAR(50)  NOT NULL DEFAULT 'scheduled',  -- scheduled, completed, cancelled, no_show
    start_time   TIMESTAMPTZ  NOT NULL,
    end_time     TIMESTAMPTZ  NOT NULL,
    notes        TEXT,
    outcome      VARCHAR(50),
    meeting_link VARCHAR(500),
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_calendar_events_start ON calendar_events(start_time);
CREATE INDEX IF NOT EXISTS idx_calendar_events_status ON calendar_events(status);

CREATE TABLE IF NOT EXISTS availability_slots (
    id          VARCHAR(64) PRIMARY KEY DEFAULT 'avail-' || gen_random_uuid()::text,
    day_of_week INTEGER     NOT NULL CHECK (day_of_week BETWEEN 0 AND 6),
    start_time  VARCHAR(5)  NOT NULL,  -- HH:MM
    end_time    VARCHAR(5)  NOT NULL,  -- HH:MM
    enabled     BOOLEAN     NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- SUPPORT TICKETS
-- =============================================================================
CREATE TABLE IF NOT EXISTS support_tickets (
    id          VARCHAR(64)  PRIMARY KEY DEFAULT 'ticket-' || gen_random_uuid()::text,
    subject     VARCHAR(500) NOT NULL,
    description TEXT         NOT NULL DEFAULT '',
    tenant_id   VARCHAR(64),
    tenant_name VARCHAR(255),
    tenant_email VARCHAR(255),
    status      VARCHAR(30)  NOT NULL DEFAULT 'open',  -- open, in_progress, waiting_on_customer, resolved, closed
    priority    VARCHAR(20)  NOT NULL DEFAULT 'medium', -- low, medium, high, urgent
    category    VARCHAR(50),  -- technical, billing, feature_request, bug, general
    assignee    VARCHAR(255),
    resolved_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_support_tickets_status ON support_tickets(status);
CREATE INDEX IF NOT EXISTS idx_support_tickets_priority ON support_tickets(priority);
CREATE INDEX IF NOT EXISTS idx_support_tickets_tenant ON support_tickets(tenant_id);

CREATE TABLE IF NOT EXISTS support_ticket_messages (
    id          VARCHAR(64)  PRIMARY KEY DEFAULT 'stm-' || gen_random_uuid()::text,
    ticket_id   VARCHAR(64)  NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
    content     TEXT         NOT NULL,
    author      VARCHAR(255) NOT NULL,
    author_type VARCHAR(20)  NOT NULL DEFAULT 'customer',  -- customer, support
    attachments JSONB        NOT NULL DEFAULT '[]',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_support_ticket_messages_ticket ON support_ticket_messages(ticket_id);

-- =============================================================================
-- AUTOPILOT INBOX MESSAGES (classified replies from campaigns)
-- =============================================================================
CREATE TABLE IF NOT EXISTS autopilot_inbox_messages (
    id               VARCHAR(64)  PRIMARY KEY DEFAULT 'aim-' || gen_random_uuid()::text,
    tenant_id        VARCHAR(64),
    lead_id          VARCHAR(64),
    campaign_id      VARCHAR(64),
    campaign_name    VARCHAR(255),
    message_id       VARCHAR(255),
    in_reply_to      VARCHAR(255),
    from_address     VARCHAR(255) NOT NULL,
    from_name        VARCHAR(255),
    to_addresses     JSONB,
    cc_addresses     JSONB,
    subject          VARCHAR(500),
    text_body        TEXT,
    html_body        TEXT,
    preview          TEXT,
    classification   VARCHAR(50),  -- interested, not_interested, out_of_office, question, spam, unsubscribe
    confidence       DOUBLE PRECISION,
    sentiment_label  VARCHAR(20),
    suggested_action VARCHAR(50),
    read             BOOLEAN      NOT NULL DEFAULT false,
    starred          BOOLEAN      NOT NULL DEFAULT false,
    processed        BOOLEAN      NOT NULL DEFAULT false,
    processed_at     TIMESTAMPTZ,
    received_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_autopilot_inbox_classification ON autopilot_inbox_messages(classification);
CREATE INDEX IF NOT EXISTS idx_autopilot_inbox_campaign ON autopilot_inbox_messages(campaign_id);
CREATE INDEX IF NOT EXISTS idx_autopilot_inbox_received ON autopilot_inbox_messages(received_at DESC);

-- =============================================================================
-- SANDBOX CAPTURED EMAILS (for DevEx)
-- =============================================================================
CREATE TABLE IF NOT EXISTS sandbox_captured_emails (
    id               VARCHAR(64)  PRIMARY KEY DEFAULT 'sce-' || gen_random_uuid()::text,
    sandbox_id       VARCHAR(64)  NOT NULL,
    from_address     VARCHAR(255),
    to_addresses     JSONB,
    cc_addresses     JSONB,
    bcc_addresses    JSONB,
    subject          VARCHAR(500),
    text_content     TEXT,
    html_content     TEXT,
    headers          JSONB        NOT NULL DEFAULT '{}',
    attachments      JSONB        NOT NULL DEFAULT '[]',
    metadata         JSONB        NOT NULL DEFAULT '{}',
    simulated_events JSONB        NOT NULL DEFAULT '[]',
    captured_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sandbox_emails_sandbox ON sandbox_captured_emails(sandbox_id);
CREATE INDEX IF NOT EXISTS idx_sandbox_emails_captured ON sandbox_captured_emails(captured_at DESC);

-- =============================================================================
-- SANDBOX STATS (atomic counters for DevEx sandbox)
-- =============================================================================
CREATE TABLE IF NOT EXISTS sandbox_stats (
    sandbox_id           VARCHAR(64) PRIMARY KEY,
    emails_captured      BIGINT NOT NULL DEFAULT 0,
    emails_forwarded     BIGINT NOT NULL DEFAULT 0,
    simulated_deliveries BIGINT NOT NULL DEFAULT 0,
    simulated_bounces    BIGINT NOT NULL DEFAULT 0,
    simulated_complaints BIGINT NOT NULL DEFAULT 0,
    webhooks_triggered   BIGINT NOT NULL DEFAULT 0,
    api_calls            BIGINT NOT NULL DEFAULT 0,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- MESSAGE ARCHIVE (for archiveOld #145)
-- =============================================================================
CREATE TABLE IF NOT EXISTS messages_archive (
    LIKE messages INCLUDING ALL
);

-- Ensure the archive table has an index on tenant + date
CREATE INDEX IF NOT EXISTS idx_messages_archive_tenant_date
    ON messages_archive(tenant_id, created_at DESC);
