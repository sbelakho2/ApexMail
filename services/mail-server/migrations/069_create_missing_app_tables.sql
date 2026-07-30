-- Migration 069: Create all application tables referenced by api-server routes
-- but missing from prior migrations. Each uses CREATE TABLE IF NOT EXISTS
-- so re-running is safe.

-- Session management (auth.rs)
CREATE TABLE IF NOT EXISTS sessions (
    id              VARCHAR(64) PRIMARY KEY,
    user_id         VARCHAR(26) NOT NULL,
    tenant_id       VARCHAR(26) NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address      VARCHAR(45),
    user_agent      TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- Client error logging (client_errors.rs)
CREATE TABLE IF NOT EXISTS client_errors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(26),
    user_id         VARCHAR(26),
    error_message   TEXT NOT NULL,
    stack_trace     TEXT,
    url             TEXT,
    user_agent      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_client_errors_tenant ON client_errors(tenant_id, created_at DESC);

-- Invoices (billing.rs, vat.rs)
CREATE TABLE IF NOT EXISTS invoices (
    id                  VARCHAR(26) PRIMARY KEY,
    tenant_id           VARCHAR(26) NOT NULL,
    amount_cents        BIGINT NOT NULL,
    currency            VARCHAR(3) NOT NULL DEFAULT 'EUR',
    status              VARCHAR(20) NOT NULL DEFAULT 'pending',
    invoice_number      VARCHAR(64),
    stripe_invoice_id   VARCHAR(128),
    pdf_url             TEXT,
    issue_date          TIMESTAMPTZ,
    due_date            TIMESTAMPTZ,
    paid_at             TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_invoices_tenant ON invoices(tenant_id, created_at DESC);

-- Stripe customer/subscription links (billing.rs)
CREATE TABLE IF NOT EXISTS stripe_customers (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           VARCHAR(26) NOT NULL UNIQUE,
    stripe_customer_id  VARCHAR(128) NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS stripe_subscriptions (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               VARCHAR(26) NOT NULL,
    stripe_subscription_id  VARCHAR(128) NOT NULL,
    plan                    VARCHAR(64),
    status                  VARCHAR(30),
    current_period_end      TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_stripe_sub_tenant ON stripe_subscriptions(tenant_id);

-- Billing addresses (billing.rs)
CREATE TABLE IF NOT EXISTS billing_addresses (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(26) NOT NULL,
    company_name    VARCHAR(255),
    vat_number      VARCHAR(64),
    address_line1   VARCHAR(255),
    address_line2   VARCHAR(255),
    city            VARCHAR(128),
    postal_code     VARCHAR(20),
    country         VARCHAR(2),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Bounce/complaint records (self_hosted_bounces.rs)
CREATE TABLE IF NOT EXISTS bounces (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(26) NOT NULL,
    recipient       VARCHAR(320) NOT NULL,
    bounce_type     VARCHAR(20) NOT NULL,
    diagnostic_code TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_bounces_tenant_recipient ON bounces(tenant_id, recipient);

CREATE TABLE IF NOT EXISTS complaints (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(26) NOT NULL,
    recipient       VARCHAR(320) NOT NULL,
    feedback_type   VARCHAR(50),
    user_agent      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_complaints_tenant ON complaints(tenant_id, created_at DESC);

-- Abuse reports (billing.rs)
CREATE TABLE IF NOT EXISTS abuse_reports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(26) NOT NULL,
    report_type     VARCHAR(64) NOT NULL,
    source          VARCHAR(128),
    details         JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- GDPR data subject access requests (gdpr.rs)
CREATE TABLE IF NOT EXISTS gdpr_requests (
    id              VARCHAR(26) PRIMARY KEY,
    tenant_id       VARCHAR(26) NOT NULL,
    email           VARCHAR(320) NOT NULL,
    request_type    VARCHAR(20) NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',
    token_hash      VARCHAR(128),
    fulfilled_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_gdpr_requests_tenant ON gdpr_requests(tenant_id, created_at DESC);

-- Marketing spend tracking (revenue.rs)
CREATE TABLE IF NOT EXISTS marketing_spend (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(26),
    amount_cents    BIGINT NOT NULL,
    spent_at        DATE NOT NULL,
    source          VARCHAR(128),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Sales autopilot state (autopilot.rs)
CREATE TABLE IF NOT EXISTS sales_autopilot_state (
    tenant_id       VARCHAR(26) PRIMARY KEY,
    status          VARCHAR(20) NOT NULL DEFAULT 'stopped',
    safe_mode       BOOLEAN NOT NULL DEFAULT false,
    last_action     TEXT,
    last_action_at  TIMESTAMPTZ,
    rules           JSONB DEFAULT '[]',
    feedback        JSONB,
    delivered_date  TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Support tickets (support.rs)
CREATE TABLE IF NOT EXISTS ticket_messages (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id       VARCHAR(26) NOT NULL,
    author_id       VARCHAR(26),
    body            TEXT NOT NULL,
    is_internal     BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ticket_messages_ticket ON ticket_messages(ticket_id, created_at);

-- Campaign jobs and recipients (campaigns.rs)
CREATE TABLE IF NOT EXISTS campaign_jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(26) NOT NULL,
    campaign_id     UUID NOT NULL,
    job_type        VARCHAR(64) NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_campaign_jobs_campaign ON campaign_jobs(campaign_id);

CREATE TABLE IF NOT EXISTS campaign_recipients (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id     UUID NOT NULL,
    contact_id      UUID NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',
    sent_at         TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(campaign_id, contact_id)
);
CREATE INDEX IF NOT EXISTS idx_campaign_recipients_campaign ON campaign_recipients(campaign_id);

-- Drip campaigns (campaigns.rs, sales.rs, autopilot.rs)
CREATE TABLE IF NOT EXISTS drip_campaigns (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(26) NOT NULL,
    name            VARCHAR(255) NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'draft',
    steps           JSONB DEFAULT '[]',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_drip_campaigns_tenant ON drip_campaigns(tenant_id);

-- Risk settings (admin/risk.rs)
CREATE TABLE IF NOT EXISTS risk_settings (
    tenant_id       VARCHAR(26) PRIMARY KEY,
    risk_tolerance  VARCHAR(20) NOT NULL DEFAULT 'standard',
    settings        JSONB DEFAULT '{}',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Sales settings (sales.rs)
CREATE TABLE IF NOT EXISTS sales_settings (
    tenant_id       VARCHAR(26) PRIMARY KEY,
    autopilot_enabled   BOOLEAN NOT NULL DEFAULT false,
    discovery_enabled   BOOLEAN NOT NULL DEFAULT true,
    settings            JSONB DEFAULT '{}',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Dunning events (billing.rs)
CREATE TABLE IF NOT EXISTS dunning_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(26) NOT NULL,
    invoice_id      VARCHAR(26),
    event_type      VARCHAR(64) NOT NULL,
    retry_count     INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dunning_events_tenant ON dunning_events(tenant_id, created_at DESC);

-- Plan overrides (billing.rs admin)
CREATE TABLE IF NOT EXISTS plan_overrides (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(26) NOT NULL UNIQUE,
    plan            VARCHAR(64) NOT NULL,
    email_quota     BIGINT,
    overridden_by   VARCHAR(26),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
