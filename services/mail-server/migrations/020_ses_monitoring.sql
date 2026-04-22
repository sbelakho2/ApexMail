-- SES Monitoring and Deliverability Metrics Schema
-- This migration adds tables for:-- 1. SES account-level quota/reputation metrics
-- 2. Domain deliverability statistics (VDM)
-- 3. Per-tenant deliverability metrics
-- 4. Per-tenant MAIL FROM configuration
-- 5. Alert tracking

-- =============================================================================
-- SES Account Metrics (historical quota/reputation tracking)
-- =============================================================================
CREATE TABLE IF NOT EXISTS ses_account_metrics (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    region                TEXT NOT NULL,
    max_24h_send          DOUBLE PRECISION NOT NULL,
    sent_24h              DOUBLE PRECISION NOT NULL,
    max_send_rate         DOUBLE PRECISION NOT NULL,
    utilization_pct       DOUBLE PRECISION NOT NULL,
    sending_enabled       BOOLEAN NOT NULL DEFAULT true,
    enforcement_status    TEXT NOT NULL DEFAULT 'HEALTHY',
    production_access     BOOLEAN NOT NULL DEFAULT true,
    recorded_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ses_account_metrics_time 
    ON ses_account_metrics(recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_ses_account_metrics_region 
    ON ses_account_metrics(region, recorded_at DESC);

-- =============================================================================
-- SES Domain Statistics (VDM data from SES)
-- =============================================================================
CREATE TABLE IF NOT EXISTS ses_domain_stats (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain                TEXT NOT NULL,
    start_date            DATE NOT NULL,
    end_date              DATE NOT NULL,
    inbox_count           BIGINT NOT NULL DEFAULT 0,
    spam_count            BIGINT NOT NULL DEFAULT 0,
    read_rate             DOUBLE PRECISION,
    inbox_placement_rate  DOUBLE PRECISION,
    recorded_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(domain, start_date, end_date)
);

CREATE INDEX IF NOT EXISTS idx_ses_domain_stats_domain 
    ON ses_domain_stats(domain, recorded_at DESC);

-- =============================================================================
-- Tenant Deliverability Metrics (computed from events)
-- =============================================================================
CREATE TABLE IF NOT EXISTS tenant_deliverability_metrics (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID NOT NULL,
    period_start          TIMESTAMPTZ NOT NULL,
    period_end            TIMESTAMPTZ NOT NULL,
    emails_sent           BIGINT NOT NULL DEFAULT 0,
    emails_delivered      BIGINT NOT NULL DEFAULT 0,
    emails_bounced        BIGINT NOT NULL DEFAULT 0,
    emails_complained     BIGINT NOT NULL DEFAULT 0,
    bounce_rate           DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    complaint_rate        DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    delivery_rate         DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tenant_deliverability_tenant 
    ON tenant_deliverability_metrics(tenant_id, period_start DESC);
CREATE INDEX IF NOT EXISTS idx_tenant_deliverability_time 
    ON tenant_deliverability_metrics(period_start DESC);

-- =============================================================================
-- Tenant MAIL FROM Configuration (per-tenant custom return path)
-- =============================================================================
CREATE TABLE IF NOT EXISTS tenant_mail_from (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID NOT NULL UNIQUE,
    mail_from_domain      TEXT NOT NULL, -- e.g., "bounce.customerdomain.com"
    status                TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'verified', 'failed')),
    spf_verified          BOOLEAN NOT NULL DEFAULT false,
    mx_verified           BOOLEAN NOT NULL DEFAULT false,
    ses_identity_arn      TEXT, -- ARN of the SES identity
    verification_token    TEXT,
    last_verified_at      TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tenant_mail_from_status 
    ON tenant_mail_from(status);

-- =============================================================================
-- System Alerts (account-level alerts)
-- =============================================================================
CREATE TABLE IF NOT EXISTS system_alerts (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_type            TEXT NOT NULL,
    message               TEXT NOT NULL,
    severity              TEXT NOT NULL DEFAULT 'info'
        CHECK (severity IN ('info', 'warning', 'critical')),
    acknowledged          BOOLEAN NOT NULL DEFAULT false,
    acknowledged_by       TEXT,
    acknowledged_at       TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_system_alerts_time 
    ON system_alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_system_alerts_unack 
    ON system_alerts(acknowledged, created_at DESC) WHERE acknowledged = false;

-- =============================================================================
-- Tenant Alerts (per-tenant alerts)
-- =============================================================================
CREATE TABLE IF NOT EXISTS tenant_alerts (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID NOT NULL,
    alert_type            TEXT NOT NULL,
    message               TEXT NOT NULL,
    severity              TEXT NOT NULL DEFAULT 'info'
        CHECK (severity IN ('info', 'warning', 'critical')),
    acknowledged          BOOLEAN NOT NULL DEFAULT false,
    acknowledged_at       TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tenant_alerts_tenant 
    ON tenant_alerts(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tenant_alerts_unack 
    ON tenant_alerts(tenant_id, acknowledged) WHERE acknowledged = false;

-- =============================================================================
-- Alert Webhook Queue (for async delivery)
-- =============================================================================
CREATE TABLE IF NOT EXISTS alert_webhook_queue (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             TEXT NOT NULL,
    alert_type            TEXT NOT NULL,
    payload               JSONB NOT NULL,
    status                TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'processing', 'delivered', 'failed')),
    attempts              INT NOT NULL DEFAULT 0,
    next_attempt_at       TIMESTAMPTZ,
    delivered_at          TIMESTAMPTZ,
    error_message         TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alert_webhook_queue_pending 
    ON alert_webhook_queue(status, next_attempt_at) WHERE status = 'pending';

-- =============================================================================
-- BYOIP Ranges (customer-owned IP ranges imported to SES)
-- =============================================================================
CREATE TABLE IF NOT EXISTS byoip_ranges (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID NOT NULL,
    cidr_block            TEXT NOT NULL, -- e.g., "198.51.100.0/24"
    aws_cidr_id           TEXT, -- AWS CIDR authorization ID after import
    status                TEXT NOT NULL DEFAULT 'pending_verification'
        CHECK (status IN ('pending_verification', 'verification_in_progress', 
                          'verified', 'provisioning', 'active', 'failed', 'deprovisioned')),
    verification_token    TEXT,
    verification_method   TEXT DEFAULT 'dns', -- 'dns' or 'email'
    message_id            TEXT, -- SES message ID for provisioning
    verified_at           TIMESTAMPTZ,
    provisioned_at        TIMESTAMPTZ,
    failure_reason        TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(cidr_block)
);

CREATE INDEX IF NOT EXISTS idx_byoip_ranges_tenant 
    ON byoip_ranges(tenant_id);
CREATE INDEX IF NOT EXISTS idx_byoip_ranges_status 
    ON byoip_ranges(status);

-- =============================================================================
-- Dedicated IP Provisioning Queue (for async AWS/Hetzner provisioning)
-- =============================================================================
CREATE TABLE IF NOT EXISTS ip_provisioning_queue (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID NOT NULL,
    request_type          TEXT NOT NULL
        CHECK (request_type IN ('ses_dedicated', 'hetzner_ip', 'byoip_import')),
    region                TEXT NOT NULL DEFAULT 'eu-west-1',
    quantity              INT NOT NULL DEFAULT 1,
    status                TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'cancelled')),
    ses_pool_name         TEXT,
    provisioned_ips       JSONB, -- Array of provisioned IP addresses
    billing_status        TEXT DEFAULT 'pending',
    error_message         TEXT,
    retry_count           INT NOT NULL DEFAULT 0,
    max_retries           INT NOT NULL DEFAULT 3,
    next_retry_at         TIMESTAMPTZ,
    started_at            TIMESTAMPTZ,
    completed_at          TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by            TEXT -- API key or system
);

CREATE INDEX IF NOT EXISTS idx_ip_provisioning_queue_pending 
    ON ip_provisioning_queue(status) WHERE status IN ('pending', 'processing');
CREATE INDEX IF NOT EXISTS idx_ip_provisioning_queue_tenant 
    ON ip_provisioning_queue(tenant_id);

-- =============================================================================
-- Data retention:auto-cleanup old metrics
-- =============================================================================
-- Keep 90 days of account metrics
CREATE INDEX IF NOT EXISTS idx_ses_account_metrics_cleanup 
    ON ses_account_metrics(recorded_at);

-- Keep 1 year of tenant metrics
CREATE INDEX IF NOT EXISTS idx_tenant_metrics_cleanup 
    ON tenant_deliverability_metrics(created_at);

COMMENT ON TABLE ses_account_metrics IS 'Historical SES account quota and reputation metrics';
COMMENT ON TABLE ses_domain_stats IS 'SES VDM domain deliverability statistics';
COMMENT ON TABLE tenant_deliverability_metrics IS 'Per-tenant bounce/complaint/delivery rates';
COMMENT ON TABLE tenant_mail_from IS 'Per-tenant custom MAIL FROM domain configuration';
COMMENT ON TABLE byoip_ranges IS 'Customer-owned IP ranges imported to SES for BYOIP';
COMMENT ON TABLE ip_provisioning_queue IS 'Async queue for dedicated IP provisioning';
