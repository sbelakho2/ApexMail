-- Migration 006: Add missing billing tables referenced in application code
-- This migration creates tables that are used by billing services but were missing from schema

-- Notification queue for billing alerts and dunning notifications
CREATE TABLE IF NOT EXISTS notification_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL, -- 'usage_alert', 'payment_reminder', 'account_soft_suspended', etc.
    payload JSONB NOT NULL DEFAULT '{}',
    status VARCHAR(20) NOT NULL DEFAULT 'pending', -- 'pending', 'sent', 'failed'
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_notification_queue_tenant ON notification_queue(tenant_id);
CREATE INDEX idx_notification_queue_status ON notification_queue(status);

-- Webhook deliveries for billing events
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL, -- 'usage.threshold_reached', etc.
    payload JSONB NOT NULL DEFAULT '{}',
    status VARCHAR(20) NOT NULL DEFAULT 'pending', -- 'pending', 'delivered', 'failed'
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_webhook_deliveries_tenant ON webhook_deliveries(tenant_id);
CREATE INDEX idx_webhook_deliveries_status ON webhook_deliveries(status);

-- Audit logs for billing actions (separate from billing_audit_log for operational auditing)
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    action VARCHAR(100) NOT NULL, -- 'plan.changed', etc.
    resource_type VARCHAR(50) NOT NULL, -- 'subscription', 'invoice', etc.
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_tenant ON audit_logs(tenant_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);

-- Proration records for plan changes
CREATE TABLE IF NOT EXISTS proration_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    stripe_subscription_id UUID REFERENCES stripe_subscriptions(id) ON DELETE CASCADE,
    old_plan VARCHAR(50),
    new_plan VARCHAR(50) NOT NULL,
    credit_amount INTEGER NOT NULL DEFAULT 0,
    charge_amount INTEGER NOT NULL DEFAULT 0,
    net_amount INTEGER NOT NULL DEFAULT 0,
    applied_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_proration_records_tenant ON proration_records(tenant_id);

-- Billing addresses for invoices
CREATE TABLE IF NOT EXISTS billing_addresses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    company_name VARCHAR(255),
    address_line1 VARCHAR(255) NOT NULL,
    address_line2 VARCHAR(255),
    city VARCHAR(100) NOT NULL,
    state VARCHAR(100),
    postal_code VARCHAR(20),
    country VARCHAR(2) NOT NULL, -- ISO 3166-1 alpha-2
    vat_number VARCHAR(50),
    email VARCHAR(255),
    is_default BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_billing_addresses_tenant ON billing_addresses(tenant_id);
CREATE UNIQUE INDEX idx_billing_addresses_default ON billing_addresses(tenant_id) WHERE is_default = true;

-- SLO breaches for SLA credit calculations
CREATE TABLE IF NOT EXISTS slo_breaches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    slo_name VARCHAR(100) NOT NULL, -- 'uptime', 'latency_p99', 'delivery_rate'
    target DECIMAL(10, 4) NOT NULL, -- target SLO value (e.g., 99.9)
    actual DECIMAL(10, 4) NOT NULL, -- actual value (e.g., 99.5)
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    credit_percentage DECIMAL(5, 2) NOT NULL DEFAULT 0, -- percentage of bill to credit
    credit_amount INTEGER NOT NULL DEFAULT 0, -- calculated credit amount (cents)
    applied_at TIMESTAMPTZ, -- when credit was applied
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_slo_breaches_tenant ON slo_breaches(tenant_id);
CREATE INDEX idx_slo_breaches_unapplied ON slo_breaches(tenant_id) WHERE applied_at IS NULL;

-- Credit memos for SLA credits and refunds
CREATE TABLE IF NOT EXISTS credit_memos (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    amount INTEGER NOT NULL, -- credit amount (cents)
    reason VARCHAR(100) NOT NULL, -- 'SLO Credit', 'refund', 'goodwill', 'billing_error'
    slo_breach_ids UUID[] DEFAULT '{}', -- array of slo_breach IDs this credit covers
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_credit_memos_tenant ON credit_memos(tenant_id);

-- Viral attributions for "powered by" footer click tracking
CREATE TABLE IF NOT EXISTS viral_attributions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    message_ref VARCHAR(255), -- reference to the email that was clicked
    clicked_at TIMESTAMPTZ,
    utm_source VARCHAR(100),
    utm_medium VARCHAR(100),
    utm_campaign VARCHAR(100),
    ip_address VARCHAR(45), -- IPv4/IPv6
    user_agent TEXT,
    converted_at TIMESTAMPTZ, -- when signup happened
    new_tenant_id VARCHAR(26) REFERENCES tenants(id) ON DELETE SET NULL, -- the new tenant that signed up
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_viral_attributions_source ON viral_attributions(source_tenant_id);
CREATE INDEX idx_viral_attributions_clicked ON viral_attributions(source_tenant_id, clicked_at);

-- Add missing last_triggered_at column to usage_alert_configs
-- This tracks when an alert threshold was last triggered (separate from generic updated_at)
ALTER TABLE usage_alert_configs 
    ADD COLUMN IF NOT EXISTS last_triggered_at TIMESTAMPTZ;
