-- Billing System Database Schema Migration
-- Phase 11: Billing, Metering & Monetization

BEGIN;

-- Plans table
CREATE TABLE IF NOT EXISTS plans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    price_monthly INTEGER NOT NULL DEFAULT 0,
    price_yearly INTEGER NOT NULL DEFAULT 0,
    currency VARCHAR(3) NOT NULL DEFAULT 'USD',
    stripe_price_id_monthly VARCHAR(255),
    stripe_price_id_yearly VARCHAR(255),
    features JSONB NOT NULL DEFAULT '{}',
    limits JSONB NOT NULL DEFAULT '{}',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_plans_active ON plans(is_active);

-- Plan overrides (admin-applied)
CREATE TABLE IF NOT EXISTS plan_overrides (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    plan_id UUID NOT NULL REFERENCES plans(id),
    reason TEXT NOT NULL,
    admin_id UUID NOT NULL,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ,
    UNIQUE(tenant_id)
);

-- Stripe customers
CREATE TABLE IF NOT EXISTS stripe_customers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    stripe_customer_id VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255),
    name VARCHAR(255),
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id)
);

CREATE INDEX idx_stripe_customers_stripe_id ON stripe_customers(stripe_customer_id);

-- Stripe subscriptions
CREATE TABLE IF NOT EXISTS stripe_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    stripe_subscription_id VARCHAR(255) UNIQUE NOT NULL,
    stripe_customer_id VARCHAR(255) NOT NULL,
    plan_id UUID REFERENCES plans(id),
    status VARCHAR(50) NOT NULL DEFAULT 'incomplete',
    amount INTEGER NOT NULL DEFAULT 0,
    currency VARCHAR(3) NOT NULL DEFAULT 'USD',
    billing_interval VARCHAR(20) NOT NULL DEFAULT 'month',
    current_period_start TIMESTAMPTZ,
    current_period_end TIMESTAMPTZ,
    cancel_at TIMESTAMPTZ,
    canceled_at TIMESTAMPTZ,
    trial_start TIMESTAMPTZ,
    trial_end TIMESTAMPTZ,
    admin_override_at TIMESTAMPTZ,
    admin_override_by UUID,
    admin_override_reason TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id)
);

CREATE INDEX idx_stripe_subscriptions_status ON stripe_subscriptions(status);
CREATE INDEX idx_stripe_subscriptions_stripe_id ON stripe_subscriptions(stripe_subscription_id);

-- Stripe webhook events (idempotency)
CREATE TABLE IF NOT EXISTS stripe_webhook_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stripe_event_id VARCHAR(255) UNIQUE NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    result JSONB
);

CREATE INDEX idx_stripe_webhook_events_type ON stripe_webhook_events(event_type);

-- Invoices
CREATE TABLE IF NOT EXISTS invoices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    invoice_number VARCHAR(20) UNIQUE NOT NULL,
    stripe_invoice_id VARCHAR(255) UNIQUE,
    status VARCHAR(20) NOT NULL DEFAULT 'draft',
    subtotal INTEGER NOT NULL DEFAULT 0,
    tax_amount INTEGER NOT NULL DEFAULT 0,
    tax_rate DECIMAL(5, 2) NOT NULL DEFAULT 0,
    total INTEGER NOT NULL DEFAULT 0,
    currency VARCHAR(3) NOT NULL DEFAULT 'USD',
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    due_date TIMESTAMPTZ NOT NULL,
    issued_at TIMESTAMPTZ,
    paid_at TIMESTAMPTZ,
    voided_at TIMESTAMPTZ,
    billing_details JSONB NOT NULL DEFAULT '{}',
    line_items JSONB NOT NULL DEFAULT '[]',
    notes TEXT,
    pdf_url TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_invoices_tenant ON invoices(tenant_id);
CREATE INDEX idx_invoices_status ON invoices(status);
CREATE INDEX idx_invoices_issued_at ON invoices(issued_at);

-- Invoice number sequence
CREATE SEQUENCE IF NOT EXISTS invoice_number_seq START WITH 1;

-- Metering events
CREATE TABLE IF NOT EXISTS metering_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    quantity BIGINT NOT NULL DEFAULT 1,
    period_key VARCHAR(10) NOT NULL,
    idempotency_key VARCHAR(255) UNIQUE,
    metadata JSONB DEFAULT '{}',
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_metering_events_tenant_period ON metering_events(tenant_id, period_key);
CREATE INDEX idx_metering_events_type ON metering_events(event_type);
CREATE INDEX idx_metering_events_recorded ON metering_events(recorded_at);

-- Metering aggregates (daily rollups)
CREATE TABLE IF NOT EXISTS metering_aggregates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    period_date DATE NOT NULL,
    total_quantity BIGINT NOT NULL DEFAULT 0,
    event_count INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, event_type, period_date)
);

CREATE INDEX idx_metering_aggregates_date ON metering_aggregates(period_date);

-- Usage alerts configuration
CREATE TABLE IF NOT EXISTS usage_alert_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    metric_type VARCHAR(50) NOT NULL,
    threshold_percent INTEGER NOT NULL,
    notification_channel VARCHAR(20) NOT NULL DEFAULT 'email',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, metric_type, threshold_percent)
);

-- Usage alerts sent
CREATE TABLE IF NOT EXISTS usage_alerts_sent (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    config_id UUID NOT NULL REFERENCES usage_alert_configs(id) ON DELETE CASCADE,
    period_key VARCHAR(10) NOT NULL,
    current_usage BIGINT NOT NULL,
    threshold_value BIGINT NOT NULL,
    sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(config_id, period_key)
);

-- Dunning states
CREATE TABLE IF NOT EXISTS dunning_states (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    dunning_state VARCHAR(30) NOT NULL DEFAULT 'healthy',
    amount_owed INTEGER NOT NULL DEFAULT 0,
    currency VARCHAR(3) NOT NULL DEFAULT 'USD',
    failure_reason TEXT,
    payment_processor VARCHAR(20) NOT NULL DEFAULT 'stripe',
    retry_count INTEGER NOT NULL DEFAULT 0,
    last_retry_at TIMESTAMPTZ,
    next_retry_at TIMESTAMPTZ,
    soft_suspended_at TIMESTAMPTZ,
    hard_suspended_at TIMESTAMPTZ,
    grace_period_ends_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id)
);

CREATE INDEX idx_dunning_states_state ON dunning_states(dunning_state);
CREATE INDEX idx_dunning_next_retry ON dunning_states(next_retry_at);

-- Dunning history
CREATE TABLE IF NOT EXISTS dunning_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    action VARCHAR(50) NOT NULL,
    details JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_dunning_history_tenant ON dunning_history(tenant_id);

-- SLA metrics
CREATE TABLE IF NOT EXISTS sla_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    period_month DATE NOT NULL,
    uptime_percent DECIMAL(6, 4) NOT NULL DEFAULT 100.0000,
    total_minutes INTEGER NOT NULL DEFAULT 0,
    downtime_minutes INTEGER NOT NULL DEFAULT 0,
    incidents INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, period_month)
);

-- SLA credits
CREATE TABLE IF NOT EXISTS sla_credits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    period_month DATE NOT NULL,
    breach_percent DECIMAL(6, 4) NOT NULL,
    credit_percent DECIMAL(5, 2) NOT NULL,
    credit_amount INTEGER NOT NULL,
    currency VARCHAR(3) NOT NULL DEFAULT 'USD',
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    applied_at TIMESTAMPTZ,
    invoice_id UUID REFERENCES invoices(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sla_credits_tenant ON sla_credits(tenant_id);
CREATE INDEX idx_sla_credits_status ON sla_credits(status);

-- Wallets
CREATE TABLE IF NOT EXISTS wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    balance INTEGER NOT NULL DEFAULT 0,
    currency VARCHAR(3) NOT NULL DEFAULT 'USD',
    reserved INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id)
);

-- Wallet transactions
CREATE TABLE IF NOT EXISTS wallet_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    type VARCHAR(10) NOT NULL,
    amount INTEGER NOT NULL,
    balance_after INTEGER NOT NULL,
    description TEXT NOT NULL,
    reference VARCHAR(255),
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_wallet_transactions_tenant ON wallet_transactions(tenant_id);
CREATE INDEX idx_wallet_transactions_created ON wallet_transactions(created_at);

-- Wallet reservations
CREATE TABLE IF NOT EXISTS wallet_reservations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    amount INTEGER NOT NULL,
    description TEXT NOT NULL,
    reference VARCHAR(255),
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    expires_at TIMESTAMPTZ NOT NULL,
    captured_at TIMESTAMPTZ,
    released_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_wallet_reservations_status ON wallet_reservations(status);
CREATE INDEX idx_wallet_reservations_expires ON wallet_reservations(expires_at);

-- Enterprise contracts
CREATE TABLE IF NOT EXISTS enterprise_contracts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    contract_number VARCHAR(30) UNIQUE NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'draft',
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    base_fee INTEGER NOT NULL,
    currency VARCHAR(3) NOT NULL DEFAULT 'USD',
    committed_volume JSONB NOT NULL DEFAULT '{}',
    overage_rates JSONB NOT NULL DEFAULT '{}',
    payment_terms VARCHAR(20) NOT NULL DEFAULT 'net30',
    allow_purchase_orders BOOLEAN NOT NULL DEFAULT FALSE,
    dedicated_support BOOLEAN NOT NULL DEFAULT FALSE,
    custom_features JSONB DEFAULT '[]',
    custom_sla JSONB,
    signature_data TEXT,
    signer_name VARCHAR(255),
    signer_title VARCHAR(255),
    signed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_enterprise_contracts_tenant ON enterprise_contracts(tenant_id);
CREATE INDEX idx_enterprise_contracts_status ON enterprise_contracts(status);
CREATE INDEX idx_enterprise_contracts_end_date ON enterprise_contracts(end_date);

-- Contract number sequence
CREATE SEQUENCE IF NOT EXISTS contract_number_seq START WITH 1;

-- Contract amendments
CREATE TABLE IF NOT EXISTS contract_amendments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    contract_id UUID NOT NULL REFERENCES enterprise_contracts(id) ON DELETE CASCADE,
    reason TEXT NOT NULL,
    proposed_changes JSONB NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    approved_at TIMESTAMPTZ,
    rejected_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_contract_amendments_contract ON contract_amendments(contract_id);

-- Purchase orders
CREATE TABLE IF NOT EXISTS purchase_orders (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    contract_id UUID REFERENCES enterprise_contracts(id) ON DELETE SET NULL,
    po_number VARCHAR(100) NOT NULL,
    amount INTEGER NOT NULL,
    currency VARCHAR(3) NOT NULL DEFAULT 'USD',
    issued_date DATE NOT NULL,
    expiry_date DATE,
    attachment_url TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_purchase_orders_tenant ON purchase_orders(tenant_id);
CREATE INDEX idx_purchase_orders_contract ON purchase_orders(contract_id);

-- Viral loop tracking
CREATE TABLE IF NOT EXISTS viral_impressions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    referrer_tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email_id UUID,
    recipient_domain VARCHAR(255) NOT NULL,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_viral_impressions_referrer ON viral_impressions(referrer_tenant_id);
CREATE INDEX idx_viral_impressions_created ON viral_impressions(created_at);

-- Viral clicks
CREATE TABLE IF NOT EXISTS viral_clicks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    impression_id UUID REFERENCES viral_impressions(id) ON DELETE SET NULL,
    referrer_tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    click_url TEXT NOT NULL,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_viral_clicks_referrer ON viral_clicks(referrer_tenant_id);

-- Viral conversions
CREATE TABLE IF NOT EXISTS viral_conversions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    referrer_tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    converted_tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    click_id UUID REFERENCES viral_clicks(id) ON DELETE SET NULL,
    conversion_type VARCHAR(30) NOT NULL DEFAULT 'signup',
    attributed BOOLEAN NOT NULL DEFAULT FALSE,
    attributed_at TIMESTAMPTZ,
    reward_issued BOOLEAN NOT NULL DEFAULT FALSE,
    reward_amount INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(converted_tenant_id)
);

CREATE INDEX idx_viral_conversions_referrer ON viral_conversions(referrer_tenant_id);
CREATE INDEX idx_viral_conversions_attributed ON viral_conversions(attributed);

-- Tenant costs
CREATE TABLE IF NOT EXISTS tenant_costs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    recorded_at DATE NOT NULL,
    storage_gb DECIMAL(12, 4) NOT NULL DEFAULT 0,
    storage_cost INTEGER NOT NULL DEFAULT 0,
    bandwidth_gb DECIMAL(12, 4) NOT NULL DEFAULT 0,
    bandwidth_cost INTEGER NOT NULL DEFAULT 0,
    compute_hours DECIMAL(12, 4) NOT NULL DEFAULT 0,
    compute_cost INTEGER NOT NULL DEFAULT 0,
    dedicated_ip_hours DECIMAL(12, 4) NOT NULL DEFAULT 0,
    dedicated_ip_cost INTEGER NOT NULL DEFAULT 0,
    total_cost INTEGER NOT NULL DEFAULT 0,
    revenue INTEGER NOT NULL DEFAULT 0,
    margin_percent DECIMAL(5, 2),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, recorded_at)
);

CREATE INDEX idx_tenant_costs_date ON tenant_costs(recorded_at);
CREATE INDEX idx_tenant_costs_margin ON tenant_costs(margin_percent);

-- Cost alerts
CREATE TABLE IF NOT EXISTS cost_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    alert_type VARCHAR(30) NOT NULL,
    margin_percent DECIMAL(5, 2),
    details JSONB DEFAULT '{}',
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_cost_alerts_tenant ON cost_alerts(tenant_id);
CREATE INDEX idx_cost_alerts_unresolved ON cost_alerts(tenant_id) WHERE resolved_at IS NULL;

-- Billing audit log
CREATE TABLE IF NOT EXISTS billing_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    actor_id UUID,
    actor_type VARCHAR(20) NOT NULL,
    details JSONB DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_billing_audit_tenant ON billing_audit_log(tenant_id);
CREATE INDEX idx_billing_audit_action ON billing_audit_log(action);
CREATE INDEX idx_billing_audit_created ON billing_audit_log(created_at);

-- Insert default plans
INSERT INTO plans (name, display_name, description, price_monthly, price_yearly, features, limits, sort_order) VALUES
('free', 'Free', 'Get started with email delivery', 0, 0,
 '{"api_access": true, "smtp_relay": true, "webhooks": true, "basic_analytics": true}',
 '{"emails_per_month": 1000, "contacts_limit": 100, "api_calls_per_minute": 60, "webhooks_per_day": 100, "team_members_limit": 1, "storage_gb": 1, "dedicated_ips": 0, "custom_domains_limit": 1}',
 1),
('starter', 'Starter', 'Perfect for growing businesses', 2900, 29000,
 '{"api_access": true, "smtp_relay": true, "webhooks": true, "basic_analytics": true, "email_templates": true, "dedicated_ip_available": true, "priority_support": true}',
 '{"emails_per_month": 50000, "contacts_limit": 5000, "api_calls_per_minute": 300, "webhooks_per_day": 1000, "team_members_limit": 3, "storage_gb": 10, "dedicated_ips": 1, "custom_domains_limit": 5}',
 2),
('pro', 'Pro', 'For scaling teams with custom tracking needs', 5900, 59000,
 '{"api_access": true, "smtp_relay": true, "webhooks": true, "basic_analytics": true, "advanced_analytics": true, "email_templates": true, "dedicated_ip_available": true, "priority_support": true, "a_b_testing": true}',
 '{"emails_per_month": 100000, "contacts_limit": 10000, "api_calls_per_minute": 450, "webhooks_per_day": 2500, "team_members_limit": 5, "storage_gb": 25, "dedicated_ips": 2, "custom_domains_limit": 10}',
 3),
('growth', 'Growth', 'Scale your email operations', 12900, 129000,
 '{"api_access": true, "smtp_relay": true, "webhooks": true, "basic_analytics": true, "advanced_analytics": true, "email_templates": true, "dedicated_ip_available": true, "priority_support": true, "a_b_testing": true, "automation": true}',
 '{"emails_per_month": 250000, "contacts_limit": 25000, "api_calls_per_minute": 600, "webhooks_per_day": 5000, "team_members_limit": 10, "storage_gb": 50, "dedicated_ips": 3, "custom_domains_limit": 20}',
 4),
('scale', 'Scale', 'Enterprise-grade email at scale', 39900, 399000,
 '{"api_access": true, "smtp_relay": true, "webhooks": true, "basic_analytics": true, "advanced_analytics": true, "email_templates": true, "dedicated_ip_available": true, "priority_support": true, "a_b_testing": true, "automation": true, "custom_tracking_domain": true, "sso": true, "audit_logs": true}',
 '{"emails_per_month": 1000000, "contacts_limit": 100000, "api_calls_per_minute": 1200, "webhooks_per_day": 25000, "team_members_limit": 25, "storage_gb": 200, "dedicated_ips": 10, "custom_domains_limit": 50}',
 5),
('enterprise', 'Enterprise', 'Custom solutions for large organizations', 129900, 1299000,
 '{"api_access": true, "smtp_relay": true, "webhooks": true, "basic_analytics": true, "advanced_analytics": true, "email_templates": true, "dedicated_ip_available": true, "priority_support": true, "a_b_testing": true, "automation": true, "custom_tracking_domain": true, "sso": true, "audit_logs": true, "dedicated_account_manager": true, "custom_sla": true, "on_premise_available": true, "hipaa_compliant": true}',
 '{"emails_per_month": -1, "contacts_limit": -1, "api_calls_per_minute": -1, "webhooks_per_day": -1, "team_members_limit": -1, "storage_gb": -1, "dedicated_ips": -1, "custom_domains_limit": -1}',
 6)
ON CONFLICT (name) DO NOTHING;

-- Trigger to update updated_at timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply triggers to tables with updated_at
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['plans', 'stripe_customers', 'stripe_subscriptions', 'invoices', 'metering_aggregates', 'usage_alert_configs', 'dunning_states', 'wallets', 'enterprise_contracts']
    LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS update_%I_updated_at ON %I', t, t);
        EXECUTE format('CREATE TRIGGER update_%I_updated_at BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()', t, t);
    END LOOP;
END $$;

COMMIT;
