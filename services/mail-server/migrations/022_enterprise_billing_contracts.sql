-- Enterprise contract and billing support tables migrated from the legacy TS billing app.
-- This adds the live backing tables required by the Rust enterprise and billing services.

BEGIN;

CREATE SEQUENCE IF NOT EXISTS contract_number_seq START WITH 1;

CREATE TABLE IF NOT EXISTS enterprise_contracts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    contract_number VARCHAR(30) NOT NULL UNIQUE DEFAULT ('ENT-' || LPAD(nextval('contract_number_seq')::text, 6, '0')),
    name VARCHAR(255) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'pending_signature', 'active', 'expired', 'terminated')),
    start_date TIMESTAMPTZ NOT NULL,
    end_date TIMESTAMPTZ NOT NULL,
    auto_renew BOOLEAN NOT NULL DEFAULT FALSE,
    base_price INTEGER NOT NULL DEFAULT 0 CHECK (base_price >= 0),
    committed_volume INTEGER NOT NULL DEFAULT 0 CHECK (committed_volume >= 0),
    overage_rate INTEGER NOT NULL DEFAULT 0 CHECK (overage_rate >= 0),
    annual_prepay_discount INTEGER NOT NULL DEFAULT 0 CHECK (annual_prepay_discount >= 0),
    additional_fees JSONB NOT NULL DEFAULT '[]'::jsonb,
    payment_terms_days INTEGER NOT NULL DEFAULT 30 CHECK (payment_terms_days >= 0),
    sla_credit_percentage INTEGER NOT NULL DEFAULT 10 CHECK (sla_credit_percentage >= 0),
    custom_terms TEXT,
    allow_purchase_orders BOOLEAN NOT NULL DEFAULT FALSE,
    dedicated_support BOOLEAN NOT NULL DEFAULT FALSE,
    custom_features JSONB NOT NULL DEFAULT '[]'::jsonb,
    custom_sla JSONB,
    signed_at TIMESTAMPTZ,
    signed_by VARCHAR(255),
    purchase_order_number VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_enterprise_contracts_tenant ON enterprise_contracts(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_enterprise_contracts_status ON enterprise_contracts(status);
CREATE INDEX IF NOT EXISTS idx_enterprise_contracts_end_date ON enterprise_contracts(end_date);

CREATE TABLE IF NOT EXISTS contract_signatures (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    contract_id UUID NOT NULL REFERENCES enterprise_contracts(id) ON DELETE CASCADE,
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    signature_data TEXT NOT NULL,
    signer_name VARCHAR(255) NOT NULL,
    signer_title VARCHAR(255) NOT NULL,
    signed_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_contract_signatures_contract ON contract_signatures(contract_id, signed_at DESC);

CREATE TABLE IF NOT EXISTS contract_amendments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    contract_id UUID NOT NULL REFERENCES enterprise_contracts(id) ON DELETE CASCADE,
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    reason TEXT NOT NULL,
    proposed_changes JSONB NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected', 'applied')),
    approved_at TIMESTAMPTZ,
    rejected_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_contract_amendments_contract ON contract_amendments(contract_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_contract_amendments_tenant ON contract_amendments(tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS purchase_orders (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    contract_id UUID REFERENCES enterprise_contracts(id) ON DELETE SET NULL,
    po_number VARCHAR(100) NOT NULL,
    amount INTEGER NOT NULL DEFAULT 0,
    currency VARCHAR(3) NOT NULL DEFAULT 'USD',
    issued_date TIMESTAMPTZ NOT NULL,
    expiry_date TIMESTAMPTZ,
    attachment_url TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'received'
        CHECK (status IN ('received', 'active', 'expired', 'cancelled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, po_number)
);

CREATE INDEX IF NOT EXISTS idx_purchase_orders_tenant ON purchase_orders(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_purchase_orders_contract ON purchase_orders(contract_id, created_at DESC);

CREATE TABLE IF NOT EXISTS dunning_states (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
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

CREATE INDEX IF NOT EXISTS idx_dunning_states_state ON dunning_states(dunning_state);
CREATE INDEX IF NOT EXISTS idx_dunning_next_retry ON dunning_states(next_retry_at);

CREATE TABLE IF NOT EXISTS dunning_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    action VARCHAR(50) NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dunning_history_tenant ON dunning_history(tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS sla_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    period_month DATE NOT NULL,
    uptime_percent DECIMAL(6, 4) NOT NULL DEFAULT 100.0000,
    total_minutes INTEGER NOT NULL DEFAULT 0,
    downtime_minutes INTEGER NOT NULL DEFAULT 0,
    incidents INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, period_month)
);

CREATE TABLE IF NOT EXISTS sla_credits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    period_month DATE NOT NULL,
    breach_percent DECIMAL(6, 4) NOT NULL DEFAULT 0,
    credit_percent DECIMAL(5, 2) NOT NULL DEFAULT 0,
    credit_amount INTEGER NOT NULL DEFAULT 0,
    currency VARCHAR(3) NOT NULL DEFAULT 'USD',
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    applied_at TIMESTAMPTZ,
    invoice_id UUID REFERENCES invoices(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sla_credits_tenant ON sla_credits(tenant_id, period_month DESC);
CREATE INDEX IF NOT EXISTS idx_sla_credits_status ON sla_credits(status);

CREATE TABLE IF NOT EXISTS wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    balance INTEGER NOT NULL DEFAULT 0,
    currency VARCHAR(3) NOT NULL DEFAULT 'USD',
    reserved INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id)
);

CREATE TABLE IF NOT EXISTS wallet_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    type VARCHAR(10) NOT NULL DEFAULT 'credit'
        CHECK (type IN ('credit', 'debit')),
    amount INTEGER NOT NULL DEFAULT 0,
    balance_after INTEGER NOT NULL DEFAULT 0,
    description TEXT NOT NULL DEFAULT '',
    reference VARCHAR(255),
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_wallet_transactions_tenant ON wallet_transactions(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_wallet_transactions_created ON wallet_transactions(created_at DESC);

CREATE TABLE IF NOT EXISTS wallet_reservations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    amount INTEGER NOT NULL DEFAULT 0,
    description TEXT NOT NULL DEFAULT '',
    reference VARCHAR(255),
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '24 hours'),
    captured_at TIMESTAMPTZ,
    released_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_wallet_reservations_status ON wallet_reservations(status);
CREATE INDEX IF NOT EXISTS idx_wallet_reservations_expires ON wallet_reservations(expires_at);

CREATE TABLE IF NOT EXISTS tenant_costs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
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

CREATE INDEX IF NOT EXISTS idx_tenant_costs_date ON tenant_costs(recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_tenant_costs_margin ON tenant_costs(margin_percent);

CREATE TABLE IF NOT EXISTS cost_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    alert_type VARCHAR(30) NOT NULL,
    margin_percent DECIMAL(5, 2),
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cost_alerts_tenant ON cost_alerts(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cost_alerts_unresolved ON cost_alerts(tenant_id) WHERE resolved_at IS NULL;

CREATE TABLE IF NOT EXISTS billing_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) REFERENCES tenants(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    actor_id UUID,
    actor_type VARCHAR(20) NOT NULL DEFAULT 'system',
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_billing_audit_tenant ON billing_audit_log(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_billing_audit_action ON billing_audit_log(action);

CREATE OR REPLACE FUNCTION enterprise_billing_update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$
DECLARE
    table_name TEXT;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'enterprise_contracts',
        'dunning_states',
        'wallets',
        'sla_metrics'
    ]
    LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS update_%I_updated_at ON %I', table_name, table_name);
        EXECUTE format(
            'CREATE TRIGGER update_%I_updated_at BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION enterprise_billing_update_updated_at_column()',
            table_name,
            table_name
        );
    END LOOP;
END $$;

COMMIT;