-- Migration 010: Enterprise schema completion
-- Creates missing ent_ prefixed tables for enterprise services

-- ============================================
-- 1. Support Tables
-- ============================================

CREATE TABLE IF NOT EXISTS ent_support_tickets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    account_id UUID,
    subject VARCHAR(500) NOT NULL,
    description TEXT,
    priority VARCHAR(50) DEFAULT 'normal',
    status VARCHAR(50) DEFAULT 'open',
    category VARCHAR(100),
    assigned_to UUID,
    sla_due_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    satisfaction_score INTEGER,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_support_tickets_tenant ON ent_support_tickets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ent_support_tickets_status ON ent_support_tickets(status);
CREATE INDEX IF NOT EXISTS idx_ent_support_tickets_priority ON ent_support_tickets(priority);

CREATE TABLE IF NOT EXISTS ent_ticket_comments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id UUID REFERENCES ent_support_tickets(id) ON DELETE CASCADE,
    author_id UUID,
    author_type VARCHAR(50) DEFAULT 'user',
    content TEXT NOT NULL,
    is_internal BOOLEAN DEFAULT false,
    attachments JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_ticket_comments_ticket ON ent_ticket_comments(ticket_id);

CREATE TABLE IF NOT EXISTS ent_support_agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    specializations JSONB DEFAULT '[]',
    max_concurrent_tickets INTEGER DEFAULT 10,
    is_available BOOLEAN DEFAULT true,
    current_ticket_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_support_agents_available ON ent_support_agents(is_available);

-- Alias for legacy code using ent_tickets
CREATE OR REPLACE VIEW ent_tickets AS SELECT * FROM ent_support_tickets;

-- ============================================
-- 2. QBR Tables
-- ============================================

CREATE TABLE IF NOT EXISTS ent_qbrs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    account_id UUID NOT NULL,
    quarter VARCHAR(10) NOT NULL,
    year INTEGER NOT NULL,
    status VARCHAR(50) DEFAULT 'draft',
    metrics JSONB DEFAULT '{}',
    recommendations JSONB DEFAULT '[]',
    action_items JSONB DEFAULT '[]',
    scheduled_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    presenter_id UUID,
    attendees JSONB DEFAULT '[]',
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_qbrs_account ON ent_qbrs(account_id);
CREATE INDEX IF NOT EXISTS idx_ent_qbrs_quarter ON ent_qbrs(year, quarter);
CREATE INDEX IF NOT EXISTS idx_ent_qbrs_status ON ent_qbrs(status);

-- ============================================
-- 3. Log Streaming Tables
-- ============================================

CREATE TABLE IF NOT EXISTS ent_log_streams (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    destination_type VARCHAR(50) NOT NULL,
    destination_config JSONB NOT NULL,
    event_types JSONB DEFAULT '["all"]',
    filters JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    last_delivered_at TIMESTAMPTZ,
    error_count INTEGER DEFAULT 0,
    last_error TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_log_streams_tenant ON ent_log_streams(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ent_log_streams_active ON ent_log_streams(is_active);

CREATE TABLE IF NOT EXISTS ent_stream_batches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stream_id UUID REFERENCES ent_log_streams(id) ON DELETE CASCADE,
    batch_size INTEGER NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    delivered_at TIMESTAMPTZ,
    retry_count INTEGER DEFAULT 0,
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_stream_batches_stream ON ent_stream_batches(stream_id);

-- ============================================
-- 4. Private Deployment Tables
-- ============================================

CREATE TABLE IF NOT EXISTS ent_private_deployments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    region VARCHAR(100) NOT NULL,
    cloud_provider VARCHAR(50) NOT NULL,
    cluster_config JSONB NOT NULL,
    status VARCHAR(50) DEFAULT 'provisioning',
    endpoint_url VARCHAR(500),
    ssl_certificate_id UUID,
    health_status VARCHAR(50) DEFAULT 'unknown',
    last_health_check TIMESTAMPTZ,
    monthly_cost_cents INTEGER,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_private_deploy_tenant ON ent_private_deployments(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ent_private_deploy_status ON ent_private_deployments(status);

CREATE TABLE IF NOT EXISTS ent_deployment_incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    deployment_id UUID REFERENCES ent_private_deployments(id) ON DELETE CASCADE,
    severity VARCHAR(50) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    status VARCHAR(50) DEFAULT 'investigating',
    impact VARCHAR(255),
    started_at TIMESTAMPTZ DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    root_cause TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_deploy_incidents_deploy ON ent_deployment_incidents(deployment_id);

CREATE TABLE IF NOT EXISTS ent_ssl_certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    deployment_id UUID REFERENCES ent_private_deployments(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    issuer VARCHAR(255),
    issued_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    auto_renew BOOLEAN DEFAULT true,
    status VARCHAR(50) DEFAULT 'active',
    certificate_chain TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_ssl_certs_deploy ON ent_ssl_certificates(deployment_id);
CREATE INDEX IF NOT EXISTS idx_ent_ssl_certs_expires ON ent_ssl_certificates(expires_at);

-- ============================================
-- 5. Template Approval Tables
-- ============================================

CREATE TABLE IF NOT EXISTS ent_template_submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    template_id UUID NOT NULL,
    template_version INTEGER NOT NULL,
    submitted_by UUID NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    review_notes TEXT,
    reviewed_by UUID,
    reviewed_at TIMESTAMPTZ,
    auto_checks JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_template_sub_tenant ON ent_template_submissions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ent_template_sub_status ON ent_template_submissions(status);

CREATE TABLE IF NOT EXISTS ent_template_comments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    submission_id UUID REFERENCES ent_template_submissions(id) ON DELETE CASCADE,
    author_id UUID NOT NULL,
    content TEXT NOT NULL,
    line_reference INTEGER,
    status VARCHAR(50) DEFAULT 'open',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_template_comments_sub ON ent_template_comments(submission_id);

CREATE TABLE IF NOT EXISTS ent_approval_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    conditions JSONB NOT NULL,
    required_approvers INTEGER DEFAULT 1,
    approver_roles JSONB DEFAULT '["admin"]',
    auto_approve_conditions JSONB,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_approval_rules_tenant ON ent_approval_rules(tenant_id);

CREATE TABLE IF NOT EXISTS ent_email_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    subject VARCHAR(500),
    html_content TEXT,
    text_content TEXT,
    variables JSONB DEFAULT '[]',
    category VARCHAR(100),
    is_approved BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_email_templates_tenant ON ent_email_templates(tenant_id);

-- ============================================
-- 6. Data Access/Deletion Requests (GDPR)
-- ============================================

CREATE TABLE IF NOT EXISTS ent_data_access_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    requester_email VARCHAR(255) NOT NULL,
    request_type VARCHAR(50) DEFAULT 'access',
    status VARCHAR(50) DEFAULT 'pending',
    verification_token VARCHAR(255),
    verified_at TIMESTAMPTZ,
    data_export_url VARCHAR(500),
    expires_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_data_access_tenant ON ent_data_access_requests(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ent_data_access_status ON ent_data_access_requests(status);

CREATE TABLE IF NOT EXISTS ent_data_deletion_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    requester_email VARCHAR(255) NOT NULL,
    scope JSONB DEFAULT '{}',
    status VARCHAR(50) DEFAULT 'pending',
    verification_token VARCHAR(255),
    verified_at TIMESTAMPTZ,
    scheduled_for TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    deletion_log JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_data_deletion_tenant ON ent_data_deletion_requests(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ent_data_deletion_status ON ent_data_deletion_requests(status);

-- ============================================
-- 7. BAA Documents (Healthcare)
-- ============================================

CREATE TABLE IF NOT EXISTS ent_baa_documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    document_name VARCHAR(255) NOT NULL,
    document_url VARCHAR(500),
    signed_by VARCHAR(255),
    signed_at TIMESTAMPTZ,
    effective_date DATE,
    expiration_date DATE,
    status VARCHAR(50) DEFAULT 'pending',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_baa_docs_tenant ON ent_baa_documents(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ent_baa_docs_status ON ent_baa_documents(status);

-- ============================================
-- 8. Dedicated IPs (Enterprise)
-- ============================================

CREATE TABLE IF NOT EXISTS ent_dedicated_ips (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    ip_address INET NOT NULL UNIQUE,
    pool_id UUID,
    warmup_status VARCHAR(50) DEFAULT 'warming',
    warmup_day INTEGER DEFAULT 1,
    warmup_plan JSONB DEFAULT '{}',
    reputation_score DECIMAL(5,2) DEFAULT 100.00,
    daily_volume_limit INTEGER,
    current_daily_volume INTEGER DEFAULT 0,
    last_used_at TIMESTAMPTZ,
    assigned_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_dedicated_ips_tenant ON ent_dedicated_ips(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ent_dedicated_ips_warmup ON ent_dedicated_ips(warmup_status);

-- ============================================
-- 9. Volume Allocations
-- ============================================

CREATE TABLE IF NOT EXISTS ent_volume_allocations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    ip_id UUID REFERENCES ent_dedicated_ips(id) ON DELETE CASCADE,
    date DATE NOT NULL,
    allocated_volume INTEGER NOT NULL,
    used_volume INTEGER DEFAULT 0,
    rollover_volume INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(ip_id, date)
);

CREATE INDEX IF NOT EXISTS idx_ent_volume_alloc_tenant ON ent_volume_allocations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ent_volume_alloc_date ON ent_volume_allocations(date);
