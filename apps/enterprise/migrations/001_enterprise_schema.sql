-- Enterprise Service Database Schema
-- Migration: 001_enterprise_schema.sql
-- Description: Creates all tables for enterprise features including SSO, sub-accounts,
--              white-label, template approval, log streaming, compliance, deployments,
--              support tickets, and QBR management.

BEGIN;

-- ==================== ENUMS ====================

CREATE TYPE sso_provider AS ENUM ('saml', 'oidc', 'azure_ad', 'okta', 'google_workspace', 'onelogin');
CREATE TYPE sso_status AS ENUM ('pending', 'active', 'disabled', 'error');

CREATE TYPE sub_account_status AS ENUM ('active', 'suspended', 'pending', 'deleted');

CREATE TYPE domain_type AS ENUM ('sending', 'tracking', 'landing', 'unsubscribe', 'custom');
CREATE TYPE domain_verification_status AS ENUM ('pending', 'verified', 'failed', 'expired');
CREATE TYPE verification_method AS ENUM ('dns_txt', 'dns_cname', 'file', 'meta_tag');

CREATE TYPE template_approval_status AS ENUM ('pending', 'approved', 'rejected', 'changes_requested', 'expired', 'revoked');
CREATE TYPE template_type AS ENUM ('marketing', 'transactional', 'notification', 'newsletter', 'promotional', 'system');

CREATE TYPE stream_destination_type AS ENUM ('s3', 'gcs', 'azure_blob', 'webhook', 'splunk', 'datadog', 'sumologic', 'elasticsearch');
CREATE TYPE stream_status AS ENUM ('active', 'paused', 'error', 'disabled');
CREATE TYPE log_category AS ENUM ('delivery', 'engagement', 'bounce', 'complaint', 'security', 'api', 'webhook', 'all');

CREATE TYPE compliance_framework AS ENUM ('hipaa', 'soc2', 'gdpr', 'ccpa', 'pci_dss', 'iso_27001');
CREATE TYPE compliance_status AS ENUM ('pending', 'active', 'expired', 'revoked');
CREATE TYPE data_request_status AS ENUM ('pending', 'approved', 'rejected', 'completed', 'expired');
CREATE TYPE data_request_type AS ENUM ('access', 'deletion');

CREATE TYPE deployment_type AS ENUM ('shared', 'dedicated', 'private_cloud', 'on_premise');
CREATE TYPE deployment_status AS ENUM ('pending', 'provisioning', 'active', 'maintenance', 'suspended', 'terminated');
CREATE TYPE ip_status AS ENUM ('pending', 'warming', 'active', 'suspended', 'retired');
CREATE TYPE byoip_status AS ENUM ('pending_verification', 'verified', 'provisioning', 'active', 'suspended');

CREATE TYPE ticket_status AS ENUM ('new', 'open', 'in_progress', 'waiting_on_customer', 'waiting_on_agent', 'escalated', 'resolved', 'closed');
CREATE TYPE ticket_priority AS ENUM ('low', 'medium', 'high', 'critical');
CREATE TYPE ticket_category AS ENUM ('billing', 'technical', 'deliverability', 'account', 'feature_request', 'security', 'api', 'compliance', 'other');
CREATE TYPE author_type AS ENUM ('customer', 'agent', 'system');

CREATE TYPE qbr_status AS ENUM ('scheduled', 'preparing', 'ready', 'delivered', 'completed', 'cancelled');
CREATE TYPE goal_status AS ENUM ('not_started', 'in_progress', 'at_risk', 'completed', 'missed');

-- ==================== SSO TABLES ====================

CREATE TABLE sso_configurations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider sso_provider NOT NULL,
    status sso_status NOT NULL DEFAULT 'pending',
    enabled BOOLEAN NOT NULL DEFAULT false,
    
    -- SAML Configuration
    saml_entity_id TEXT,
    saml_sso_url TEXT,
    saml_slo_url TEXT,
    saml_certificate TEXT,
    saml_sign_authn_requests BOOLEAN DEFAULT true,
    saml_want_assertions_signed BOOLEAN DEFAULT true,
    saml_name_id_format TEXT DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    
    -- OIDC Configuration
    oidc_issuer TEXT,
    oidc_client_id TEXT,
    oidc_client_secret_encrypted TEXT,
    oidc_authorization_url TEXT,
    oidc_token_url TEXT,
    oidc_userinfo_url TEXT,
    oidc_jwks_uri TEXT,
    oidc_scopes TEXT[] DEFAULT ARRAY['openid', 'email', 'profile'],
    
    -- General Settings
    domain TEXT UNIQUE,
    enforce_sso BOOLEAN DEFAULT false,
    allow_password_login BOOLEAN DEFAULT true,
    auto_provision_users BOOLEAN DEFAULT true,
    default_role TEXT DEFAULT 'user',
    attribute_mapping JSONB DEFAULT '{}',
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(tenant_id)
);

CREATE TABLE sso_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    sso_config_id UUID NOT NULL REFERENCES sso_configurations(id) ON DELETE CASCADE,
    session_token TEXT NOT NULL UNIQUE,
    idp_session_id TEXT,
    user_email TEXT NOT NULL,
    user_attributes JSONB DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_activity_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE sso_oidc_state (
    state TEXT PRIMARY KEY,
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    code_verifier TEXT,
    redirect_uri TEXT,
    nonce TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_sso_config_account ON sso_configurations(tenant_id);
CREATE INDEX idx_sso_config_domain ON sso_configurations(domain) WHERE domain IS NOT NULL;
CREATE INDEX idx_sso_sessions_user ON sso_sessions(user_id);
CREATE INDEX idx_sso_sessions_token ON sso_sessions(session_token);
CREATE INDEX idx_sso_sessions_expires ON sso_sessions(expires_at);

-- ==================== SUB-ACCOUNT TABLES ====================

CREATE TABLE sub_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    company_name TEXT,
    contact_email TEXT NOT NULL,
    contact_name TEXT,
    status sub_account_status NOT NULL DEFAULT 'active',
    
    -- Volume Allocation
    allocated_volume_monthly BIGINT NOT NULL DEFAULT 0,
    allocated_volume_daily BIGINT,
    used_volume_monthly BIGINT NOT NULL DEFAULT 0,
    used_volume_daily BIGINT NOT NULL DEFAULT 0,
    overage_allowed BOOLEAN DEFAULT false,
    overage_limit_percent INTEGER DEFAULT 10,
    
    -- Settings
    settings JSONB DEFAULT '{}',
    custom_metadata JSONB DEFAULT '{}',
    webhook_url TEXT,
    webhook_secret TEXT,
    
    -- Tracking
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    suspended_at TIMESTAMPTZ,
    suspension_reason TEXT,
    deleted_at TIMESTAMPTZ,
    
    UNIQUE(parent_tenant_id, name)
);

CREATE TABLE sub_account_api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sub_tenant_id UUID NOT NULL REFERENCES sub_accounts(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT ARRAY['send'],
    last_used_at TIMESTAMPTZ,
    last_used_ip INET,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    
    UNIQUE(key_prefix)
);

CREATE TABLE sub_account_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sub_tenant_id UUID NOT NULL REFERENCES sub_accounts(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    event_data JSONB DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sub_accounts_parent ON sub_accounts(parent_tenant_id);
CREATE INDEX idx_sub_accounts_status ON sub_accounts(status);
CREATE INDEX idx_sub_account_keys_sub ON sub_account_api_keys(sub_tenant_id);
CREATE INDEX idx_sub_account_events_sub ON sub_account_events(sub_tenant_id, created_at DESC);

-- ==================== WHITE-LABEL TABLES ====================

CREATE TABLE whitelabel_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT false,
    
    -- Branding
    company_name TEXT,
    logo_url TEXT,
    logo_dark_url TEXT,
    favicon_url TEXT,
    primary_color TEXT DEFAULT '#4F46E5',
    secondary_color TEXT DEFAULT '#10B981',
    accent_color TEXT DEFAULT '#F59E0B',
    font_family TEXT DEFAULT 'Inter, system-ui, sans-serif',
    custom_css TEXT,
    
    -- Links
    support_url TEXT,
    documentation_url TEXT,
    privacy_policy_url TEXT,
    terms_of_service_url TEXT,
    
    -- Contact
    support_email TEXT,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(tenant_id)
);

CREATE TABLE whitelabel_domains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_id UUID NOT NULL REFERENCES whitelabel_configs(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    type domain_type NOT NULL,
    verification_status domain_verification_status NOT NULL DEFAULT 'pending',
    verification_method verification_method NOT NULL DEFAULT 'dns_txt',
    verification_token TEXT NOT NULL,
    verification_record TEXT,
    verified_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    ssl_certificate_id TEXT,
    ssl_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(domain)
);

CREATE TABLE whitelabel_email_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    name TEXT NOT NULL,
    subject TEXT,
    html_content TEXT,
    text_content TEXT,
    variables JSONB DEFAULT '[]',
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(tenant_id, type)
);

CREATE INDEX idx_whitelabel_config_account ON whitelabel_configs(tenant_id);
CREATE INDEX idx_whitelabel_domains_config ON whitelabel_domains(config_id);
CREATE INDEX idx_whitelabel_domains_domain ON whitelabel_domains(domain);
CREATE INDEX idx_whitelabel_templates_account ON whitelabel_email_templates(tenant_id);

-- ==================== TEMPLATE APPROVAL TABLES ====================

CREATE TABLE template_submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    template_type template_type NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    subject_template TEXT,
    html_content TEXT NOT NULL,
    text_content TEXT,
    headers JSONB DEFAULT '{}',
    variables JSONB DEFAULT '[]',
    sample_data JSONB DEFAULT '{}',
    
    -- Submission Info
    submitted_by UUID NOT NULL,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status template_approval_status NOT NULL DEFAULT 'pending',
    
    -- Review Info
    reviewed_by UUID,
    reviewed_at TIMESTAMPTZ,
    reviewer_notes TEXT,
    rejection_reason TEXT,
    
    -- Scoring
    spam_score INTEGER,
    spam_details JSONB DEFAULT '{}',
    compliance_check_passed BOOLEAN,
    compliance_issues JSONB DEFAULT '[]',
    
    -- Version Info
    version INTEGER NOT NULL DEFAULT 1,
    previous_version_id UUID REFERENCES template_submissions(id),
    
    -- Expiration
    expires_at TIMESTAMPTZ,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE template_approval_comments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    submission_id UUID NOT NULL REFERENCES template_submissions(id) ON DELETE CASCADE,
    author_id UUID NOT NULL,
    author_name TEXT NOT NULL,
    author_type author_type NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE template_approval_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    priority INTEGER NOT NULL DEFAULT 0,
    conditions JSONB NOT NULL DEFAULT '{}',
    action TEXT NOT NULL DEFAULT 'flag',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_template_submissions_account ON template_submissions(tenant_id);
CREATE INDEX idx_template_submissions_status ON template_submissions(status);
CREATE INDEX idx_template_submissions_submitted ON template_submissions(submitted_at DESC);
CREATE INDEX idx_template_comments_submission ON template_approval_comments(submission_id, created_at);
CREATE INDEX idx_template_rules_account ON template_approval_rules(tenant_id, priority);

-- ==================== LOG STREAMING TABLES ====================

CREATE TABLE log_streams (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    destination_type stream_destination_type NOT NULL,
    status stream_status NOT NULL DEFAULT 'active',
    enabled BOOLEAN NOT NULL DEFAULT true,
    
    -- Destination Configuration (encrypted sensitive fields)
    destination_config JSONB NOT NULL DEFAULT '{}',
    credentials_encrypted TEXT,
    
    -- Filter Settings
    log_categories log_category[] DEFAULT ARRAY['all']::log_category[],
    filter_rules JSONB DEFAULT '[]',
    
    -- Batch Settings
    batch_size INTEGER DEFAULT 1000,
    batch_interval_seconds INTEGER DEFAULT 60,
    compression_enabled BOOLEAN DEFAULT true,
    format TEXT DEFAULT 'json',
    
    -- Stats
    last_delivery_at TIMESTAMPTZ,
    last_error TEXT,
    last_error_at TIMESTAMPTZ,
    total_events_delivered BIGINT DEFAULT 0,
    total_bytes_delivered BIGINT DEFAULT 0,
    delivery_failures_count INTEGER DEFAULT 0,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE log_stream_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stream_id UUID NOT NULL REFERENCES log_streams(id) ON DELETE CASCADE,
    batch_id TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    bytes_delivered BIGINT NOT NULL,
    duration_ms INTEGER,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_log_streams_account ON log_streams(tenant_id);
CREATE INDEX idx_log_streams_status ON log_streams(status) WHERE enabled = true;
CREATE INDEX idx_log_deliveries_stream ON log_stream_deliveries(stream_id, created_at DESC);

-- ==================== COMPLIANCE TABLES ====================

CREATE TABLE compliance_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    enabled_frameworks compliance_framework[] NOT NULL DEFAULT '{}',
    status compliance_status NOT NULL DEFAULT 'pending',
    
    -- Settings
    zero_retention_mode BOOLEAN DEFAULT false,
    encryption_at_rest BOOLEAN DEFAULT true,
    encryption_in_transit BOOLEAN DEFAULT true,
    audit_log_retention_days INTEGER DEFAULT 365,
    data_retention_days INTEGER DEFAULT 90,
    require_mfa BOOLEAN DEFAULT true,
    ip_whitelist INET[] DEFAULT '{}',
    
    -- BAA (HIPAA)
    baa_signed BOOLEAN DEFAULT false,
    baa_signed_at TIMESTAMPTZ,
    baa_signatory_name TEXT,
    baa_signatory_title TEXT,
    baa_signatory_email TEXT,
    baa_document_id TEXT,
    baa_version TEXT,
    
    -- DPA (GDPR)
    dpa_signed BOOLEAN DEFAULT false,
    dpa_signed_at TIMESTAMPTZ,
    dpa_document_id TEXT,
    
    -- Certification
    last_audit_at TIMESTAMPTZ,
    next_audit_at TIMESTAMPTZ,
    audit_report_url TEXT,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(tenant_id)
);

CREATE TABLE compliance_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL,
    user_id UUID,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    old_value JSONB,
    new_value JSONB,
    ip_address INET,
    user_agent TEXT,
    session_id TEXT,
    request_id TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
) PARTITION BY RANGE (created_at);

-- Create partitions for audit logs (1 per quarter for 2 years)
CREATE TABLE compliance_audit_logs_2024_q1 PARTITION OF compliance_audit_logs
    FOR VALUES FROM ('2024-01-01') TO ('2024-04-01');
CREATE TABLE compliance_audit_logs_2024_q2 PARTITION OF compliance_audit_logs
    FOR VALUES FROM ('2024-04-01') TO ('2024-07-01');
CREATE TABLE compliance_audit_logs_2024_q3 PARTITION OF compliance_audit_logs
    FOR VALUES FROM ('2024-07-01') TO ('2024-10-01');
CREATE TABLE compliance_audit_logs_2024_q4 PARTITION OF compliance_audit_logs
    FOR VALUES FROM ('2024-10-01') TO ('2025-01-01');
CREATE TABLE compliance_audit_logs_2025_q1 PARTITION OF compliance_audit_logs
    FOR VALUES FROM ('2025-01-01') TO ('2025-04-01');
CREATE TABLE compliance_audit_logs_2025_q2 PARTITION OF compliance_audit_logs
    FOR VALUES FROM ('2025-04-01') TO ('2025-07-01');
CREATE TABLE compliance_audit_logs_2025_q3 PARTITION OF compliance_audit_logs
    FOR VALUES FROM ('2025-07-01') TO ('2025-10-01');
CREATE TABLE compliance_audit_logs_2025_q4 PARTITION OF compliance_audit_logs
    FOR VALUES FROM ('2025-10-01') TO ('2026-01-01');

CREATE TABLE data_access_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    type data_request_type NOT NULL,
    status data_request_status NOT NULL DEFAULT 'pending',
    requester_id UUID NOT NULL,
    requester_email TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    scope TEXT,
    identifiers JSONB DEFAULT '[]',
    justification TEXT NOT NULL,
    reason TEXT,
    
    -- Access grant details
    approved_by UUID,
    approved_at TIMESTAMPTZ,
    reviewer_notes TEXT,
    access_token TEXT,
    expires_at TIMESTAMPTZ,
    duration_minutes INTEGER,
    
    -- Completion tracking
    completed_at TIMESTAMPTZ,
    completion_details JSONB,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_compliance_config_account ON compliance_configs(tenant_id);
CREATE INDEX idx_compliance_audit_account ON compliance_audit_logs(tenant_id, created_at DESC);
CREATE INDEX idx_compliance_audit_user ON compliance_audit_logs(user_id, created_at DESC);
CREATE INDEX idx_compliance_audit_action ON compliance_audit_logs(action, created_at DESC);
CREATE INDEX idx_data_access_account ON data_access_requests(tenant_id, status);

-- ==================== DEPLOYMENT TABLES ====================

CREATE TABLE private_deployments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    deployment_type deployment_type NOT NULL,
    status deployment_status NOT NULL DEFAULT 'pending',
    
    -- Infrastructure
    region TEXT NOT NULL,
    availability_zones TEXT[] DEFAULT '{}',
    vpc_id TEXT,
    subnet_ids TEXT[] DEFAULT '{}',
    security_group_ids TEXT[] DEFAULT '{}',
    
    -- Resources
    instance_type TEXT,
    instance_count INTEGER DEFAULT 1,
    storage_gb INTEGER DEFAULT 100,
    
    -- Configuration
    config JSONB DEFAULT '{}',
    custom_domain TEXT,
    ssl_certificate_arn TEXT,
    
    -- Network
    private_ip_ranges TEXT[] DEFAULT '{}',
    nat_gateway_ips INET[] DEFAULT '{}',
    
    -- Monitoring
    health_check_url TEXT,
    last_health_check_at TIMESTAMPTZ,
    health_status TEXT DEFAULT 'unknown',
    
    -- Provisioning
    provisioned_at TIMESTAMPTZ,
    provisioning_details JSONB DEFAULT '{}',
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE dedicated_ips (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    deployment_id UUID REFERENCES private_deployments(id) ON DELETE SET NULL,
    ip_address INET NOT NULL UNIQUE,
    ptr_record TEXT,
    status ip_status NOT NULL DEFAULT 'pending',
    
    -- Warming
    warming_started_at TIMESTAMPTZ,
    warming_completed_at TIMESTAMPTZ,
    warming_progress_percent INTEGER DEFAULT 0,
    warming_plan JSONB DEFAULT '{}',
    current_daily_limit INTEGER,
    
    -- Reputation
    reputation_score DECIMAL(5,2) DEFAULT 100.0,
    last_reputation_check_at TIMESTAMPTZ,
    reputation_history JSONB DEFAULT '[]',
    
    -- Stats
    emails_sent_total BIGINT DEFAULT 0,
    emails_sent_today INTEGER DEFAULT 0,
    bounces_total BIGINT DEFAULT 0,
    complaints_total BIGINT DEFAULT 0,
    
    -- Blocklist
    blocklisted BOOLEAN DEFAULT false,
    blocklist_details JSONB DEFAULT '[]',
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE byoip_ranges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    cidr_block CIDR NOT NULL UNIQUE,
    status byoip_status NOT NULL DEFAULT 'pending_verification',
    
    -- Verification
    verification_token TEXT NOT NULL,
    verification_method TEXT DEFAULT 'roa',
    verified_at TIMESTAMPTZ,
    
    -- LOA
    loa_document_id TEXT,
    loa_uploaded_at TIMESTAMPTZ,
    
    -- Provisioning
    aws_byoip_state TEXT,
    provisioned_at TIMESTAMPTZ,
    advertisement_state TEXT,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_deployments_account ON private_deployments(tenant_id);
CREATE INDEX idx_deployments_status ON private_deployments(status);
CREATE INDEX idx_dedicated_ips_account ON dedicated_ips(tenant_id);
CREATE INDEX idx_dedicated_ips_status ON dedicated_ips(status);
CREATE INDEX idx_dedicated_ips_ip ON dedicated_ips(ip_address);
CREATE INDEX idx_byoip_account ON byoip_ranges(tenant_id);

-- ==================== SUPPORT TABLES ====================

CREATE TABLE support_tickets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    number SERIAL NOT NULL,
    subject TEXT NOT NULL,
    description TEXT NOT NULL,
    category ticket_category NOT NULL DEFAULT 'other',
    priority ticket_priority NOT NULL DEFAULT 'medium',
    status ticket_status NOT NULL DEFAULT 'new',
    
    -- Assignment
    assigned_to UUID,
    assigned_at TIMESTAMPTZ,
    team TEXT,
    
    -- SLA
    sla_first_response_due TIMESTAMPTZ,
    sla_resolution_due TIMESTAMPTZ,
    sla_breached BOOLEAN DEFAULT false,
    sla_breach_type TEXT,
    
    -- Response tracking
    first_response_at TIMESTAMPTZ,
    last_response_at TIMESTAMPTZ,
    last_customer_response_at TIMESTAMPTZ,
    
    -- Escalation
    escalation_level INTEGER DEFAULT 0,
    escalated_at TIMESTAMPTZ,
    escalation_reason TEXT,
    
    -- Resolution
    resolved_at TIMESTAMPTZ,
    resolution_summary TEXT,
    resolution_type TEXT,
    
    -- Contact
    created_by UUID NOT NULL,
    contact_email TEXT NOT NULL,
    contact_name TEXT,
    contact_phone TEXT,
    
    -- Satisfaction
    satisfaction_rating INTEGER CHECK (satisfaction_rating BETWEEN 1 AND 5),
    satisfaction_comment TEXT,
    satisfaction_submitted_at TIMESTAMPTZ,
    
    -- Metadata
    tags TEXT[] DEFAULT '{}',
    custom_fields JSONB DEFAULT '{}',
    related_ticket_ids UUID[] DEFAULT '{}',
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at TIMESTAMPTZ
);

CREATE TABLE ticket_comments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id UUID NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
    author_id UUID NOT NULL,
    author_name TEXT NOT NULL,
    author_type author_type NOT NULL,
    content TEXT NOT NULL,
    is_internal BOOLEAN DEFAULT false,
    attachments JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE ticket_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id UUID NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
    user_id UUID,
    field_name TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE support_agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL UNIQUE,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    team TEXT,
    role TEXT DEFAULT 'agent',
    max_tickets INTEGER DEFAULT 20,
    current_ticket_count INTEGER DEFAULT 0,
    specialties TEXT[] DEFAULT '{}',
    available BOOLEAN DEFAULT true,
    last_assignment_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tickets_account ON support_tickets(tenant_id);
CREATE INDEX idx_tickets_status ON support_tickets(status);
CREATE INDEX idx_tickets_priority ON support_tickets(priority, status);
CREATE INDEX idx_tickets_assigned ON support_tickets(assigned_to) WHERE assigned_to IS NOT NULL;
CREATE INDEX idx_tickets_created ON support_tickets(created_at DESC);
CREATE INDEX idx_ticket_comments_ticket ON ticket_comments(ticket_id, created_at);
CREATE INDEX idx_ticket_history_ticket ON ticket_history(ticket_id, created_at DESC);

-- ==================== QBR TABLES ====================

CREATE TABLE quarterly_business_reviews (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    quarter TEXT NOT NULL,
    year INTEGER NOT NULL,
    status qbr_status NOT NULL DEFAULT 'scheduled',
    
    -- Scheduling
    scheduled_date TIMESTAMPTZ,
    delivered_date TIMESTAMPTZ,
    delivered_by UUID,
    
    -- Attendees
    attendees JSONB DEFAULT '[]',
    
    -- Metrics (gathered data)
    metrics JSONB DEFAULT '{}',
    
    -- Analysis
    insights JSONB DEFAULT '[]',
    recommendations JSONB DEFAULT '[]',
    highlights JSONB DEFAULT '[]',
    concerns JSONB DEFAULT '[]',
    
    -- Goals
    goals JSONB DEFAULT '[]',
    
    -- Comparison
    previous_qbr_id UUID REFERENCES quarterly_business_reviews(id),
    quarter_over_quarter_change JSONB DEFAULT '{}',
    year_over_year_change JSONB DEFAULT '{}',
    
    -- Documents
    presentation_url TEXT,
    report_url TEXT,
    recording_url TEXT,
    
    -- Feedback
    feedback JSONB DEFAULT '{}',
    
    -- Notes
    preparation_notes TEXT,
    meeting_notes TEXT,
    action_items JSONB DEFAULT '[]',
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(tenant_id, quarter, year)
);

CREATE TABLE qbr_goals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    qbr_id UUID NOT NULL REFERENCES quarterly_business_reviews(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT,
    category TEXT NOT NULL,
    target_metric TEXT,
    target_value DECIMAL(15,4),
    current_value DECIMAL(15,4),
    baseline_value DECIMAL(15,4),
    unit TEXT,
    due_date DATE,
    status goal_status NOT NULL DEFAULT 'not_started',
    progress_percent INTEGER DEFAULT 0,
    owner TEXT,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE industry_benchmarks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    industry TEXT NOT NULL,
    metric_name TEXT NOT NULL,
    metric_value DECIMAL(15,4) NOT NULL,
    percentile_25 DECIMAL(15,4),
    percentile_50 DECIMAL(15,4),
    percentile_75 DECIMAL(15,4),
    percentile_90 DECIMAL(15,4),
    unit TEXT,
    period TEXT NOT NULL,
    source TEXT,
    valid_from DATE NOT NULL,
    valid_until DATE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(industry, metric_name, period, valid_from)
);

CREATE INDEX idx_qbr_account ON quarterly_business_reviews(tenant_id);
CREATE INDEX idx_qbr_quarter ON quarterly_business_reviews(quarter, year);
CREATE INDEX idx_qbr_status ON quarterly_business_reviews(status);
CREATE INDEX idx_qbr_goals_qbr ON qbr_goals(qbr_id);
CREATE INDEX idx_benchmarks_industry ON industry_benchmarks(industry, metric_name);

-- ==================== TRIGGERS ====================

-- Update timestamps
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_sso_configurations_updated_at
    BEFORE UPDATE ON sso_configurations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER update_sub_accounts_updated_at
    BEFORE UPDATE ON sub_accounts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER update_whitelabel_configs_updated_at
    BEFORE UPDATE ON whitelabel_configs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER update_whitelabel_domains_updated_at
    BEFORE UPDATE ON whitelabel_domains
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER update_template_submissions_updated_at
    BEFORE UPDATE ON template_submissions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER update_log_streams_updated_at
    BEFORE UPDATE ON log_streams
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER update_compliance_configs_updated_at
    BEFORE UPDATE ON compliance_configs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER update_private_deployments_updated_at
    BEFORE UPDATE ON private_deployments
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER update_dedicated_ips_updated_at
    BEFORE UPDATE ON dedicated_ips
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER update_support_tickets_updated_at
    BEFORE UPDATE ON support_tickets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER update_qbr_updated_at
    BEFORE UPDATE ON quarterly_business_reviews
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Ticket number sequence per account
CREATE OR REPLACE FUNCTION set_ticket_number()
RETURNS TRIGGER AS $$
DECLARE
    next_number INTEGER;
BEGIN
    SELECT COALESCE(MAX(number), 0) + 1 INTO next_number
    FROM support_tickets
    WHERE tenant_id = NEW.tenant_id;
    
    NEW.number = next_number;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER set_support_ticket_number
    BEFORE INSERT ON support_tickets
    FOR EACH ROW EXECUTE FUNCTION set_ticket_number();

-- Audit log for compliance
CREATE OR REPLACE FUNCTION audit_sensitive_tables()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        INSERT INTO compliance_audit_logs (tenant_id, action, resource_type, resource_id, old_value)
        VALUES (OLD.tenant_id, 'DELETE', TG_TABLE_NAME, OLD.id::text, row_to_json(OLD));
        RETURN OLD;
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO compliance_audit_logs (tenant_id, action, resource_type, resource_id, old_value, new_value)
        VALUES (NEW.tenant_id, 'UPDATE', TG_TABLE_NAME, NEW.id::text, row_to_json(OLD), row_to_json(NEW));
        RETURN NEW;
    ELSIF TG_OP = 'INSERT' THEN
        INSERT INTO compliance_audit_logs (tenant_id, action, resource_type, resource_id, new_value)
        VALUES (NEW.tenant_id, 'INSERT', TG_TABLE_NAME, NEW.id::text, row_to_json(NEW));
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Enable audit logging for sensitive tables
CREATE TRIGGER audit_sso_configurations
    AFTER INSERT OR UPDATE OR DELETE ON sso_configurations
    FOR EACH ROW EXECUTE FUNCTION audit_sensitive_tables();

CREATE TRIGGER audit_compliance_configs
    AFTER INSERT OR UPDATE OR DELETE ON compliance_configs
    FOR EACH ROW EXECUTE FUNCTION audit_sensitive_tables();

CREATE TRIGGER audit_data_access_requests
    AFTER INSERT OR UPDATE OR DELETE ON data_access_requests
    FOR EACH ROW EXECUTE FUNCTION audit_sensitive_tables();

-- ==================== SAMPLE DATA ====================

-- Insert default industry benchmarks
INSERT INTO industry_benchmarks (industry, metric_name, metric_value, percentile_25, percentile_50, percentile_75, percentile_90, unit, period, source, valid_from)
VALUES
    ('saas', 'delivery_rate', 98.5, 96.0, 98.0, 99.0, 99.5, 'percent', '2024-Q1', 'Industry Report', '2024-01-01'),
    ('saas', 'open_rate', 22.5, 15.0, 20.0, 25.0, 32.0, 'percent', '2024-Q1', 'Industry Report', '2024-01-01'),
    ('saas', 'click_rate', 3.2, 1.5, 2.5, 4.0, 6.0, 'percent', '2024-Q1', 'Industry Report', '2024-01-01'),
    ('saas', 'bounce_rate', 1.2, 0.5, 1.0, 2.0, 3.5, 'percent', '2024-Q1', 'Industry Report', '2024-01-01'),
    ('saas', 'complaint_rate', 0.02, 0.005, 0.01, 0.03, 0.05, 'percent', '2024-Q1', 'Industry Report', '2024-01-01'),
    ('ecommerce', 'delivery_rate', 97.8, 95.0, 97.0, 98.5, 99.2, 'percent', '2024-Q1', 'Industry Report', '2024-01-01'),
    ('ecommerce', 'open_rate', 18.5, 12.0, 16.0, 22.0, 28.0, 'percent', '2024-Q1', 'Industry Report', '2024-01-01'),
    ('ecommerce', 'click_rate', 2.8, 1.2, 2.0, 3.5, 5.0, 'percent', '2024-Q1', 'Industry Report', '2024-01-01'),
    ('financial', 'delivery_rate', 99.2, 98.0, 99.0, 99.5, 99.8, 'percent', '2024-Q1', 'Industry Report', '2024-01-01'),
    ('financial', 'open_rate', 28.0, 20.0, 25.0, 32.0, 40.0, 'percent', '2024-Q1', 'Industry Report', '2024-01-01'),
    ('healthcare', 'delivery_rate', 98.8, 97.0, 98.5, 99.2, 99.6, 'percent', '2024-Q1', 'Industry Report', '2024-01-01'),
    ('healthcare', 'open_rate', 24.0, 18.0, 22.0, 28.0, 35.0, 'percent', '2024-Q1', 'Industry Report', '2024-01-01');

COMMIT;
