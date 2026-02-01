-- Multi-Tenant Isolation Schema Migration
-- Version: 001
-- Description: Core tables for multi-tenant isolation system

BEGIN;

-- Enable UUID extension if not exists
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ==================== Enums ====================

-- Tenant status
CREATE TYPE tenant_status AS ENUM (
    'active',
    'suspended',
    'pending',
    'deleted'
);

-- Tenant role
CREATE TYPE tenant_role AS ENUM (
    'owner',
    'admin',
    'member',
    'readonly',
    'billing'
);

-- Isolation level
CREATE TYPE isolation_level AS ENUM (
    'shared',
    'dedicated_schema',
    'dedicated_database',
    'dedicated_instance'
);

-- Audit severity
CREATE TYPE audit_severity AS ENUM (
    'info',
    'warning',
    'critical'
);

-- ==================== Organizations ====================

CREATE TABLE iso_organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL UNIQUE,
    billing_email VARCHAR(255) NOT NULL,
    plan VARCHAR(50) NOT NULL DEFAULT 'free',
    status tenant_status NOT NULL DEFAULT 'active',
    isolation_level isolation_level NOT NULL DEFAULT 'shared',
    schema_name VARCHAR(100),
    database_name VARCHAR(100),
    owner_id UUID NOT NULL,
    settings JSONB NOT NULL DEFAULT '{}',
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    suspended_at TIMESTAMPTZ,
    suspended_by UUID,
    suspended_reason TEXT,
    deleted_at TIMESTAMPTZ
);

-- Organization indexes
CREATE INDEX idx_iso_organizations_slug ON iso_organizations(slug);
CREATE INDEX idx_iso_organizations_status ON iso_organizations(status);
CREATE INDEX idx_iso_organizations_owner ON iso_organizations(owner_id);
CREATE INDEX idx_iso_organizations_plan ON iso_organizations(plan);
CREATE INDEX idx_iso_organizations_created ON iso_organizations(created_at DESC);

-- ==================== Workspaces ====================

CREATE TABLE iso_workspaces (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES iso_organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL,
    status tenant_status NOT NULL DEFAULT 'active',
    creator_id UUID NOT NULL,
    settings JSONB NOT NULL DEFAULT '{}',
    -- Quota configuration
    quota_emails_per_day INTEGER NOT NULL DEFAULT 1000,
    quota_contacts INTEGER NOT NULL DEFAULT 10000,
    quota_storage_bytes BIGINT NOT NULL DEFAULT 1073741824, -- 1GB
    quota_team_members INTEGER NOT NULL DEFAULT 5,
    quota_api_rate_per_minute INTEGER NOT NULL DEFAULT 60,
    quota_webhooks INTEGER NOT NULL DEFAULT 10,
    -- Current usage
    usage_emails_today INTEGER NOT NULL DEFAULT 0,
    usage_contacts INTEGER NOT NULL DEFAULT 0,
    usage_storage_bytes BIGINT NOT NULL DEFAULT 0,
    usage_team_members INTEGER NOT NULL DEFAULT 0,
    usage_webhooks INTEGER NOT NULL DEFAULT 0,
    usage_reset_at TIMESTAMPTZ NOT NULL DEFAULT DATE_TRUNC('day', NOW()) + INTERVAL '1 day',
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    deleted_by UUID,
    UNIQUE(organization_id, slug)
);

-- Workspace indexes
CREATE INDEX idx_iso_workspaces_organization ON iso_workspaces(organization_id);
CREATE INDEX idx_iso_workspaces_slug ON iso_workspaces(organization_id, slug);
CREATE INDEX idx_iso_workspaces_status ON iso_workspaces(status);
CREATE INDEX idx_iso_workspaces_created ON iso_workspaces(created_at DESC);

-- ==================== Workspace Members ====================

CREATE TABLE iso_workspace_members (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workspace_id UUID NOT NULL REFERENCES iso_workspaces(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    role tenant_role NOT NULL DEFAULT 'member',
    permissions JSONB NOT NULL DEFAULT '[]',
    invited_by UUID,
    invited_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    accepted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(workspace_id, user_id)
);

-- Member indexes
CREATE INDEX idx_iso_workspace_members_workspace ON iso_workspace_members(workspace_id);
CREATE INDEX idx_iso_workspace_members_user ON iso_workspace_members(user_id);
CREATE INDEX idx_iso_workspace_members_role ON iso_workspace_members(role);

-- ==================== Encryption Keys ====================

CREATE TABLE iso_encryption_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES iso_organizations(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    algorithm VARCHAR(50) NOT NULL DEFAULT 'AES-256-GCM',
    key_material BYTEA NOT NULL, -- Encrypted with master key
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at TIMESTAMPTZ,
    rotated_at TIMESTAMPTZ,
    rotated_by UUID,
    expires_at TIMESTAMPTZ,
    retired_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}',
    UNIQUE(organization_id, version)
);

-- Encryption key indexes
CREATE INDEX idx_iso_encryption_keys_org ON iso_encryption_keys(organization_id);
CREATE INDEX idx_iso_encryption_keys_status ON iso_encryption_keys(status);
CREATE INDEX idx_iso_encryption_keys_active ON iso_encryption_keys(organization_id) 
    WHERE status = 'active';

-- ==================== Encryption Policies ====================

CREATE TABLE iso_encryption_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL,
    resource VARCHAR(100) NOT NULL,
    fields JSONB NOT NULL DEFAULT '[]',
    algorithm VARCHAR(50) NOT NULL DEFAULT 'AES-256-GCM',
    key_rotation_days INTEGER NOT NULL DEFAULT 90,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Policy indexes
CREATE INDEX idx_iso_encryption_policies_resource ON iso_encryption_policies(resource);
CREATE INDEX idx_iso_encryption_policies_enabled ON iso_encryption_policies(enabled);

-- ==================== Audit Logs ====================

CREATE TABLE iso_audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES iso_organizations(id) ON DELETE SET NULL,
    workspace_id UUID REFERENCES iso_workspaces(id) ON DELETE SET NULL,
    event_type VARCHAR(100) NOT NULL,
    severity audit_severity NOT NULL DEFAULT 'info',
    actor_id VARCHAR(255) NOT NULL,
    actor_type VARCHAR(50) NOT NULL,
    actor_ip INET,
    actor_user_agent TEXT,
    resource VARCHAR(100) NOT NULL,
    resource_id UUID,
    action VARCHAR(100) NOT NULL,
    details JSONB NOT NULL DEFAULT '{}',
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
) PARTITION BY RANGE (created_at);

-- Create partitions for audit logs (by month)
CREATE TABLE iso_audit_logs_2024_01 PARTITION OF iso_audit_logs
    FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');
CREATE TABLE iso_audit_logs_2024_02 PARTITION OF iso_audit_logs
    FOR VALUES FROM ('2024-02-01') TO ('2024-03-01');
CREATE TABLE iso_audit_logs_2024_03 PARTITION OF iso_audit_logs
    FOR VALUES FROM ('2024-03-01') TO ('2024-04-01');
CREATE TABLE iso_audit_logs_2024_04 PARTITION OF iso_audit_logs
    FOR VALUES FROM ('2024-04-01') TO ('2024-05-01');
CREATE TABLE iso_audit_logs_2024_05 PARTITION OF iso_audit_logs
    FOR VALUES FROM ('2024-05-01') TO ('2024-06-01');
CREATE TABLE iso_audit_logs_2024_06 PARTITION OF iso_audit_logs
    FOR VALUES FROM ('2024-06-01') TO ('2024-07-01');
CREATE TABLE iso_audit_logs_2024_07 PARTITION OF iso_audit_logs
    FOR VALUES FROM ('2024-07-01') TO ('2024-08-01');
CREATE TABLE iso_audit_logs_2024_08 PARTITION OF iso_audit_logs
    FOR VALUES FROM ('2024-08-01') TO ('2024-09-01');
CREATE TABLE iso_audit_logs_2024_09 PARTITION OF iso_audit_logs
    FOR VALUES FROM ('2024-09-01') TO ('2024-10-01');
CREATE TABLE iso_audit_logs_2024_10 PARTITION OF iso_audit_logs
    FOR VALUES FROM ('2024-10-01') TO ('2024-11-01');
CREATE TABLE iso_audit_logs_2024_11 PARTITION OF iso_audit_logs
    FOR VALUES FROM ('2024-11-01') TO ('2024-12-01');
CREATE TABLE iso_audit_logs_2024_12 PARTITION OF iso_audit_logs
    FOR VALUES FROM ('2024-12-01') TO ('2025-01-01');
CREATE TABLE iso_audit_logs_2025_01 PARTITION OF iso_audit_logs
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
CREATE TABLE iso_audit_logs_2025_02 PARTITION OF iso_audit_logs
    FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');
CREATE TABLE iso_audit_logs_2025_03 PARTITION OF iso_audit_logs
    FOR VALUES FROM ('2025-03-01') TO ('2025-04-01');
CREATE TABLE iso_audit_logs_2025_04 PARTITION OF iso_audit_logs
    FOR VALUES FROM ('2025-04-01') TO ('2025-05-01');
CREATE TABLE iso_audit_logs_2025_05 PARTITION OF iso_audit_logs
    FOR VALUES FROM ('2025-05-01') TO ('2025-06-01');
CREATE TABLE iso_audit_logs_2025_06 PARTITION OF iso_audit_logs
    FOR VALUES FROM ('2025-06-01') TO ('2025-07-01');
CREATE TABLE iso_audit_logs_2025_07 PARTITION OF iso_audit_logs
    FOR VALUES FROM ('2025-07-01') TO ('2025-08-01');
CREATE TABLE iso_audit_logs_2025_08 PARTITION OF iso_audit_logs
    FOR VALUES FROM ('2025-08-01') TO ('2025-09-01');
CREATE TABLE iso_audit_logs_2025_09 PARTITION OF iso_audit_logs
    FOR VALUES FROM ('2025-09-01') TO ('2025-10-01');
CREATE TABLE iso_audit_logs_2025_10 PARTITION OF iso_audit_logs
    FOR VALUES FROM ('2025-10-01') TO ('2025-11-01');
CREATE TABLE iso_audit_logs_2025_11 PARTITION OF iso_audit_logs
    FOR VALUES FROM ('2025-11-01') TO ('2025-12-01');
CREATE TABLE iso_audit_logs_2025_12 PARTITION OF iso_audit_logs
    FOR VALUES FROM ('2025-12-01') TO ('2026-01-01');

-- Audit log indexes
CREATE INDEX idx_iso_audit_logs_org ON iso_audit_logs(organization_id, created_at DESC);
CREATE INDEX idx_iso_audit_logs_workspace ON iso_audit_logs(workspace_id, created_at DESC);
CREATE INDEX idx_iso_audit_logs_type ON iso_audit_logs(event_type, created_at DESC);
CREATE INDEX idx_iso_audit_logs_actor ON iso_audit_logs(actor_id, created_at DESC);
CREATE INDEX idx_iso_audit_logs_severity ON iso_audit_logs(severity, created_at DESC);
CREATE INDEX idx_iso_audit_logs_resource ON iso_audit_logs(resource, resource_id);
CREATE INDEX idx_iso_audit_logs_created ON iso_audit_logs(created_at DESC);

-- ==================== Access Control ====================

CREATE TABLE iso_access_attempts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES iso_organizations(id) ON DELETE SET NULL,
    workspace_id UUID REFERENCES iso_workspaces(id) ON DELETE SET NULL,
    actor_id UUID NOT NULL,
    target_workspace_id UUID REFERENCES iso_workspaces(id) ON DELETE SET NULL,
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    allowed BOOLEAN NOT NULL,
    reason TEXT,
    context JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Access attempt indexes
CREATE INDEX idx_iso_access_attempts_org ON iso_access_attempts(organization_id, created_at DESC);
CREATE INDEX idx_iso_access_attempts_actor ON iso_access_attempts(actor_id, created_at DESC);
CREATE INDEX idx_iso_access_attempts_denied ON iso_access_attempts(organization_id, created_at DESC)
    WHERE allowed = false;

-- ==================== Rate Limit Records ====================

CREATE TABLE iso_rate_limits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key VARCHAR(255) NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(key, window_start)
);

-- Rate limit indexes
CREATE INDEX idx_iso_rate_limits_key ON iso_rate_limits(key);
CREATE INDEX idx_iso_rate_limits_window ON iso_rate_limits(window_end);

-- ==================== Data Isolation Tracking ====================

CREATE TABLE iso_isolation_configs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workspace_id UUID NOT NULL REFERENCES iso_workspaces(id) ON DELETE CASCADE,
    current_level isolation_level NOT NULL DEFAULT 'shared',
    target_level isolation_level,
    migration_status VARCHAR(50),
    migration_started_at TIMESTAMPTZ,
    migration_completed_at TIMESTAMPTZ,
    schema_name VARCHAR(100),
    database_connection_string TEXT, -- Encrypted
    settings JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(workspace_id)
);

-- Isolation config indexes
CREATE INDEX idx_iso_isolation_configs_workspace ON iso_isolation_configs(workspace_id);
CREATE INDEX idx_iso_isolation_configs_level ON iso_isolation_configs(current_level);

-- ==================== Functions ====================

-- Function to update timestamps
CREATE OR REPLACE FUNCTION iso_update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Function to reset daily usage
CREATE OR REPLACE FUNCTION iso_reset_daily_usage()
RETURNS void AS $$
BEGIN
    UPDATE iso_workspaces
    SET 
        usage_emails_today = 0,
        usage_reset_at = DATE_TRUNC('day', NOW()) + INTERVAL '1 day'
    WHERE usage_reset_at <= NOW();
END;
$$ LANGUAGE plpgsql;

-- Function to create tenant schema
CREATE OR REPLACE FUNCTION iso_create_tenant_schema(schema_name TEXT)
RETURNS void AS $$
BEGIN
    EXECUTE format('CREATE SCHEMA IF NOT EXISTS %I', schema_name);
END;
$$ LANGUAGE plpgsql;

-- Function to drop tenant schema
CREATE OR REPLACE FUNCTION iso_drop_tenant_schema(schema_name TEXT)
RETURNS void AS $$
BEGIN
    EXECUTE format('DROP SCHEMA IF EXISTS %I CASCADE', schema_name);
END;
$$ LANGUAGE plpgsql;

-- Function to set up RLS on a table
CREATE OR REPLACE FUNCTION iso_setup_rls(
    p_table_name TEXT,
    p_schema_name TEXT DEFAULT 'public'
)
RETURNS void AS $$
DECLARE
    v_full_table TEXT;
BEGIN
    v_full_table := p_schema_name || '.' || p_table_name;
    
    -- Enable RLS
    EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', v_full_table);
    
    -- Create policy for workspace isolation
    EXECUTE format(
        'CREATE POLICY workspace_isolation ON %s
         FOR ALL
         USING (workspace_id = current_setting(''app.workspace_id'', true)::uuid)
         WITH CHECK (workspace_id = current_setting(''app.workspace_id'', true)::uuid)',
        v_full_table
    );
END;
$$ LANGUAGE plpgsql;

-- Function to get workspace quota status
CREATE OR REPLACE FUNCTION iso_get_quota_status(p_workspace_id UUID)
RETURNS TABLE (
    metric VARCHAR,
    current_usage BIGINT,
    quota_limit BIGINT,
    percentage NUMERIC,
    is_exceeded BOOLEAN
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        m.metric,
        m.current_usage,
        m.quota_limit,
        ROUND((m.current_usage::NUMERIC / NULLIF(m.quota_limit, 0) * 100), 2) as percentage,
        m.current_usage >= m.quota_limit as is_exceeded
    FROM (
        SELECT 'emails_per_day' as metric, 
               w.usage_emails_today::BIGINT as current_usage,
               w.quota_emails_per_day::BIGINT as quota_limit
        FROM iso_workspaces w WHERE w.id = p_workspace_id
        UNION ALL
        SELECT 'contacts',
               w.usage_contacts::BIGINT,
               w.quota_contacts::BIGINT
        FROM iso_workspaces w WHERE w.id = p_workspace_id
        UNION ALL
        SELECT 'storage_bytes',
               w.usage_storage_bytes,
               w.quota_storage_bytes
        FROM iso_workspaces w WHERE w.id = p_workspace_id
        UNION ALL
        SELECT 'team_members',
               w.usage_team_members::BIGINT,
               w.quota_team_members::BIGINT
        FROM iso_workspaces w WHERE w.id = p_workspace_id
        UNION ALL
        SELECT 'webhooks',
               w.usage_webhooks::BIGINT,
               w.quota_webhooks::BIGINT
        FROM iso_workspaces w WHERE w.id = p_workspace_id
    ) m;
END;
$$ LANGUAGE plpgsql;

-- Function to create audit partition for a month
CREATE OR REPLACE FUNCTION iso_create_audit_partition(year INT, month INT)
RETURNS void AS $$
DECLARE
    partition_name TEXT;
    start_date DATE;
    end_date DATE;
BEGIN
    partition_name := format('iso_audit_logs_%s_%s', year, LPAD(month::TEXT, 2, '0'));
    start_date := make_date(year, month, 1);
    end_date := start_date + INTERVAL '1 month';
    
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF iso_audit_logs
         FOR VALUES FROM (%L) TO (%L)',
        partition_name, start_date, end_date
    );
END;
$$ LANGUAGE plpgsql;

-- Function to archive old audit logs
CREATE OR REPLACE FUNCTION iso_archive_audit_logs(retention_days INT DEFAULT 365)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    WITH deleted AS (
        DELETE FROM iso_audit_logs
        WHERE created_at < NOW() - (retention_days || ' days')::INTERVAL
        RETURNING 1
    )
    SELECT COUNT(*) INTO deleted_count FROM deleted;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- ==================== Triggers ====================

-- Organization timestamp trigger
CREATE TRIGGER iso_organizations_timestamp
    BEFORE UPDATE ON iso_organizations
    FOR EACH ROW
    EXECUTE FUNCTION iso_update_timestamp();

-- Workspace timestamp trigger
CREATE TRIGGER iso_workspaces_timestamp
    BEFORE UPDATE ON iso_workspaces
    FOR EACH ROW
    EXECUTE FUNCTION iso_update_timestamp();

-- Member timestamp trigger
CREATE TRIGGER iso_workspace_members_timestamp
    BEFORE UPDATE ON iso_workspace_members
    FOR EACH ROW
    EXECUTE FUNCTION iso_update_timestamp();

-- Encryption policy timestamp trigger
CREATE TRIGGER iso_encryption_policies_timestamp
    BEFORE UPDATE ON iso_encryption_policies
    FOR EACH ROW
    EXECUTE FUNCTION iso_update_timestamp();

-- Isolation config timestamp trigger
CREATE TRIGGER iso_isolation_configs_timestamp
    BEFORE UPDATE ON iso_isolation_configs
    FOR EACH ROW
    EXECUTE FUNCTION iso_update_timestamp();

-- Rate limit timestamp trigger
CREATE TRIGGER iso_rate_limits_timestamp
    BEFORE UPDATE ON iso_rate_limits
    FOR EACH ROW
    EXECUTE FUNCTION iso_update_timestamp();

-- ==================== Views ====================

-- Active organizations view
CREATE VIEW iso_active_organizations AS
SELECT *
FROM iso_organizations
WHERE status = 'active' AND deleted_at IS NULL;

-- Active workspaces view
CREATE VIEW iso_active_workspaces AS
SELECT w.*, o.name as organization_name, o.plan, o.isolation_level
FROM iso_workspaces w
JOIN iso_organizations o ON w.organization_id = o.id
WHERE w.status = 'active' AND w.deleted_at IS NULL
  AND o.status = 'active' AND o.deleted_at IS NULL;

-- Quota overview view
CREATE VIEW iso_quota_overview AS
SELECT 
    w.id as workspace_id,
    w.name as workspace_name,
    o.name as organization_name,
    w.quota_emails_per_day,
    w.usage_emails_today,
    ROUND((w.usage_emails_today::NUMERIC / NULLIF(w.quota_emails_per_day, 0) * 100), 2) as email_usage_percent,
    w.quota_contacts,
    w.usage_contacts,
    ROUND((w.usage_contacts::NUMERIC / NULLIF(w.quota_contacts, 0) * 100), 2) as contact_usage_percent,
    w.quota_storage_bytes,
    w.usage_storage_bytes,
    ROUND((w.usage_storage_bytes::NUMERIC / NULLIF(w.quota_storage_bytes, 0) * 100), 2) as storage_usage_percent,
    w.quota_team_members,
    w.usage_team_members,
    ROUND((w.usage_team_members::NUMERIC / NULLIF(w.quota_team_members, 0) * 100), 2) as member_usage_percent,
    w.usage_reset_at
FROM iso_workspaces w
JOIN iso_organizations o ON w.organization_id = o.id
WHERE w.status = 'active' AND w.deleted_at IS NULL;

-- Security audit summary view
CREATE VIEW iso_security_audit_summary AS
SELECT 
    organization_id,
    DATE_TRUNC('day', created_at) as audit_date,
    event_type,
    severity,
    COUNT(*) as event_count
FROM iso_audit_logs
WHERE created_at >= NOW() - INTERVAL '30 days'
GROUP BY organization_id, DATE_TRUNC('day', created_at), event_type, severity
ORDER BY audit_date DESC, event_count DESC;

-- Access denial summary view
CREATE VIEW iso_access_denial_summary AS
SELECT 
    organization_id,
    DATE_TRUNC('day', created_at) as denial_date,
    resource,
    action,
    COUNT(*) as denial_count
FROM iso_access_attempts
WHERE allowed = false AND created_at >= NOW() - INTERVAL '30 days'
GROUP BY organization_id, DATE_TRUNC('day', created_at), resource, action
ORDER BY denial_date DESC, denial_count DESC;

-- ==================== Default Data ====================

-- Default encryption policies
INSERT INTO iso_encryption_policies (name, resource, fields, algorithm, key_rotation_days)
VALUES
    ('email_content', 'email', '["body", "subject"]', 'AES-256-GCM', 90),
    ('contact_pii', 'contact', '["email", "phone", "address"]', 'AES-256-GCM', 90),
    ('api_keys', 'api_key', '["key", "secret"]', 'AES-256-GCM', 30),
    ('webhooks', 'webhook', '["secret", "signing_key"]', 'AES-256-GCM', 60),
    ('user_credentials', 'user', '["password_hash", "mfa_secret"]', 'AES-256-GCM', 90)
ON CONFLICT DO NOTHING;

COMMIT;
