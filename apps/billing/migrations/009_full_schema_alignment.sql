-- Migration 009: Full schema alignment
-- Creates missing tables and adds compatibility views for enterprise/compliance/HA/isolation apps

-- ============================================
-- 1. Enterprise App - Create ent_ prefixed views
-- ============================================

-- Views for sub_accounts to ent_sub_accounts mapping (guarded to avoid missing-table failures)
DO $$
BEGIN
    IF to_regclass('public.sub_accounts') IS NOT NULL THEN
        EXECUTE 'CREATE OR REPLACE VIEW ent_sub_accounts AS SELECT * FROM sub_accounts';
    END IF;
    IF to_regclass('public.sub_account_api_keys') IS NOT NULL THEN
        EXECUTE 'CREATE OR REPLACE VIEW ent_sub_account_api_keys AS SELECT * FROM sub_account_api_keys';
    END IF;
    IF to_regclass('public.sub_account_events') IS NOT NULL THEN
        EXECUTE 'CREATE OR REPLACE VIEW ent_sub_account_events AS SELECT * FROM sub_account_events';
    END IF;

    IF to_regclass('public.sso_configurations') IS NOT NULL THEN
        EXECUTE 'CREATE OR REPLACE VIEW ent_sso_configurations AS SELECT * FROM sso_configurations';
    END IF;

    IF to_regclass('public.compliance_configs') IS NOT NULL THEN
        EXECUTE 'CREATE OR REPLACE VIEW ent_compliance_configs AS SELECT * FROM compliance_configs';
    END IF;
    IF to_regclass('public.compliance_audit_logs') IS NOT NULL THEN
        EXECUTE 'CREATE OR REPLACE VIEW ent_compliance_audit_logs AS SELECT * FROM compliance_audit_logs';
    END IF;

    IF to_regclass('public.whitelabel_configs') IS NOT NULL THEN
        EXECUTE 'CREATE OR REPLACE VIEW ent_whitelabel_configs AS SELECT * FROM whitelabel_configs';
    END IF;
    IF to_regclass('public.whitelabel_domains') IS NOT NULL THEN
        EXECUTE 'CREATE OR REPLACE VIEW ent_whitelabel_domains AS SELECT * FROM whitelabel_domains';
    END IF;
END $$;

-- ============================================
-- 2. Missing Enterprise tables
-- ============================================

-- ent_sso_users - missing entirely
CREATE TABLE IF NOT EXISTS ent_sso_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    sso_config_id UUID REFERENCES sso_configurations(id),
    external_id VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    attributes JSONB DEFAULT '{}',
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(sso_config_id, external_id)
);

CREATE INDEX IF NOT EXISTS idx_ent_sso_users_tenant ON ent_sso_users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ent_sso_users_email ON ent_sso_users(email);

-- ent_ip_warming_plans - missing entirely
CREATE TABLE IF NOT EXISTS ent_ip_warming_plans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    ip_address INET NOT NULL,
    name VARCHAR(255),
    target_volume INTEGER NOT NULL,
    current_day INTEGER DEFAULT 1,
    daily_schedule JSONB NOT NULL DEFAULT '[]',
    status VARCHAR(50) DEFAULT 'active',
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_ip_warming_tenant ON ent_ip_warming_plans(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ent_ip_warming_status ON ent_ip_warming_plans(status);

-- ============================================
-- 3. Isolation App - Missing tables
-- ============================================

-- iso_org_members (code expects this but schema has iso_workspace_members)
DO $$
BEGIN
    IF to_regclass('public.iso_workspace_members') IS NOT NULL THEN
        EXECUTE $view$
            CREATE OR REPLACE VIEW iso_org_members AS
            SELECT
                id,
                workspace_id as org_id,
                user_id,
                role,
                created_at,
                updated_at
            FROM iso_workspace_members
        $view$;
    END IF;
END $$;

-- iso_cleanup_queue - missing
CREATE TABLE IF NOT EXISTS iso_cleanup_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id UUID NOT NULL,
    reason VARCHAR(255),
    scheduled_for TIMESTAMPTZ NOT NULL,
    processed_at TIMESTAMPTZ,
    status VARCHAR(50) DEFAULT 'pending',
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_iso_cleanup_scheduled ON iso_cleanup_queue(scheduled_for) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_iso_cleanup_tenant ON iso_cleanup_queue(tenant_id);

-- iso_access_audit_logs (code expects this but schema has iso_access_attempts)
DO $$
BEGIN
    IF to_regclass('public.iso_access_attempts') IS NOT NULL THEN
        EXECUTE $view$
            CREATE OR REPLACE VIEW iso_access_audit_logs AS
            SELECT
                id,
                tenant_id,
                user_id,
                action as access_type,
                resource_id,
                resource_type,
                ip_address,
                user_agent,
                allowed as success,
                NULL as metadata,
                created_at
            FROM iso_access_attempts
        $view$;
    END IF;
END $$;

-- ============================================
-- 4. HA App - Missing tables
-- ============================================

-- ha_wal_replay_log
CREATE TABLE IF NOT EXISTS ha_wal_replay_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    region VARCHAR(50) NOT NULL,
    lsn pg_lsn NOT NULL,
    replayed_at TIMESTAMPTZ DEFAULT NOW(),
    replay_lag_ms INTEGER,
    status VARCHAR(50) DEFAULT 'success',
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ha_wal_replay_region ON ha_wal_replay_log(region);
CREATE INDEX IF NOT EXISTS idx_ha_wal_replay_lsn ON ha_wal_replay_log(lsn);

-- ha_fencing_events
CREATE TABLE IF NOT EXISTS ha_fencing_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    leader_id UUID NOT NULL,
    fenced_node_id UUID NOT NULL,
    fence_type VARCHAR(50) NOT NULL,
    reason TEXT,
    success BOOLEAN DEFAULT true,
    executed_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ha_fencing_leader ON ha_fencing_events(leader_id);
CREATE INDEX IF NOT EXISTS idx_ha_fencing_fenced ON ha_fencing_events(fenced_node_id);

-- ============================================
-- 5. Compliance App - Missing tables
-- ============================================

-- abuse_reports
CREATE TABLE IF NOT EXISTS abuse_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    reporter_email VARCHAR(255),
    reported_message_id UUID,
    abuse_type VARCHAR(100) NOT NULL,
    description TEXT,
    evidence JSONB DEFAULT '{}',
    status VARCHAR(50) DEFAULT 'pending',
    resolved_by UUID,
    resolved_at TIMESTAMPTZ,
    resolution_notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_abuse_reports_tenant ON abuse_reports(tenant_id);
CREATE INDEX IF NOT EXISTS idx_abuse_reports_status ON abuse_reports(status);
CREATE INDEX IF NOT EXISTS idx_abuse_reports_created ON abuse_reports(created_at);

-- content_violations
CREATE TABLE IF NOT EXISTS content_violations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    message_id UUID,
    campaign_id UUID,
    violation_type VARCHAR(100) NOT NULL,
    severity VARCHAR(50) DEFAULT 'medium',
    detected_content TEXT,
    confidence_score DECIMAL(5,4),
    auto_blocked BOOLEAN DEFAULT false,
    reviewed_by UUID,
    reviewed_at TIMESTAMPTZ,
    action_taken VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_content_violations_tenant ON content_violations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_content_violations_type ON content_violations(violation_type);
CREATE INDEX IF NOT EXISTS idx_content_violations_created ON content_violations(created_at);

-- blocklist_entries
CREATE TABLE IF NOT EXISTS blocklist_entries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    list_type VARCHAR(50) NOT NULL, -- 'domain', 'email', 'ip', 'content_hash'
    value VARCHAR(255) NOT NULL,
    reason VARCHAR(255),
    source VARCHAR(100), -- 'manual', 'automated', 'external_feed'
    severity VARCHAR(50) DEFAULT 'block',
    expires_at TIMESTAMPTZ,
    created_by UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(list_type, value)
);

CREATE INDEX IF NOT EXISTS idx_blocklist_type_value ON blocklist_entries(list_type, value);
CREATE INDEX IF NOT EXISTS idx_blocklist_expires ON blocklist_entries(expires_at) WHERE expires_at IS NOT NULL;

-- tenant_ips
CREATE TABLE IF NOT EXISTS tenant_ips (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    ip_address INET NOT NULL,
    ip_type VARCHAR(50) DEFAULT 'sending', -- 'sending', 'webhook', 'api_access'
    reputation_score DECIMAL(5,2) DEFAULT 100.00,
    is_dedicated BOOLEAN DEFAULT false,
    assigned_at TIMESTAMPTZ DEFAULT NOW(),
    released_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, ip_address, ip_type)
);

CREATE INDEX IF NOT EXISTS idx_tenant_ips_tenant ON tenant_ips(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_ips_address ON tenant_ips(ip_address);

-- campaign_stats
CREATE TABLE IF NOT EXISTS campaign_stats (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    campaign_id UUID NOT NULL,
    sent_count INTEGER DEFAULT 0,
    delivered_count INTEGER DEFAULT 0,
    opened_count INTEGER DEFAULT 0,
    clicked_count INTEGER DEFAULT 0,
    bounced_count INTEGER DEFAULT 0,
    complaint_count INTEGER DEFAULT 0,
    unsubscribe_count INTEGER DEFAULT 0,
    calculated_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_campaign_stats_tenant ON campaign_stats(tenant_id);
CREATE INDEX IF NOT EXISTS idx_campaign_stats_campaign ON campaign_stats(campaign_id);
CREATE INDEX IF NOT EXISTS idx_campaign_stats_created ON campaign_stats(created_at);

-- ============================================
-- 6. scan_results - add created_at alias
-- ============================================

-- Add created_at column as alias for scanned_at if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'scan_results' AND column_name = 'created_at'
    ) THEN
        ALTER TABLE scan_results ADD COLUMN created_at TIMESTAMPTZ;
        UPDATE scan_results SET created_at = scanned_at WHERE created_at IS NULL;
    END IF;
END $$;

-- Create trigger to sync columns
CREATE OR REPLACE FUNCTION sync_scan_results_timestamps()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.created_at IS NULL THEN
        NEW.created_at := NEW.scanned_at;
    END IF;
    IF NEW.scanned_at IS NULL THEN
        NEW.scanned_at := NEW.created_at;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS sync_scan_timestamps ON scan_results;
CREATE TRIGGER sync_scan_timestamps
    BEFORE INSERT ON scan_results
    FOR EACH ROW EXECUTE FUNCTION sync_scan_results_timestamps();

-- ============================================
-- 7. Additional indexes for performance
-- ============================================

CREATE INDEX IF NOT EXISTS idx_ent_sso_users_sso_config ON ent_sso_users(sso_config_id);
CREATE INDEX IF NOT EXISTS idx_abuse_reports_message ON abuse_reports(reported_message_id) WHERE reported_message_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_content_violations_severity ON content_violations(severity);
