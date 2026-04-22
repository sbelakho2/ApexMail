-- ApexMail Database Schema - Missing Tables Migration
-- Version:1.0.1
-- This migration adds tables and columns that are referenced in code but missing from schema

-- =============================================================================
-- DEAD LETTER QUEUES
-- =============================================================================

-- Email Dead Letter Queue - stores permanently failed emails for debugging
CREATE TABLE IF NOT EXISTS email_dlq (
    id VARCHAR(26) PRIMARY KEY,
    original_job JSONB NOT NULL,
    error_message TEXT,
    failed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_email_dlq_failed ON email_dlq(failed_at DESC);

-- Webhook Dead Letter Queue - stores permanently failed webhook deliveries
CREATE TABLE IF NOT EXISTS webhook_dlq (
    id VARCHAR(26) PRIMARY KEY,
    original_job JSONB NOT NULL,
    error_message TEXT,
    failed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webhook_dlq_failed ON webhook_dlq(failed_at DESC);

-- =============================================================================
-- WEBHOOK DELIVERIES TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id VARCHAR(26) PRIMARY KEY,
    webhook_id VARCHAR(26) NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    tenant_id VARCHAR(26) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    event_id VARCHAR(26),
    payload JSONB NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    status_code INTEGER,
    http_status INTEGER,
    response_time INTEGER,
    response_body TEXT,
    error_message TEXT,
    attempt INTEGER NOT NULL DEFAULT 1,
    attempts INTEGER NOT NULL DEFAULT 0,
    latency_ms INTEGER,
    delivered_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webhook_deliveries_webhook ON webhook_deliveries(webhook_id);
CREATE INDEX idx_webhook_deliveries_tenant ON webhook_deliveries(tenant_id);
CREATE INDEX idx_webhook_deliveries_status ON webhook_deliveries(status);
CREATE INDEX idx_webhook_deliveries_created ON webhook_deliveries(created_at DESC);

-- =============================================================================
-- ADD MISSING COLUMNS TO MESSAGES TABLE
-- =============================================================================

-- Reply tracking columns
ALTER TABLE messages ADD COLUMN IF NOT EXISTS reply_count INTEGER DEFAULT 0;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS last_reply_at TIMESTAMPTZ;

-- Backfill legacy rows
UPDATE messages
SET reply_count = 0
WHERE reply_count IS NULL;

-- User ID column (referenced in MessagesRepository)
ALTER TABLE messages ADD COLUMN IF NOT EXISTS user_id VARCHAR(26);

-- Explicitly normalize legacy empty-string user ids
UPDATE messages
SET user_id = NULL
WHERE user_id = '';

-- =============================================================================
-- ADD MISSING COLUMNS TO INBOUND MESSAGES TABLE
-- =============================================================================

-- Reply tracking for inbound messages
ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS in_reply_to_message_id VARCHAR(26);

CREATE INDEX IF NOT EXISTS idx_inbound_in_reply_to ON inbound_messages(in_reply_to_message_id) 
    WHERE in_reply_to_message_id IS NOT NULL;

-- =============================================================================
-- ADD MISSING COLUMNS TO EVENTS TABLE
-- =============================================================================

-- Deduplication key for idempotent event processing
ALTER TABLE events ADD COLUMN IF NOT EXISTS deduplication_key VARCHAR(255);
ALTER TABLE events ADD COLUMN IF NOT EXISTS processed_at TIMESTAMPTZ;
ALTER TABLE events ADD COLUMN IF NOT EXISTS metadata JSONB;

CREATE UNIQUE INDEX IF NOT EXISTS idx_events_dedup ON events(deduplication_key) 
    WHERE deduplication_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_events_dedup_lookup ON events(deduplication_key);

-- =============================================================================
-- IP POOLS FOR WARMUP
-- =============================================================================

CREATE TABLE IF NOT EXISTS ip_pools (
    id VARCHAR(26) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    warmup_enabled BOOLEAN NOT NULL DEFAULT true,
    warmup_started_at TIMESTAMPTZ,
    warmup_day INTEGER DEFAULT 0,
    daily_limit INTEGER,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ip_pool_addresses (
    id VARCHAR(26) PRIMARY KEY,
    pool_id VARCHAR(26) NOT NULL REFERENCES ip_pools(id) ON DELETE CASCADE,
    ip_address INET NOT NULL UNIQUE,
    hostname VARCHAR(255),
    ptr_verified BOOLEAN NOT NULL DEFAULT false,
    warmup_enabled BOOLEAN NOT NULL DEFAULT true,
    warmup_started_at TIMESTAMPTZ,
    warmup_day INTEGER DEFAULT 0,
    daily_limit INTEGER,
    daily_sent INTEGER NOT NULL DEFAULT 0,
    last_reset_at DATE,
    reputation_score DECIMAL(5,2),
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ip_pool_addresses_pool ON ip_pool_addresses(pool_id);
CREATE INDEX idx_ip_pool_addresses_status ON ip_pool_addresses(status);

-- Domain to IP pool assignment
ALTER TABLE domains ADD COLUMN IF NOT EXISTS ip_pool_id VARCHAR(26) REFERENCES ip_pools(id);

-- =============================================================================
-- ISP-SPECIFIC WARMUP SCHEDULES
-- =============================================================================

CREATE TABLE IF NOT EXISTS isp_warmup_schedules (
    id VARCHAR(26) PRIMARY KEY,
    isp_name VARCHAR(100) NOT NULL UNIQUE,
    mx_patterns JSONB NOT NULL DEFAULT '[]',
    warmup_schedule JSONB NOT NULL, -- Array of daily limits by day
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Insert default ISP schedules
INSERT INTO isp_warmup_schedules (id, isp_name, mx_patterns, warmup_schedule, notes) VALUES
    ('isp_gmail', 'Gmail', '["*.google.com", "*.googlemail.com"]', 
     '[50,100,200,400,800,1500,2500,4000,6000,8000,10000,15000,20000,30000]',
     'Gmail is strict - ramp slowly'),
    ('isp_microsoft', 'Microsoft', '["*.outlook.com", "*.hotmail.com", "*.live.com"]',
     '[100,200,400,800,1500,3000,5000,8000,12000,18000,25000,35000,50000]',
     'Microsoft allows faster warmup'),
    ('isp_yahoo', 'Yahoo', '["*.yahoodns.net", "*.yahoo.com"]',
     '[50,100,200,400,800,1500,2500,4000,6000,8000,10000,15000,20000]',
     'Yahoo similar to Gmail'),
    ('isp_default', 'Default', '["*"]',
     '[100,200,400,800,1500,3000,5000,8000,12000,18000,25000,35000,50000,75000,100000]',
     'Default schedule for other ISPs')
ON CONFLICT (isp_name) DO NOTHING;

-- =============================================================================
-- FBL (FEEDBACK LOOP) REGISTRATIONS
-- =============================================================================

CREATE TABLE IF NOT EXISTS fbl_registrations (
    id VARCHAR(26) PRIMARY KEY,
    isp_name VARCHAR(100) NOT NULL,
    registration_email VARCHAR(255),
    registration_url TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    registered_at TIMESTAMPTZ,
    last_report_at TIMESTAMPTZ,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- FBL complaints received (links to unmatched_complaints when matched)
CREATE TABLE IF NOT EXISTS fbl_complaints (
    id VARCHAR(26) PRIMARY KEY,
    tenant_id VARCHAR(26) REFERENCES tenants(id) ON DELETE SET NULL,
    message_id VARCHAR(26) REFERENCES messages(id) ON DELETE SET NULL,
    isp_name VARCHAR(100),
    recipient VARCHAR(255) NOT NULL,
    complaint_type VARCHAR(50),
    feedback_type VARCHAR(50),
    user_agent TEXT,
    arrival_date TIMESTAMPTZ,
    source_ip VARCHAR(45),
    authentication_results TEXT,
    original_mail_from VARCHAR(255),
    original_rcpt_to VARCHAR(255),
    raw_report TEXT,
    webhook_delivered BOOLEAN NOT NULL DEFAULT false,
    webhook_delivered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_fbl_complaints_tenant ON fbl_complaints(tenant_id);
CREATE INDEX idx_fbl_complaints_recipient ON fbl_complaints(recipient);
CREATE INDEX idx_fbl_complaints_created ON fbl_complaints(created_at DESC);
CREATE INDEX idx_fbl_complaints_pending_webhook ON fbl_complaints(webhook_delivered) 
    WHERE webhook_delivered = false;

-- =============================================================================
-- DNS PROVIDER CONFIGURATION
-- =============================================================================

CREATE TABLE IF NOT EXISTS dns_providers (
    id VARCHAR(26) PRIMARY KEY,
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_type VARCHAR(50) NOT NULL, -- 'cloudflare', 'route53', 'manual'
    name VARCHAR(100) NOT NULL,
    credentials_encrypted TEXT, -- Encrypted API key/token
    zone_id VARCHAR(100),
    is_default BOOLEAN NOT NULL DEFAULT false,
    last_sync_at TIMESTAMPTZ,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_dns_providers_tenant ON dns_providers(tenant_id);

-- DNS records managed by ApexMail
CREATE TABLE IF NOT EXISTS dns_records (
    id VARCHAR(26) PRIMARY KEY,
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain_id VARCHAR(26) REFERENCES domains(id) ON DELETE CASCADE,
    provider_id VARCHAR(26) REFERENCES dns_providers(id) ON DELETE SET NULL,
    record_type VARCHAR(20) NOT NULL, -- 'TXT', 'CNAME', 'MX'
    name VARCHAR(255) NOT NULL,
    value TEXT NOT NULL,
    ttl INTEGER NOT NULL DEFAULT 3600,
    purpose VARCHAR(50) NOT NULL, -- 'verification', 'dkim', 'spf', 'dmarc', 'mx'
    provider_record_id VARCHAR(100),
    is_verified BOOLEAN NOT NULL DEFAULT false,
    verified_at TIMESTAMPTZ,
    last_checked_at TIMESTAMPTZ,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_dns_records_tenant ON dns_records(tenant_id);
CREATE INDEX idx_dns_records_domain ON dns_records(domain_id);

-- =============================================================================
-- UPDATE SCHEMA VERSION
-- =============================================================================

INSERT INTO schema_migrations (version) VALUES ('1.0.1') ON CONFLICT DO NOTHING;
