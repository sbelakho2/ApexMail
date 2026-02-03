-- Sales Autopilot - Drip Campaigns Schema
-- This migration creates tables for persistent storage of drip campaign data

BEGIN;

-- Drip Campaigns table
CREATE TABLE IF NOT EXISTS drip_campaigns (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'draft',
    from_email VARCHAR(255) NOT NULL,
    from_name VARCHAR(255) NOT NULL,
    reply_to VARCHAR(255),
    sequence_steps JSONB NOT NULL DEFAULT '[]',
    triggers JSONB NOT NULL DEFAULT '[]',
    exit_conditions JSONB NOT NULL DEFAULT '[]',
    settings JSONB NOT NULL DEFAULT '{}',
    -- Stats stored as JSONB for flexibility
    stats JSONB NOT NULL DEFAULT '{
        "totalEnrolled": 0,
        "activeCount": 0,
        "completedCount": 0,
        "exitedCount": 0,
        "emailsSent": 0,
        "emailsOpened": 0,
        "emailsClicked": 0,
        "repliesReceived": 0,
        "unsubscribed": 0,
        "bounced": 0
    }',
    created_by VARCHAR(64) NOT NULL,
    started_at TIMESTAMPTZ,
    paused_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_drip_campaigns_tenant ON drip_campaigns(tenant_id);
CREATE INDEX idx_drip_campaigns_status ON drip_campaigns(status);

-- Campaign Enrollments table
CREATE TABLE IF NOT EXISTS campaign_enrollments (
    id VARCHAR(64) PRIMARY KEY,
    campaign_id VARCHAR(64) NOT NULL REFERENCES drip_campaigns(id) ON DELETE CASCADE,
    lead_id VARCHAR(64) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    current_step_id VARCHAR(64),
    completed_steps JSONB NOT NULL DEFAULT '[]',
    next_step_at TIMESTAMPTZ,
    emails_sent INTEGER NOT NULL DEFAULT 0,
    emails_opened INTEGER NOT NULL DEFAULT 0,
    emails_clicked INTEGER NOT NULL DEFAULT 0,
    replied BOOLEAN NOT NULL DEFAULT false,
    exit_reason VARCHAR(255),
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    paused_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_enrollments_campaign ON campaign_enrollments(campaign_id);
CREATE INDEX idx_enrollments_lead ON campaign_enrollments(lead_id);
CREATE INDEX idx_enrollments_status ON campaign_enrollments(status);
CREATE INDEX idx_enrollments_scheduled ON campaign_enrollments(next_step_at) WHERE status = 'active';

-- Prevent duplicate active enrollments for same lead in same campaign
CREATE UNIQUE INDEX idx_enrollments_unique ON campaign_enrollments(campaign_id, lead_id) 
    WHERE status NOT IN ('completed', 'exited');

-- Rate limiter state (for scraping)
CREATE TABLE IF NOT EXISTS scraper_rate_limits (
    domain VARCHAR(255) PRIMARY KEY,
    tokens REAL NOT NULL DEFAULT 5.0,
    last_refill TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Leads table (for CRM functionality)
CREATE TABLE IF NOT EXISTS sales_leads (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    company_name VARCHAR(255) NOT NULL,
    domain VARCHAR(255),
    contact_name VARCHAR(255),
    contact_email VARCHAR(255),
    contact_title VARCHAR(255),
    industry VARCHAR(100),
    employees VARCHAR(50),
    score INTEGER NOT NULL DEFAULT 0,
    score_breakdown JSONB NOT NULL DEFAULT '{}',
    status VARCHAR(50) NOT NULL DEFAULT 'new',
    source VARCHAR(100),
    tags JSONB NOT NULL DEFAULT '[]',
    enrichment_data JSONB NOT NULL DEFAULT '{}',
    activity_history JSONB NOT NULL DEFAULT '[]',
    notes TEXT,
    assigned_to VARCHAR(64),
    last_activity_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_leads_tenant ON sales_leads(tenant_id);
CREATE INDEX idx_leads_domain ON sales_leads(domain);
CREATE INDEX idx_leads_email ON sales_leads(contact_email);
CREATE INDEX idx_leads_score ON sales_leads(score DESC);
CREATE INDEX idx_leads_status ON sales_leads(status);

-- Trigger for updated_at timestamps
CREATE OR REPLACE FUNCTION sales_update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_drip_campaigns_timestamp
    BEFORE UPDATE ON drip_campaigns
    FOR EACH ROW EXECUTE FUNCTION sales_update_timestamp();

CREATE TRIGGER update_leads_timestamp
    BEFORE UPDATE ON sales_leads
    FOR EACH ROW EXECUTE FUNCTION sales_update_timestamp();

COMMIT;
