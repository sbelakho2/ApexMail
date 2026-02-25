-- 014: Add campaigns, contacts, and automations tables
-- Required for the new /v1/campaigns, /v1/contacts, and /v1/automations API routes

BEGIN;

-- ═══════════════════════════════════════════════════════
-- CAMPAIGNS TABLE
-- ═══════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS campaigns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    subject VARCHAR(998),
    list_id UUID,
    template_id UUID,
    scheduled_at TIMESTAMPTZ,
    status VARCHAR(20) NOT NULL DEFAULT 'draft' 
        CHECK (status IN ('draft', 'sending', 'paused', 'stopped', 'completed', 'failed')),
    total_recipients INT DEFAULT 0,
    sent_count INT DEFAULT 0,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_campaigns_tenant ON campaigns(tenant_id);
CREATE INDEX IF NOT EXISTS idx_campaigns_status ON campaigns(tenant_id, status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_campaigns_name_tenant ON campaigns(tenant_id, name);

-- ═══════════════════════════════════════════════════════
-- CONTACTS TABLE
-- ═══════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS contacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(320) NOT NULL,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    tags TEXT[] DEFAULT '{}',
    list_id UUID,
    metadata JSONB DEFAULT '{}',
    subscribed BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_contacts_tenant_email ON contacts(tenant_id, email);
CREATE INDEX IF NOT EXISTS idx_contacts_tags ON contacts USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_contacts_list ON contacts(tenant_id, list_id) WHERE list_id IS NOT NULL;

-- ═══════════════════════════════════════════════════════
-- AUTOMATIONS TABLE
-- ═══════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS automations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    trigger_type VARCHAR(50) NOT NULL DEFAULT 'manual'
        CHECK (trigger_type IN ('on_subscribe', 'on_event', 'on_tag', 'on_date', 'on_inactivity', 'on_link_click', 'manual')),
    trigger_config JSONB DEFAULT '{}',
    steps JSONB DEFAULT '[]',
    enabled BOOLEAN DEFAULT false,
    last_triggered_at TIMESTAMPTZ,
    total_runs INT DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_automations_tenant ON automations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_automations_enabled ON automations(tenant_id, enabled) WHERE enabled = true;

-- Add campaign_id column to messages if not exists
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'messages' AND column_name = 'campaign_id'
    ) THEN
        ALTER TABLE messages ADD COLUMN campaign_id UUID REFERENCES campaigns(id);
        CREATE INDEX idx_messages_campaign ON messages(campaign_id) WHERE campaign_id IS NOT NULL;
    END IF;
END $$;

COMMIT;
