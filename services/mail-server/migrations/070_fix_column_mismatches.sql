-- Migration 070: Fix column name mismatches between DB schema and api-server code
-- These were discovered during live server testing.

-- Domains: code uses 'name', table had 'domain'
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='domains' AND column_name='domain') THEN
    ALTER TABLE domains RENAME COLUMN domain TO name;
  END IF;
END $$;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'pending';
ALTER TABLE domains ADD COLUMN IF NOT EXISTS spf_verified BOOLEAN DEFAULT false;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS dkim_verified BOOLEAN DEFAULT false;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS dmarc_verified BOOLEAN DEFAULT false;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS return_path_verified BOOLEAN DEFAULT false;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS mta_sts_verified BOOLEAN DEFAULT false;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS bimi_verified BOOLEAN DEFAULT false;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS tlsrpt_verified BOOLEAN DEFAULT false;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

-- Contacts: code expects 'status'
ALTER TABLE contacts ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'subscribed';
ALTER TABLE contacts ADD COLUMN IF NOT EXISTS phone VARCHAR(32);
ALTER TABLE contacts ADD COLUMN IF NOT EXISTS unsubscribed_at TIMESTAMPTZ;

-- Events: code uses 'event_type', table has 'type'
ALTER TABLE events ADD COLUMN IF NOT EXISTS event_type VARCHAR(50);
UPDATE events SET event_type = type WHERE event_type IS NULL AND type IS NOT NULL;
ALTER TABLE events ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}';

-- Webhooks: code expects 'status'
ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active';
ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

-- Templates: ensure code-expected columns
ALTER TABLE templates ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

-- Lists: code expects 'status'
ALTER TABLE lists ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active';
