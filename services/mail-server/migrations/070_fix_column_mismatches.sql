-- Migration 070: Fix column name mismatches between DB schema and api-server code
-- These were discovered during live server testing.
-- contacts/events/webhooks/templates are created by migration 075; every
-- statement touching them is guarded with to_regclass so a fresh in-order
-- run does not abort (075's own CREATE carries the final shape).

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
DO $$
BEGIN
    IF to_regclass('public.contacts') IS NOT NULL THEN
        ALTER TABLE contacts ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'subscribed';
        ALTER TABLE contacts ADD COLUMN IF NOT EXISTS phone VARCHAR(32);
        ALTER TABLE contacts ADD COLUMN IF NOT EXISTS unsubscribed_at TIMESTAMPTZ;
    END IF;
END $$;

-- Events: code uses 'event_type', table has 'type'
DO $$
BEGIN
    IF to_regclass('public.events') IS NOT NULL THEN
        ALTER TABLE events ADD COLUMN IF NOT EXISTS event_type VARCHAR(50);
        IF EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema='public' AND table_name='events' AND column_name='type') THEN
            UPDATE events SET event_type = type WHERE event_type IS NULL AND type IS NOT NULL;
        END IF;
        ALTER TABLE events ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}';
    END IF;
END $$;

-- Webhooks: code expects 'status'
DO $$
BEGIN
    IF to_regclass('public.webhooks') IS NOT NULL THEN
        ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active';
        ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();
    END IF;
END $$;

-- Templates: ensure code-expected columns
DO $$
BEGIN
    IF to_regclass('public.templates') IS NOT NULL THEN
        ALTER TABLE templates ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();
    END IF;
END $$;

-- Lists: code expects 'status'
ALTER TABLE lists ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active';
