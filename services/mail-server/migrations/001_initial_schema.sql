-- ApexMail Mail Server Schema
-- Creates tables for the mail server (email queue, accounts, messages)

-- =============================================================================
-- Email Queue Table (for outbound delivery)
-- =============================================================================

CREATE TABLE IF NOT EXISTS email_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Email content
    from_address TEXT NOT NULL,
    to_addresses TEXT[] NOT NULL,
    cc_addresses TEXT[] DEFAULT '{}',
    bcc_addresses TEXT[] DEFAULT '{}',
    reply_to TEXT,
    subject TEXT NOT NULL,
    text_body TEXT,
    html_body TEXT,
    headers JSONB DEFAULT '{}'::jsonb,
    attachments JSONB DEFAULT '[]'::jsonb,
    
    -- Queue status
    status TEXT NOT NULL DEFAULT 'pending' 
        CHECK (status IN ('pending', 'processing', 'sent', 'failed', 'deferred', 'cancelled')),
    attempts INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 5,
    last_error TEXT,
    next_retry_at TIMESTAMPTZ,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sent_at TIMESTAMPTZ,
    
    -- Sales automation integration
    tenant_id UUID,
    campaign_id UUID,
    sequence_id UUID,
    contact_id UUID,
    
    -- Priority and metadata
    priority INT NOT NULL DEFAULT 0,
    tags TEXT[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Indexes for email queue
CREATE INDEX IF NOT EXISTS idx_email_queue_status_retry 
    ON email_queue(status, next_retry_at, priority DESC) 
    WHERE status IN ('pending', 'deferred');

CREATE INDEX IF NOT EXISTS idx_email_queue_campaign 
    ON email_queue(campaign_id) 
    WHERE campaign_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_email_queue_tenant 
    ON email_queue(tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_email_queue_sent_at 
    ON email_queue(sent_at DESC) 
    WHERE sent_at IS NOT NULL;

-- =============================================================================
-- Mail Accounts Table (for receiving mail)
-- =============================================================================

CREATE TABLE IF NOT EXISTS mail_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL UNIQUE,
    domain TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    display_name TEXT,
    
    -- Quota management
    quota_bytes BIGINT NOT NULL DEFAULT 1073741824, -- 1GB default
    used_bytes BIGINT NOT NULL DEFAULT 0,
    
    -- Status
    is_active BOOLEAN NOT NULL DEFAULT true,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mail_accounts_domain 
    ON mail_accounts(domain);

-- =============================================================================
-- Mailboxes Table (folders for organizing mail)
-- =============================================================================

CREATE TABLE IF NOT EXISTS mail_mailboxes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES mail_accounts(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    parent_id UUID REFERENCES mail_mailboxes(id) ON DELETE CASCADE,
    
    -- Mailbox type
    mailbox_type TEXT NOT NULL DEFAULT 'custom'
        CHECK (mailbox_type IN ('inbox', 'sent', 'drafts', 'trash', 'spam', 'archive', 'custom')),
    
    -- Message counts (cached for performance)
    total_messages BIGINT NOT NULL DEFAULT 0,
    unread_messages BIGINT NOT NULL DEFAULT 0,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Unique mailbox name per account (using index for COALESCE expression)
CREATE UNIQUE INDEX IF NOT EXISTS idx_mail_mailboxes_unique_name
    ON mail_mailboxes(account_id, name, COALESCE(parent_id, '00000000-0000-0000-0000-000000000000'::UUID));

CREATE INDEX IF NOT EXISTS idx_mail_mailboxes_account 
    ON mail_mailboxes(account_id);

-- =============================================================================
-- Messages Table (stored emails)
-- =============================================================================

CREATE TABLE IF NOT EXISTS mail_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES mail_accounts(id) ON DELETE CASCADE,
    mailbox_id UUID NOT NULL REFERENCES mail_mailboxes(id) ON DELETE CASCADE,
    
    -- Message identifiers
    message_id TEXT NOT NULL, -- RFC 5322 Message-ID
    
    -- Envelope
    from_address TEXT NOT NULL,
    from_name TEXT,
    to_addresses JSONB NOT NULL DEFAULT '[]'::jsonb,
    cc_addresses JSONB NOT NULL DEFAULT '[]'::jsonb,
    bcc_addresses JSONB NOT NULL DEFAULT '[]'::jsonb,
    subject TEXT NOT NULL,
    date TIMESTAMPTZ NOT NULL,
    
    -- Content
    text_body TEXT,
    html_body TEXT,
    raw_size BIGINT NOT NULL DEFAULT 0,
    
    -- Flags
    is_read BOOLEAN NOT NULL DEFAULT false,
    is_starred BOOLEAN NOT NULL DEFAULT false,
    is_deleted BOOLEAN NOT NULL DEFAULT false,
    is_spam BOOLEAN NOT NULL DEFAULT false,
    labels TEXT[] DEFAULT '{}',
    
    -- Headers and attachments
    headers JSONB DEFAULT '{}'::jsonb,
    attachments JSONB DEFAULT '[]'::jsonb,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for messages
CREATE INDEX IF NOT EXISTS idx_mail_messages_mailbox 
    ON mail_messages(account_id, mailbox_id, date DESC);

CREATE INDEX IF NOT EXISTS idx_mail_messages_unread 
    ON mail_messages(account_id, is_read) 
    WHERE is_read = false AND is_deleted = false;

CREATE INDEX IF NOT EXISTS idx_mail_messages_message_id 
    ON mail_messages(message_id);

-- Full-text search index
CREATE INDEX IF NOT EXISTS idx_mail_messages_search 
    ON mail_messages USING GIN (
        to_tsvector('english', 
            COALESCE(subject, '') || ' ' || 
            COALESCE(text_body, '') || ' ' ||
            COALESCE(from_address, '')
        )
    );

-- =============================================================================
-- Delivery Log Table (for tracking email delivery)
-- =============================================================================

CREATE TABLE IF NOT EXISTS email_delivery_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email_id UUID NOT NULL REFERENCES email_queue(id) ON DELETE CASCADE,
    
    -- Delivery attempt info
    attempt_number INT NOT NULL,
    mx_host TEXT,
    smtp_response TEXT,
    
    -- Status
    success BOOLEAN NOT NULL,
    error_message TEXT,
    
    -- Timestamps
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_email_delivery_log_email 
    ON email_delivery_log(email_id, attempted_at DESC);

-- =============================================================================
-- DKIM Keys Table (for signing outbound mail)
-- =============================================================================

CREATE TABLE IF NOT EXISTS dkim_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain TEXT NOT NULL,
    selector TEXT NOT NULL,
    private_key_pem TEXT NOT NULL,
    public_key_pem TEXT NOT NULL,
    
    -- Status
    is_active BOOLEAN NOT NULL DEFAULT true,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_at TIMESTAMPTZ,
    
    -- Unique constraint
    UNIQUE(domain, selector)
);

CREATE INDEX IF NOT EXISTS idx_dkim_keys_domain_active 
    ON dkim_keys(domain, is_active) 
    WHERE is_active = true;

-- =============================================================================
-- Updated At Trigger
-- =============================================================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply trigger to all tables with updated_at
DO $$
DECLARE
    t TEXT;
BEGIN
    FOR t IN 
        SELECT unnest(ARRAY['email_queue', 'mail_accounts', 'mail_mailboxes', 'mail_messages'])
    LOOP
        EXECUTE format('
            DROP TRIGGER IF EXISTS update_%s_updated_at ON %s;
            CREATE TRIGGER update_%s_updated_at
            BEFORE UPDATE ON %s
            FOR EACH ROW
            EXECUTE FUNCTION update_updated_at_column();
        ', t, t, t, t);
    END LOOP;
END;
$$;

-- =============================================================================
-- Comments
-- =============================================================================

COMMENT ON TABLE email_queue IS 'Queue for outbound email delivery via purpose-built mail infrastructure';
COMMENT ON TABLE mail_accounts IS 'Email accounts for receiving mail';
COMMENT ON TABLE mail_mailboxes IS 'Mailbox folders for organizing received mail';
COMMENT ON TABLE mail_messages IS 'Stored email messages';
COMMENT ON TABLE email_delivery_log IS 'Delivery attempt history for outbound emails';
COMMENT ON TABLE dkim_keys IS 'DKIM signing keys for domains';
