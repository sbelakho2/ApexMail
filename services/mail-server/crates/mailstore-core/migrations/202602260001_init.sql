CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS mail_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL UNIQUE,
    domain TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    display_name TEXT,
    quota_bytes BIGINT NOT NULL DEFAULT 1073741824,
    used_bytes BIGINT NOT NULL DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS mail_mailboxes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES mail_accounts(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    parent_id UUID REFERENCES mail_mailboxes(id) ON DELETE CASCADE,
    mailbox_type TEXT NOT NULL DEFAULT 'custom',
    total_messages BIGINT NOT NULL DEFAULT 0,
    unread_messages BIGINT NOT NULL DEFAULT 0,
    uidnext BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(account_id, name, parent_id)
);

CREATE TABLE IF NOT EXISTS mail_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES mail_accounts(id) ON DELETE CASCADE,
    mailbox_id UUID NOT NULL REFERENCES mail_mailboxes(id) ON DELETE CASCADE,
    uid BIGINT,
    -- DI-003: message_id is the RFC5322 Message-Id; dedup scoped per (account_id, mailbox_id, message_id)
    message_id TEXT NOT NULL,
    from_address TEXT NOT NULL,
    from_name TEXT,
    to_addresses JSONB NOT NULL DEFAULT '[]'::jsonb,
    cc_addresses JSONB NOT NULL DEFAULT '[]'::jsonb,
    bcc_addresses JSONB NOT NULL DEFAULT '[]'::jsonb,
    subject TEXT NOT NULL,
    date TIMESTAMPTZ NOT NULL,
    text_body TEXT,
    html_body TEXT,
    raw_size BIGINT NOT NULL DEFAULT 0,
    is_read BOOLEAN NOT NULL DEFAULT false,
    is_starred BOOLEAN NOT NULL DEFAULT false,
    is_deleted BOOLEAN NOT NULL DEFAULT false,
    is_spam BOOLEAN NOT NULL DEFAULT false,
    labels TEXT[] DEFAULT '{}',
    headers JSONB DEFAULT '{}'::jsonb,
    attachments JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mail_messages_account_mailbox
ON mail_messages(account_id, mailbox_id, date DESC);

CREATE INDEX IF NOT EXISTS idx_mail_messages_search
ON mail_messages USING GIN (to_tsvector('english', subject || ' ' || COALESCE(text_body, '')));

CREATE UNIQUE INDEX IF NOT EXISTS idx_mail_messages_mailbox_uid
ON mail_messages(mailbox_id, uid);

-- DI-006: Prevent duplicate messages with same Message-Id within the same mailbox
CREATE UNIQUE INDEX IF NOT EXISTS idx_mail_messages_dedup
ON mail_messages(account_id, mailbox_id, message_id)
WHERE message_id IS NOT NULL AND message_id != '';
