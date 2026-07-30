-- Migration 086: Add reply_to, headers, attachments, and stream columns to messages + email_queue tables.
-- Implements ITEM #22 (Transactional Sending Core — reply_to, custom headers, attachments)
-- and ITEM #23 (Message Streams — transactional/broadcast stream field).

-- ── Messages table ──────────────────────────────────────────────────
ALTER TABLE messages ADD COLUMN IF NOT EXISTS reply_to TEXT;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS headers JSONB;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS attachments JSONB;

-- stream: 'transactional' (default) or 'broadcast'. NULL = transactional for backward compatibility.
ALTER TABLE messages ADD COLUMN IF NOT EXISTS stream TEXT
    CHECK (stream IS NULL OR stream IN ('transactional', 'broadcast'));

CREATE INDEX IF NOT EXISTS idx_messages_stream ON messages(tenant_id, stream);

-- ── Email queue table ───────────────────────────────────────────────
ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS reply_to TEXT;
ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS headers JSONB;
ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS attachments JSONB;
ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS stream TEXT
    CHECK (stream IS NULL OR stream IN ('transactional', 'broadcast'));

CREATE INDEX IF NOT EXISTS idx_email_queue_stream ON email_queue(tenant_id, stream);

DO $$
BEGIN
    RAISE NOTICE 'Migration 086: Added reply_to, headers, attachments, and stream columns to messages + email_queue';
END $$;
