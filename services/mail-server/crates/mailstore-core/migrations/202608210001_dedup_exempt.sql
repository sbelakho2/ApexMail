-- Scope message-id deduplication to the delivery path (see the shared
-- migration 102_message_dedup_delivery_scope.sql for the full rationale).
-- Exempt rows (user-initiated copies) may share a Message-ID within a
-- mailbox; delivery-path rows remain unique per mailbox.
ALTER TABLE mail_messages
    ADD COLUMN IF NOT EXISTS dedup_exempt BOOLEAN NOT NULL DEFAULT FALSE;

DROP INDEX IF EXISTS idx_mail_messages_dedup;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mail_messages_dedup
    ON mail_messages(account_id, mailbox_id, message_id)
    WHERE message_id IS NOT NULL AND message_id != ''
      AND dedup_exempt = FALSE;
