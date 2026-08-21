-- Revert the delivery-scoped dedup index back to the unconditional
-- per-mailbox unique (exempt copies would violate it if any exist, so
-- they are collapsed back to one row per Message-ID first).
DELETE FROM mail_messages m
USING mail_messages keep
WHERE m.dedup_exempt = TRUE
  AND keep.account_id = m.account_id
  AND keep.mailbox_id = m.mailbox_id
  AND keep.message_id = m.message_id
  AND keep.id < m.id;

DROP INDEX IF EXISTS idx_mail_messages_dedup;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mail_messages_dedup
    ON mail_messages(account_id, mailbox_id, message_id)
    WHERE message_id IS NOT NULL AND message_id != '';

ALTER TABLE mail_messages DROP COLUMN IF EXISTS dedup_exempt;
