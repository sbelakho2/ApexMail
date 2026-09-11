-- 113: folded from crates/mailstore-core/migrations/202608210001_dedup_exempt.sql (idempotent copy) —
-- the canonical chain owns the shared database's _sqlx_migrations; mailstore's
-- runtime auto-migrate is gated behind MAILSTORE_RUN_EMBEDDED_MIGRATIONS.
-- Scope message-id deduplication to the delivery path (see the shared
-- migration 102_message_dedup_delivery_scope.sql for the full rationale).
-- Exempt rows (user-initiated copies) may share a Message-ID within a
-- mailbox; delivery-path rows remain unique per mailbox.
ALTER TABLE mail_messages
    ADD COLUMN IF NOT EXISTS dedup_exempt BOOLEAN NOT NULL DEFAULT FALSE;

DROP INDEX IF EXISTS idx_mail_messages_dedup;

-- Partitioned (050+) shape requires the partition key in unique indexes;
-- the plain (mailstore-first) shape keeps the three-column unique. Same
-- guard pattern as 097/102 (which this recreation mirrors).
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_partitioned_table
        WHERE partrelid = 'mail_messages'::regclass
    ) THEN
        CREATE UNIQUE INDEX IF NOT EXISTS idx_mail_messages_dedup
            ON mail_messages(account_id, mailbox_id, message_id, created_at)
            WHERE message_id IS NOT NULL AND message_id != ''
              AND dedup_exempt = FALSE;
    ELSE
        CREATE UNIQUE INDEX IF NOT EXISTS idx_mail_messages_dedup
            ON mail_messages(account_id, mailbox_id, message_id)
            WHERE message_id IS NOT NULL AND message_id != ''
              AND dedup_exempt = FALSE;
    END IF;
END
$$;
