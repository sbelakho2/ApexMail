-- Migration 102: Scope message-id deduplication to the DELIVERY path.
--
-- Problem (audit item I.5 / migrations_needed proposal
-- 20260821_message_dedup_delivery_scope.sql): idx_mail_messages_dedup
-- enforces uniqueness on (account_id, mailbox_id, message_id) and
-- store_message collapses duplicates by returning the existing row:
--
--   * COPY of a message into a mailbox that already has that Message-ID
--     returned a COPYUID mapping to the EXISTING uid — no new row was
--     created, so the "copy" was an alias, not a copy.
--   * When the aliased original was expunged, the copy vanished: the
--     client was told the copy exists, but the backing row was gone.
--
-- Dedup is the right behavior for SMTP delivery (redelivery must not
-- duplicate a message) but wrong for user-initiated COPY, which the user
-- explicitly asked to duplicate. This migration adds a `dedup_exempt`
-- flag and narrows the unique index to non-exempt (delivery-path) rows so
-- exempt rows can coexist with — and alongside — delivery rows.
--
-- Application contract: mailstore-core sets dedup_exempt = TRUE on rows
-- created by user-initiated copies (service.copy_message); the delivery
-- path (StoreMessage RPC) keeps the default FALSE so redelivery still
-- collapses. Dedup matching in store_message also ignores exempt rows.
--
-- All statements are idempotent and safe to re-run.

DO $$
BEGIN
    IF to_regclass('public.mail_messages') IS NOT NULL THEN
        ALTER TABLE mail_messages
            ADD COLUMN IF NOT EXISTS dedup_exempt BOOLEAN NOT NULL DEFAULT FALSE;

        DROP INDEX IF EXISTS idx_mail_messages_dedup;

        -- On the partitioned shape (050+), a unique index must include the
        -- partition key; on the plain shape (mailstore-first DBs) the
        -- three-column unique works as-is. Exempt rows are excluded either
        -- way. Mirrors the guarded recreation in 097.
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
    END IF;
END
$$;
