-- Drop the account-wide UNIQUE(account_id, message_id) index on mail_messages.
--
-- RFC 3501 COPY/MOVE (and IMAP APPEND of the same message into another
-- mailbox) legitimately create a second row with the same Message-ID in a
-- different mailbox of the same account. The account-wide index made every
-- such copy fail with a unique-violation. Deduplication is correctly scoped
-- per mailbox (DI-006), which is what the mailstore schema enforces with
-- idx_mail_messages_dedup; the equivalent per-mailbox index is (re)created
-- here so DB-level dedup still holds after the account-wide index is dropped.

DROP INDEX IF EXISTS idx_mail_messages_account_message_id;

-- On the partitioned shape (050+), a unique index must include the
-- partition key; on the plain shape (mailstore-first DBs) the three-column
-- unique works as-is. Guard accordingly.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_partitioned_table
        WHERE partrelid = 'mail_messages'::regclass
    ) THEN
        CREATE UNIQUE INDEX IF NOT EXISTS idx_mail_messages_dedup
            ON mail_messages(account_id, mailbox_id, message_id, created_at)
            WHERE message_id IS NOT NULL AND message_id != '';
    ELSE
        CREATE UNIQUE INDEX IF NOT EXISTS idx_mail_messages_dedup
            ON mail_messages(account_id, mailbox_id, message_id)
            WHERE message_id IS NOT NULL AND message_id != '';
    END IF;
END
$$;
