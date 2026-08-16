-- Add per-mailbox UID tracking for mailstore messages
-- C-09/C-18: Prevent race condition by locking table and doing a second backfill

ALTER TABLE mail_mailboxes
    ADD COLUMN IF NOT EXISTS uidnext BIGINT NOT NULL DEFAULT 1;

ALTER TABLE mail_messages
    ADD COLUMN IF NOT EXISTS uid BIGINT;

-- First backfill: assign UIDs to existing rows
WITH ranked AS (
    SELECT id,
           mailbox_id,
           ROW_NUMBER() OVER (PARTITION BY mailbox_id ORDER BY date, created_at, id) AS uid
    FROM mail_messages
    WHERE uid IS NULL
)
UPDATE mail_messages m
SET uid = r.uid
FROM ranked r
WHERE m.id = r.id;

-- Set uidnext to max(uid) + 1 for each mailbox
UPDATE mail_mailboxes mb
SET uidnext = COALESCE((
    SELECT MAX(uid) + 1 FROM mail_messages mm WHERE mm.mailbox_id = mb.id
), 1);

-- C-09/C-18: Lock the table with ACCESS EXCLUSIVE to prevent concurrent
-- inserts with NULL uid, then do a second backfill for any rows inserted
-- between the first backfill and the lock, before applying SET NOT NULL.
-- ACCESS EXCLUSIVE MODE is required because IN EXCLUSIVE MODE still allows
-- concurrent reads, which could allow INSERTs to slip through the window.
BEGIN;
LOCK TABLE mail_messages IN ACCESS EXCLUSIVE MODE;

-- Second backfill: catch any rows inserted after the first backfill
WITH ranked AS (
    SELECT id,
           mailbox_id,
           ROW_NUMBER() OVER (PARTITION BY mailbox_id ORDER BY date, created_at, id) AS uid
    FROM mail_messages
    WHERE uid IS NULL
)
UPDATE mail_messages m
SET uid = r.uid
FROM ranked r
WHERE m.id = r.id;

ALTER TABLE mail_messages
    ALTER COLUMN uid SET NOT NULL;
COMMIT;

DO $$
BEGIN
    -- Partitioned (050+) shape requires the partition key in unique indexes;
    -- IF NOT EXISTS makes the re-run a no-op once either variant exists.
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_mail_messages_mailbox_uid') THEN
        IF EXISTS (SELECT 1 FROM pg_partitioned_table
                   WHERE partrelid = 'mail_messages'::regclass) THEN
            CREATE UNIQUE INDEX idx_mail_messages_mailbox_uid
                ON mail_messages(mailbox_id, uid, created_at);
        ELSE
            CREATE UNIQUE INDEX idx_mail_messages_mailbox_uid
                ON mail_messages(mailbox_id, uid);
        END IF;
    END IF;
END $$;
