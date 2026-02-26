-- Add per-mailbox UID tracking for mailstore messages

ALTER TABLE mail_mailboxes
    ADD COLUMN IF NOT EXISTS uidnext BIGINT NOT NULL DEFAULT 1;

ALTER TABLE mail_messages
    ADD COLUMN IF NOT EXISTS uid BIGINT;

-- Backfill UIDs per mailbox ordered by date
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

ALTER TABLE mail_messages
    ALTER COLUMN uid SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mail_messages_mailbox_uid
    ON mail_messages(mailbox_id, uid);
