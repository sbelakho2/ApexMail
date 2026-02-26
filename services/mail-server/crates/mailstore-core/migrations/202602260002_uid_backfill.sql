ALTER TABLE mail_mailboxes ADD COLUMN IF NOT EXISTS uidnext BIGINT NOT NULL DEFAULT 1;
ALTER TABLE mail_messages ADD COLUMN IF NOT EXISTS uid BIGINT;

WITH ranked AS (
    SELECT id, mailbox_id,
           ROW_NUMBER() OVER (PARTITION BY mailbox_id ORDER BY date, created_at, id) AS uid
    FROM mail_messages
    WHERE uid IS NULL
)
UPDATE mail_messages m
SET uid = r.uid
FROM ranked r
WHERE m.id = r.id;

UPDATE mail_mailboxes mb
SET uidnext = COALESCE((
    SELECT MAX(uid) + 1 FROM mail_messages mm WHERE mm.mailbox_id = mb.id
), 1);
