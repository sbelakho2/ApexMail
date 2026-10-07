-- 110: folded from crates/mailstore-core/migrations/202602260002_uid_backfill.sql (idempotent copy) —
-- the canonical chain owns the shared database's _sqlx_migrations; mailstore's
-- runtime auto-migrate is gated behind MAILSTORE_RUN_EMBEDDED_MIGRATIONS.
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

-- UIDNEXT must be NON-DECREASING (RFC 3501): a mailbox whose highest-UID
-- message was expunged has uidnext > max(uid)+1, and the original statement
-- recomputed it downward, telling cached clients deliveries were lost and
-- permitting UID reuse after expunge. GREATEST guard added 2026-10-07
-- (gates review).
UPDATE mail_mailboxes mb
SET uidnext = GREATEST(mb.uidnext, COALESCE((
    SELECT MAX(uid) + 1 FROM mail_messages mm WHERE mm.mailbox_id = mb.id
), 1));
