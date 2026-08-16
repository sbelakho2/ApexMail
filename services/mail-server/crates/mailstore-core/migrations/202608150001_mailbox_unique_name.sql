-- Make mailbox names unique per (account, name, parent) with NULL parent
-- treated as equal.
--
-- The init migration only created a plain UNIQUE(account_id, name, parent_id)
-- constraint, which is NULL-distinct in PostgreSQL: two "Work" mailboxes with
-- a NULL parent can coexist, and the targeted ON CONFLICT clause used by
-- create_mailbox() — (account_id, name, COALESCE(parent_id, sentinel)) — finds
-- no matching unique index on mailstore-first databases. This migration merges
-- any such duplicates and adds the expression unique index the services schema
-- (001_initial_schema.sql) already has, so the ON CONFLICT target is valid
-- everywhere and duplicate top-level names cannot be created.

-- 1) Identify duplicate mailboxes per (account, name, coalesced parent),
--    keeping the one with the most messages (tie-break: oldest).
DROP TABLE IF EXISTS mailbox_merge_victims;
CREATE TEMP TABLE mailbox_merge_victims AS
WITH ranked AS (
    SELECT id,
           ROW_NUMBER() OVER (
               PARTITION BY account_id, name,
                            COALESCE(parent_id, '00000000-0000-0000-0000-000000000000'::uuid)
               ORDER BY total_messages DESC, created_at, id
           ) AS rn,
           FIRST_VALUE(id) OVER (
               PARTITION BY account_id, name,
                            COALESCE(parent_id, '00000000-0000-0000-0000-000000000000'::uuid)
               ORDER BY total_messages DESC, created_at, id
           ) AS keeper_id
    FROM mail_mailboxes
)
SELECT id AS victim_id, keeper_id FROM ranked WHERE rn > 1;

-- 2) Disambiguate message-ids that already exist in the keeper mailbox so the
--    per-mailbox dedup index (account_id, mailbox_id, message_id) still holds
--    after the messages are moved in.
UPDATE mail_messages m
SET message_id = m.message_id || '-merged-' || left(m.id::text, 8),
    updated_at = NOW()
FROM mailbox_merge_victims v
WHERE m.mailbox_id = v.victim_id
  AND EXISTS (
      SELECT 1 FROM mail_messages k
      WHERE k.mailbox_id = v.keeper_id
        AND k.message_id = m.message_id
        AND k.id <> m.id
  );

-- 3) Move the victims' messages into the keeper, assigning fresh UIDs above
--    the keeper's uidnext so the (mailbox_id, uid) unique index keeps holding.
WITH moved AS (
    SELECT m.id,
           v.keeper_id,
           k.uidnext + ROW_NUMBER() OVER (
               PARTITION BY v.keeper_id ORDER BY m.uid, m.id
           ) - 1 AS new_uid
    FROM mail_messages m
    JOIN mailbox_merge_victims v ON v.victim_id = m.mailbox_id
    JOIN mail_mailboxes k ON k.id = v.keeper_id
)
UPDATE mail_messages m
SET mailbox_id = moved.keeper_id,
    uid = moved.new_uid,
    updated_at = NOW()
FROM moved
WHERE m.id = moved.id;

-- 4) Drop the now-empty duplicate mailboxes.
DELETE FROM mail_mailboxes m
USING mailbox_merge_victims v
WHERE m.id = v.victim_id;

-- 5) Refresh cached counts and uidnext for the keepers.
UPDATE mail_mailboxes k
SET total_messages = (
        SELECT COUNT(*) FROM mail_messages mm
        WHERE mm.mailbox_id = k.id AND mm.is_deleted = false
    ),
    unread_messages = (
        SELECT COUNT(*) FROM mail_messages mm
        WHERE mm.mailbox_id = k.id AND mm.is_deleted = false AND mm.is_read = false
    ),
    uidnext = GREATEST(
        k.uidnext,
        COALESCE((SELECT MAX(mm.uid) + 1 FROM mail_messages mm WHERE mm.mailbox_id = k.id), 1)
    ),
    updated_at = NOW()
FROM (SELECT DISTINCT keeper_id FROM mailbox_merge_victims) v
WHERE k.id = v.keeper_id;

DROP TABLE IF EXISTS mailbox_merge_victims;

-- 6) The expression unique index that create_mailbox()'s ON CONFLICT targets.
CREATE UNIQUE INDEX IF NOT EXISTS idx_mail_mailboxes_unique_name
    ON mail_mailboxes(account_id, name, (COALESCE(parent_id, '00000000-0000-0000-0000-000000000000'::uuid)));
