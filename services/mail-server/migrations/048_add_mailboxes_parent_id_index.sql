-- Add index on parent_id for self-referencing FK lookups in mail_mailboxes
--
-- Accelerates thread-resolution queries that navigate the nested
-- mailbox hierarchy (e.g., finding child mailboxes of a given parent).
--
-- Uses CONCURRENTLY to avoid blocking writes during migration.
-- H-10: Use partial index WHERE parent_id IS NOT NULL since most rows
-- have NULL parent_id (top-level mailboxes), making the index smaller/faster.
CREATE INDEX IF NOT EXISTS idx_mail_mailboxes_parent_id
  ON mail_mailboxes (parent_id)
  WHERE parent_id IS NOT NULL;
