-- Add GIN index for array search on mail_messages.labels
--
-- Accelerates queries filtering messages by label membership, e.g.:
--   SELECT * FROM mail_messages WHERE labels @> ARRAY['important']::TEXT[];
--
-- Uses CONCURRENTLY to avoid blocking writes during migration.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mail_messages_labels_gin
  ON mail_messages USING GIN (labels);
