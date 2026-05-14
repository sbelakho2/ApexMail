-- Partial index for delivery retry queries
--
-- Accelerates the retry worker's query to find pending/retrying deliveries:
--   SELECT * FROM email_delivery_log
--   WHERE status IN ('pending', 'retrying')
--   ORDER BY attempted_at ASC
--   LIMIT 100;
--
-- The partial index only covers rows with status 'pending' or 'retrying',
-- keeping the index small and efficient.  Uses CONCURRENTLY to avoid
-- blocking writes during migration.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_email_delivery_log_status_attempted
  ON email_delivery_log (status, attempted_at)
  WHERE status IN ('pending', 'retrying');
