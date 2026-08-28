-- Add composite index on metering_events for common query patterns.
--
-- Query patterns:
--   1. SELECT event_type, SUM(quantity) FROM metering_events
--      WHERE tenant_id = $1 AND timestamp >= $2 AND timestamp < $3 GROUP BY event_type
--   2. SELECT SUM(quantity) FROM metering_events
--      WHERE tenant_id = $1 AND event_type = 'emails_sent' AND timestamp >= $2
--
-- A single composite index on (tenant_id, event_type, timestamp) covers both
-- patterns efficiently via a single index scan, avoiding bitmap combine of
-- three separate single-column indexes.
--
-- NOTE: The index is a plain CREATE INDEX (NOT CONCURRENTLY): sqlx wraps
-- every migration file in a transaction, and CREATE INDEX CONCURRENTLY is
-- not permitted inside a transaction block — with the guard passing it
-- failed the whole chain (same reasoning as migration 106's header). The
-- DO block with to_regclass guard prevents failure when metering_events
-- hasn't been created yet (it's created in migration 052).

DO $$
BEGIN
  IF to_regclass('public.metering_events') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_metering_events_tenant_type_ts') THEN
    EXECUTE 'CREATE INDEX idx_metering_events_tenant_type_ts
      ON metering_events (tenant_id, event_type, timestamp)';
  END IF;
END $$;
