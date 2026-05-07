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

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_metering_events_tenant_type_ts
    ON metering_events (tenant_id, event_type, timestamp);
