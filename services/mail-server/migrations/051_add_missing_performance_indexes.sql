-- 051_add_missing_performance_indexes.sql
--
-- T-201: Add Missing Database Indexes (Performance & Scalability Remediation)
-- =============================================================================
-- Adds 6 targeted indexes identified by query profiling to accelerate the
-- most expensive remaining query patterns in the system.
--
-- Indexes added:
--   1. idx_email_queue_tenant_status_created    — tenant-scoped queue scans
--   2. idx_email_delivery_log_email_id          — delivery lookup by email_id
--   3. idx_audit_logs_tenant_resource           — compliance queries on audit_logs
--   4. idx_metering_events_tenant_type_ts_desc  — billing queries (desc timestamp)
--   5. idx_api_keys_tenant_revoked              — active API key lookups (partial)
--   6. idx_webhook_events_tenant_delivery       — failed webhook retries (partial)
--
-- NOTE: This migration MUST NOT be wrapped in a transaction block.
-- CREATE INDEX CONCURRENTLY requires running outside any explicit transaction.
-- =============================================================================

-- =============================================================================
-- 1. Composite index on email_queue (tenant_id, status, created_at)
--    Used by: tenant-scoped queue scans filtering by status and age
-- =============================================================================
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_email_queue_tenant_status_created') THEN
    EXECUTE format('CREATE INDEX CONCURRENTLY idx_email_queue_tenant_status_created
      ON email_queue (tenant_id, status, created_at)');
  END IF;
END $$;

-- =============================================================================
-- 2. Index on email_delivery_log (email_id)
--    Used by: delivery lookup queries joining on email_id
-- =============================================================================
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_email_delivery_log_email_id') THEN
    EXECUTE format('CREATE INDEX CONCURRENTLY idx_email_delivery_log_email_id
      ON email_delivery_log (email_id)');
  END IF;
END $$;

-- =============================================================================
-- 3. Composite index on audit_logs (tenant_id, resource, timestamp)
--    Used by: compliance queries filtering by tenant, resource type, and time
--    NOTE: The actual column names in audit_logs are "resource" and "timestamp"
--          (not "resource_type" and "created_at") — see migrations 038/050.
-- =============================================================================
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_audit_logs_tenant_resource') THEN
    EXECUTE format('CREATE INDEX CONCURRENTLY idx_audit_logs_tenant_resource
      ON audit_logs (tenant_id, resource, timestamp)');
  END IF;
END $$;

-- =============================================================================
-- 4. Composite index on metering_events (tenant_id, event_type, timestamp DESC)
--    Used by: billing aggregation queries with descending timestamp ordering
-- =============================================================================
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_metering_events_tenant_type_ts_desc') THEN
    EXECUTE format('CREATE INDEX CONCURRENTLY idx_metering_events_tenant_type_ts_desc
      ON metering_events (tenant_id, event_type, timestamp DESC)');
  END IF;
END $$;

-- =============================================================================
-- 5. Partial index on api_keys (tenant_id, revoked_at) WHERE revoked_at IS NULL
--    Used by: active API key lookups (only non-revoked keys)
--    Note: Table wrapped in conditional check — api_keys may not exist
--          depending on migration order in some environments.
-- =============================================================================
DO $$
BEGIN
  IF to_regclass('public.api_keys') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_api_keys_tenant_revoked') THEN
    EXECUTE format('CREATE INDEX CONCURRENTLY idx_api_keys_tenant_revoked
      ON api_keys (tenant_id, revoked_at)
      WHERE revoked_at IS NULL');
  END IF;
END $$;

-- =============================================================================
-- 6. Index on webhook_events (tenant_id, delivery_status, created_at)
--    Used by: failed webhook delivery retry scans
--    Note: Table wrapped in conditional check — webhook_events may not exist
--          depending on migration order in some environments.
-- =============================================================================
DO $$
BEGIN
  IF to_regclass('public.webhook_events') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_webhook_events_tenant_delivery') THEN
    EXECUTE format('CREATE INDEX CONCURRENTLY idx_webhook_events_tenant_delivery
      ON webhook_events (tenant_id, delivery_status, created_at)');
  END IF;
END $$;
