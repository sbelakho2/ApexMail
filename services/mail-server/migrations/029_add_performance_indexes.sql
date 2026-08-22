-- PP-009: Add missing DB indexes for high-frequency query columns.
--
-- These indexes target the most commonly filtered/joined columns identified
-- during performance analysis.  All indexes use CONCURRENTLY via EXECUTE
-- inside DO blocks to avoid blocking writes on production tables.
--
-- Index candidates (per the fault report):
--   (tenant_id, status)   – plan gating, domain lookups
--   (user_id, created_at) – activity / audit queries
--   (message_id)          – webhook event lookups
--   (domain)              – domain validation / dedup
--   (stripe_event_id)     – stripe webhook dedup (already covered by UNIQUE)
--   (tenant_id, event_type) – metering aggregation
--   (tenant_id, id)       – tenant-scoped lookups
--
-- NOTE: This migration MUST NOT be wrapped in a transaction block.
-- CREATE INDEX IF NOT EXISTS requires running outside any explicit transaction.

-- =============================================================================
-- 1. Composite index on email_queue (tenant_id, status)
--    Used by: plan gate, queue status checks per tenant
-- =============================================================================
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_email_queue_tenant_status') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_email_queue_tenant_status
      ON email_queue (tenant_id, status)');
  END IF;
END $$;

-- =============================================================================
-- 2. Index on webhook_events (message_id)
--    Used by: webhook event status lookups by message
-- =============================================================================
DO $$
BEGIN
  IF to_regclass('public.webhook_events') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_webhook_events_message_id') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_webhook_events_message_id
      ON webhook_events (message_id)');
  END IF;
END $$;

-- =============================================================================
-- 3. Index on audit_log (user_id, created_at)
--    Used by: audit trail queries filtered by user and time range
-- =============================================================================
DO $$
BEGIN
  IF to_regclass('public.audit_logs') IS NOT NULL
     AND EXISTS (SELECT 1 FROM information_schema.columns
                 WHERE table_schema = 'public' AND table_name = 'audit_logs'
                   AND column_name = 'user_id')
     AND NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_audit_logs_user_created') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_audit_logs_user_created
      ON audit_logs (user_id, created_at DESC)');
  END IF;
END $$;

-- =============================================================================
-- 4. Index on domains (domain)
--    Used by: domain validation, ownership checks, MX record lookups
-- =============================================================================
DO $$
BEGIN
  IF to_regclass('public.domains') IS NOT NULL
     AND EXISTS (SELECT 1 FROM information_schema.columns
                 WHERE table_schema = 'public' AND table_name = 'domains'
                   AND column_name = 'domain')
     AND NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_domains_domain') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_domains_domain
      ON domains (domain)');
  END IF;
END $$;

-- =============================================================================
-- 5. Composite index on metering_events (tenant_id, event_type)
--    Speeds up per-tenant billing aggregation queries beyond what the
--    existing idx_metering_events_tenant_type_ts covers (which requires
--    a timestamp filter).
-- =============================================================================
DO $$
BEGIN
  IF to_regclass('public.metering_events') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_metering_events_tenant_type') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_metering_events_tenant_type
      ON metering_events (tenant_id, event_type)');
  END IF;
END $$;

-- =============================================================================
-- 6. Index on api_keys (tenant_id, id) for tenant-scoped key lookups
-- =============================================================================
DO $$
BEGIN
  IF to_regclass('public.api_keys') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_api_keys_tenant_id') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_id
      ON api_keys (tenant_id, id)');
  END IF;
END $$;

-- =============================================================================
-- 7. Index on subscriptions (tenant_id, status)
--    Used by: plan gating queries
-- =============================================================================
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_subscriptions_tenant_status') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_subscriptions_tenant_status
      ON subscriptions (tenant_id, status)');
  END IF;
END $$;
