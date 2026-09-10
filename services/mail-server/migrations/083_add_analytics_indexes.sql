-- Migration 083: Add analytics indexes
-- =============================================================================
-- Adds targeted composite indexes to accelerate ALL analytics query patterns
-- identified during an extreme performance audit of every query across:
--   - analytics.rs             (tenant-scoped dashboard/volume/engagement)
--   - admin/analytics.rs       (admin event stats, time-series, providers)
--   - admin/delivery_analytics.rs (latency percentiles, queue, provider breakdown)
--   - admin/growth_analytics.rs   (signups, activation, trial conversion, churn)
--   - admin/predictive_analytics.rs (churn risk, capacity, anomaly detection)
--   - admin/insights.rs           (metric comparisons, trends, recommendations)
--   - admin/cross_tenant.rs       (platform health, plan distribution, growth)
--   - admin/revenue.rs            (MRR, ARR, LTV, CAC, expansion revenue)
--   - admin/dashboard.rs          (sales, compliance, pipeline, activity)
--
-- Each index targets the exact WHERE / JOIN / ORDER BY pattern used by the
-- most expensive queries. Indexes are created non-concurrently (SQLx compat).
-- =============================================================================

-- =============================================================================
-- 1. events(tenant_id, event_type, timestamp) — SINGLE MOST IMPACTFUL INDEX
--    Used by: analytics.rs:220-246,307-344,387-396,805-842
--             admin/analytics.rs:148-198 (via format!)
--             admin/growth_analytics.rs:328-357 (DAU/MAU/WAU)
--             admin/insights.rs:280-333 (open/complaint count)
--             admin/cross_tenant.rs:93-94 (bounce count by tenant)
--    Pattern: WHERE tenant_id = $1 AND timestamp >= $2 AND timestamp <= $3
--             AND event_type = 'opened'/'clicked'/'complained'/'bounce'
--             GROUP BY DATE(timestamp) / COUNT(DISTINCT tenant_id)
--    Without this: bitmap scan of 4 single-column indexes on every request.
-- =============================================================================
DO $$
BEGIN
  IF to_regclass('public.events') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_events_tenant_type_ts') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_events_tenant_type_ts
      ON events (tenant_id, event_type, timestamp)');
  END IF;
END $$;

-- =============================================================================
-- 2. events(message_id, timestamp DESC) — export LATERAL JOIN
--    Used by: analytics.rs:527-533
--    Pattern: SELECT event_type, created_at FROM events
--             WHERE message_id = $1 ORDER BY created_at DESC LIMIT 1
--    Without this: idx_events_message on (message_id) alone forces a sort.
-- =============================================================================
DO $$
BEGIN
  IF to_regclass('public.events') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_events_message_ts_desc') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_events_message_ts_desc
      ON events (message_id, timestamp DESC)');
  END IF;
END $$;

-- =============================================================================
-- 3. tenants(status, created_at) — admin growth queries
--    Used by: admin/growth_analytics.rs:159-200,329-358,566-584
--             admin/insights.rs:336-351
--             admin/cross_tenant.rs:65,589-596,600-621
--             admin/dashboard.rs:223-225
--             admin/predictive_analytics.rs:229-233
--    Pattern: SELECT COUNT(*) FROM tenants WHERE status = 'active'
--             AND created_at >= NOW() - INTERVAL 'X days'
-- =============================================================================
DO $$
BEGIN
  IF to_regclass('public.tenants') IS NOT NULL
     AND EXISTS (
       SELECT 1 FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name = 'tenants'
         AND column_name = 'status'
     )
     AND NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_tenants_status_created') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_tenants_status_created
      ON tenants (status, created_at)');
  END IF;
END $$;

-- =============================================================================
-- 4. tenants(plan, status, created_at) — plan distribution queries
--    Used by: admin/cross_tenant.rs:260-262 (GROUP BY plan)
--             admin/revenue.rs:359-362 (GROUP BY plan)
--             admin/growth_analytics.rs:202-206 (signups by plan)
--    Pattern: SELECT COALESCE(NULLIF(plan, ''), 'free'), COUNT(*) FROM tenants
--             WHERE created_at >= ... GROUP BY 1
-- =============================================================================
DO $$
BEGIN
  IF to_regclass('public.tenants') IS NOT NULL
     AND EXISTS (
       SELECT 1 FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name = 'tenants'
         AND column_name = 'plan'
     )
     AND NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_tenants_plan_status_created') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_tenants_plan_status_created
      ON tenants (plan, status, created_at)');
  END IF;
END $$;

-- =============================================================================
-- 5. subscriptions(status, updated_at) — churn / cancel queries
--    Used by: admin/growth_analytics.rs:443-450
--             admin/predictive_analytics.rs:828-836 (failed queue updated_at check)
--             admin/cross_tenant.rs:601-621 (churned tenants)
--    Pattern: SELECT COUNT(*) FROM subscriptions
--             WHERE status = 'canceled' AND updated_at >= NOW() - INTERVAL '30 days'
-- =============================================================================
DO $$
BEGIN
  IF to_regclass('public.subscriptions') IS NOT NULL
     AND EXISTS (
       SELECT 1 FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name = 'subscriptions'
         AND column_name = 'updated_at'
     )
     AND NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_subscriptions_status_updated') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_subscriptions_status_updated
      ON subscriptions (status, updated_at)');
  END IF;
END $$;

-- =============================================================================
-- 6. subscriptions(status, created_at) — trial lifecycle queries
--    Used by: admin/growth_analytics.rs:361-413 (trials, trial conversion)
--             admin/insights.rs:752-759 (stale trials)
--    Pattern: SELECT COUNT(*) FROM subscriptions
--             WHERE status = 'trialing' AND created_at >= NOW() - INTERVAL 'X days'
-- =============================================================================
DO $$
BEGIN
  IF to_regclass('public.subscriptions') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_subscriptions_status_created') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_subscriptions_status_created
      ON subscriptions (status, created_at)');
  END IF;
END $$;

-- =============================================================================
-- 7. email_queue(status, created_at) — queue depth health queries
--    Used by: admin/delivery_analytics.rs:254-257,398-408
--             admin/predictive_analytics.rs:386-407,775-810
--             admin/insights.rs:386-392,641-645
--    Pattern: SELECT COUNT(*) FROM email_queue
--             WHERE status IN ('pending', 'processing', 'deferred', 'failed')
--             GROUP BY DATE(created_at)
-- =============================================================================
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_email_queue_status_created') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_email_queue_status_created
      ON email_queue (status, created_at)');
  END IF;
END $$;

-- =============================================================================
-- 8. email_queue(sent_at, status) — throughput queries
--    Used by: admin/delivery_analytics.rs:421-423
--    Pattern: SELECT COUNT(*) FROM email_queue
--             WHERE sent_at >= NOW() - INTERVAL '1 hour'
--    Existing idx_email_queue_sent_at is partial (WHERE sent_at IS NOT NULL).
--    This composite index doubles for provider latency JOINs.
-- =============================================================================
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_email_queue_sent_at_status') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_email_queue_sent_at_status
      ON email_queue (sent_at, status)');
  END IF;
END $$;

-- =============================================================================
-- 9. email_delivery_log(attempted_at, success) — latency percentile queries
--    Used by: admin/delivery_analytics.rs:441-458,290-311
--    Pattern: WHERE dl.success = true AND eq.sent_at IS NOT NULL
--             AND dl.attempted_at >= NOW() - $1::interval
--    Existing idx_email_delivery_log_status_attempted is partial on
--    (status IN ('pending','retrying')). This index helps the percentile queries.
-- =============================================================================
DO $$
BEGIN
  IF to_regclass('public.email_delivery_log') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_email_delivery_log_attempted_success') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_email_delivery_log_attempted_success
      ON email_delivery_log (attempted_at, success)');
  END IF;
END $$;

-- =============================================================================
-- 10. messages(tenant_id, sent_at DESC) — export queries using sent_at column
--    Used by: analytics.rs:518-536 (export with WHERE m.sent_at >= $2)
--             analytics.rs:805-813 (PDF export with WHERE sent_at >= $2)
--    Existing idx_messages_tenant covers (tenant_id, created_at DESC).
--    The export queries filter on sent_at, not created_at.
-- =============================================================================
DO $$
BEGIN
  IF to_regclass('public.messages') IS NOT NULL
     AND EXISTS (
       SELECT 1 FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name = 'messages'
         AND column_name = 'sent_at'
     )
     AND NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_messages_tenant_sent_at') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_messages_tenant_sent_at
      ON messages (tenant_id, sent_at DESC)');
  END IF;
END $$;

-- =============================================================================
-- 11. messages(tenant_id, status, created_at) — deliverability aggregates
--    Used by: analytics.rs:73-106,220-228,373-380
--             admin/delivery_analytics.rs:178-183
--             admin/insights.rs:172-183,233-242
--    Existing: idx_messages_tenant(tenant_id, created_at DESC) and
--              idx_messages_status(tenant_id, status).
--    A 3-column composite covers FILTER (WHERE status = 'X') in one index scan.
-- =============================================================================
DO $$
BEGIN
  IF to_regclass('public.messages') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_messages_tenant_status_created') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_messages_tenant_status_created
      ON messages (tenant_id, status, created_at)');
  END IF;
END $$;

-- =============================================================================
-- 12. sales_leads(status, created_at) — dashboard & pipeline queries
--    Used by: admin/dashboard.rs:161-214,290-304,311-313
--    Pattern: SELECT COUNT(*) FROM sales_leads WHERE status NOT IN (...)
--             SELECT status, COUNT(*) FROM sales_leads GROUP BY status
--             SELECT ... FROM sales_leads ORDER BY created_at DESC LIMIT 5
-- =============================================================================
DO $$
BEGIN
  IF to_regclass('public.sales_leads') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_sales_leads_status_created') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_sales_leads_status_created
      ON sales_leads (status, created_at DESC)');
  END IF;
END $$;

-- =============================================================================
-- 13. audit_logs(tenant_id, created_at) — analytics filtering by tenant + time
--    Used by: admin/insights.rs (via compare_metric with format! SQL)
--             admin/dashboard.rs:217-218 (audit_events_today)
--    Existing: idx_audit_logs_tenant_ts covers (tenant_id, timestamp),
--              idx_audit_logs_tenant_resource covers (tenant_id, resource, timestamp),
--              idx_audit_logs_user_created covers (user_id, created_at DESC).
--    This adds (tenant_id, created_at) for the case where queries use created_at
--    and not timestamp (code uses both interchangeably via column detection).
-- =============================================================================
DO $$
BEGIN
  IF to_regclass('public.audit_logs') IS NOT NULL
     AND EXISTS (
       SELECT 1 FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name = 'audit_logs'
         AND column_name = 'created_at'
     )
     AND NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_audit_logs_tenant_created') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_created
      ON audit_logs (tenant_id, created_at DESC)');
  END IF;
END $$;

-- =============================================================================
-- 14. subscriptions(tenant_id, status, created_at) — churn prediction queries
--    Used by: admin/predictive_analytics.rs:426-436 (paid-no-activity check)
--    Pattern: JOIN subscriptions s ON s.tenant_id::text = t.id::text
--             WHERE s.status IN ('active', 'trialing', 'past_due')
--    Existing: idx_subscriptions_tenant_status covers (tenant_id, status).
--    Adding created_at to the tuple enables the paid-no-activity EXISTS subquery.
-- =============================================================================
DO $$
BEGIN
  IF to_regclass('public.subscriptions') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_subscriptions_tenant_status_created') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_subscriptions_tenant_status_created
      ON subscriptions (tenant_id, status, created_at)');
  END IF;
END $$;

-- =============================================================================
-- 15. system_alerts(acknowledged, severity) — dashboard health queries
--    Used by: admin/dashboard.rs:242-246
--    Pattern: SELECT severity, COUNT(*) FROM system_alerts
--             WHERE acknowledged = false AND severity IN ('high', 'critical')
--             GROUP BY severity
-- =============================================================================
DO $$
BEGIN
  IF to_regclass('public.system_alerts') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_system_alerts_acknowledged_severity') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_system_alerts_acknowledged_severity
      ON system_alerts (acknowledged, severity)');
  END IF;
END $$;

-- =============================================================================
-- 16. domains(tenant_id, is_verified) — activation funnel
--    Used by: admin/growth_analytics.rs:244-248,573-576
--             admin/insights.rs:728-736 (unverified domain check)
--    Existing: idx_domains_tenant covers (tenant_id).
--    Adding is_verified enables index-only scans for the filter.
--    NOTE: Column name may be 'verified' or 'is_verified' depending on schema.
-- =============================================================================
DO $$
BEGIN
  IF to_regclass('public.domains') IS NOT NULL THEN
    -- Check if is_verified column exists
    IF EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'domains'
        AND column_name = 'is_verified'
    ) AND NOT EXISTS (
      SELECT 1 FROM pg_class WHERE relname = 'idx_domains_tenant_verified_v2'
    ) THEN
      EXECUTE format('CREATE INDEX IF NOT EXISTS idx_domains_tenant_verified
        ON domains (tenant_id, is_verified)');
    -- Fall back to 'verified' column name
    ELSIF EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'domains'
        AND column_name = 'verified'
    ) AND NOT EXISTS (
      SELECT 1 FROM pg_class WHERE relname = 'idx_domains_tenant_verified_v2'
    ) THEN
      EXECUTE format('CREATE INDEX IF NOT EXISTS idx_domains_tenant_verified_v2
        ON domains (tenant_id, verified)');
    END IF;
  END IF;
END $$;

-- =============================================================================
-- 17. messages(created_at, status) — admin-wide cross-tenant message counts
--    Used by: admin/delivery_analytics.rs:178-183
--             admin/cross_tenant.rs:77-106,522-553
--             admin/predictive_analytics.rs:242-313
--    Existing: idx_messages_created covers (created_at DESC).
--    Adding status allows COUNT FILTERs to use index-only scan.
--    Pattern: SELECT COUNT(*) FILTER (WHERE status = 'delivered'), ...
--             FROM messages WHERE created_at >= NOW() - INTERVAL 'X days'
-- =============================================================================
DO $$
BEGIN
  IF to_regclass('public.messages') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_messages_created_status') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_messages_created_status
      ON messages (created_at, status)');
  END IF;
END $$;

-- =============================================================================
-- END migration 083
-- =============================================================================
