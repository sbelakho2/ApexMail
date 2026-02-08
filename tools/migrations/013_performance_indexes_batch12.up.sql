-- Migration 013: Additional performance indexes (Batch 12, items #221-228)
--
-- These indexes cover common query patterns identified during production
-- readiness review. All use CONCURRENTLY to avoid blocking writes.

-- #221: Composite index on events (tenant_id, message_id) for per-message event lookups
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_events_tenant_message
  ON events (tenant_id, message_id);

-- #222: Composite index on audit_logs (tenant_id, created_at) for tenant-scoped audit queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_tenant_created
  ON audit_logs (tenant_id, created_at DESC);

-- #223: Partial index on smtp_credentials for active-only lookups
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_smtp_credentials_active
  ON smtp_credentials (tenant_id, domain_id) WHERE active = true;

-- #224: Functional index on events for domain extraction (used by domain stats)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_events_tenant_type_created
  ON events (tenant_id, event_type, created_at DESC);

-- #225: Composite index on messages (tenant_id, to_address, created_at)
-- Used by recipient history, unsubscribe lookups, and message search
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_messages_tenant_recipient_created
  ON messages (tenant_id, to_address, created_at DESC);

-- #226: Index on webhook_deliveries (webhook_id, created_at) for delivery history
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_webhook_deliveries_webhook_created
  ON webhook_deliveries (webhook_id, created_at DESC);

-- #227: Unique index on compaction_log (date) to prevent duplicate compaction runs
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_compaction_log_date_unique
  ON compaction_log (date);

-- #228: Index on inbound_messages (processing_at) for queue polling
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_inbound_messages_processing
  ON inbound_messages (processing_at) WHERE processing_at IS NOT NULL;
