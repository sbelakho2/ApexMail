-- Rollback migration 013: Remove performance indexes from Batch 12

DROP INDEX CONCURRENTLY IF EXISTS idx_events_tenant_message;
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_logs_tenant_created;
DROP INDEX CONCURRENTLY IF EXISTS idx_smtp_credentials_active;
DROP INDEX CONCURRENTLY IF EXISTS idx_events_tenant_type_created;
DROP INDEX CONCURRENTLY IF EXISTS idx_messages_tenant_recipient_created;
DROP INDEX CONCURRENTLY IF EXISTS idx_webhook_deliveries_webhook_created;
DROP INDEX CONCURRENTLY IF EXISTS idx_compaction_log_date_unique;
DROP INDEX CONCURRENTLY IF EXISTS idx_inbound_messages_processing;
