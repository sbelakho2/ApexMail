-- Rollback migration 010: Remove performance indexes

DROP INDEX CONCURRENTLY IF EXISTS idx_messages_mta_message_id;
DROP INDEX CONCURRENTLY IF EXISTS idx_events_recipient_domain;
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_logs_resource_lookup;
