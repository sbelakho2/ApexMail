-- no-transaction
-- Migration 010: Performance indexes for FIX-500-048, FIX-500-049, FIX-500-050
-- These indexes improve query performance for common access patterns.
-- All use CREATE INDEX CONCURRENTLY to avoid locking production tables.
-- Requires -- no-transaction pragma since CONCURRENTLY cannot run inside a transaction.

-- FIX-500-048: Partial index on messages.mta_message_id
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_messages_mta_message_id
  ON messages (mta_message_id)
  WHERE mta_message_id IS NOT NULL;

-- FIX-500-049: Functional index on recipient domain
-- Uses the 'recipient' column (the actual column name in the events table).
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_events_recipient_domain
  ON events (SPLIT_PART(recipient, '@', 2));

-- FIX-500-050: Composite index for audit log resource lookups
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_resource_lookup
  ON audit_logs (tenant_id, resource_type, resource_id, timestamp DESC, id DESC);
