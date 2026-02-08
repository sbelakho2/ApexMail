-- Migration 010: Performance indexes for FIX-500-048, FIX-500-049, FIX-500-050
-- These indexes improve query performance for common access patterns.
-- All use CREATE INDEX CONCURRENTLY to avoid locking production tables.

-- FIX-500-048: Partial index on messages.mta_message_id
-- Speeds up MTA bounce/reply correlation (findByMtaMessageId).
-- Partial index excludes NULLs since most messages lack an mta_message_id
-- until they are actually sent via SMTP.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_messages_mta_message_id
  ON messages (mta_message_id)
  WHERE mta_message_id IS NOT NULL;

-- FIX-500-049: Functional index on recipient email domain
-- Speeds up analytics GROUP BY domain queries without storing redundant data.
-- SPLIT_PART extracts the domain portion of the email address.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_events_recipient_domain
  ON events (SPLIT_PART(recipient_email, '@', 2));

-- FIX-500-050: Composite index for audit log resource lookups
-- Covers the findByResource query pattern (tenant + resource_type + resource_id)
-- with a trailing sort on (timestamp DESC, id DESC) for ORDER BY pushdown.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_resource_lookup
  ON audit_logs (tenant_id, resource_type, resource_id, timestamp DESC, id DESC);
