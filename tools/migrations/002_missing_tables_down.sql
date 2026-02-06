-- Rollback: 002_missing_tables.sql
-- Reverses all changes from the missing tables migration

-- =============================================================================
-- DROP DNS records and providers
-- =============================================================================

DROP TABLE IF EXISTS dns_records CASCADE;
DROP TABLE IF EXISTS dns_providers CASCADE;

-- =============================================================================
-- DROP FBL tables
-- =============================================================================

DROP TABLE IF EXISTS fbl_complaints CASCADE;
DROP TABLE IF EXISTS fbl_registrations CASCADE;

-- =============================================================================
-- DROP ISP warmup schedules
-- =============================================================================

DROP TABLE IF EXISTS isp_warmup_schedules CASCADE;

-- =============================================================================
-- REMOVE ip_pool_id column from domains
-- =============================================================================

ALTER TABLE domains DROP COLUMN IF EXISTS ip_pool_id;

-- =============================================================================
-- DROP IP pool tables
-- =============================================================================

DROP TABLE IF EXISTS ip_pool_addresses CASCADE;
DROP TABLE IF EXISTS ip_pools CASCADE;

-- =============================================================================
-- REMOVE added columns from events
-- =============================================================================

DROP INDEX IF EXISTS idx_events_dedup;
ALTER TABLE events DROP COLUMN IF EXISTS metadata;
ALTER TABLE events DROP COLUMN IF EXISTS processed_at;
ALTER TABLE events DROP COLUMN IF EXISTS deduplication_key;

-- =============================================================================
-- REMOVE added columns from inbound_messages
-- =============================================================================

DROP INDEX IF EXISTS idx_inbound_in_reply_to;
ALTER TABLE inbound_messages DROP COLUMN IF EXISTS in_reply_to_message_id;

-- =============================================================================
-- REMOVE added columns from messages
-- =============================================================================

ALTER TABLE messages DROP COLUMN IF EXISTS user_id;
ALTER TABLE messages DROP COLUMN IF EXISTS last_reply_at;
ALTER TABLE messages DROP COLUMN IF EXISTS reply_count;

-- =============================================================================
-- DROP webhook_deliveries
-- =============================================================================

DROP TABLE IF EXISTS webhook_deliveries CASCADE;

-- =============================================================================
-- DROP dead letter queues
-- =============================================================================

DROP TABLE IF EXISTS webhook_dlq CASCADE;
DROP TABLE IF EXISTS email_dlq CASCADE;

-- =============================================================================
-- REMOVE schema version record
-- =============================================================================

DELETE FROM schema_migrations WHERE version = '1.0.1';
