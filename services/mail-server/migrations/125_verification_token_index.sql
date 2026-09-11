-- 125: Supporting indexes for two unindexed hot paths.
--
--   1. Email verification lookup (routes/auth.rs verify_email_token):
--        SELECT ... FROM users
--        WHERE metadata->>'verification_token_hash' = $1
--          AND email_verified = false
--      The expression has no index, so every verification click is a full
--      JSONB scan of the users table. The partial index below matches the
--      query's expression and predicate exactly and only indexes the
--      (small) set of not-yet-verified accounts.
--
--   2. Analytics reconciliation (crates/analytics reconciliation.rs):
--        SELECT message_id, tenant_id, array_agg(...)
--        FROM events WHERE timestamp >= $1 GROUP BY message_id, tenant_id
--      Migration 083 added (tenant_id, event_type, timestamp) and
--      (message_id, timestamp DESC) composites; neither serves a pure
--      timestamp range scan that then groups by message_id. The
--      (timestamp, message_id) composite below covers both the range
--      predicate and an index-only group-by input.
--
-- The indexes are plain CREATE INDEX (not CONCURRENTLY): repository
-- migrations execute inside a transaction, where CREATE INDEX CONCURRENTLY
-- is not permitted; both tables are append-heavy and the brief build lock
-- was deemed acceptable for 083's indexes on the same tables.

CREATE INDEX IF NOT EXISTS idx_users_verification_token_hash
    ON users ((metadata->>'verification_token_hash'))
    WHERE email_verified = false;

DO $$
BEGIN
  IF to_regclass('public.events') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_events_timestamp_message') THEN
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_events_timestamp_message
      ON events (timestamp, message_id)');
  END IF;
END $$;
