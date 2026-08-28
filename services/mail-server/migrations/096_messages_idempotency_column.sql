-- 096_messages_idempotency_column.sql
--
-- =============================================================================
-- Idempotency key column on `messages`
-- =============================================================================
-- The send path (api-server messages.rs) deduplicates sends by an
-- `Idempotency-Key` request header. Previously the key was only embedded inside
-- the JSONB `metadata->>'idempotency_key'` and looked up via a JSONB path, so
-- the canonical `UNIQUE(tenant_id, idempotency_key)` table constraint had no
-- column to act on and was inert — concurrent identical requests could both
-- insert and double-send.
--
-- This migration adds the dedicated `idempotency_key` column plus a unique
-- index so the application can:
--   1. dedup-check against an indexed column (`WHERE idempotency_key = $1
--      AND tenant_id = $2`), and
--   2. use `INSERT ... ON CONFLICT (tenant_id, idempotency_key) DO NOTHING`
--      as a race-condition safety net, then inspect `rows_affected`.
--
-- The index is non-partial: standard SQL semantics treat multiple NULL
-- idempotency keys as distinct, so messages sent without an idempotency key
-- (e.g. every item in a batch send) never conflict with each other.
--
-- Note: `tools/migrations/001_initial_schema.sql` already ships this column
-- and constraint for the test lineage; this migration brings the services
-- deployment lineage to parity.
--
-- Idempotent: safe to re-run on any deployment.
-- Rollback: DROP INDEX IF EXISTS idx_messages_tenant_idempotency_key;
--           ALTER TABLE messages DROP COLUMN IF EXISTS idempotency_key;
-- =============================================================================


ALTER TABLE messages ADD COLUMN IF NOT EXISTS idempotency_key VARCHAR(255);

-- Unique index (not a partial index) so the ON CONFLICT inference in the send
-- path matches both this index and the UNIQUE constraint in the tools lineage.
CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_tenant_idempotency_key
    ON messages (tenant_id, idempotency_key);

