-- Migration 267: Provider throttle operator surface support.
--
-- The re-wired provider throttle (crates/outbound-mta/src/throttle.rs) writes
-- one audit row per actual deferral and exposes operator overrides through
-- /v1/admin/deliverability/throttle-overrides. Two pieces are required:
--
-- 1. `outbound_throttle_decisions.override_id` records WHICH operator
--    override caused a deferral (migration 041's table predates the need).
-- 2. Unique active-override keys make the PUT upsert deterministic:
--    one ACTIVE row per (provider, tenant) — `tenant_id IS NULL` is the
--    global override. `COALESCE(tenant_id, '')` is used because a plain
--    unique index treats NULLs as distinct.
--
-- Forward-only; every statement is guarded.

ALTER TABLE outbound_throttle_decisions
    ADD COLUMN IF NOT EXISTS override_id UUID;

-- Collapse any duplicate active override rows left by the pre-267 surface
-- (041's indexes are not unique) before the unique keys are installed. The
-- resolver always ordered `updated_at DESC`, so the newest row is the one an
-- operator most recently pinned; the older duplicates were unreachable.
WITH ranked AS (
    SELECT id,
           ROW_NUMBER() OVER (
               PARTITION BY provider, COALESCE(tenant_id, ''), expires_at
               ORDER BY updated_at DESC, created_at DESC, id DESC
           ) AS rn
    FROM outbound_provider_throttle_overrides
)
DELETE FROM outbound_provider_throttle_overrides AS stale
USING ranked
WHERE stale.id = ranked.id AND ranked.rn > 1;

CREATE UNIQUE INDEX IF NOT EXISTS idx_throttle_overrides_unique_noexpiry
    ON outbound_provider_throttle_overrides (provider, COALESCE(tenant_id, ''))
    WHERE expires_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_throttle_overrides_unique_expiry
    ON outbound_provider_throttle_overrides (provider, COALESCE(tenant_id, ''), expires_at)
    WHERE expires_at IS NOT NULL;
