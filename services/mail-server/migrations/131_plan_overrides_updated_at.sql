-- Migration 131: plan_overrides.updated_at (audit F06).
--
-- The admin plan-override upsert writes `updated_at = NOW()` in its
-- ON CONFLICT branch, but no migration ever added the column — the update
-- (and therefore every override replacement) failed with 42703. Add the
-- column with the same NOT NULL DEFAULT NOW() shape every sibling table
-- uses so both the INSERT and the conflict branch can write it.

ALTER TABLE plan_overrides
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
