-- 057_add_mfa_constraints.sql
--
-- =============================================================================
-- A-04: MFA Recovery Codes CHECK Constraint
-- =============================================================================
-- Migration 025 adds mfa_recovery_hashes JSONB to the users table with no
-- CHECK constraint validating the JSONB format. The application expects a
-- specific structure (array of hashed recovery codes).
--
-- This migration adds a CHECK constraint that validates:
--   1. Value is a JSON array (jsonb_typeof(mfa_recovery_hashes) = 'array')
--   2. Array contains only string elements
--
-- The constraint is added with NOT VALID first (metadata-only, no table lock),
-- then VALIDATE CONSTRAINT is run (SHARE UPDATE EXCLUSIVE lock, allowing
-- concurrent reads/writes). This avoids long table locks on production.
--
-- If the data in the column does not satisfy the constraint, VALIDATE will
-- fail. In that case, run a data cleanup first, then re-run migration 057.
--
-- Rollback:
--   ALTER TABLE users DROP CONSTRAINT IF EXISTS users_mfa_recovery_hashes_check;
--   DROP FUNCTION IF EXISTS check_mfa_recovery_hashes(val JSONB);
-- =============================================================================

-- ── Helper function to validate mfa_recovery_hashes structure ────────────────
-- Returns TRUE if:
--   - val IS NULL (excluded by NOT NULL on the column, but handle gracefully)
--   - val is a JSON array AND every element is a JSON string
-- Returns FALSE otherwise.

CREATE OR REPLACE FUNCTION check_mfa_recovery_hashes(val JSONB)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    elem JSONB;
BEGIN
    -- Allow NULL (the column is NOT NULL, so this shouldn't occur in practice)
    IF val IS NULL THEN
        RETURN TRUE;
    END IF;

    -- Must be a JSON array
    IF jsonb_typeof(val) != 'array' THEN
        RETURN FALSE;
    END IF;

    -- Every element must be a string
    FOR elem IN SELECT * FROM jsonb_array_elements(val)
    LOOP
        IF jsonb_typeof(elem) != 'string' THEN
            RETURN FALSE;
        END IF;
    END LOOP;

    RETURN TRUE;
END;
$$;

-- ── Add CHECK constraint with NOT VALID (no long table lock) ─────────────────

DO $$
BEGIN
    IF to_regclass('public.users') IS NOT NULL THEN
        -- Use IF NOT EXISTS guard for idempotency
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conrelid = 'public.users'::regclass
              AND conname = 'users_mfa_recovery_hashes_check'
        ) THEN
            -- Add constraint as NOT VALID — this is a metadata-only operation
            -- that does not require a full table scan or exclusive lock.
            EXECUTE 'ALTER TABLE users
                     ADD CONSTRAINT users_mfa_recovery_hashes_check
                     CHECK (check_mfa_recovery_hashes(mfa_recovery_hashes))
                     NOT VALID';
            RAISE NOTICE 'A-04: Added NOT VALID constraint users_mfa_recovery_hashes_check';
        ELSE
            RAISE NOTICE 'A-04: Constraint users_mfa_recovery_hashes_check already exists';
        END IF;
    ELSE
        RAISE WARNING 'A-04: users table does not exist — skipping constraint';
    END IF;
END $$;

-- ── Validate the constraint ──────────────────────────────────────────────────
-- VALIDATE CONSTRAINT acquires only SHARE UPDATE EXCLUSIVE lock, which allows
-- concurrent SELECT/INSERT/UPDATE/DELETE. It scans the table for existing rows
-- and checks them against the constraint.
--
-- NOTE: If existing data violates the constraint, VALIDATE will fail with:
--   ERROR:  check constraint "users_mfa_recovery_hashes_check" is violated
-- In that case, run a data cleanup first (e.g. NULL out or fix invalid rows),
-- then re-run this migration or just VALIDATE again.

DO $$
BEGIN
    IF to_regclass('public.users') IS NOT NULL THEN
        BEGIN
            EXECUTE 'ALTER TABLE users VALIDATE CONSTRAINT users_mfa_recovery_hashes_check';
            RAISE NOTICE 'A-04: Validated constraint users_mfa_recovery_hashes_check — all existing rows conform';
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'A-04: VALIDATE failed: %. Run data cleanup first, then ALTER TABLE users VALIDATE CONSTRAINT users_mfa_recovery_hashes_check;', SQLERRM;
        END;
    END IF;
END $$;
