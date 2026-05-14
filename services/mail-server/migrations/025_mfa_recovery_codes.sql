-- MFA recovery codes support.
-- Stores SHA-256 hashes of one-time-use recovery/backup codes in a JSONB array.
-- C-03: Guard against missing users table (created later in migration 052).

DO $$
BEGIN
    IF to_regclass('public.users') IS NOT NULL THEN
        EXECUTE 'ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_recovery_hashes JSONB NOT NULL DEFAULT ''[]''::jsonb';
    ELSE
        RAISE WARNING 'Migration 025: users table does not exist — skipping ALTER TABLE. Create the users table first.';
    END IF;
END $$;
