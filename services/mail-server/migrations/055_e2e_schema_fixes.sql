-- Migration 055: schema fixes discovered while running the live signup → MFA →
-- login E2E flow against a freshly-bootstrapped dev database.
--
-- Each statement is idempotent so the migration is safe to re-apply.

-- 1. mfa_recovery_hashes column on users.
--    Migration 025 introduced this column but it was missing from some legacy
--    databases that pre-dated the migrator. The login handler in
--    services/mail-server/crates/api-server/src/routes/auth.rs SELECTs this
--    column unconditionally, so its absence breaks every login attempt.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS mfa_recovery_hashes JSONB NOT NULL DEFAULT '[]'::jsonb;

-- 2. audit_logs.created_at column.
--    Some insert paths reference `created_at`, others reference `timestamp`.
--    Both are now present; existing rows backfill via the DEFAULT.
ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT now();

-- 3. audit_logs id widths.
--    `insert_auth_audit_log` generates `gen_random_uuid()` (36 chars) but the
--    legacy schema declared `varchar(26)` for ULIDs. Widen to varchar(64) so
--    both ULIDs and UUIDs fit.
--    On runtime-provisioned databases audit_logs.id is UUID (apexmail-db
--    SCHEMA shape) — a UUID column cannot be cast to varchar in place, so
--    leave it typed as UUID there.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'audit_logs'
                 AND column_name = 'id' AND udt_name IN ('varchar', 'bpchar', 'text')) THEN
        ALTER TABLE audit_logs ALTER COLUMN id TYPE varchar(64);
    ELSE
        RAISE NOTICE '055: audit_logs.id is not a varchar column — skipping width fix';
    END IF;
END $$;
ALTER TABLE audit_logs ALTER COLUMN resource_id TYPE varchar(64);

-- 4. audit_logs.hash nullability.
--    The auth audit insert path does not compute a tamper-evident hash for
--    every event. Allow NULL and provide a default so unrelated callers that
--    do supply a hash continue to work.
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS hash TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_logs ALTER COLUMN hash DROP NOT NULL;
ALTER TABLE audit_logs ALTER COLUMN hash SET DEFAULT '';
