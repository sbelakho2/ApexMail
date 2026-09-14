-- Migration 229: user_id columns that carry `users.id` become UUID
--
-- =============================================================================
-- `users.id` is UUID (its text form is 36 characters), but three tables
-- declared `user_id VARCHAR(26)`:
--
--   * sessions.user_id               — session revocation bookkeeping (auth.rs)
--   * client_errors.user_id          — control-plane client error reporting
--   * user_tenant_membership.user_id — cross-tenant membership verification
--                                      (middleware/auth.rs)
--
-- A UUID string cannot fit 26 characters, so every one of those columns was
-- structurally unable to hold the value the code binds:
--
--   * client_errors writes bound the JWT subject and failed with
--     `value too long for type character varying(26)` — the endpoint 500'd for
--     every authenticated report;
--   * `DELETE FROM sessions WHERE user_id = $1` compared a 36-char subject
--     against a 26-char column: text equality is well-typed but can never be
--     true, so revocation deleted nothing;
--   * the membership `COUNT(*)` could never match a real membership row, so a
--     user legitimately belonging to a second tenant was refused.
--
-- This migration converts the three columns to UUID and adds the foreign keys
-- that make the relationship real (`users.id`), so a bad value is rejected at
-- write time instead of silently never matching.
--
-- LEGACY VALUES
-- ---------------------------------------------------------------------------
-- A value that is not a UUID cannot reference a user and can only predate this
-- fix. It is copied into `schema_quarantine` (never silently destroyed) with a
-- WARNING naming the table and count; the live column is then emptied of it so
-- the type change can proceed. `sessions` is ephemeral auth bookkeeping (the
-- authoritative revocation state lives in Redis); `user_tenant_membership`
-- rows are authorization data — both are preserved for operator review.
--
-- IDEMPOTENCY: every step first probes the column's current type, so
-- re-applying the chain over an already-converted database is a no-op.
-- =============================================================================

CREATE TABLE IF NOT EXISTS schema_quarantine (
    id             BIGSERIAL PRIMARY KEY,
    migration      TEXT NOT NULL,
    source_table   TEXT NOT NULL,
    source_pk      TEXT,
    user_id_raw    TEXT NOT NULL,
    detail         JSONB NOT NULL DEFAULT '{}'::jsonb,
    quarantined_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON TABLE schema_quarantine IS
    'Values a later migration could not represent in the target column type, preserved verbatim for '
    'operator review instead of being silently deleted (first writer: migration 229, non-UUID '
    'user_id values in sessions / client_errors / user_tenant_membership).';

-- ---------------------------------------------------------------------------
-- 1. sessions.user_id — NOT NULL, revocation bookkeeping.
-- ---------------------------------------------------------------------------
DO $sessions$
DECLARE
    current_type TEXT;
    quarantined  BIGINT := 0;
BEGIN
    IF to_regclass('public.sessions') IS NULL THEN
        RETURN;
    END IF;
    SELECT data_type INTO current_type
      FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name = 'sessions'
       AND column_name = 'user_id';
    IF current_type IS NULL OR current_type = 'uuid' THEN
        RETURN; -- absent or already converted
    END IF;

    INSERT INTO schema_quarantine (migration, source_table, source_pk, user_id_raw, detail)
    SELECT '229', 'sessions', s.id::text, s.user_id,
           jsonb_build_object('tenant_id', s.tenant_id, 'expires_at', s.expires_at)
      FROM sessions s
     WHERE s.user_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
    GET DIAGNOSTICS quarantined = ROW_COUNT;

    DELETE FROM sessions
     WHERE user_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';

    ALTER TABLE sessions ALTER COLUMN user_id TYPE UUID USING user_id::uuid;

    IF quarantined > 0 THEN
        RAISE WARNING USING
            MESSAGE = format('migration 229: quarantined %s sessions row(s) whose user_id is not a '
                             'UUID (copied to schema_quarantine, removed from sessions)', quarantined),
            HINT = 'Inspect schema_quarantine WHERE migration = ''229'' AND source_table = ''sessions''.';
    END IF;
END
$sessions$;

-- ---------------------------------------------------------------------------
-- 2. client_errors.user_id — nullable, informational.
-- ---------------------------------------------------------------------------
DO $client_errors$
DECLARE
    current_type TEXT;
    quarantined  BIGINT := 0;
BEGIN
    IF to_regclass('public.client_errors') IS NULL THEN
        RETURN;
    END IF;
    SELECT data_type INTO current_type
      FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name = 'client_errors'
       AND column_name = 'user_id';
    IF current_type IS NULL OR current_type = 'uuid' THEN
        RETURN;
    END IF;

    INSERT INTO schema_quarantine (migration, source_table, source_pk, user_id_raw, detail)
    SELECT '229', 'client_errors', c.id::text, c.user_id,
           jsonb_build_object('tenant_id', c.tenant_id, 'created_at', c.created_at)
      FROM client_errors c
     WHERE c.user_id IS NOT NULL
       AND c.user_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
    GET DIAGNOSTICS quarantined = ROW_COUNT;

    UPDATE client_errors
       SET user_id = NULL
     WHERE user_id IS NOT NULL
       AND user_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';

    ALTER TABLE client_errors ALTER COLUMN user_id TYPE UUID USING user_id::uuid;

    IF quarantined > 0 THEN
        RAISE WARNING USING
            MESSAGE = format('migration 229: %s client_errors row(s) carried a non-UUID user_id; the '
                             'value is preserved in schema_quarantine and the live column is NULL for '
                             'those rows (an anonymous report)', quarantined),
            HINT = 'Inspect schema_quarantine WHERE migration = ''229'' AND source_table = ''client_errors''.';
    END IF;
END
$client_errors$;

-- ---------------------------------------------------------------------------
-- 3. user_tenant_membership.user_id — NOT NULL, authorization data.
-- ---------------------------------------------------------------------------
DO $membership$
DECLARE
    current_type TEXT;
    quarantined  BIGINT := 0;
BEGIN
    IF to_regclass('public.user_tenant_membership') IS NULL THEN
        RETURN;
    END IF;
    SELECT data_type INTO current_type
      FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name = 'user_tenant_membership'
       AND column_name = 'user_id';
    IF current_type IS NULL OR current_type = 'uuid' THEN
        RETURN;
    END IF;

    INSERT INTO schema_quarantine (migration, source_table, source_pk, user_id_raw, detail)
    SELECT '229', 'user_tenant_membership', m.id::text, m.user_id,
           jsonb_build_object('tenant_id', m.tenant_id, 'role', m.role)
      FROM user_tenant_membership m
     WHERE m.user_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
    GET DIAGNOSTICS quarantined = ROW_COUNT;

    DELETE FROM user_tenant_membership
     WHERE user_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';

    ALTER TABLE user_tenant_membership ALTER COLUMN user_id TYPE UUID USING user_id::uuid;

    IF quarantined > 0 THEN
        RAISE WARNING USING
            MESSAGE = format('migration 229: quarantined %s user_tenant_membership row(s) whose '
                             'user_id is not a UUID (copied to schema_quarantine, removed from the '
                             'live table)', quarantined),
            HINT = 'Inspect schema_quarantine WHERE migration = ''229'' AND source_table = ''user_tenant_membership''.';
    END IF;
END
$membership$;

-- ---------------------------------------------------------------------------
-- 4. Foreign keys — the relationship the VARCHAR(26) shape could not express.
--    NOT VALID first so a pre-existing orphan cannot abort a deploy; validated
--    immediately when the data allows, with a WARNING naming the orphans
--    otherwise. New rows are enforced either way.
-- ---------------------------------------------------------------------------
DO $sessions_fk$
BEGIN
    IF to_regclass('public.sessions') IS NULL OR to_regclass('public.users') IS NULL THEN
        RETURN;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'fk_sessions_user'
           AND conrelid = 'sessions'::regclass
    ) THEN
        ALTER TABLE sessions
            ADD CONSTRAINT fk_sessions_user
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE NOT VALID;
    END IF;
    BEGIN
        ALTER TABLE sessions VALIDATE CONSTRAINT fk_sessions_user;
    EXCEPTION
        WHEN foreign_key_violation THEN
            RAISE WARNING USING
                MESSAGE = 'migration 229: fk_sessions_user stays NOT VALID (orphan sessions.user_id '
                          'values reference no users row); new rows are still enforced.',
                HINT = 'Attribute or delete the orphan rows, then '
                       'ALTER TABLE sessions VALIDATE CONSTRAINT fk_sessions_user;';
    END;
END
$sessions_fk$;

DO $client_errors_fk$
BEGIN
    IF to_regclass('public.client_errors') IS NULL OR to_regclass('public.users') IS NULL THEN
        RETURN;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'fk_client_errors_user'
           AND conrelid = 'client_errors'::regclass
    ) THEN
        ALTER TABLE client_errors
            ADD CONSTRAINT fk_client_errors_user
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL NOT VALID;
    END IF;
    BEGIN
        ALTER TABLE client_errors VALIDATE CONSTRAINT fk_client_errors_user;
    EXCEPTION
        WHEN foreign_key_violation THEN
            RAISE WARNING USING
                MESSAGE = 'migration 229: fk_client_errors_user stays NOT VALID (orphan '
                          'client_errors.user_id values reference no users row).',
                HINT = 'Attribute or delete the orphan rows, then '
                       'ALTER TABLE client_errors VALIDATE CONSTRAINT fk_client_errors_user;';
    END;
END
$client_errors_fk$;

DO $membership_fk$
BEGIN
    IF to_regclass('public.user_tenant_membership') IS NULL OR to_regclass('public.users') IS NULL THEN
        RETURN;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'fk_user_tenant_membership_user'
           AND conrelid = 'user_tenant_membership'::regclass
    ) THEN
        ALTER TABLE user_tenant_membership
            ADD CONSTRAINT fk_user_tenant_membership_user
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE NOT VALID;
    END IF;
    BEGIN
        ALTER TABLE user_tenant_membership VALIDATE CONSTRAINT fk_user_tenant_membership_user;
    EXCEPTION
        WHEN foreign_key_violation THEN
            RAISE WARNING USING
                MESSAGE = 'migration 229: fk_user_tenant_membership_user stays NOT VALID (orphan '
                          'user_tenant_membership.user_id values reference no users row).',
                HINT = 'Attribute or delete the orphan rows, then '
                       'ALTER TABLE user_tenant_membership VALIDATE CONSTRAINT fk_user_tenant_membership_user;';
    END;
END
$membership_fk$;
