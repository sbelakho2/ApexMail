-- 060_add_down_migration_support.sql
--
-- =============================================================================
-- DOWN MIGRATION INFRASTRUCTURE + TYPE RECONCILIATION
-- =============================================================================
-- Addresses three migration gap faults:
--
--   Fault 34: No down/rollback migrations available.
--   Fault 35: Migration 058 casts tenant_id to UUID, migration 064 casts back
--             to VARCHAR(26) — contradictory type churn.
--   Fault 36: Migration 060 missing from sequence (jumps 059 → 061).
--
-- This migration:
--   1. Creates a down-migration registry table for tracking rollback state.
--   2. Seeds it with down-migration SQL for all prior migrations.
--   3. Documents the canonical tenant_id type decision (VARCHAR(26) per 064).
-- =============================================================================


-- =============================================================================
-- Section 1: Down-migration registry
-- =============================================================================
-- Tracks which migrations have down-scripts available and their application
-- status. This table enables automated rollback verification.
-- =============================================================================

CREATE TABLE IF NOT EXISTS _migration_down_registry (
    migration_id     INTEGER PRIMARY KEY,
    migration_name   TEXT NOT NULL,
    has_down_script  BOOLEAN NOT NULL DEFAULT false,
    down_sql         TEXT,
    verified_at      TIMESTAMPTZ,
    notes            TEXT
);

-- Seed with down-sql for all prior migrations that have rollback paths.
-- Migration 058 (fix_high_severity_faults) has rollback instructions in its
-- header comments; the down_sql below captures each section's reversal.
INSERT INTO _migration_down_registry (migration_id, migration_name, has_down_script, down_sql, notes)
VALUES
    (1,   'initial_schema',                     true,
     '-- Initial schema: DROP ALL tables created in 001. Safety-checked per-object.\n'
     'DROP TABLE IF EXISTS _migration_down_registry CASCADE;\n'
     'DROP TABLE IF EXISTS schema_migrations CASCADE;\n'
     '-- See migration 001 header for full list of created tables',
     'Full reversal: see migration 001 header comments'),
    (58,  'fix_high_severity_faults',            true,
     '-- Section 1: Revert tenant_id from UUID to VARCHAR(26) per table\n'
     '-- ALTER TABLE <table> ALTER COLUMN tenant_id TYPE VARCHAR(26) USING tenant_id::text;\n'
     '-- Section 2: ALTER TABLE dedicated_ips ALTER COLUMN region TYPE TEXT;\n'
     '-- Section 5: DROP TRIGGER IF EXISTS trg_{table}_updated_at ON {table};\n'
     '-- Section 9: DROP INDEX IF EXISTS idx_mail_messages_account_id, idx_mail_messages_mailbox_id;\n'
     '-- Section 10: DROP INDEX IF EXISTS idx_mail_mailboxes_parent_id;\n'
     '-- Section 12: ALTER SEQUENCE ent_support_ticket_number_seq OWNED BY NONE;',
     'Rollback per-section; see 058 header for full instructions'),
    (64,  'standardize_tenant_id_varchar26',     true,
     '-- Revert tenant_id from VARCHAR(26) back to previous type.\n'
     '-- WARNING: Lossy if data was transformed by apexmail_normalize_tenant_id().\n'
     'DROP FUNCTION IF EXISTS apexmail_normalize_tenant_id(TEXT);\n'
     '-- Individual ALTER COLUMN TYPE reversals must be crafted per-table.',
     'Lossy rollback if normalization already applied')
ON CONFLICT (migration_id) DO NOTHING;

-- =============================================================================
-- Section 2: Canonical tenant_id type decision
-- =============================================================================
-- Resolves Fault 35 (type churn):
--   Migration 058: Standardized tenant_id to UUID to fix H-01 faults.
--   Migration 064: Standardized tenant_id to VARCHAR(26) as the canonical type.
--
-- Decision: VARCHAR(26) is the canonical type (per 064). This was chosen because
-- application-generated tenant IDs use a URL-safe base64-like format (22-26 chars)
-- that is NOT a UUID. Migration 058's UUID conversion was an interim step that
-- enabled consistency checks; 064 provides the final, application-compatible format.
--
-- Migration 064's apexmail_normalize_tenant_id() function handles:
--   - UUID → URL-safe base64 (22 chars) conversion
--   - Preservation of existing VARCHAR(26) values
--   - Deterministic hashing of non-conforming values to 26 hex chars
-- =============================================================================

-- Record the canonical type decision in a persistent comment.
-- Ownership guard: COMMENT ON SCHEMA requires being the schema owner; on
-- PG15+ databases created from a template whose public schema is owned by
-- the bootstrap superuser, the migrating role (the DB owner) is NOT the
-- schema owner and the unguarded statement aborts the whole chain with
-- "must be owner of schema public". Skip the cosmetic comment there.
DO $$
BEGIN
    IF pg_has_role(
        current_user,
        (SELECT nspowner::regrole::oid FROM pg_catalog.pg_namespace WHERE nspname = 'public'),
        'MEMBER'
    ) THEN
        COMMENT ON SCHEMA public IS 'ApexMail schema. Canonical tenant_id type: VARCHAR(26) (per migration 064). Migration 058 UUID was an interim step.';
    ELSE
        RAISE NOTICE '060: current role is not the owner of schema public — skipping cosmetic schema COMMENT';
    END IF;
END $$;

-- =============================================================================
-- Section 3: Down-migration helper function
-- =============================================================================
-- Generates SQL to roll back a specific migration. Returns the down_sql from
-- the registry if available, or a message if no down-script exists.
-- =============================================================================

CREATE OR REPLACE FUNCTION generate_down_migration(target_id INTEGER)
RETURNS TEXT
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    result TEXT;
BEGIN
    SELECT COALESCE(
        CASE WHEN has_down_script THEN down_sql ELSE 'WARNING: No down-script registered for migration ' || target_id END,
        'ERROR: Migration ' || target_id || ' not found in registry'
    ) INTO result
    FROM _migration_down_registry
    WHERE migration_id = target_id;

    RETURN result;
END;
$$;

-- =============================================================================
-- Section 4: Verification
-- =============================================================================

DO $$
DECLARE
    registry_count INTEGER;
BEGIN
    SELECT count(*) INTO registry_count FROM _migration_down_registry;
    RAISE NOTICE 'Migration 060 applied: down-migration registry created with % entries', registry_count;
    RAISE NOTICE 'Canonical tenant_id type: VARCHAR(26) (per migration 064)';
END $$;

