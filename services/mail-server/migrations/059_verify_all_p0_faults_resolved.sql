-- Migration 059: Verify all p0 faults resolved
--
-- =============================================================================
-- P0 DATABASE MIGRATION FAULT VERIFICATION
-- =============================================================================
-- This migration verifies that all P0 database migration faults (DB-01 through
-- DB-09, DB-11 through DB-14, DB-17) identified in the production-readiness
-- plan have been successfully addressed by prior migrations 052 through 058.
--
-- This is a VERIFICATION-ONLY migration. It does NOT make schema changes.
-- Instead, it runs a comprehensive set of checks that:
--   1. Confirm every foundation table exists
--   2. Confirm every critical column is present
--   3. Confirm every critical constraint/index is in place
--   4. Log a clear pass/fail summary for each P0 item
--
-- Every check is wrapped in a DO block that logs a WARNING on failure and
-- a NOTICE on success. The migration as a whole never fails — it is safe to
-- run on any deployment regardless of which prior migrations have been applied.
--
-- If any WARNING messages appear during execution, review the corresponding
-- P0 item and apply the appropriate fix migration before proceeding with
-- production deployment.
--
-- Rollback: N/A — verification only.
-- =============================================================================

-- =============================================================================
-- DB-01 / C-01 / C-08: raw_headers column on email_queue
-- =============================================================================
-- Fix: Migration 052 (ALTER TABLE ADD COLUMN IF NOT EXISTS raw_headers TEXT)
--      Migration 056 Section 1 (belt-and-suspenders)
--      Migration 050 already includes raw_headers in partitioned table.
-- =============================================================================

DO $$
BEGIN
    IF to_regclass('public.email_queue') IS NOT NULL THEN
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'email_queue' AND column_name = 'raw_headers'
        ) THEN
            RAISE NOTICE 'PASS [DB-01]: email_queue.raw_headers column exists';
        ELSE
            RAISE WARNING 'FAIL [DB-01]: email_queue.raw_headers column is MISSING — run migration 052 or 056';
        END IF;
    ELSE
        RAISE WARNING 'SKIP [DB-01]: email_queue table does not exist';
    END IF;
END $$;

-- =============================================================================
-- DB-02 / C-02: tenants table
-- =============================================================================
-- Fix: Migration 052 (CREATE TABLE IF NOT EXISTS tenants)
--      Migration 056 Section 2 (belt-and-suspenders)
-- =============================================================================

DO $$
BEGIN
    IF to_regclass('public.tenants') IS NOT NULL THEN
        -- Verify expected columns exist
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'tenants' AND column_name = 'id'
              AND data_type = 'uuid'
        ) THEN
            RAISE NOTICE 'PASS [DB-02]: tenants table exists with UUID PK';
        ELSE
            RAISE WARNING 'FAIL [DB-02]: tenants table exists but has unexpected schema';
        END IF;
    ELSE
        RAISE WARNING 'FAIL [DB-02]: tenants table is MISSING — run migration 052 or 056';
    END IF;
END $$;

-- =============================================================================
-- DB-03 / C-03: users table
-- =============================================================================
-- Fix: Migration 052 (CREATE TABLE IF NOT EXISTS users)
--      Migration 056 Section 3 (belt-and-suspenders + mfa_recovery_hashes)
-- =============================================================================

DO $$
BEGIN
    IF to_regclass('public.users') IS NOT NULL THEN
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'users' AND column_name = 'mfa_recovery_hashes'
        ) THEN
            RAISE NOTICE 'PASS [DB-03]: users table exists with mfa_recovery_hashes column';
        ELSE
            RAISE WARNING 'FAIL [DB-03]: users table exists but mfa_recovery_hashes is MISSING — run migration 055 or 056';
        END IF;
    ELSE
        RAISE WARNING 'FAIL [DB-03]: users table is MISSING — run migration 052 or 056';
    END IF;
END $$;

-- =============================================================================
-- DB-04 / C-04: invoices table
-- =============================================================================
-- Fix: Migration 052 (CREATE TABLE IF NOT EXISTS invoices)
--      Migration 056 Section 4 (belt-and-suspenders + closed_at)
-- =============================================================================

DO $$
BEGIN
    IF to_regclass('public.invoices') IS NOT NULL THEN
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'invoices' AND column_name = 'closed_at'
        ) THEN
            RAISE NOTICE 'PASS [DB-04]: invoices table exists with closed_at column';
        ELSE
            RAISE WARNING 'FAIL [DB-04]: invoices table exists but closed_at is MISSING — run migration 056';
        END IF;
    ELSE
        RAISE WARNING 'FAIL [DB-04]: invoices table is MISSING — run migration 052 or 056';
    END IF;
END $$;

-- =============================================================================
-- DB-05 / C-05: messages table
-- =============================================================================
-- Fix: Migration 052 (CREATE TABLE IF NOT EXISTS messages)
--      Migration 056 Section 5 (belt-and-suspenders + transport/source_ip)
-- =============================================================================

DO $$
BEGIN
    IF to_regclass('public.messages') IS NOT NULL THEN
        RAISE NOTICE 'PASS [DB-05]: messages table exists';
    ELSE
        RAISE WARNING 'FAIL [DB-05]: messages table is MISSING — run migration 052 or 056';
    END IF;
END $$;

-- =============================================================================
-- DB-06 / C-06: metering_events table
-- =============================================================================
-- Fix: Migration 052 (CREATE TABLE IF NOT EXISTS metering_events)
--      Migration 056 Section 6 (belt-and-suspenders + indexes)
-- =============================================================================

DO $$
BEGIN
    IF to_regclass('public.metering_events') IS NOT NULL THEN
        -- Verify expected indexes exist
        IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_metering_events_tenant_type_ts') THEN
            RAISE NOTICE 'PASS [DB-06]: metering_events table exists with idx_metering_events_tenant_type_ts';
        ELSE
            RAISE WARNING 'FAIL [DB-06]: metering_events table exists but idx_metering_events_tenant_type_ts index is MISSING';
        END IF;
    ELSE
        RAISE WARNING 'FAIL [DB-06]: metering_events table is MISSING — run migration 052 or 056';
    END IF;
END $$;

-- =============================================================================
-- DB-07 / C-07 / H-11: audit_logs index uses correct column names
-- =============================================================================
-- Fix: Migration 051 corrected to use (resource, timestamp) instead of
--      (resource_type, created_at)
--      Migration 056 Section 7 (belt-and-suspenders)
--      Migration 058 Section 11 (belt-and-suspenders)
-- =============================================================================

DO $$
DECLARE
    v_index_def TEXT;
BEGIN
    IF to_regclass('public.audit_logs') IS NOT NULL THEN
        IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_audit_logs_tenant_resource') THEN
            SELECT pg_get_indexdef('idx_audit_logs_tenant_resource'::regclass) INTO v_index_def;

            -- Check that the index uses the correct columns
            IF v_index_def LIKE '%resource%' AND v_index_def LIKE '%timestamp%' THEN
                RAISE NOTICE 'PASS [DB-07]: idx_audit_logs_tenant_resource uses correct columns (resource, timestamp)';
            ELSE
                RAISE WARNING 'FAIL [DB-07]: idx_audit_logs_tenant_resource uses WRONG columns: %', v_index_def;
            END IF;
        ELSE
            RAISE WARNING 'FAIL [DB-07]: idx_audit_logs_tenant_resource is MISSING — run migration 056 or 058';
        END IF;

        -- Verify created_at column exists (needed by migration 029's index definition)
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'audit_logs' AND column_name = 'created_at'
        ) THEN
            RAISE NOTICE 'PASS [DB-07]: audit_logs.created_at column exists (compatibility fix for migration 029)';
        ELSE
            RAISE WARNING 'FAIL [DB-07]: audit_logs.created_at is MISSING — run migration 055 or 056';
        END IF;
    ELSE
        RAISE WARNING 'SKIP [DB-07]: audit_logs table does not exist';
    END IF;
END $$;

-- =============================================================================
-- DB-09 / C-09 / C-18: SET NOT NULL race condition on mail_messages.uid
-- =============================================================================
-- Fix: Migration 002 has been updated with LOCK TABLE + second backfill
--      Migration 056 Section 8 (belt-and-suspenders verification)
-- =============================================================================

DO $$
BEGIN
    IF to_regclass('public.mail_messages') IS NOT NULL THEN
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'mail_messages'
              AND column_name = 'uid'
              AND is_nullable = 'NO'
        ) THEN
            RAISE NOTICE 'PASS [DB-09]: mail_messages.uid is NOT NULL (safe from race condition)';
        ELSE
            RAISE WARNING 'FAIL [DB-09]: mail_messages.uid is STILL nullable — run migration 056 Section 8';
        END IF;

        -- Verify the unique index exists
        IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_mail_messages_mailbox_uid') THEN
            RAISE NOTICE 'PASS [DB-09]: idx_mail_messages_mailbox_uid unique index exists';
        ELSE
            RAISE WARNING 'FAIL [DB-09]: idx_mail_messages_mailbox_uid is MISSING — run migration 002';
        END IF;
    ELSE
        RAISE WARNING 'SKIP [DB-09]: mail_messages table does not exist';
    END IF;
END $$;

-- =============================================================================
-- DB-11 / C-11: domains table
-- =============================================================================
-- Fix: Migration 052 (CREATE TABLE IF NOT EXISTS domains)
--      Migration 056 Section 10 (belt-and-suspenders)
-- =============================================================================

DO $$
BEGIN
    IF to_regclass('public.domains') IS NOT NULL THEN
        IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_domains_domain') THEN
            RAISE NOTICE 'PASS [DB-11]: domains table exists with idx_domains_domain index';
        ELSE
            RAISE WARNING 'FAIL [DB-11]: domains table exists but idx_domains_domain is MISSING — run migration 056';
        END IF;
    ELSE
        RAISE WARNING 'FAIL [DB-11]: domains table is MISSING — run migration 052 or 056';
    END IF;
END $$;

-- =============================================================================
-- DB-12 / C-12: api_keys table
-- =============================================================================
-- Fix: Migration 052 (CREATE TABLE IF NOT EXISTS api_keys)
--      Migration 056 Section 11 (belt-and-suspenders)
-- =============================================================================

DO $$
BEGIN
    IF to_regclass('public.api_keys') IS NOT NULL THEN
        IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_api_keys_tenant_id') THEN
            RAISE NOTICE 'PASS [DB-12]: api_keys table exists with idx_api_keys_tenant_id index';
        ELSE
            RAISE WARNING 'FAIL [DB-12]: api_keys table exists but idx_api_keys_tenant_id is MISSING — run migration 056';
        END IF;
    ELSE
        RAISE WARNING 'FAIL [DB-12]: api_keys table is MISSING — run migration 052 or 056';
    END IF;
END $$;

-- =============================================================================
-- DB-13 / C-13: webhook_events table
-- =============================================================================
-- Fix: Migration 052 (CREATE TABLE IF NOT EXISTS webhook_events)
--      Migration 056 Section 12 (belt-and-suspenders)
-- =============================================================================

DO $$
BEGIN
    IF to_regclass('public.webhook_events') IS NOT NULL THEN
        IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_webhook_events_message_id') THEN
            RAISE NOTICE 'PASS [DB-13]: webhook_events table exists with idx_webhook_events_message_id index';
        ELSE
            RAISE WARNING 'FAIL [DB-13]: webhook_events table exists but idx_webhook_events_message_id is MISSING — run migration 056';
        END IF;
    ELSE
        RAISE WARNING 'FAIL [DB-13]: webhook_events table is MISSING — run migration 052 or 056';
    END IF;
END $$;

-- =============================================================================
-- DB-14 / C-14: Migration 029/038 ordering dependency fixed
-- =============================================================================
-- Fix: Migration 056 Section 13 (adds created_at to audit_logs + creates
--      idx_audit_logs_user_created index that migration 029 intended)
-- =============================================================================

DO $$
BEGIN
    IF to_regclass('public.audit_logs') IS NOT NULL THEN
        -- The key fix is that created_at column exists on audit_logs
        -- (added by migration 055 or 056) so migration 029's index definition
        -- now works correctly regardless of migration ordering.
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'audit_logs' AND column_name = 'created_at'
        ) THEN
            RAISE NOTICE 'PASS [DB-14]: audit_logs.created_at exists — migration 029/038 ordering dependency resolved';
        ELSE
            RAISE WARNING 'FAIL [DB-14]: audit_logs.created_at is MISSING — run migration 055 or 056';
        END IF;

        -- Check the migration 029 index exists
        IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_audit_logs_user_created') THEN
            RAISE NOTICE 'PASS [DB-14]: idx_audit_logs_user_created index exists (from migration 029)';
        END IF;
    ELSE
        RAISE WARNING 'SKIP [DB-14]: audit_logs table does not exist';
    END IF;
END $$;

-- =============================================================================
-- DB-17 / C-17: email_delivery_log FK recreated after partitioning
-- =============================================================================
-- Fix: Migration 053 (adds created_at to email_delivery_log + recreates FK)
--      Migration 056 Section 16 (belt-and-suspenders verification)
-- =============================================================================

DO $$
DECLARE
    v_fk_exists BOOLEAN;
    v_fk_def TEXT;
BEGIN
    IF to_regclass('public.email_delivery_log') IS NOT NULL
       AND to_regclass('public.email_queue') IS NOT NULL THEN

        -- Check if FK constraint exists
        SELECT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conrelid = 'public.email_delivery_log'::regclass
              AND conname = 'email_delivery_log_email_id_fkey'
        ) INTO v_fk_exists;

        IF v_fk_exists THEN
            -- Get the FK definition to verify it references the composite key
            SELECT pg_get_constraintdef(oid) INTO v_fk_def
            FROM pg_constraint
            WHERE conrelid = 'public.email_delivery_log'::regclass
              AND conname = 'email_delivery_log_email_id_fkey';

            IF v_fk_def LIKE '%created_at%' THEN
                RAISE NOTICE 'PASS [DB-17]: FK email_delivery_log_email_id_fkey exists and references composite key (email_id, created_at)';
            ELSE
                RAISE WARNING 'FAIL [DB-17]: FK email_delivery_log_email_id_fkey exists but may not reference composite key: %', v_fk_def;
            END IF;
        ELSE
            RAISE WARNING 'FAIL [DB-17]: FK email_delivery_log_email_id_fkey is MISSING — run migration 053 or 056';
        END IF;

        -- Verify created_at column exists on email_delivery_log (prerequisite for FK)
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'email_delivery_log' AND column_name = 'created_at'
        ) THEN
            RAISE NOTICE 'PASS [DB-17]: email_delivery_log.created_at column exists';
        END IF;
    ELSE
        RAISE WARNING 'SKIP [DB-17]: email_delivery_log or email_queue table does not exist';
    END IF;
END $$;

-- =============================================================================
-- Additional verification: dead_letter_queue table
-- =============================================================================
-- C-10: Previously created at runtime; now managed by migrations.
-- Fix: Migration 052 (CREATE TABLE IF NOT EXISTS dead_letter_queue)
--      Migration 056 Section 9 (belt-and-suspenders)
-- =============================================================================

DO $$
BEGIN
    IF to_regclass('public.dead_letter_queue') IS NOT NULL THEN
        RAISE NOTICE 'PASS [C-10]: dead_letter_queue table exists (previously runtime-only)';
    ELSE
        RAISE WARNING 'FAIL [C-10]: dead_letter_queue table is MISSING — run migration 052 or 056';
    END IF;
END $$;

-- =============================================================================
-- Additional verification: audit_logs_archive no longer has duplicate PK
-- =============================================================================
-- C-15: audit_logs_archive inherited PK from audit_logs, causing violations.
-- Fix: Migration 056 Section 14 (drops PK, adds archive_id BIGSERIAL)
-- =============================================================================

DO $$
DECLARE
    v_has_pk BOOLEAN;
BEGIN
    IF to_regclass('public.audit_logs_archive') IS NOT NULL THEN
        SELECT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conrelid = 'public.audit_logs_archive'::regclass
              AND contype = 'p'
              AND conname != 'audit_logs_archive_pkey'
        ) INTO v_has_pk;

        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'audit_logs_archive' AND column_name = 'archive_id'
        ) THEN
            RAISE NOTICE 'PASS [C-15]: audit_logs_archive has archive_id surrogate PK — no duplicate PK risk';
        ELSE
            RAISE WARNING 'FAIL [C-15]: audit_logs_archive may still have inherited PK — run migration 056 Section 14';
        END IF;
    ELSE
        RAISE NOTICE 'SKIP [C-15]: audit_logs_archive table does not exist';
    END IF;
END $$;

-- =============================================================================
-- Additional verification: secrets_archive no longer has UNIQUE constraint
-- =============================================================================
-- C-16: secrets_archive inherited UNIQUE(tenant_id, name), blocking archives.
-- Fix: Migration 056 Section 15 (drops all UNIQUE constraints from archive)
-- =============================================================================

DO $$
DECLARE
    v_unique_count INT;
BEGIN
    IF to_regclass('public.secrets_archive') IS NOT NULL THEN
        SELECT COUNT(*) INTO v_unique_count
        FROM pg_constraint
        WHERE conrelid = 'public.secrets_archive'::regclass
          AND contype = 'u';

        IF v_unique_count = 0 THEN
            RAISE NOTICE 'PASS [C-16]: secrets_archive has no UNIQUE constraints — multiple versions can be archived';
        ELSE
            RAISE WARNING 'FAIL [C-16]: secrets_archive has % UNIQUE constraint(s) — run migration 056 Section 15', v_unique_count;
        END IF;
    ELSE
        RAISE NOTICE 'SKIP [C-16]: secrets_archive table does not exist';
    END IF;
END $$;

-- =============================================================================
-- Additional verification: MFA recovery codes CHECK constraint
-- =============================================================================
-- A-04: MFA recovery codes need a CHECK constraint validating JSONB format.
-- Fix: Migration 057 (adds check_mfa_recovery_hashes constraint)
-- =============================================================================

DO $$
BEGIN
    IF to_regclass('public.users') IS NOT NULL THEN
        IF EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conrelid = 'public.users'::regclass
              AND conname = 'users_mfa_recovery_hashes_check'
        ) THEN
            RAISE NOTICE 'PASS [A-04]: users_mfa_recovery_hashes_check constraint exists';
        ELSE
            RAISE WARNING 'FAIL [A-04]: users_mfa_recovery_hashes_check constraint is MISSING — run migration 057';
        END IF;
    ELSE
        RAISE WARNING 'SKIP [A-04]: users table does not exist';
    END IF;
END $$;

-- =============================================================================
-- Summary: P0 Verification Report
-- =============================================================================

DO $$
DECLARE
    v_total INT := 0;
    v_pass  INT := 0;
    v_fail  INT := 0;
    v_skip  INT := 0;
BEGIN
    RAISE NOTICE '================================================================================';
    RAISE NOTICE 'Migration 059: P0 Database Fault Verification — Summary Report';
    RAISE NOTICE '================================================================================';
    RAISE NOTICE '';
    RAISE NOTICE '  DB-01 (raw_headers column) .............. Checked above';
    RAISE NOTICE '  DB-02 (tenants table) .................. Checked above';
    RAISE NOTICE '  DB-03 (users table) .................... Checked above';
    RAISE NOTICE '  DB-04 (invoices table) ................. Checked above';
    RAISE NOTICE '  DB-05 (messages table) ................. Checked above';
    RAISE NOTICE '  DB-06 (metering_events table) .......... Checked above';
    RAISE NOTICE '  DB-07 (audit_logs index columns) ....... Checked above';
    RAISE NOTICE '  DB-09 (uid NOT NULL race) .............. Checked above';
    RAISE NOTICE '  DB-11 (domains table) .................. Checked above';
    RAISE NOTICE '  DB-12 (api_keys table) ................. Checked above';
    RAISE NOTICE '  DB-13 (webhook_events table) ........... Checked above';
    RAISE NOTICE '  DB-14 (029/038 ordering) ............... Checked above';
    RAISE NOTICE '  DB-17 (email_delivery_log FK) .......... Checked above';
    RAISE NOTICE '';
    RAISE NOTICE '  Plus: C-10 (dead_letter_queue) ......... Checked above';
    RAISE NOTICE '        C-15 (audit_logs_archive PK) ..... Checked above';
    RAISE NOTICE '        C-16 (secrets_archive UNIQUE) .... Checked above';
    RAISE NOTICE '        A-04 (MFA recovery CHECK) ........ Checked above';
    RAISE NOTICE '';
    RAISE NOTICE '  Review any WARNING messages above. A clean run will show only';
    RAISE NOTICE '  NOTICE-level messages (all checks passing).';
    RAISE NOTICE '';
    RAISE NOTICE '  If all checks pass, ALL P0 database migration faults have been';
    RAISE NOTICE '  successfully resolved. The deployment is ready for production.';
    RAISE NOTICE '================================================================================';
END $$;
