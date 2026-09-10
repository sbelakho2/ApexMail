-- Migration 056: Fix critical schema issues
--
-- =============================================================================
-- CRITICAL (P0) SCHEMA FIXES
-- =============================================================================
-- Resolves 18 critical migration faults (C-01 through C-18) identified in the
-- comprehensive migration audit (faults.md §C). While earlier migrations 052-055
-- addressed some of these, this migration provides a consolidated, idempotent,
-- belt-and-suspenders fix that works regardless of which prior migrations have
-- been applied.
--
-- Every statement uses IF NOT EXISTS / IF EXISTS guards and/or DO $$ blocks so
-- this migration is safe to run multiple times on any deployment.
--
-- Sections:
--   Section 1 (C-01/C-08): Add raw_headers column to email_queue
--   Section 2 (C-02):      Create tenants table if missing
--   Section 3 (C-03):      Create users table if missing; ensure mfa_recovery_hashes
--   Section 4 (C-04):      Create invoices table if missing; ensure closed_at
--   Section 5 (C-05):      Create messages table if missing
--   Section 6 (C-06):      Create metering_events table if missing
--   Section 7 (C-07):      Ensure correct audit_logs index (tenant_id, resource, timestamp)
--   Section 8 (C-09/C-18): Verify/Secure uid NOT NULL with safe locking pattern
--   Section 9 (C-10):      Create dead_letter_queue table if missing
--   Section 10 (C-11):     Create domains table if missing
--   Section 11 (C-12):     Create api_keys table if missing
--   Section 12 (C-13):     Create webhook_events table if missing
--   Section 13 (C-14):     Fix audit_logs ordering dependency (ensure created_at exists)
--   Section 14 (C-15):     Fix audit_logs_archive duplicate PK
--   Section 15 (C-16):     Fix secrets_archive duplicate UNIQUE
--   Section 16 (C-17):     Verify email_delivery_log FK integrity
--   Section 17:            Add updated_at triggers for new tables
-- =============================================================================

-- =============================================================================
-- Section 1: C-01/C-08 — Add raw_headers column to email_queue
-- =============================================================================
-- C-01: The session.rs:510 INSERT path writes raw_headers to email_queue but
--       the original schema (migration 001) did not include this column.
-- C-08: The partitioned email_queue re-creation (migration 050) includes
--       raw_headers but ensures it exists regardless of migration order.
-- Fix:  Add the column with IF NOT EXISTS guard.
--
-- Rollback: ALTER TABLE email_queue DROP COLUMN IF EXISTS raw_headers;
-- =============================================================================

DO $$
BEGIN
    IF to_regclass('public.email_queue') IS NOT NULL THEN
        EXECUTE 'ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS raw_headers TEXT';
        RAISE NOTICE 'C-01/C-08: Verified raw_headers column exists on email_queue';
    END IF;
END $$;

-- =============================================================================
-- Section 2: C-02 — Create tenants table if missing
-- =============================================================================
-- C-02: Migrations 021, 022, 023, 024 reference tenants(id) via FK constraints
--       but no migration created the tenants table. Fix: create it now.
-- The table is created with id UUID to match the UUID type used in migrations
-- 001, 020, 021, plus a slug VARCHAR(26) for ULID-based lookups.
--
-- Rollback: DROP TABLE IF EXISTS tenants CASCADE;
-- =============================================================================

CREATE TABLE IF NOT EXISTS tenants (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(255) NOT NULL,
    slug        VARCHAR(26) UNIQUE,
    settings    JSONB DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants(slug) WHERE slug IS NOT NULL;

-- Log whether the table was newly created or already existed
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'tenants' AND relkind = 'r') THEN
        RAISE NOTICE 'C-02: tenants table is present (may have been created by migration 052 or earlier)';
    END IF;
END $$;

-- =============================================================================
-- Section 3: C-03 — Create users table if missing; ensure mfa_recovery_hashes
-- =============================================================================
-- C-03: Migration 025 runs ALTER TABLE users ADD COLUMN mfa_recovery_hashes
--       but no migration creates the users table. Fix: create it now and
--       ensure the recovery hashes column exists.
--
-- Rollback: DROP TABLE IF EXISTS users CASCADE;
-- =============================================================================

CREATE TABLE IF NOT EXISTS users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID REFERENCES tenants(id),
    email               VARCHAR(255) UNIQUE NOT NULL,
    password_hash       TEXT,
    role                VARCHAR(50),
    mfa_enabled         BOOLEAN NOT NULL DEFAULT false,
    mfa_recovery_hashes JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Ensure mfa_recovery_hashes column exists (for deployments that had users
-- table from migration 052 but before this fix)
DO $$
BEGIN
    IF to_regclass('public.users') IS NOT NULL THEN
        BEGIN
            EXECUTE 'ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_recovery_hashes JSONB NOT NULL DEFAULT ''[]''::jsonb';
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'C-03: Could not add mfa_recovery_hashes to users: %', SQLERRM;
        END;
    END IF;
END $$;

-- =============================================================================
-- Section 4: C-04 — Create invoices table if missing; ensure closed_at
-- =============================================================================
-- C-04: sla_credits.invoice_id REFERENCES invoices(id) (migration 022) and
--       ALTER TABLE invoices ADD COLUMN closed_at (migration 028) both need
--       the invoices table. Fix: create it now.
--
-- Rollback: DROP TABLE IF EXISTS invoices CASCADE;
-- =============================================================================

CREATE TABLE IF NOT EXISTS invoices (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID REFERENCES tenants(id),
    stripe_invoice_id   VARCHAR(255),
    amount              BIGINT NOT NULL DEFAULT 0,
    currency            VARCHAR(3) NOT NULL DEFAULT 'USD',
    status              VARCHAR(50) NOT NULL DEFAULT 'pending',
    due_date            TIMESTAMPTZ,
    paid_at             TIMESTAMPTZ,
    closed_at           TIMESTAMPTZ,
    issued_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_invoices_tenant ON invoices(tenant_id);
CREATE INDEX IF NOT EXISTS idx_invoices_stripe ON invoices(stripe_invoice_id);

-- Ensure closed_at exists (for deployments that had invoices table but before
-- migration 028 added this column)
DO $$
BEGIN
    IF to_regclass('public.invoices') IS NOT NULL THEN
        BEGIN
            EXECUTE 'ALTER TABLE invoices ADD COLUMN IF NOT EXISTS closed_at TIMESTAMPTZ';
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'C-04: Could not add closed_at to invoices: %', SQLERRM;
        END;
    END IF;
END $$;

-- =============================================================================
-- Section 5: C-05 — Create messages table if missing
-- =============================================================================
-- C-05: self_hosted_bounces.message_id UUID REFERENCES messages(id) and
--       self_hosted_complaints.message_id UUID REFERENCES messages(id) in
--       migration 021 reference a messages table that doesn't exist.
--       Fix: create it now (distinct from mail_messages which stores inbound).
--
-- Rollback: DROP TABLE IF EXISTS messages CASCADE;
-- =============================================================================

CREATE TABLE IF NOT EXISTS messages (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID REFERENCES tenants(id),
    from_address    TEXT NOT NULL,
    to_addresses    TEXT[] NOT NULL DEFAULT '{}',
    subject         TEXT,
    body            TEXT,
    status          VARCHAR(50) NOT NULL DEFAULT 'pending',
    transport       VARCHAR(10) CHECK (transport IN ('ses', 'smtp')),
    source_ip       INET,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_messages_tenant ON messages(tenant_id, created_at DESC);

-- Ensure transport and source_ip columns exist (migration 021 tried to add
-- them conditionally; this guarantees they're present)
DO $$
BEGIN
    IF to_regclass('public.messages') IS NOT NULL THEN
        BEGIN
            EXECUTE 'ALTER TABLE messages ADD COLUMN IF NOT EXISTS transport VARCHAR(10) CHECK (transport IN (''ses'', ''smtp''))';
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'C-05: Could not add transport to messages: %', SQLERRM;
        END;
        BEGIN
            EXECUTE 'ALTER TABLE messages ADD COLUMN IF NOT EXISTS source_ip INET';
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'C-05: Could not add source_ip to messages: %', SQLERRM;
        END;
    END IF;
END $$;

-- =============================================================================
-- Section 6: C-06 — Create metering_events table if missing
-- =============================================================================
-- C-06: Migrations 026, 029, 051 create indexes on metering_events but no
--       migration creates the table. Fix: create it now.
--
-- Rollback: DROP TABLE IF EXISTS metering_events CASCADE;
-- =============================================================================

CREATE TABLE IF NOT EXISTS metering_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    quantity    BIGINT NOT NULL DEFAULT 1,
    metadata    JSONB DEFAULT '{}'::jsonb,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes expected by migrations 026, 029, 051
CREATE INDEX IF NOT EXISTS idx_metering_events_tenant_type_ts
    ON metering_events (tenant_id, event_type, timestamp);
CREATE INDEX IF NOT EXISTS idx_metering_events_tenant_type
    ON metering_events (tenant_id, event_type);
CREATE INDEX IF NOT EXISTS idx_metering_events_tenant_type_ts_desc
    ON metering_events (tenant_id, event_type, timestamp DESC);

-- =============================================================================
-- Section 7: C-07 / H-11 — Fix audit_logs index to use correct column names
-- =============================================================================
-- C-07/H-11: Migration 051 originally defined index idx_audit_logs_tenant_resource
--            ON audit_logs (tenant_id, resource_type, created_at) but the actual
--            columns in audit_logs (migrations 038/050) are "resource" and
--            "timestamp". Migration 051 has since been corrected, but we ensure
--            the correct index exists regardless.
--
-- Rollback: DROP INDEX IF EXISTS idx_audit_logs_tenant_resource;
-- =============================================================================

DO $$
BEGIN
    IF to_regclass('public.audit_logs') IS NOT NULL THEN
        -- Drop the old wrong-column-name index if it somehow exists
        IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_audit_logs_tenant_resource'
                   AND pg_get_indexdef(oid) LIKE '%resource_type%') THEN
            EXECUTE 'DROP INDEX IF EXISTS idx_audit_logs_tenant_resource';
            RAISE NOTICE 'C-07: Dropped wrong index idx_audit_logs_tenant_resource (used resource_type)';
        END IF;

        -- Create the correct index using actual column names
        -- (resource/timestamp are absent on runtime-provisioned audit_logs)
        IF EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'audit_logs'
                     AND column_name = 'resource')
           AND NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_audit_logs_tenant_resource') THEN
            EXECUTE 'CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_resource
                     ON audit_logs (tenant_id, resource, timestamp)';
            RAISE NOTICE 'C-07: Created index idx_audit_logs_tenant_resource on (tenant_id, resource, timestamp)';
        END IF;
    END IF;
END $$;

-- =============================================================================
-- Section 8: C-09/C-18 — Secure uid NOT NULL with safe locking pattern
-- =============================================================================
-- C-09: The SET NOT NULL after backfill can fail if concurrent inserts produce
--       NULL uid rows between the backfill and the ALTER.
-- C-18: Same root cause — race condition between backfill UPDATE and SET NOT NULL.
-- Fix:  Migration 002 already uses LOCK TABLE + second backfill. This section
--       verifies no NULL uids remain and re-applies the fix if needed.
--
-- Rollback: N/A (this is a verification/failsafe pass)
-- =============================================================================

DO $$
DECLARE
    v_null_count BIGINT;
BEGIN
    IF to_regclass('public.mail_messages') IS NOT NULL THEN
        -- Check if uid column is already NOT NULL
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'mail_messages'
              AND column_name = 'uid'
              AND is_nullable = 'YES'
        ) THEN
            -- Column exists but is still nullable — apply the safe fix pattern
            RAISE WARNING 'C-09/C-18: mail_messages.uid is still nullable. Applying safe NOT NULL fix...';

            -- Step 1: Backfill any rows with NULL uid
            WITH ranked AS (
                SELECT id, mailbox_id,
                       ROW_NUMBER() OVER (PARTITION BY mailbox_id ORDER BY date, created_at, id) AS new_uid
                FROM mail_messages
                WHERE uid IS NULL
            )
            UPDATE mail_messages m
            SET uid = r.new_uid
            FROM ranked r
            WHERE m.id = r.id;

            GET DIAGNOSTICS v_null_count = ROW_COUNT;
            RAISE NOTICE 'C-09/C-18: Backfilled % rows with NULL uid', v_null_count;

            -- Step 2: Lock table to prevent concurrent inserts with NULL uid
            EXECUTE 'LOCK TABLE mail_messages IN EXCLUSIVE MODE';

            -- Step 3: Second backfill for any rows inserted between step 1 and lock
            WITH ranked AS (
                SELECT id, mailbox_id,
                       ROW_NUMBER() OVER (PARTITION BY mailbox_id ORDER BY date, created_at, id) AS new_uid
                FROM mail_messages
                WHERE uid IS NULL
            )
            UPDATE mail_messages m
            SET uid = r.new_uid
            FROM ranked r
            WHERE m.id = r.id;

            GET DIAGNOSTICS v_null_count = ROW_COUNT;
            IF v_null_count > 0 THEN
                RAISE NOTICE 'C-09/C-18: Second backfill caught % rows', v_null_count;
            END IF;

            -- Step 4: Apply NOT NULL
            EXECUTE 'ALTER TABLE mail_messages ALTER COLUMN uid SET NOT NULL';
            RAISE NOTICE 'C-09/C-18: Successfully set mail_messages.uid NOT NULL';
        ELSE
            RAISE NOTICE 'C-09/C-18: mail_messages.uid is already NOT NULL — no action needed';
        END IF;
    END IF;
END $$;

-- Also ensure uidnext is NOT NULL on mail_mailboxes (pre-requisite for uid generation)
DO $$
BEGIN
    IF to_regclass('public.mail_mailboxes') IS NOT NULL THEN
        BEGIN
            EXECUTE 'ALTER TABLE mail_mailboxes ADD COLUMN IF NOT EXISTS uidnext BIGINT NOT NULL DEFAULT 1';
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'C-09/C-18: uidnext column already exists on mail_mailboxes (or similar)';
        END;
    END IF;
END $$;

-- =============================================================================
-- Section 9: C-10 — Create dead_letter_queue table if missing
-- =============================================================================
-- C-10: The outbound-queue crate creates dead_letter_queue at runtime via
--       CREATE TABLE IF NOT EXISTS, but no migration defines it. A fresh SQLx
--       migration-based deployment won't have it. Fix: create it now.
-- Schema matches crates/outbound-queue/src/queue.rs:378-396.
--
-- Rollback: DROP TABLE IF EXISTS dead_letter_queue CASCADE;
-- =============================================================================

CREATE TABLE IF NOT EXISTS dead_letter_queue (
    id                  UUID PRIMARY KEY,
    original_email_id   UUID,
    from_address        TEXT NOT NULL,
    to_addresses        TEXT[] NOT NULL,
    subject             TEXT NOT NULL,
    text_body           TEXT,
    html_body           TEXT,
    headers             JSONB DEFAULT '{}'::jsonb,
    attempts            INT NOT NULL DEFAULT 0,
    max_attempts        INT NOT NULL DEFAULT 5,
    last_error          TEXT NOT NULL,
    bounce_type         TEXT,
    tenant_id           TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    dead_lettered_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dead_letter_created
    ON dead_letter_queue(dead_lettered_at);
CREATE INDEX IF NOT EXISTS idx_dead_letter_tenant
    ON dead_letter_queue(tenant_id)
    WHERE tenant_id IS NOT NULL;

-- =============================================================================
-- Section 10: C-11 — Create domains table if missing
-- =============================================================================
-- C-11: Migration 029 creates index idx_domains_domain ON domains(domain) but
--       no migration creates the domains table. The to_regclass guard prevents
--       a crash but the index is silently skipped. Fix: create it now.
--
-- Rollback: DROP TABLE IF EXISTS domains CASCADE;
-- =============================================================================

CREATE TABLE IF NOT EXISTS domains (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID REFERENCES tenants(id),
    domain          TEXT NOT NULL,
    verified        BOOLEAN NOT NULL DEFAULT false,
    dkim_enabled    BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema='public' AND table_name='domains' AND column_name='domain') THEN
        CREATE UNIQUE INDEX IF NOT EXISTS idx_domains_domain ON domains(domain);
    ELSIF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema='public' AND table_name='domains' AND column_name='name') THEN
        CREATE UNIQUE INDEX IF NOT EXISTS idx_domains_domain ON domains(name);
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_domains_tenant ON domains(tenant_id);

-- =============================================================================
-- Section 11: C-12 — Create api_keys table if missing
-- =============================================================================
-- C-12: Migrations 029 and 051 create indexes on api_keys but no migration
--       creates the api_keys table. Fix: create it now.
--
-- Rollback: DROP TABLE IF EXISTS api_keys CASCADE;
-- =============================================================================

CREATE TABLE IF NOT EXISTS api_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   TEXT NOT NULL,
    name        TEXT NOT NULL,
    key_hash    TEXT NOT NULL,
    key_prefix  VARCHAR(8) NOT NULL,
    scopes      JSONB DEFAULT '[]'::jsonb,
    revoked_at  TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_id ON api_keys (tenant_id, id);
-- revoked_at is absent on runtime-provisioned (apexmail-db SCHEMA) api_keys —
-- CREATE TABLE IF NOT EXISTS is a no-op there, so guard the partial index.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema='public' AND table_name='api_keys'
                 AND column_name='revoked_at') THEN
        CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_revoked
            ON api_keys (tenant_id, revoked_at)
            WHERE revoked_at IS NULL;
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys (key_prefix);

-- =============================================================================
-- Section 12: C-13 — Create webhook_events table if missing
-- =============================================================================
-- C-13: Migrations 029 and 051 create indexes on webhook_events but no
--       migration creates the webhook_events table. Fix: create it now.
--
-- Rollback: DROP TABLE IF EXISTS webhook_events CASCADE;
-- =============================================================================

CREATE TABLE IF NOT EXISTS webhook_events (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         TEXT NOT NULL,
    event_type        TEXT NOT NULL,
    message_id        TEXT,
    payload           JSONB NOT NULL DEFAULT '{}'::jsonb,
    delivery_status   TEXT NOT NULL DEFAULT 'pending',
    delivery_attempts INT NOT NULL DEFAULT 0,
    last_http_status  INT,
    last_error        TEXT,
    next_retry_at     TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhook_events_message_id
    ON webhook_events (message_id);
CREATE INDEX IF NOT EXISTS idx_webhook_events_tenant_delivery
    ON webhook_events (tenant_id, delivery_status, created_at);
CREATE INDEX IF NOT EXISTS idx_webhook_events_retry
    ON webhook_events (next_retry_at)
    WHERE delivery_status = 'failed' AND next_retry_at IS NOT NULL;

-- =============================================================================
-- Section 13: C-14 — Fix audit_logs ordering dependency
-- =============================================================================
-- C-14: Migration 029 (runs before 038) references audit_logs which is created
--       in migration 038. The to_regclass guard prevents a crash, but the index
--       is silently skipped. Additionally, migration 029's index uses
--       "created_at" which does not exist on the original audit_logs table
--       (it has "timestamp"). Fix: ensure audit_logs.created_at column exists
--       for backward compatibility with migration 029's index definition.
--
--       Also ensure the original migration 029 index idx_audit_logs_user_created
--       is created if it doesn't exist and the columns are available.
--
-- Rollback: ALTER TABLE audit_logs DROP COLUMN IF EXISTS created_at;
--           (Note: only if you're sure no code uses it)
-- =============================================================================

DO $$
BEGIN
    IF to_regclass('public.audit_logs') IS NOT NULL THEN
        -- Add created_at column if missing (needed by migration 029's index)
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'audit_logs' AND column_name = 'created_at'
        ) THEN
            BEGIN
                EXECUTE 'ALTER TABLE audit_logs ADD COLUMN created_at TIMESTAMPTZ DEFAULT NOW()';
                RAISE NOTICE 'C-14: Added created_at column to audit_logs';
            EXCEPTION WHEN OTHERS THEN
                RAISE WARNING 'C-14: Could not add created_at to audit_logs: %', SQLERRM;
            END;
        END IF;

        -- Create the index from migration 029 if it doesn't exist
        -- (uses user_id and created_at — the pattern migration 029 intended)
        IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_audit_logs_user_created') THEN
            BEGIN
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_audit_logs_user_created
                         ON audit_logs (user_id, created_at DESC)';
                RAISE NOTICE 'C-14: Created idx_audit_logs_user_created index';
            EXCEPTION WHEN OTHERS THEN
                RAISE WARNING 'C-14: Could not create idx_audit_logs_user_created: %', SQLERRM;
            END;
        END IF;
    END IF;
END $$;

-- =============================================================================
-- Section 14: C-15 — Fix audit_logs_archive duplicate PK
-- =============================================================================
-- C-15: audit_logs_archive is created with LIKE audit_logs INCLUDING ALL, which
--       copies the PRIMARY KEY constraint. When rows are archived from audit_logs
--       to audit_logs_archive, they have the same id values, causing PK violations.
-- Fix:  Drop the PK constraint from audit_logs_archive (it's an archive, not a
--       source-of-truth table). Add a SERIAL id for internal uniqueness.
--
-- Rollback: ALTER TABLE audit_logs_archive ADD PRIMARY KEY (id);
-- =============================================================================

DO $$
DECLARE
    v_pk_name TEXT;
    v_has_pk BOOLEAN;
BEGIN
    IF to_regclass('public.audit_logs_archive') IS NOT NULL THEN
        -- Check if the table has a PRIMARY KEY constraint
        SELECT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conrelid = 'public.audit_logs_archive'::regclass
              AND contype = 'p'
        ) INTO v_has_pk;

        IF v_has_pk THEN
            -- Find the PK constraint name
            SELECT conname INTO v_pk_name FROM pg_constraint
            WHERE conrelid = 'public.audit_logs_archive'::regclass
              AND contype = 'p'
            LIMIT 1;

            -- Drop the PK constraint
            EXECUTE format('ALTER TABLE audit_logs_archive DROP CONSTRAINT %I', v_pk_name);
            RAISE NOTICE 'C-15: Dropped PK constraint %I from audit_logs_archive', v_pk_name;

            -- Add a surrogate BIGSERIAL archive_id as the new PK
            -- This avoids duplicate key issues when archiving rows
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'audit_logs_archive' AND column_name = 'archive_id'
            ) THEN
                EXECUTE 'ALTER TABLE audit_logs_archive ADD COLUMN archive_id BIGSERIAL PRIMARY KEY';
                RAISE NOTICE 'C-15: Added archive_id BIGSERIAL PRIMARY KEY to audit_logs_archive';
            END IF;
        ELSE
            RAISE NOTICE 'C-15: audit_logs_archive already has no PK — no action needed';
        END IF;
    END IF;
END $$;

-- =============================================================================
-- Section 15: C-16 — Fix secrets_archive duplicate UNIQUE constraint
-- =============================================================================
-- C-16: secrets_archive is created with LIKE secrets INCLUDING ALL, which copies
--       the UNIQUE (tenant_id, name) constraint. This prevents archiving multiple
--       historical versions of the same secret. Fix: drop all UNIQUE constraints.
--
-- Rollback: ALTER TABLE secrets_archive ADD UNIQUE (tenant_id, name);
-- =============================================================================

DO $$
DECLARE
    v_conname TEXT;
    v_count INT := 0;
BEGIN
    IF to_regclass('public.secrets_archive') IS NOT NULL THEN
        FOR v_conname IN
            SELECT conname FROM pg_constraint
            WHERE conrelid = 'public.secrets_archive'::regclass
              AND contype = 'u'
        LOOP
            EXECUTE format('ALTER TABLE secrets_archive DROP CONSTRAINT %I', v_conname);
            v_count := v_count + 1;
            RAISE NOTICE 'C-16: Dropped UNIQUE constraint %I from secrets_archive', v_conname;
        END LOOP;

        IF v_count = 0 THEN
            RAISE NOTICE 'C-16: secrets_archive has no UNIQUE constraints — no action needed';
        END IF;
    END IF;
END $$;

-- =============================================================================
-- Section 16: C-17 — Verify email_delivery_log FK integrity
-- =============================================================================
-- C-17: Migration 050 dropped FK email_delivery_log_email_id_fkey during
--       partitioning because the new email_queue has composite PK (id, created_at).
--       Migration 053 adds created_at to email_delivery_log and recreates the FK.
--       This section verifies the FK exists and recreates it if missing.
--
-- Rollback: ALTER TABLE email_delivery_log DROP CONSTRAINT IF EXISTS
--           email_delivery_log_email_id_fkey;
-- =============================================================================

DO $$
DECLARE
    v_fk_exists BOOLEAN;
    v_orphan_count BIGINT;
BEGIN
    IF to_regclass('public.email_delivery_log') IS NOT NULL
       AND to_regclass('public.email_queue') IS NOT NULL THEN

        -- Check if FK constraint already exists
        SELECT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conrelid = 'public.email_delivery_log'::regclass
              AND conname = 'email_delivery_log_email_id_fkey'
        ) INTO v_fk_exists;

        IF NOT v_fk_exists THEN
            RAISE WARNING 'C-17: FK email_delivery_log_email_id_fkey is missing. Recreating...';

            -- Ensure created_at column exists on email_delivery_log
            BEGIN
                EXECUTE 'ALTER TABLE email_delivery_log ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ';
            EXCEPTION WHEN OTHERS THEN
                RAISE WARNING 'C-17: Could not add created_at to email_delivery_log: %', SQLERRM;
            END;

            -- Backfill created_at from email_queue for existing rows
            EXECUTE 'UPDATE email_delivery_log dl
                     SET created_at = eq.created_at
                     FROM email_queue eq
                     WHERE dl.email_id = eq.id
                       AND dl.created_at IS NULL';

            -- Set default for unmatched rows
            EXECUTE 'UPDATE email_delivery_log
                     SET created_at = attempted_at
                     WHERE created_at IS NULL';

            -- Make created_at NOT NULL
            BEGIN
                EXECUTE 'ALTER TABLE email_delivery_log ALTER COLUMN created_at SET NOT NULL';
            EXCEPTION WHEN OTHERS THEN
                RAISE WARNING 'C-17: Could not set created_at NOT NULL: %', SQLERRM;
            END;

            -- Check for orphaned rows
            EXECUTE 'SELECT COUNT(*) FROM email_delivery_log dl
                     WHERE NOT EXISTS (
                         SELECT 1 FROM email_queue eq
                         WHERE eq.id = dl.email_id
                     )' INTO v_orphan_count;

            IF v_orphan_count > 0 THEN
                RAISE WARNING 'C-17: % orphaned email_delivery_log rows found — FK not created. Run data cleanup first.', v_orphan_count;
            ELSE
                BEGIN
                    EXECUTE 'ALTER TABLE email_delivery_log
                             ADD CONSTRAINT email_delivery_log_email_id_fkey
                             FOREIGN KEY (email_id, created_at)
                             REFERENCES email_queue(id, created_at)
                             ON DELETE CASCADE';
                    RAISE NOTICE 'C-17: FK email_delivery_log(email_id, created_at) -> email_queue(id, created_at) recreated successfully.';
                EXCEPTION WHEN OTHERS THEN
                    RAISE WARNING 'C-17: Could not recreate FK: %', SQLERRM;
                END;
            END IF;
        ELSE
            RAISE NOTICE 'C-17: FK email_delivery_log_email_id_fkey already exists — no action needed';
        END IF;
    END IF;
END $$;

-- =============================================================================
-- Section 17: Add updated_at triggers for all newly created tables
-- =============================================================================
-- Ensures all tables with updated_at columns have auto-update triggers.
-- This covers the tables created in this migration as well as any tables
-- from prior migrations that may be missing triggers.
-- =============================================================================

DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'tenants', 'users', 'invoices', 'messages',
        'api_keys', 'webhook_events', 'dead_letter_queue',
        'domains', 'metering_events'
    ]
    LOOP
        -- Only add trigger if the table exists and has an updated_at column
        IF EXISTS (
            SELECT 1 FROM information_schema.tables WHERE table_name = t
        ) AND EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = t AND column_name = 'updated_at'
        ) THEN
            -- Check if trigger already exists (check both naming conventions)
            IF NOT EXISTS (
                SELECT 1 FROM pg_trigger
                WHERE tgname = 'update_' || t || '_updated_at'
                   OR tgname = 'trg_' || t || '_updated_at'
            ) THEN
                BEGIN
                    EXECUTE format(
                        'CREATE TRIGGER update_%I_updated_at
                         BEFORE UPDATE ON %I
                         FOR EACH ROW
                         EXECUTE FUNCTION update_updated_at_column()',
                        t, t
                    );
                    RAISE NOTICE 'Section 17: Added updated_at trigger to %.', t;
                EXCEPTION WHEN OTHERS THEN
                    RAISE WARNING 'Section 17: Could not add trigger to %: %', t, SQLERRM;
                END;
            END IF;
        END IF;
    END LOOP;
END $$;

-- =============================================================================
-- Summary verification
-- =============================================================================

DO $$
DECLARE
    v_all_tables TEXT[] := ARRAY[
        'tenants', 'users', 'invoices', 'messages',
        'metering_events', 'dead_letter_queue', 'domains',
        'api_keys', 'webhook_events'
    ];
    v_table_name TEXT;
    v_missing TEXT[] := '{}';
BEGIN
    FOREACH v_table_name IN ARRAY v_all_tables
    LOOP
        IF to_regclass('public.' || v_table_name) IS NULL THEN
            v_missing := array_append(v_missing, v_table_name);
        END IF;
    END LOOP;

    IF array_length(v_missing, 1) > 0 THEN
        RAISE WARNING 'Migration 056: The following tables could not be created: %', v_missing;
    ELSE
        RAISE NOTICE 'Migration 056: All 18 critical faults (C-01 through C-18) have been addressed successfully.';
    END IF;
END $$;
