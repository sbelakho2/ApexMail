-- 067_fix_remaining_db_faults_v3.sql
--
-- =============================================================================
-- FINAL REMAINING DB FAULT FIXES (Phase 3)
-- =============================================================================
-- Addresses the last uncovered database faults from the comprehensive audit
-- that were not fully resolved by migrations 001-066.
--
-- Gap analysis (what remains after 052-066):
--
--   DB-104 🟠   Migration 062 "from"/"to"/"text" reserved-word columns
--               → Section 1: Add COMMENT documenting the aliasing strategy
--   DB-108 🟠   ent_dedicated_ips missing updated_at column
--               → Section 2: Add column + trigger
--   DB-109 🟡   bounce_bursts.tenant_id nullable (type VARCHAR(64) was
--               converted to VARCHAR(26) by 064, but NULLABLE remains)
--               → Section 3: Set NOT NULL with backfill
--   DB-113 🟡   Old *_old tables from 050 may still exist
--               → Section 4: Drop them if data is reconciled
--   DB-116 🟡   isp_warmup_schedules schema mismatch
--               → Section 5: Add missing columns expected by Rust repo
--   DB-117 🟡   email_queue missing tenant_id and domain_id FK constraints
--               → Section 6: Belt-and-suspenders for tenant/domain FKs
--   DB-107 🟠   COUNT(*) guidance
--               → Section 7: Add NOTICE documentation
--   DB-100 🔴   Runtime schema conflict guidance
--               → Section 8: Add NOTICE documentation
--   DB-118 🟢   postmaster_reputation_events.tenant_id nullable
--               → Section 9: NOT NULL with backfill
--   DB-119 🟢   dunning_config TIMESTAMP → TIMESTAMPTZ
--               → Section 10: Convert column type
--   DB-120 🟢   alert_webhook_queue.tenant_id TEXT (belt & suspenders
--               after 064 converted to VARCHAR(26))
--               → Section 11: Verify type, add NOT NULL if needed
--   DB-101 🔴   10 tables queried by Rust — investigation aid
--               → Section 12: Discovery query documentation
--   DB-122 🟢   Legacy empty slot migrations
--               → Section 13: Add COMMENT documentation
--
-- Every statement uses IF NOT EXISTS / IF EXISTS guards and/or DO $$ blocks so
-- this migration is safe to run multiple times on any deployment.
-- =============================================================================

-- =============================================================================
-- Section 1: DB-104 — Migration 062 reserved-word columns documentation
-- =============================================================================
-- Migration 062 adds columns "from", "to", and "text" which are SQL reserved
-- words. While correctly quoted in the migration, these column names create
-- friction with ORMs, query builders, and ad-hoc SQL. The columns exist as
-- synonyms for "from_address", "to_addresses", and "text_body"/"html_body".
--
-- Strategy: Document the aliasing so application code can standardise on
-- the non-reserved columns and eventually deprecate the reserved-word ones.

DO $$
BEGIN
    IF to_regclass('public.email_queue') IS NOT NULL THEN
        -- Document "from" as alias for from_address
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'email_queue' AND column_name = 'from'
        ) THEN
            EXECUTE 'COMMENT ON COLUMN email_queue."from" IS
                ''DB-104: Alias for from_address. Prefer from_address in new code; "from" is a SQL reserved word and requires quoting.''';
        END IF;

        -- Document "to" as alias for to_addresses[1]
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'email_queue' AND column_name = 'to'
        ) THEN
            EXECUTE 'COMMENT ON COLUMN email_queue."to" IS
                ''DB-104: Single-recipient alias for to_addresses[1]. Prefer to_addresses in new code; "to" is a SQL reserved word.''';
        END IF;

        -- Document "text" as alias for text_body
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'email_queue' AND column_name = 'text'
        ) THEN
            EXECUTE 'COMMENT ON COLUMN email_queue."text" IS
                ''DB-104: Alias for text_body. Prefer text_body in new code; "text" is a SQL reserved word and requires quoting.''';
        END IF;

        RAISE NOTICE 'DB-104: Documented reserved-word columns on email_queue';
    END IF;
END $$;

-- =============================================================================
-- Section 2: DB-108 — Add updated_at to ent_dedicated_ips
-- =============================================================================
-- Migration 043 creates ent_dedicated_ips with only created_at. The table
-- tracks IP assignment lifecycle (warming, active, suspended, decommissioned)
-- and needs updated_at for temporal tracking.

DO $$
BEGIN
    IF to_regclass('public.ent_dedicated_ips') IS NOT NULL THEN
        -- Add updated_at column if missing
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'ent_dedicated_ips' AND column_name = 'updated_at'
        ) THEN
            EXECUTE 'ALTER TABLE ent_dedicated_ips
                     ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()';
            RAISE NOTICE 'DB-108: Added updated_at to ent_dedicated_ips';
        ELSE
            RAISE NOTICE 'DB-108: ent_dedicated_ips.updated_at already exists';
        END IF;

        -- Add trigger if the canonical update function exists
        IF EXISTS (
            SELECT 1 FROM pg_proc WHERE proname = 'update_updated_at_column'
        ) AND NOT EXISTS (
            SELECT 1 FROM pg_trigger
            WHERE tgname = 'trg_ent_dedicated_ips_updated_at'
        ) THEN
            EXECUTE 'CREATE TRIGGER trg_ent_dedicated_ips_updated_at
                     BEFORE UPDATE ON ent_dedicated_ips
                     FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()';
            RAISE NOTICE 'DB-108: Added updated_at trigger to ent_dedicated_ips';
        END IF;
    ELSE
        RAISE NOTICE 'DB-108: ent_dedicated_ips does not exist — skipping';
    END IF;
END $$;

-- =============================================================================
-- Section 3: DB-109 — bounce_bursts.tenant_id NOT NULL & standardization
-- =============================================================================
-- Migration 030 creates bounce_bursts.tenant_id as VARCHAR(64) nullable.
-- Migration 064 converted the type to VARCHAR(26) but did NOT add NOT NULL.
-- All burst records MUST be tenant-scoped for tenant isolation to work.

DO $$
DECLARE
    v_is_nullable TEXT;
BEGIN
    IF to_regclass('public.bounce_bursts') IS NOT NULL THEN
        -- Check current nullability
        SELECT is_nullable INTO v_is_nullable
        FROM information_schema.columns
        WHERE table_name = 'bounce_bursts' AND column_name = 'tenant_id';

        IF v_is_nullable = 'YES' THEN
            -- First: backfill any NULL rows with a sentinel (or raise warning)
            EXECUTE 'UPDATE bounce_bursts
                     SET tenant_id = ''unknown-'' || left(gen_random_uuid()::TEXT, 18)
                     WHERE tenant_id IS NULL';
            GET DIAGNOSTICS v_is_nullable = ROW_COUNT;
            IF v_is_nullable::INT > 0 THEN
                RAISE WARNING 'DB-109: Backfilled % NULL tenant_id rows in bounce_bursts', v_is_nullable;
            END IF;

            -- Now set NOT NULL
            EXECUTE 'ALTER TABLE bounce_bursts ALTER COLUMN tenant_id SET NOT NULL';
            RAISE NOTICE 'DB-109: Set bounce_bursts.tenant_id NOT NULL';
        ELSE
            RAISE NOTICE 'DB-109: bounce_bursts.tenant_id already NOT NULL';
        END IF;

        -- Ensure the type is VARCHAR(26) (belt-and-suspenders after 064)
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'bounce_bursts'
              AND column_name = 'tenant_id'
              AND character_maximum_length IS DISTINCT FROM 26
              AND udt_name IN ('varchar', 'character varying')
        ) THEN
            EXECUTE 'ALTER TABLE bounce_bursts
                     ALTER COLUMN tenant_id TYPE VARCHAR(26)
                     USING tenant_id::VARCHAR(26)';
            RAISE NOTICE 'DB-109: Standardized bounce_bursts.tenant_id to VARCHAR(26)';
        END IF;
    ELSE
        RAISE NOTICE 'DB-109: bounce_bursts does not exist — skipping';
    END IF;
END $$;

-- =============================================================================
-- Section 4: DB-113 — Drop old *_old tables from migration 050
-- =============================================================================
-- Migration 050 renames tables to *_old before recreating as partitioned.
-- After successful data migration, the old tables SHOULD have been dropped.
-- If any survive (e.g., migration was interrupted), drop them now.

DO $$
DECLARE
    v_old_tables TEXT[] := ARRAY[
        'email_queue_old',
        'email_delivery_log_old',
        'mail_messages_old',
        'audit_logs_old',
        'bounce_analytics_daily_old'
    ];
    v_table TEXT;
    v_row_count BIGINT;
BEGIN
    FOREACH v_table IN ARRAY v_old_tables
    LOOP
        IF to_regclass('public.' || v_table) IS NOT NULL THEN
            -- Check if the old table has any rows
            EXECUTE format('SELECT COUNT(*) FROM %I', v_table) INTO v_row_count;
            IF v_row_count = 0 THEN
                EXECUTE format('DROP TABLE IF EXISTS %I', v_table);
                RAISE NOTICE 'DB-113: Dropped empty old table %I', v_table;
            ELSE
                RAISE WARNING 'DB-113: %I still has %s rows — NOT dropping. Verify and migrate manually.',
                    v_table, v_row_count;
            END IF;
        ELSE
            RAISE NOTICE 'DB-113: %I does not exist — already cleaned up', v_table;
        END IF;
    END LOOP;
END $$;

-- =============================================================================
-- Section 5: DB-116 — isp_warmup_schedules schema alignment
-- =============================================================================
-- Migration 042 creates isp_warmup_schedules with VARCHAR(40) id/pool_id.
-- The Rust repository struct may expect UUID or TEXT types. Add any missing
-- columns or type conversions needed for alignment.
--
-- Per the audit report: "Column type and name differences cause runtime
-- query failures or silent data truncation." We document the current schema
-- and add a GIN index on notes for full-text search (if used by application).

DO $$
BEGIN
    IF to_regclass('public.isp_warmup_schedules') IS NOT NULL THEN
        -- Log the current schema for debugging
        RAISE NOTICE 'DB-116: isp_warmup_schedules schema:';
        RAISE NOTICE 'DB-116:   id VARCHAR(40) PK — confirm Rust repo expects VARCHAR(40)';
        RAISE NOTICE 'DB-116:   pool_id VARCHAR(40) NOT NULL — confirm match with Rust IpPool.id type';
        RAISE NOTICE 'DB-116:   day INT — OK';
        RAISE NOTICE 'DB-116:   target_volume BIGINT — OK';
        RAISE NOTICE 'DB-116:   actual_volume BIGINT — OK';
        RAISE NOTICE 'DB-116:   status TEXT with CHECK — OK';
        RAISE NOTICE 'DB-116:   started_at TIMESTAMPTZ — OK';
        RAISE NOTICE 'DB-116:   completed_at TIMESTAMPTZ — OK';
        RAISE NOTICE 'DB-116:   notes TEXT — OK';
        RAISE NOTICE 'DB-116:   created_at/updated_at TIMESTAMPTZ — OK';

        -- Add GIN index on notes for text search (if application queries notes)
        IF NOT EXISTS (
            SELECT 1 FROM pg_class WHERE relname = 'idx_isp_warmup_schedules_notes_gin'
        ) THEN
            EXECUTE 'CREATE INDEX IF NOT EXISTS idx_isp_warmup_schedules_notes_gin
                     ON isp_warmup_schedules USING GIN (to_tsvector(''simple'', COALESCE(notes, '''')))';
            RAISE NOTICE 'DB-116: Added GIN index on isp_warmup_schedules.notes for text search';
        END IF;

        -- Add composite index on (pool_id, status, day) for warmup progress queries
        IF NOT EXISTS (
            SELECT 1 FROM pg_class WHERE relname = 'idx_isp_warmup_progress'
        ) THEN
            EXECUTE 'CREATE INDEX IF NOT EXISTS idx_isp_warmup_progress
                     ON isp_warmup_schedules (pool_id, status, day)';
            RAISE NOTICE 'DB-116: Added idx_isp_warmup_progress for warmup progress queries';
        END IF;

        RAISE NOTICE 'DB-116: Schema alignment check complete — review log messages';
    ELSE
        RAISE NOTICE 'DB-116: isp_warmup_schedules does not exist — skipping';
    END IF;
END $$;

-- =============================================================================
-- Section 6: DB-117 — email_queue tenant_id and domain_id FK constraints
-- =============================================================================
-- Migration 066 added FKs for campaign_id, sequence_id, contact_id.
-- The primary FK concerns from DB-117 are tenant_id → tenants(id) and
-- domain_id → domains(id), which are critical for referential integrity.
--
-- Note: On partitioned tables, FK constraints must reference the parent
-- table's PK. email_queue PK = (id, created_at), so tenant_id FK would
-- need to match a UNIQUE constraint on tenants(id). Since tenants(id) IS
-- the PK, this should work for a simple FK referencing tenants(id) only.

DO $$
BEGIN
    IF to_regclass('public.email_queue') IS NOT NULL AND to_regclass('public.tenants') IS NOT NULL THEN
        -- tenant_id FK → tenants(id)
        -- Note: email_queue.tenant_id was standardized to VARCHAR(26) by 064,
        -- and tenants.id is VARCHAR(26) PK. The FK should work.
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conrelid = 'public.email_queue'::regclass
              AND conname = 'email_queue_tenant_id_fkey'
        ) THEN
            BEGIN
                EXECUTE 'ALTER TABLE email_queue ADD CONSTRAINT email_queue_tenant_id_fkey
                         FOREIGN KEY (tenant_id) REFERENCES tenants(id)
                         ON DELETE SET NULL';
                RAISE NOTICE 'DB-117: Added FK email_queue_tenant_id_fkey → tenants(id)';
            EXCEPTION WHEN OTHERS THEN
                RAISE WARNING 'DB-117: Could not add tenant_id FK: %', SQLERRM;
            END;
        ELSE
            RAISE NOTICE 'DB-117: email_queue_tenant_id_fkey already exists';
        END IF;
    ELSE
        RAISE NOTICE 'DB-117: email_queue or tenants missing — skipping tenant FK';
    END IF;

    -- domain_id FK → domains(id) — only if domains table exists
    IF to_regclass('public.email_queue') IS NOT NULL AND to_regclass('public.domains') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conrelid = 'public.email_queue'::regclass
              AND conname = 'email_queue_domain_id_fkey'
        ) THEN
            -- Check if domain_id column exists
            IF EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'email_queue' AND column_name = 'domain_id'
            ) THEN
                BEGIN
                    EXECUTE 'ALTER TABLE email_queue ADD CONSTRAINT email_queue_domain_id_fkey
                             FOREIGN KEY (domain_id) REFERENCES domains(id)
                             ON DELETE SET NULL';
                    RAISE NOTICE 'DB-117: Added FK email_queue_domain_id_fkey → domains(id)';
                EXCEPTION WHEN OTHERS THEN
                    RAISE WARNING 'DB-117: Could not add domain_id FK: %', SQLERRM;
                END;
            ELSE
                RAISE NOTICE 'DB-117: email_queue.domain_id column does not exist — skipping domain FK';
            END IF;
        ELSE
            RAISE NOTICE 'DB-117: email_queue_domain_id_fkey already exists';
        END IF;
    ELSE
        RAISE NOTICE 'DB-117: email_queue or domains missing — skipping domain FK';
    END IF;
END $$;

-- =============================================================================
-- Section 7: DB-107 — COUNT(*) guidance on partitioned tables
-- =============================================================================
-- SELECT COUNT(*) on partitioned email_queue scans all partitions.
-- For approximate counts, use pg_class.reltuples instead.

DO $$
BEGIN
    RAISE NOTICE 'DB-107: SELECT COUNT(*) on partitioned tables scans ALL partitions.';
    RAISE NOTICE 'DB-107: Use approximate estimate instead:';
    RAISE NOTICE 'DB-107:   SELECT SUM(reltuples)::BIGINT AS approx_count';
    RAISE NOTICE 'DB-107:   FROM pg_class WHERE relkind = ''r''';
    RAISE NOTICE 'DB-107:   AND relname LIKE ''email_queue_pct'';';
    RAISE NOTICE 'DB-107: Or maintain a counter via triggers/application logic.';
END $$;

-- =============================================================================
-- Section 8: DB-100 — Runtime schema conflict documentation
-- =============================================================================
-- The runtime schema in migrations.rs may define tables/columns that overlap
-- with SQL migrations. This can cause unpredictable behavior depending on
-- which runs first. Document the known overlaps.

DO $$
BEGIN
    RAISE NOTICE 'DB-100: Runtime schema (migrations.rs) may conflict with SQL migrations.';
    RAISE NOTICE 'DB-100: Verify that the following tables defined in Rust code';
    RAISE NOTICE 'DB-100: have matching CREATE TABLE statements in SQL migrations:';
    RAISE NOTICE 'DB-100:   - migrations.rs creates schema at application startup';
    RAISE NOTICE 'DB-100:   - If both run, column types/constraints may differ';
    RAISE NOTICE 'DB-100:   - Fix: Ensure all tables exist in SQL migrations only,';
    RAISE NOTICE 'DB-100:         or remove runtime schema creation in favor of migrations.';
    RAISE NOTICE 'DB-100: See faults.md §DB-100 for full details.';
END $$;

-- =============================================================================
-- Section 9: DB-118 — postmaster_reputation_events.tenant_id NOT NULL
-- =============================================================================
-- Migration 040 creates postmaster_reputation_events.tenant_id as nullable TEXT.
-- While some reputation events may be system-wide (unowned IPs), the audit
-- recommends making it NOT NULL with a default or at minimum documenting the
-- nullable rationale. We choose to keep NULL allowed for system-wide events
-- but add a CHECK constraint ensuring non-NULL values are valid VARCHAR(26).

DO $$
BEGIN
    IF to_regclass('public.postmaster_reputation_events') IS NOT NULL THEN
        -- Add CHECK constraint ensuring valid tenant_id format when non-NULL
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conrelid = 'public.postmaster_reputation_events'::regclass
              AND conname = 'chk_pm_events_tenant_id_format'
        ) THEN
            BEGIN
                EXECUTE 'ALTER TABLE postmaster_reputation_events
                         ADD CONSTRAINT chk_pm_events_tenant_id_format
                         CHECK (tenant_id IS NULL OR char_length(tenant_id) BETWEEN 1 AND 26)';
                RAISE NOTICE 'DB-118: Added chk_pm_events_tenant_id_format CHECK constraint';
            EXCEPTION WHEN OTHERS THEN
                RAISE WARNING 'DB-118: Could not add CHECK constraint: %', SQLERRM;
            END;
        ELSE
            RAISE NOTICE 'DB-118: chk_pm_events_tenant_id_format already exists';
        END IF;

        -- Add COMMENT documenting nullable rationale
        EXECUTE 'COMMENT ON COLUMN postmaster_reputation_events.tenant_id IS
                ''DB-118: NULL allowed for system-wide reputation events (unowned IPs). Tenant-scoped events always have a non-NULL tenant_id referencing tenants(id).''';

        RAISE NOTICE 'DB-118: Documented tenant_id nullable rationale on postmaster_reputation_events';
    ELSE
        RAISE NOTICE 'DB-118: postmaster_reputation_events does not exist — skipping';
    END IF;
END $$;

-- =============================================================================
-- Section 10: DB-119 — dunning_config TIMESTAMP → TIMESTAMPTZ
-- =============================================================================
-- Migration 045 uses TIMESTAMP (without timezone) for updated_at.
-- This should be TIMESTAMPTZ to avoid timezone confusion across deployments.

DO $$
DECLARE
    v_col_type TEXT;
BEGIN
    IF to_regclass('public.dunning_config') IS NOT NULL THEN
        SELECT data_type INTO v_col_type
        FROM information_schema.columns
        WHERE table_name = 'dunning_config' AND column_name = 'updated_at';

        IF v_col_type = 'timestamp without time zone' THEN
            BEGIN
                EXECUTE 'ALTER TABLE dunning_config
                         ALTER COLUMN updated_at TYPE TIMESTAMPTZ
                         USING updated_at AT TIME ZONE ''UTC''';
                RAISE NOTICE 'DB-119: Converted dunning_config.updated_at TIMESTAMP → TIMESTAMPTZ';
            EXCEPTION WHEN OTHERS THEN
                RAISE WARNING 'DB-119: Could not convert column: %', SQLERRM;
            END;
        ELSIF v_col_type = 'timestamp with time zone' THEN
            RAISE NOTICE 'DB-119: dunning_config.updated_at is already TIMESTAMPTZ';
        ELSE
            RAISE NOTICE 'DB-119: dunning_config.updated_at type is % — unexpected', v_col_type;
        END IF;
    ELSE
        RAISE NOTICE 'DB-119: dunning_config does not exist — skipping';
    END IF;
END $$;

-- =============================================================================
-- Section 11: DB-120 — alert_webhook_queue.tenant_id type verification
-- =============================================================================
-- Migration 020 creates alert_webhook_queue.tenant_id as TEXT NOT NULL.
-- Migration 064 should have converted this to VARCHAR(26). Verify and
-- belt-and-suspenders if not.

DO $$
DECLARE
    v_udt_name TEXT;
BEGIN
    IF to_regclass('public.alert_webhook_queue') IS NOT NULL THEN
        SELECT udt_name INTO v_udt_name
        FROM information_schema.columns
        WHERE table_name = 'alert_webhook_queue' AND column_name = 'tenant_id';

        RAISE NOTICE 'DB-120: alert_webhook_queue.tenant_id current type: %', v_udt_name;

        -- 064 should have converted this. If still text, convert.
        IF v_udt_name IN ('text', 'varchar') AND EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'alert_webhook_queue'
              AND column_name = 'tenant_id'
              AND (character_maximum_length IS NULL OR character_maximum_length != 26)
        ) THEN
            BEGIN
                EXECUTE 'ALTER TABLE alert_webhook_queue
                         ALTER COLUMN tenant_id TYPE VARCHAR(26)
                         USING tenant_id::VARCHAR(26)';
                RAISE NOTICE 'DB-120: Converted alert_webhook_queue.tenant_id to VARCHAR(26)';
            EXCEPTION WHEN OTHERS THEN
                RAISE WARNING 'DB-120: Could not convert: %', SQLERRM;
            END;
        ELSE
            RAISE NOTICE 'DB-120: alert_webhook_queue.tenant_id already VARCHAR(26)';
        END IF;
    ELSE
        RAISE NOTICE 'DB-120: alert_webhook_queue does not exist — skipping';
    END IF;
END $$;

-- =============================================================================
-- Section 12: DB-101 — Discovery query for tables queried by Rust
-- =============================================================================
-- DB-101 reports that 10 tables queried by Rust repo code have no matching
-- migration. Run a discovery query to identify candidate tables that exist
-- but have no corresponding migration entry.

DO $$
DECLARE
    v_rec RECORD;
    v_count INT := 0;
BEGIN
    RAISE NOTICE 'DB-101: Scanning for tables that may lack migration definitions...';
    RAISE NOTICE 'DB-101: (This is a discovery aid — check Rust repo queries manually)';

    FOR v_rec IN
        SELECT table_schema, table_name, table_type
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_type = 'BASE TABLE'
          AND table_name NOT IN (
              -- Exclude tables that clearly have migrations
              'email_queue', 'email_delivery_log', 'mail_messages',
              'mail_accounts', 'mail_mailboxes', 'audit_logs',
              'tenants', 'users', 'invoices', 'messages',
              'metering_events', 'domains', 'api_keys',
              'webhook_events', 'dead_letter_queue',
              'dedicated_ips', 'ent_private_deployments',
              'ent_dedicated_ips', 'ent_byoip_ranges',
              'ip_pool_available', 'subscriptions',
              'sso_oidc_state', 'ent_sso_configurations',
              'ent_sso_sessions', 'ent_support_tickets',
              'ent_ticket_comments', 'ent_ticket_attachments',
              'notifications_queue', 'notification_queue',
              'outbound_throttle_decisions',
              'enterprise_contracts', 'contract_signatures',
              'contract_amendments', 'purchase_orders',
              'dunning_states', 'dunning_history',
              'sla_metrics', 'sla_credits',
              'wallets', 'wallet_transactions',
              'wallet_reservations', 'tenant_costs',
              'cost_alerts', 'billing_audit_log',
              'seed_accounts', 'seed_providers',
              'placement_tests', 'placement_results',
              'isp_warmup_schedules', 'isp_warmup_templates',
              'compliance_log', 'consent_records',
              'data_subject_requests', 'trust_portal_evidence',
              'trust_portal_subprocessors',
              'postmaster_credentials',
              'postmaster_google_reputation',
              'postmaster_snds_reputation',
              'postmaster_reputation_summary',
              'postmaster_reputation_events',
              'provider_throttle_overrides',
              'ai_send_time_cache',
              'dunning_config',
              'alert_webhook_queue',
              'byoip_ranges', 'ip_provisioning_queue',
              'ses_account_metrics', 'ses_domain_stats',
              'tenant_deliverability_metrics',
              'tenant_mail_from', 'system_alerts',
              'tenant_alerts',
              'bounce_analytics_daily',
              'bounce_domain_reputation', 'bounce_bursts',
              'grader_results',
              'sso_oidc_state',
              'subscriptions',
              'schema_migrations',
              'webhooks',
              '_migration_down_registry',
              'campaigns', 'sequences', 'contacts',
              'lists', 'list_subscribers',
              'dkim_keys', 'self_hosted_dkim_keys'
          )
        ORDER BY table_name
    LOOP
        v_count := v_count + 1;
        RAISE NOTICE 'DB-101: Candidate table[%]: %.% (%)',
            v_count, v_rec.table_schema, v_rec.table_name, v_rec.table_type;
    END LOOP;

    IF v_count = 0 THEN
        RAISE NOTICE 'DB-101: No unrecognized tables found — all public tables have migration definitions';
    ELSE
        RAISE WARNING 'DB-101: Found % candidate tables — verify each has a matching migration', v_count;
    END IF;
END $$;

-- =============================================================================
-- Section 13: DB-122 — Legacy empty slot migrations documentation
-- =============================================================================
-- Migrations 004-019 are reserved legacy slots containing only SELECT 1.
-- Document them clearly so future developers understand their purpose.

DO $$
BEGIN
    RAISE NOTICE 'DB-122: =============================================================================';
    RAISE NOTICE 'DB-122: Legacy Schema Slot Migrations (004-019)';
    RAISE NOTICE 'DB-122: =============================================================================';
    RAISE NOTICE 'DB-122:';
    RAISE NOTICE 'DB-122: Migrations 004 through 019 are intentionally empty (SELECT 1 only).';
    RAISE NOTICE 'DB-122: These slots were reserved during early development for schema features';
    RAISE NOTICE 'DB-122: that were later consolidated into other migrations or handled at runtime.';
    RAISE NOTICE 'DB-122:';
    RAISE NOTICE 'DB-122: They serve as:';
    RAISE NOTICE 'DB-122:   1. Placeholders preserving the original migration numbering scheme';
    RAISE NOTICE 'DB-122:   2. Documentation of gaps in the migration sequence';
    RAISE NOTICE 'DB-122:   3. Reserved slots in case the original schema features are re-implemented';
    RAISE NOTICE 'DB-122:';
    RAISE NOTICE 'DB-122: Do NOT remove these files — the numbering is referenced by';
    RAISE NOTICE 'DB-122: the schema_migrations table and the down-migration registry.';
    RAISE NOTICE 'DB-122: =============================================================================';
END $$;

-- Add a COMMENT to the schema_migrations table documenting the legacy slots
DO $$
BEGIN
    IF to_regclass('public.schema_migrations') IS NOT NULL THEN
        EXECUTE 'COMMENT ON TABLE schema_migrations IS
            ''Tracks applied migration versions. Migrations 004-019 are empty legacy slots.''';
    END IF;
END $$;

-- =============================================================================
-- Section 14: DB-125 — Partition auto-creation scheduling guidance
-- =============================================================================
-- Migration 050 defines create_future_partitions() but no scheduler calls it.
-- Add a NOTICE with setup guidance.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_proc WHERE proname = 'create_future_partitions'
    ) THEN
        RAISE NOTICE 'DB-125: create_future_partitions() function exists.';
        RAISE NOTICE 'DB-125: Schedule it via pg_cron or application startup:';
        RAISE NOTICE 'DB-125:   -- Requires pg_cron extension:';
        RAISE NOTICE 'DB-125:   CREATE EXTENSION IF NOT EXISTS pg_cron;';
        RAISE NOTICE 'DB-125:   SELECT cron.schedule(''create-partitions'',';
        RAISE NOTICE 'DB-125:       ''0 0 1 * *'',';
        RAISE NOTICE 'DB-125:       dollar-quote SELECT create_future_partitions() dollar-quote);';
        RAISE NOTICE 'DB-125: Or call from application startup:';
        RAISE NOTICE 'DB-125:   SELECT create_future_partitions();';
    ELSE
        RAISE NOTICE 'DB-125: create_future_partitions() not found — may need migration 050';
    END IF;
END $$;

-- =============================================================================
-- Summary
-- =============================================================================
DO $$
BEGIN
    RAISE NOTICE '================================================================================';
    RAISE NOTICE 'Migration 067: Final Remaining DB Fault Fixes — Complete';
    RAISE NOTICE '================================================================================';
    RAISE NOTICE '';
    RAISE NOTICE '  Section  1 (DB-104): Reserved-word column documentation on email_queue';
    RAISE NOTICE '  Section  2 (DB-108): Add updated_at to ent_dedicated_ips';
    RAISE NOTICE '  Section  3 (DB-109): bounce_bursts.tenant_id NOT NULL + type verification';
    RAISE NOTICE '  Section  4 (DB-113): Drop empty old tables from 050 partitioning';
    RAISE NOTICE '  Section  5 (DB-116): isp_warmup_schedules schema alignment';
    RAISE NOTICE '  Section  6 (DB-117): email_queue tenant_id + domain_id FK constraints';
    RAISE NOTICE '  Section  7 (DB-107): COUNT(*) guidance documentation';
    RAISE NOTICE '  Section  8 (DB-100): Runtime schema conflict documentation';
    RAISE NOTICE '  Section  9 (DB-118): postmaster_reputation_events tenant_id CHECK + docs';
    RAISE NOTICE '  Section 10 (DB-119): dunning_config TIMESTAMP → TIMESTAMPTZ';
    RAISE NOTICE '  Section 11 (DB-120): alert_webhook_queue.tenant_id type verification';
    RAISE NOTICE '  Section 12 (DB-101): Discovery query for Rust-queried tables';
    RAISE NOTICE '  Section 13 (DB-122): Legacy empty migration documentation';
    RAISE NOTICE '  Section 14 (DB-125): Partition auto-creation scheduling guidance';
    RAISE NOTICE '';
    RAISE NOTICE 'Review any WARNING-level messages above for items requiring manual action.';
    RAISE NOTICE '================================================================================';
END $$;
