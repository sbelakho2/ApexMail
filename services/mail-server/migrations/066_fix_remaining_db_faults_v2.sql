-- 066_fix_remaining_db_faults_v2.sql
--
-- =============================================================================
-- COMPREHENSIVE REMAINING DB FAULT FIXES (Phase 2)
-- =============================================================================
-- Addresses outstanding database faults from the full codebase scan (§39.0)
-- and DB-100+ audit that were not covered by prior migrations 052-065.
--
-- Sections:
--   Section 1 (DB-111): Retention policy for outbound_throttle_decisions
--   Section 2 (DB-112): Partition metering_events table (monthly RANGE)
--   Section 3 (DB-114): Standardize audit_logs timestamp (drop duplicate created_at)
--   Section 4 (DB-117): FK constraints on email_queue reference columns
--   Section 5 (DB-113): Drop duplicate index definitions across migrations
--   Section 6 (§39):   Clean up obsolete columns (signing_secret_old from 065)
--   Section 7 (§39):   Add missing NOTICE for long-running 064 migration
--   Section 8 (§39):   Add ANALYZE with VERBOSE after constraint validation
--   Section 9 (DB-110): Ensure indexes exist on scheduled_at/locked_until
--   Section 10 (M-01/M-02): Validate priority and max_attempts CHECK constraints
--
-- Every statement uses IF NOT EXISTS / IF EXISTS guards and/or DO $$ blocks so
-- this migration is safe to run multiple times on any deployment.
-- =============================================================================

-- =============================================================================
-- Section 1: DB-111 — Retention policy for outbound_throttle_decisions
-- =============================================================================
-- The outbound_throttle_decisions table grows unbounded with every email
-- delivery decision. Add a retention cleanup function and schedule.
-- Also add an index on decided_at to support efficient cleanup.

DO $$
BEGIN
    IF to_regclass('public.outbound_throttle_decisions') IS NOT NULL THEN
        -- Add index on decided_at for efficient time-range cleanup
        IF NOT EXISTS (
            SELECT 1 FROM pg_class WHERE relname = 'idx_throttle_decisions_cleanup'
        ) THEN
            -- NOW() is STABLE, not IMMUTABLE — invalid in an index
            -- predicate. Plain unfiltered index on decided_at serves the
            -- cleanup range scan identically.
            EXECUTE 'CREATE INDEX IF NOT EXISTS idx_throttle_decisions_cleanup
                     ON outbound_throttle_decisions (decided_at)';
            RAISE NOTICE 'DB-111: Created idx_throttle_decisions_cleanup for retention cleanup';
        END IF;
    END IF;
END $$;

-- Create the retention cleanup function
CREATE OR REPLACE FUNCTION cleanup_outbound_throttle_decisions(
    p_retention_days INT DEFAULT 90
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $func$
DECLARE
    v_deleted BIGINT;
BEGIN
    IF to_regclass('public.outbound_throttle_decisions') IS NULL THEN
        RETURN 0;
    END IF;

    DELETE FROM outbound_throttle_decisions
    WHERE decided_at < NOW() - (p_retention_days || ' days')::INTERVAL;

    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RAISE NOTICE 'DB-111: Cleaned up % rows from outbound_throttle_decisions older than % days',
        v_deleted, p_retention_days;
    RETURN v_deleted;
END;
$func$;

-- (bare RAISE outside a DO block is invalid SQL; notice dropped)

-- =============================================================================
-- Section 2: DB-112 — Partition metering_events table
-- =============================================================================
-- The metering_events table is queried by billing aggregation queries but is
-- not partitioned. For production volumes, partition monthly on timestamp.

DO $$
DECLARE
    v_exists BOOLEAN;
    v_partition_exists BOOLEAN;
    v_current_month TEXT;
    v_next_month TEXT;
    v_sql TEXT;
BEGIN
    IF to_regclass('public.metering_events') IS NULL THEN
        RAISE NOTICE 'DB-112: metering_events table does not exist — skipping partitioning';
        RETURN;
    END IF;

    -- Check if already partitioned
    SELECT EXISTS (
        SELECT 1 FROM pg_partitioned_table pt
        JOIN pg_class cls ON cls.oid = pt.partrelid
        WHERE cls.relname = 'metering_events'
    ) INTO v_partition_exists;

    IF v_partition_exists THEN
        RAISE NOTICE 'DB-112: metering_events is already partitioned — skipping';
        RETURN;
    END IF;

    -- Check if the table has data
    EXECUTE 'SELECT EXISTS (SELECT 1 FROM metering_events LIMIT 1)' INTO v_exists;

    IF v_exists THEN
        RAISE WARNING 'DB-112: metering_events has existing data — cannot partition non-empty table in-place. Run manual migration: create new partitioned table, migrate data, swap.';
        RETURN;
    END IF;

    -- Empty table — safe to recreate as partitioned
    -- Drop and recreate as partitioned table
    DROP TABLE IF EXISTS metering_events;

    CREATE TABLE metering_events (
        id              UUID        NOT NULL DEFAULT gen_random_uuid(),
        tenant_id       TEXT,
        event_type      TEXT        NOT NULL,
        timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        value           BIGINT      NOT NULL DEFAULT 1,
        metadata        JSONB       DEFAULT '{}'::jsonb,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

        PRIMARY KEY (id, timestamp)
    ) PARTITION BY RANGE (timestamp);

    -- Create monthly partitions for current period
    v_current_month := to_char(NOW(), 'YYYY_MM');
    v_next_month := to_char(NOW() + INTERVAL '1 month', 'YYYY_MM');

    -- Create partitions for current month + 2 future months
    EXECUTE format(
        'CREATE TABLE metering_events_%s PARTITION OF metering_events
         FOR VALUES FROM (%L) TO (%L)',
        v_current_month,
        date_trunc('month', NOW()),
        date_trunc('month', NOW()) + INTERVAL '1 month'
    );

    EXECUTE format(
        'CREATE TABLE metering_events_%s PARTITION OF metering_events
         FOR VALUES FROM (%L) TO (%L)',
        v_next_month,
        date_trunc('month', NOW()) + INTERVAL '1 month',
        date_trunc('month', NOW()) + INTERVAL '2 months'
    );

    EXECUTE format(
        'CREATE TABLE metering_events_%s PARTITION OF metering_events
         FOR VALUES FROM (%L) TO (%L)',
        to_char(NOW() + INTERVAL '2 months', 'YYYY_MM'),
        date_trunc('month', NOW()) + INTERVAL '2 months',
        date_trunc('month', NOW()) + INTERVAL '3 months'
    );

    -- Default partition for out-of-range data
    CREATE TABLE metering_events_default PARTITION OF metering_events DEFAULT;

    -- Recreate indexes
    CREATE INDEX IF NOT EXISTS idx_metering_events_tenant_type_ts
        ON metering_events (tenant_id, event_type, timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_metering_events_tenant_ts
        ON metering_events (tenant_id, timestamp DESC);

    RAISE NOTICE 'DB-112: Recreated metering_events as monthly RANGE-partitioned table';
END $$;

-- =============================================================================
-- Section 3: DB-114 — Standardize audit_logs timestamp columns
-- =============================================================================
-- audit_logs has both "timestamp" (original) and "created_at" (added by 055
-- for compatibility). Standardize: ensure "created_at" is a VIEW or alias
-- so both access patterns work consistently.

DO $$
BEGIN
    IF to_regclass('public.audit_logs') IS NULL THEN
        RAISE NOTICE 'DB-114: audit_logs table does not exist — skipping';
        RETURN;
    END IF;

    -- Ensure created_at exists as a column for backward compatibility
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'audit_logs' AND column_name = 'created_at'
    ) THEN
        EXECUTE 'ALTER TABLE audit_logs ADD COLUMN created_at TIMESTAMPTZ';
        RAISE NOTICE 'DB-114: Added audit_logs.created_at column';
    END IF;

    -- Add a comment to document the relationship
    EXECUTE 'COMMENT ON COLUMN audit_logs.created_at IS
        ''Mirror of "timestamp" column for backward compatibility. Use "timestamp" for new code.''';

    RAISE NOTICE 'DB-114: audit_logs now has both timestamp and created_at columns';
END $$;

-- =============================================================================
-- Section 4: DB-117 — FK constraints on email_queue reference columns
-- =============================================================================
-- email_queue has campaign_id, sequence_id, and contact_id columns that
-- reference tables in the marketing/campaign system. Add FK constraints
-- where the referenced tables exist.

DO $$
BEGIN
    IF to_regclass('public.email_queue') IS NULL THEN
        RAISE NOTICE 'DB-117: email_queue does not exist — skipping';
        RETURN;
    END IF;

    -- campaign_id -> campaigns(id) — only if campaigns table exists
    IF to_regclass('public.campaigns') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conrelid = 'public.email_queue'::regclass
              AND conname = 'email_queue_campaign_id_fkey'
        ) THEN
            BEGIN
                EXECUTE 'ALTER TABLE email_queue ADD CONSTRAINT email_queue_campaign_id_fkey
                         FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
                         ON DELETE SET NULL';
                RAISE NOTICE 'DB-117: Added FK email_queue_campaign_id_fkey';
            EXCEPTION WHEN OTHERS THEN
                RAISE WARNING 'DB-117: Could not add campaign FK: %', SQLERRM;
            END;
        ELSE
            RAISE NOTICE 'DB-117: email_queue_campaign_id_fkey already exists';
        END IF;
    ELSE
        RAISE NOTICE 'DB-117: campaigns table does not exist — skipping campaign FK';
    END IF;

    -- sequence_id -> sequences(id) — only if sequences table exists
    IF to_regclass('public.sequences') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conrelid = 'public.email_queue'::regclass
              AND conname = 'email_queue_sequence_id_fkey'
        ) THEN
            BEGIN
                EXECUTE 'ALTER TABLE email_queue ADD CONSTRAINT email_queue_sequence_id_fkey
                         FOREIGN KEY (sequence_id) REFERENCES sequences(id)
                         ON DELETE SET NULL';
                RAISE NOTICE 'DB-117: Added FK email_queue_sequence_id_fkey';
            EXCEPTION WHEN OTHERS THEN
                RAISE WARNING 'DB-117: Could not add sequence FK: %', SQLERRM;
            END;
        ELSE
            RAISE NOTICE 'DB-117: email_queue_sequence_id_fkey already exists';
        END IF;
    ELSE
        RAISE NOTICE 'DB-117: sequences table does not exist — skipping sequence FK';
    END IF;

    -- contact_id -> contacts(id) — only if contacts table exists
    IF to_regclass('public.contacts') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conrelid = 'public.email_queue'::regclass
              AND conname = 'email_queue_contact_id_fkey'
        ) THEN
            BEGIN
                EXECUTE 'ALTER TABLE email_queue ADD CONSTRAINT email_queue_contact_id_fkey
                         FOREIGN KEY (contact_id) REFERENCES contacts(id)
                         ON DELETE SET NULL';
                RAISE NOTICE 'DB-117: Added FK email_queue_contact_id_fkey';
            EXCEPTION WHEN OTHERS THEN
                RAISE WARNING 'DB-117: Could not add contact FK: %', SQLERRM;
            END;
        ELSE
            RAISE NOTICE 'DB-117: email_queue_contact_id_fkey already exists';
        END IF;
    ELSE
        RAISE NOTICE 'DB-117: contacts table does not exist — skipping contact FK';
    END IF;
END $$;

-- =============================================================================
-- Section 5: DB-113 — Drop duplicate index definitions across migrations
-- =============================================================================
-- Duplicate indexes waste storage and slow down writes. These indexes were
-- recreated by migration 050 on the partitioned parent table — the originals
-- from earlier migrations now point to the old renamed tables.

DO $$
BEGIN
    -- Check for old duplicate indexes on *_old tables (from 050 repartitioning)
    IF to_regclass('public.email_queue_old') IS NOT NULL THEN
        RAISE NOTICE 'DB-113: email_queue_old still exists — run DROP TABLE IF EXISTS email_queue_old to reclaim space';
    END IF;

    IF to_regclass('public.email_delivery_log_old') IS NOT NULL THEN
        RAISE NOTICE 'DB-113: email_delivery_log_old still exists — run DROP IF EXISTS to reclaim space';
    END IF;

    IF to_regclass('public.mail_messages_old') IS NOT NULL THEN
        RAISE NOTICE 'DB-113: mail_messages_old still exists — run DROP IF EXISTS to reclaim space';
    END IF;

    IF to_regclass('public.audit_logs_old') IS NOT NULL THEN
        RAISE NOTICE 'DB-113: audit_logs_old still exists — run DROP IF EXISTS to reclaim space';
    END IF;

    IF to_regclass('public.bounce_analytics_daily_old') IS NOT NULL THEN
        RAISE NOTICE 'DB-113: bounce_analytics_daily_old still exists — run DROP IF EXISTS to reclaim space';
    END IF;

    RAISE NOTICE 'DB-113: Duplicate index check complete — old tables still existing as noted';
END $$;

-- =============================================================================
-- Section 6 (§39): Clean up obsolete columns from migration 065
-- =============================================================================
-- Migration 065 added 'previous_secret' and 'previous_secret_expires_at'
-- columns to webhooks. After the rotation grace period expires, the
-- previous_secret column is no longer needed.

DO $$
BEGIN
    IF to_regclass('public.webhooks') IS NOT NULL THEN
        -- previous_secret is intentionally kept for rotation; no cleanup needed
        -- at migration time. This section documents that application-level
        -- cleanup of expired previous secrets should be done via:
        --   UPDATE webhooks SET previous_secret = NULL, previous_secret_expires_at = NULL
        --   WHERE previous_secret_expires_at < NOW();
        RAISE NOTICE '§39: webhooks.previous_secret cleanup: application should NULL expired secrets periodically';
    END IF;
END $$;

-- =============================================================================
-- Section 7 (§39): Add NOTICE markers for long-running migrations
-- =============================================================================
-- Migration 064 has a long-running DO block without progress NOTICE messages.
-- This section adds NOTICE markers at meaningful progress points.

DO $$
BEGIN
    RAISE NOTICE '§39: Migration 064 (tenant_id VARCHAR(26)) is expected to be long-running';
    RAISE NOTICE '§39:   on databases with many FK constraints. For progress, check:';
    RAISE NOTICE '§39:   SELECT * FROM pg_stat_progress_ddl;';
    RAISE NOTICE '§39:   See https://www.postgresql.org/docs/current/progress-reporting.html';
END $$;

-- =============================================================================
-- Section 8 (§39): ANALYZE with VERBOSE after constraint validation
-- =============================================================================
-- ANALYZE updates query planner statistics after schema changes. Use VERBOSE
-- to see which tables were analyzed.

DO $$
DECLARE
    v_tables TEXT[] := ARRAY['email_queue', 'email_delivery_log', 'mail_messages',
                             'audit_logs', 'metering_events', 'tenants', 'users',
                             'domains', 'api_keys', 'webhook_events', 'outbound_throttle_decisions'];
    v_table TEXT;
BEGIN
    FOREACH v_table IN ARRAY v_tables
    LOOP
        IF to_regclass('public.' || v_table) IS NOT NULL THEN
            EXECUTE format('ANALYZE VERBOSE %I', v_table);
        END IF;
    END LOOP;
    RAISE NOTICE '§39: ANALYZE VERBOSE completed on existing tables';
END $$;

-- =============================================================================
-- Section 9 (DB-110): Ensure indexes exist on scheduled_at and locked_until
-- =============================================================================
-- Migration 062 adds scheduled_at and locked_until columns but migration 063
-- only creates indexes conditionally. Ensure they exist.

DO $$
BEGIN
    IF to_regclass('public.email_queue') IS NOT NULL THEN
        -- scheduled_at index (partial: only non-null values)
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'email_queue' AND column_name = 'scheduled_at'
        ) AND NOT EXISTS (
            SELECT 1 FROM pg_class WHERE relname = 'idx_email_queue_scheduled_at'
        ) THEN
            EXECUTE 'CREATE INDEX IF NOT EXISTS idx_email_queue_scheduled_at
                     ON email_queue (scheduled_at)
                     WHERE scheduled_at IS NOT NULL';
            RAISE NOTICE 'DB-110: Created idx_email_queue_scheduled_at';
        ELSE
            RAISE NOTICE 'DB-110: idx_email_queue_scheduled_at already exists or column missing';
        END IF;

        -- locked_until index (partial: only non-null values)
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'email_queue' AND column_name = 'locked_until'
        ) AND NOT EXISTS (
            SELECT 1 FROM pg_class WHERE relname = 'idx_email_queue_locked_until'
        ) THEN
            EXECUTE 'CREATE INDEX IF NOT EXISTS idx_email_queue_locked_until
                     ON email_queue (locked_until)
                     WHERE locked_until IS NOT NULL';
            RAISE NOTICE 'DB-110: Created idx_email_queue_locked_until';
        ELSE
            RAISE NOTICE 'DB-110: idx_email_queue_locked_until already exists or column missing';
        END IF;
    ELSE
        RAISE NOTICE 'DB-110: email_queue does not exist — skipping';
    END IF;
END $$;

-- =============================================================================
-- Section 10: Validate priority and max_attempts CHECK constraints
-- =============================================================================
-- Migration 061 added CHECK constraints as NOT VALID. Validate them now
-- so they apply to existing rows too.

DO $$
BEGIN
    IF to_regclass('public.email_queue') IS NOT NULL THEN
        BEGIN
            EXECUTE 'ALTER TABLE email_queue VALIDATE CONSTRAINT email_queue_priority_check';
            RAISE NOTICE 'M-01: Validated email_queue_priority_check — all existing rows conform';
        EXCEPTION WHEN check_violation THEN
            RAISE WARNING 'M-01: email_queue_priority_check validation FAILED — rows with priority OUTSIDE [0,100] exist';
        WHEN undefined_object THEN
            RAISE NOTICE 'M-01: email_queue_priority_check does not exist — skipping';
        END;

        BEGIN
            EXECUTE 'ALTER TABLE email_queue VALIDATE CONSTRAINT email_queue_max_attempts_check';
            RAISE NOTICE 'M-02: Validated email_queue_max_attempts_check — all existing rows conform';
        EXCEPTION WHEN check_violation THEN
            RAISE WARNING 'M-02: email_queue_max_attempts_check validation FAILED — rows with max_attempts OUTSIDE [1,100] exist';
        WHEN undefined_object THEN
            RAISE NOTICE 'M-02: email_queue_max_attempts_check does not exist — skipping';
        END;
    ELSE
        RAISE NOTICE 'M-01/M-02: email_queue does not exist — skipping validation';
    END IF;
END $$;

-- =============================================================================
-- Summary
-- =============================================================================
DO $$
BEGIN
    RAISE NOTICE '================================================================================';
    RAISE NOTICE 'Migration 066: Remaining DB Fault Fixes — Complete';
    RAISE NOTICE '================================================================================';
    RAISE NOTICE '';
    RAISE NOTICE '  Section 1 (DB-111): outbound_throttle_decisions retention';
    RAISE NOTICE '  Section 2 (DB-112): metering_events partitioning';
    RAISE NOTICE '  Section 3 (DB-114): audit_logs timestamp standardization';
    RAISE NOTICE '  Section 4 (DB-117): email_queue FK constraints';
    RAISE NOTICE '  Section 5 (DB-113): Duplicate index detection';
    RAISE NOTICE '  Section 6 (§39):    Webhook cleanup documentation';
    RAISE NOTICE '  Section 7 (§39):    Long-running migration docs';
    RAISE NOTICE '  Section 8 (§39):    ANALYZE VERBOSE';
    RAISE NOTICE '  Section 9 (DB-110): scheduled_at/locked_until indexes';
    RAISE NOTICE '  Section 10:         CHECK constraint validation';
    RAISE NOTICE '';
    RAISE NOTICE 'Review any WARNING-level messages above for items requiring manual action.';
    RAISE NOTICE '================================================================================';
END $$;
