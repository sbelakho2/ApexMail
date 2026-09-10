-- Migration 062: Add email queue new schema
--
-- Adds columns to email_queue that the EmailProcessor worker and the
-- API send-message flow (routes/messages.rs) expect but were never
-- created by earlier migrations.
--
-- New columns bridge the gap between the original email_queue schema
-- (from_address, to_addresses[], html_body, text_body, attempts) and
-- the column names used by the worker processor:
--   "from"         ↔ from_address
--   "to"           ↔ to_addresses[]  (single recipient, not array)
--   html           ↔ html_body
--   text           ↔ text_body
--   attempt        ↔ attempts
--   message_id     (NEW — FK-style link to the messages log table)
--   domain_id      (NEW — FK-style link to the domains table)
--   scheduled_at   (NEW — delayed delivery)
--   locked_until   (NEW — visibility-timeout lock for multi-worker
--                   concurrency)
--
-- All statements are idempotent (IF NOT EXISTS / IF NOT) so the
-- migration is safe to re-run.
--
-- Rollback:
--   ALTER TABLE email_queue
--     DROP COLUMN IF EXISTS message_id,
--     DROP COLUMN IF EXISTS domain_id,
--     DROP COLUMN IF EXISTS "from",
--     DROP COLUMN IF EXISTS "to",
--     DROP COLUMN IF EXISTS html,
--     DROP COLUMN IF EXISTS text,
--     DROP COLUMN IF EXISTS scheduled_at,
--     DROP COLUMN IF EXISTS attempt,
--     DROP COLUMN IF EXISTS locked_until;
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. message_id — links email_queue rows to the messages audit/log table
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('public.email_queue') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'email_queue' AND column_name = 'message_id'
        ) THEN
            EXECUTE 'ALTER TABLE email_queue ADD COLUMN message_id UUID';
            RAISE NOTICE 'Added email_queue.message_id column';
        ELSE
            RAISE NOTICE 'email_queue.message_id already exists';
        END IF;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 2. domain_id — domain routing / DKIM lookup key
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('public.email_queue') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'email_queue' AND column_name = 'domain_id'
        ) THEN
            EXECUTE 'ALTER TABLE email_queue ADD COLUMN domain_id UUID';
            RAISE NOTICE 'Added email_queue.domain_id column';
        ELSE
            RAISE NOTICE 'email_queue.domain_id already exists';
        END IF;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 3. "from" — sender email (quoted because FROM is a reserved word)
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('public.email_queue') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'email_queue' AND column_name = 'from'
        ) THEN
            EXECUTE 'ALTER TABLE email_queue ADD COLUMN "from" TEXT';
            RAISE NOTICE 'Added email_queue."from" column';
        ELSE
            RAISE NOTICE 'email_queue."from" already exists';
        END IF;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 4. "to" — recipient email (quoted because TO is a reserved word)
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('public.email_queue') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'email_queue' AND column_name = 'to'
        ) THEN
            EXECUTE 'ALTER TABLE email_queue ADD COLUMN "to" TEXT';
            RAISE NOTICE 'Added email_queue."to" column';
        ELSE
            RAISE NOTICE 'email_queue."to" already exists';
        END IF;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 5. html — HTML body (parallel to existing html_body)
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('public.email_queue') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'email_queue' AND column_name = 'html'
        ) THEN
            EXECUTE 'ALTER TABLE email_queue ADD COLUMN html TEXT';
            RAISE NOTICE 'Added email_queue.html column';
        ELSE
            RAISE NOTICE 'email_queue.html already exists';
        END IF;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 6. text — plain-text body (parallel to existing text_body)
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('public.email_queue') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'email_queue' AND column_name = 'text'
        ) THEN
            EXECUTE 'ALTER TABLE email_queue ADD COLUMN "text" TEXT';
            RAISE NOTICE 'Added email_queue."text" column';
        ELSE
            RAISE NOTICE 'email_queue."text" already exists';
        END IF;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 7. scheduled_at — deferred/delayed delivery timestamp
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('public.email_queue') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'email_queue' AND column_name = 'scheduled_at'
        ) THEN
            EXECUTE 'ALTER TABLE email_queue ADD COLUMN scheduled_at TIMESTAMPTZ';
            RAISE NOTICE 'Added email_queue.scheduled_at column';
        ELSE
            RAISE NOTICE 'email_queue.scheduled_at already exists';
        END IF;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 8. attempt — current attempt counter (worker uses singular; old schema
--              had `attempts` as the max-attempts config)
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('public.email_queue') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'email_queue' AND column_name = 'attempt'
        ) THEN
            EXECUTE 'ALTER TABLE email_queue ADD COLUMN attempt INT NOT NULL DEFAULT 0';
            RAISE NOTICE 'Added email_queue.attempt column';
        ELSE
            RAISE NOTICE 'email_queue.attempt already exists';
        END IF;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 9. locked_until — visibility timeout for multi-worker concurrency
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('public.email_queue') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'email_queue' AND column_name = 'locked_until'
        ) THEN
            EXECUTE 'ALTER TABLE email_queue ADD COLUMN locked_until TIMESTAMPTZ';
            RAISE NOTICE 'Added email_queue.locked_until column';
        ELSE
            RAISE NOTICE 'email_queue.locked_until already exists';
        END IF;
    END IF;
END $$;
