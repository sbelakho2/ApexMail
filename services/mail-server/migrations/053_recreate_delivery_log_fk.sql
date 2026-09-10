-- Migration 053: Recreate delivery log fk
--
-- C-17: Recreate FK constraint dropped during partitioning in migration 050.
--
-- Migration 050 dropped email_delivery_log.email_id -> email_queue(id) FK
-- because the partitioned email_queue now has a composite PK (id, created_at).
-- This migration adds a created_at column to email_delivery_log and recreates
-- the FK referencing the composite key, restoring referential integrity.
--
-- For existing rows, we backfill created_at from the email_queue join.

-- =============================================================================
-- Step 1: Add created_at column to email_delivery_log
-- =============================================================================

ALTER TABLE email_delivery_log
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ;

-- Backfill created_at from email_queue for existing rows
UPDATE email_delivery_log dl
SET created_at = eq.created_at
FROM email_queue eq
WHERE dl.email_id = eq.id
  AND dl.created_at IS NULL;

-- Set a default for any rows that couldn't be matched
UPDATE email_delivery_log
SET created_at = attempted_at
WHERE created_at IS NULL;

-- Make created_at NOT NULL after backfill
ALTER TABLE email_delivery_log
    ALTER COLUMN created_at SET NOT NULL;

-- =============================================================================
-- Step 2: Recreate the FK constraint referencing the composite PK
-- =============================================================================

-- First verify that all email_id values exist in email_queue
DO $$
DECLARE
    v_orphan_count BIGINT;
BEGIN
    SELECT COUNT(*) INTO v_orphan_count
    FROM email_delivery_log dl
    WHERE NOT EXISTS (
        SELECT 1 FROM email_queue eq
        WHERE eq.id = dl.email_id
          AND eq.created_at = dl.created_at
    );

    IF v_orphan_count > 0 THEN
        RAISE WARNING 'C-17: % email_delivery_log rows have no matching email_queue entry — FK will not be created. Run data cleanup first.', v_orphan_count;
    ELSE
        -- Safe to add FK (skip if already present on re-run)
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'email_delivery_log_email_id_fkey') THEN
        ALTER TABLE email_delivery_log
            ADD CONSTRAINT email_delivery_log_email_id_fkey
            FOREIGN KEY (email_id, created_at)
            REFERENCES email_queue(id, created_at)
            ON DELETE CASCADE;
        RAISE NOTICE 'C-17: FK email_delivery_log(email_id, created_at) -> email_queue(id, created_at) recreated successfully.';
        END IF;
    END IF;
END $$;
