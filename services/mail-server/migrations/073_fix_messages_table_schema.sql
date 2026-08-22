-- Migration 073: Fix messages table schema to match runtime application code
-- 
-- The messages table was created by migrations 052/056 with column names
-- (from_address, to_addresses, body, transport, source_ip) that do not
-- match what the application code expects (from_email, to_emails, html_body,
-- text_body, tags, metadata, cc_emails, bcc_emails, scheduled_at, sent_at).
--
-- The authoritative schema is defined in crates/apexmail-db/src/migrations.rs
-- (CREATE_MESSAGES constant), which is the schema the application code
-- actually queries. This migration aligns the SQL-migration-created table
-- with that runtime schema.
--
-- All statements use IF NOT EXISTS / IF EXISTS guards so this migration
-- is safe to run multiple times.

-- Step 1: Add missing columns from the runtime schema
ALTER TABLE messages ADD COLUMN IF NOT EXISTS from_email TEXT;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS to_emails JSONB;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS cc_emails JSONB;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS bcc_emails JSONB;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS html_body TEXT;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS text_body TEXT;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS tags JSONB;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS metadata JSONB;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS scheduled_at TIMESTAMPTZ;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS sent_at TIMESTAMPTZ;

-- Step 2: Migrate data from old column names to new column names.
-- The legacy columns exist only when the table was created by the SQL chain
-- (052/056); the runtime-provisioned shape (apexmail-db CREATE_MESSAGES)
-- never had them, so every copy is guarded by a column-existence check and
-- no-ops on databases that were already runtime-shaped.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'messages' AND column_name = 'from_address') THEN
        UPDATE messages
        SET from_email = COALESCE(from_email, from_address)
        WHERE from_email IS NULL AND from_address IS NOT NULL;

        UPDATE messages
        SET to_emails = COALESCE(to_emails, to_jsonb(to_addresses))
        WHERE to_emails IS NULL AND from_address IS NOT NULL;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'messages' AND column_name = 'body') THEN
        UPDATE messages
        SET text_body = COALESCE(text_body, body)
        WHERE text_body IS NULL AND body IS NOT NULL;
    END IF;
END $$;

-- Step 3: Set defaults for required columns where data may be missing
UPDATE messages SET from_email = '' WHERE from_email IS NULL;
UPDATE messages SET to_emails = '[]'::jsonb WHERE to_emails IS NULL;

-- Step 4: Add NOT NULL constraints after data migration
ALTER TABLE messages ALTER COLUMN from_email SET NOT NULL;
ALTER TABLE messages ALTER COLUMN to_emails SET NOT NULL;

-- Step 5: Add index for the runtime schema's expected query patterns
CREATE INDEX IF NOT EXISTS idx_messages_status ON messages(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at DESC);

-- Step 6: Fix dead_letter_queue table (same migration created it, same column naming issue)
-- The runtime schema uses from_address/to_addresses which matches here, so no fix needed.
-- But ensure html_body and text_body exist (they might from migration 052).
ALTER TABLE dead_letter_queue ADD COLUMN IF NOT EXISTS html_body TEXT;
ALTER TABLE dead_letter_queue ADD COLUMN IF NOT EXISTS text_body TEXT;

DO $$
BEGIN
    RAISE NOTICE 'Migration 073: messages table schema aligned with runtime application code';
END $$;
