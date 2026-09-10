-- Migration 169: complete 073's messages-table convergence (audit F01).
--
-- 073 declared the runtime application shape authoritative for `messages`
-- (from_email/to_emails NOT NULL; see crates/apexmail-db CREATE_MESSAGES,
-- which has no from_address column at all) and aligned every column EXCEPT
-- one relic: the legacy NOT NULL on `from_address`, inherited from the
-- 001-created table, was never relaxed or dropped.
--
-- Consequence: every production writer of `messages` — api-server's
-- insert_message_and_queue, system_sender's transactional verification-mail
-- queue write, test_mode, ai_insights, and sales-autopilot's dispatcher —
-- inserts the runtime-shape columns only, so against a fully migrated
-- database every INSERT failed with:
--   null value in column "from_address" of relation "messages"
--        violates not-null constraint
-- The divergence was invisible to CI because DB-backed tests bootstrapped
-- the archived tools/migrations tree (whose messages table predates the
-- split) instead of this canonical chain — exactly the blindness audit F01
-- removes: tests now migrate through the real production migrator, which
-- surfaced this immediately.
--
-- from_address is legacy-only: it still carries any pre-073 data (this
-- migration never NULLs it) and is read by no application code. Drop the
-- constraint, keep the data. The 001 CHECK on the column treats NULL as
-- satisfied, so no further change is needed. DROP NOT NULL on the
-- partitioned parent propagates to every partition.
-- Existence-guarded: production's live chain partitioned/recreated `messages`
-- via the runtime shape (050/073) and no longer carries from_address at all —
-- the canonical scratch chain (001 legacy base) does. Both lineages are valid
-- post-073; the constraint relaxation only applies where the column exists.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public'
                 AND table_name = 'messages'
                 AND column_name = 'from_address') THEN
        EXECUTE 'ALTER TABLE messages ALTER COLUMN from_address DROP NOT NULL';
    END IF;
END $$;

-- Same convergence class, second instance surfaced by the F01 test
-- centralization: `support_tickets` (075) was created without the id DEFAULT
-- its writer was built against — admin/support.rs's insert_support_ticket
-- INSERTs without an id and reads it back via `RETURNING id::text`, which
-- only works when the column is database-generated. The pre-canonical
-- control-plane lineage (tools/migrations 011) carried exactly this default;
-- restore it on the canonical table so the writer works on migrated
-- databases:
ALTER TABLE support_tickets
    ALTER COLUMN id
    SET DEFAULT SUBSTRING(REPLACE(gen_random_uuid()::text, '-', '') FROM 1 FOR 26);

-- Third instance of the same class: `plans.id` VARCHAR(26) carries a raw
-- gen_random_uuid() default whose 36-char text form can never fit the
-- column — every id-less INSERT into plans failed with 22001. (The other
-- uuid-defaulted varchar, dedicated_ips.id VARCHAR(64), fits and is left
-- untouched.) Use the same trimmed 26-char default:
ALTER TABLE plans
    ALTER COLUMN id
    SET DEFAULT SUBSTRING(REPLACE(gen_random_uuid()::text, '-', '') FROM 1 FOR 26);
