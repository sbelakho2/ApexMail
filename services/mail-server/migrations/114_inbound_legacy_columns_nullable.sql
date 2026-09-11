-- 114_inbound_legacy_columns_nullable.sql
--
-- =============================================================================
-- inbound_messages: the MTA inbound writer and the legacy columns
-- =============================================================================
-- Migration 088 converged inbound_messages to a superset: the MTA writes
-- mail_from/rcpt_to/client_ip/helo_hostname/raw_message/..., but the
-- pre-088 columns from_email/to_email kept their NOT NULL constraints and
-- no defaults. Every MTA inbound insert (the unified column family) then
-- failed with "null value in column from_email violates not-null
-- constraint" — live inbound mail 451'd at end-of-DATA.
--
-- The legacy pair is a denormalized mirror of mail_from/rcpt_to kept for
-- older readers; writers that do not populate it must be allowed to omit
-- it. Make both nullable (they carry no data the canonical columns lack).
--
-- Idempotent: safe to re-run on any deployment.
--
-- Guarded: no canonical migration before this one created inbound_messages
-- until 088 was folded to create it (CREATE TABLE IF NOT EXISTS superset).
-- Databases where inbound_messages still does not exist (runtime-provisioned
-- or older lineages) must not abort the chain here — the unguarded ALTER
-- failed the whole fresh chain with "relation inbound_messages does not
-- exist". The guard also tolerates shapes that lack the legacy mirror
-- columns entirely (088's fresh-create declares them nullable already).
-- =============================================================================

DO $$
BEGIN
    IF to_regclass('public.inbound_messages') IS NULL THEN
        RAISE NOTICE '114: inbound_messages does not exist — nothing to relax';
    ELSE
        IF EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'inbound_messages'
                     AND column_name = 'from_email' AND is_nullable = 'NO') THEN
            ALTER TABLE inbound_messages ALTER COLUMN from_email DROP NOT NULL;
        END IF;
        IF EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'inbound_messages'
                     AND column_name = 'to_email' AND is_nullable = 'NO') THEN
            ALTER TABLE inbound_messages ALTER COLUMN to_email DROP NOT NULL;
        END IF;
    END IF;
END $$;
