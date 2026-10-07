-- 095_mta_bounce_fbl_hardening.sql
--
-- =============================================================================
-- MTA bounce / FBL hardening support
-- =============================================================================
-- 1. bounce_events dedupe (C3): one bounce row per (original_message_id,
--    original_recipient) so ISP retries and attacker replays cannot run
--    side effects (suppression/webhook) more than once. The code inserts
--    with ON CONFLICT ... DO NOTHING against this index.
-- 2. complaint_events: the canonical definition is 093_deep_schema_convergence
--    (id UUID PK, feedback_type TEXT nullable, arrival_date TIMESTAMPTZ —
--    the shape crates/mta/src/servers/feedback_loop.rs binds). This file adds
--    the partial unique index for complaint idempotency (M55) and restores
--    the feedback_type default on databases where 093's definition applies.
--    An earlier revision carried its own CREATE TABLE (TEXT id, TEXT
--    arrival_date) that could NEVER take effect on a chain database — 093
--    always runs first and its shape wins — so it was a trap for anyone
--    reconciling drift (gates review 2026-10-07).
-- 3. sender_reputation: canonical definition (ad-hoc drift outside the chain)
--    matching the FBL upsert and the worker's sent-counter write (M56).
--
-- Idempotent: safe to re-run on any deployment.
-- =============================================================================


-- Clean up any pre-existing duplicate bounce rows so the unique index can be
-- created on live deployments (keep the newest row per natural key). The
-- table may be absent on deployments that only ever ran the tools lineage —
-- guard on to_regclass.
DO $$
BEGIN
    IF to_regclass('public.bounce_events') IS NOT NULL THEN
        DELETE FROM bounce_events a
        USING bounce_events b
        WHERE a.created_at < b.created_at
          AND a.original_message_id IS NOT NULL
          AND a.original_recipient IS NOT NULL
          AND a.original_message_id = b.original_message_id
          AND a.original_recipient = b.original_recipient;

        CREATE UNIQUE INDEX IF NOT EXISTS uq_bounce_events_natural_key
            ON bounce_events (original_message_id, original_recipient)
            WHERE original_message_id IS NOT NULL AND original_recipient IS NOT NULL;
    END IF;
END $$;

-- Complaint events: shape owned by 093 (see the header note). The drift
-- this file repairs is the feedback_type default the FBL upsert documents;
-- both statements sit behind the same existence probe the old CREATE TABLE
-- IF NOT EXISTS provided, so the file stays safe on any deployment.
DO $$
BEGIN
    IF to_regclass('public.complaint_events') IS NOT NULL THEN
        ALTER TABLE complaint_events ALTER COLUMN feedback_type SET DEFAULT 'abuse';
        CREATE UNIQUE INDEX IF NOT EXISTS uq_complaint_events_natural_key
            ON complaint_events (source_ip, original_message_id, original_recipient)
            WHERE original_message_id IS NOT NULL AND original_recipient IS NOT NULL;
    END IF;
END $$;

-- Sender reputation: canonical schema matching the FBL upsert
-- (feedback_loop.rs) and the worker sent counter (worker-processors).
CREATE TABLE IF NOT EXISTS sender_reputation (
    domain TEXT NOT NULL,
    date DATE NOT NULL,
    sent BIGINT NOT NULL DEFAULT 0,
    complaints BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (domain, date)
);

-- Drift repair: production had an ad-hoc sender_reputation (uuid PK,
-- no sent column) created before this migration. Align it with the code
-- contract without touching existing rows.
ALTER TABLE sender_reputation ADD COLUMN IF NOT EXISTS sent BIGINT NOT NULL DEFAULT 0;
ALTER TABLE sender_reputation ADD COLUMN IF NOT EXISTS complaints BIGINT NOT NULL DEFAULT 0;

