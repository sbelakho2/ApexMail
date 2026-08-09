-- 095_mta_bounce_fbl_hardening.sql
--
-- =============================================================================
-- MTA bounce / FBL hardening support
-- =============================================================================
-- 1. bounce_events dedupe (C3): one bounce row per (original_message_id,
--    original_recipient) so ISP retries and attacker replays cannot run
--    side effects (suppression/webhook) more than once. The code inserts
--    with ON CONFLICT ... DO NOTHING against this index.
-- 2. complaint_events: canonical definition (the table was created ad-hoc on
--    production and does not exist in any migration) plus a partial unique
--    index for complaint idempotency (M55).
-- 3. sender_reputation: canonical definition (same ad-hoc drift) matching the
--    FBL upsert and the worker's sent-counter write (M56).
--
-- Idempotent: safe to re-run on any deployment.
-- =============================================================================

BEGIN;

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

-- Complaint events: canonical schema matching crates/mta/src/servers/feedback_loop.rs.
CREATE TABLE IF NOT EXISTS complaint_events (
    id TEXT PRIMARY KEY,
    original_message_id TEXT,
    original_recipient TEXT,
    feedback_type TEXT NOT NULL DEFAULT 'abuse',
    source_ip TEXT,
    reporting_mta TEXT,
    user_agent TEXT,
    arrival_date TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_complaint_events_natural_key
    ON complaint_events (source_ip, original_message_id, original_recipient)
    WHERE original_message_id IS NOT NULL AND original_recipient IS NOT NULL;

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

COMMIT;
