-- 090_widen_events_id_columns.sql
--
-- =============================================================================
-- SPLIT-BRAIN RESOLUTION (cont.): events id column widths
-- =============================================================================
-- The worker EmailProcessor records sent/bounced events via
-- crates/worker-processors/src/email/processor.rs:
--
--   INSERT INTO events (id, tenant_id, message_id, domain_id, campaign_id,
--                       event_type, recipient, timestamp)
--
-- message_id and domain_id now carry canonical UUIDs (36 chars) sourced from
-- email_queue.message_id / email_queue.domain_id. events.message_id is
-- VARCHAR(64) (fits), but events.domain_id is VARCHAR(26) — every event with a
-- resolved domain failed with "value too long for type character varying(26)"
-- (silently, at debug level, after the queue row was already marked sent).
--
-- Widen the id columns to TEXT. Widening is safe for all existing consumers
-- (tracking-service, api-server dashboards) and idempotent.
-- =============================================================================

BEGIN;

ALTER TABLE events
    ALTER COLUMN domain_id TYPE TEXT;

ALTER TABLE events
    ALTER COLUMN campaign_id TYPE TEXT;

COMMIT;
