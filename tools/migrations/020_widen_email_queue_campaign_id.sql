-- 020_widen_email_queue_campaign_id.sql
--
-- =============================================================================
-- Campaign attribution width (companion to services/mail-server migration 090)
-- =============================================================================
-- The sales-autopilot dispatcher writes the sales campaign UUID into
-- email_queue.campaign_id (crates/sales-autopilot/src/dispatcher.rs) so the
-- delivery worker attributes every 'sent'/'bounced' event it records back to
-- the campaign. On this schema lineage the column was VARCHAR(26) (a nanoid
-- width), while a canonical UUID is 36 characters — every attributed enqueue
-- failed with "value too long for type character varying(26)", silently
-- keeping campaign attribution metadata-only.
--
-- The same width gap hits the events table on this lineage: the delivery
-- worker records events with id = 'evt_' || <uuid> (41 chars) and
-- message_id = <uuid> (36 chars), but events.id / events.message_id were
-- VARCHAR(26). Migration 090 already widened events.domain_id /
-- events.campaign_id on the services/mail-server lineage for exactly this
-- reason; this mirrors it for the remaining columns on THIS lineage.
--
-- Widening to TEXT is safe for all existing consumers and idempotent.
-- =============================================================================

BEGIN;

ALTER TABLE email_queue
    ALTER COLUMN campaign_id TYPE TEXT USING campaign_id::text;

ALTER TABLE events
    ALTER COLUMN id TYPE TEXT USING id::text;

ALTER TABLE events
    ALTER COLUMN message_id TYPE TEXT USING message_id::text;

COMMIT;
