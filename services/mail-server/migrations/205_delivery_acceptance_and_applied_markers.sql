-- Migration 205: Durable delivery acceptance and applied-event markers
--
-- =============================================================================
-- Two related durably-exactly-once gaps.
--
-- 1. SMTP exactly-once rested on a Redis SETNX marker with a TTL. That is a
--    cache, not a ledger: once the marker expires, an externally accepted
--    message whose DB completion never committed can be submitted again. The
--    failure model includes application crashes and Redis eviction, so the
--    acceptance record has to be durable and keyed by the stable logical send
--    unit rather than by a counter with a lifetime.
--
--    The protocol is reserve → submit → record:
--      * INSERT a `reserved` row for the send unit. A unique violation means
--        this logical send already has an acceptance record, so the caller
--        must NOT submit again.
--      * submit to the transport.
--      * UPDATE the row to `accepted` with the transport's message id, or to
--        `failed` on a refusal (which frees the unit for a retry).
--    A crash between reserve and submit leaves a `reserved` row: it is
--    reclaimed by a documented lease timeout rather than being trusted, which
--    is why `reserved_at` exists.
--
-- 2. The sender-health projector used the sender-wide `sales_sender_health.
--    updated_at` as evidence that one specific event had been applied. A
--    different event touching the same sender could make recovery conclude a
--    crashed claim was already applied, permanently undercounting that
--    bounce or complaint. The applied marker must be per event.
--
-- Both tables are additive; existing rows are unaffected.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. Delivery acceptance ledger
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sales_delivery_acceptances (
    -- The stable logical send unit: the same value the queue uses as its
    -- idempotency key (`sa-send:{step_execution_id}`), so a retry of the same
    -- unit can never produce a second external submission.
    send_unit            TEXT PRIMARY KEY,
    tenant_id            TEXT NOT NULL,
    queue_id             UUID,
    state                TEXT NOT NULL DEFAULT 'reserved'
        CHECK (state IN ('reserved', 'accepted', 'failed')),
    transport            TEXT,
    transport_message_id TEXT,
    -- For a dedicated route: what was requested and what the relay reported.
    -- Recording both is what makes "the send went out from the IP we reserved"
    -- auditable after the fact rather than only asserted at send time.
    requested_source_ip  INET,
    actual_source_ip     INET,
    reserved_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    accepted_at          TIMESTAMPTZ,
    last_error           TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- A reserved row that never reached a terminal state is a crashed submission.
-- The sweep that reclaims them reads this index; the lease window itself is a
-- named constant in the worker so the intent is greppable.
CREATE INDEX IF NOT EXISTS idx_sales_delivery_acceptances_stale_reservations
    ON sales_delivery_acceptances (reserved_at)
    WHERE state = 'reserved';

CREATE INDEX IF NOT EXISTS idx_sales_delivery_acceptances_tenant
    ON sales_delivery_acceptances (tenant_id, accepted_at DESC);

COMMENT ON TABLE sales_delivery_acceptances IS
    'Durable per-send-unit submission ledger. Replaces the Redis TTL marker as the exactly-once authority: a unique violation on INSERT means the logical send already has an acceptance record and must not be submitted again.';

-- ---------------------------------------------------------------------------
-- 2. Event-level applied marker for sender health
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sales_sender_health_applied (
    event_id   UUID PRIMARY KEY REFERENCES sales_sender_events(id) ON DELETE CASCADE,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sales_sender_health_applied_at
    ON sales_sender_health_applied (applied_at);

COMMENT ON TABLE sales_sender_health_applied IS
    'Per-event applied marker. Written in the SAME transaction as the aggregate update, so recovery can ask "was THIS event applied?" instead of inferring it from the sender-wide updated_at (which another event could have bumped).';
