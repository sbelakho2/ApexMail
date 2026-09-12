-- Migration 212: Recipient-facing outbound relay ledger (durable queue)
--
-- Numbering note: this repair originally targeted 210, but 210 and 211 were
-- concurrently claimed by the inbound-delivery-ledger / VERP-registry work in
-- this same tree; sqlx requires globally unique versions, so the outbound
-- relay ledger takes the next free number (212). The table and its contract
-- are unchanged.
--
-- =============================================================================
-- P0: there is no recipient-facing outbound MTA. The worker's
-- `SmtpTransport` injects the reserved internal header
--
--     X-ApexMail-Route: v1 dedicated <dedicated_ip_id> <source_ip>
--
-- and refuses to submit a dedicated route because no component owns the
-- receiving side of that contract (worker-processors/src/email/transport.rs,
-- TODO(mta-owner)). This migration adds the durable ledger the new
-- `crates/outbound-mta` relay owns for that contract: each accepted unit of
-- work is one row carrying the message bytes, the envelope, the requested
-- source IP, the retry schedule and the eventual acceptance record.
--
-- WHY A DEDICATED TABLE (not sales_delivery_acceptances)
--
-- `sales_delivery_acceptances` (migration 205) is the WORKER's ledger for its
-- own reserve -> submit -> record protocol: the worker claims a `send_unit`
-- BEFORE it contacts the relay. Reusing that table from the relay would make
-- the relay's INSERT collide with a `reserved` row written by the worker for
-- the very same send_unit — the relay would read someone else's in-flight
-- reservation and could never claim the unit it is asked to deliver. The two
-- schemas also differ: the relay must durably hold the message payload, the
-- recipient set, `attempt`/`next_attempt_at`/lease state and the resolved-MX /
-- TLS outcome, which the worker ledger deliberately does not carry. The
-- tables are joinable for audit via `send_unit` (and `queue_id`).
--
-- STATE MACHINE
--
--     pending  --(claim; inline submit or due retry)-->  delivering
--     delivering --(post-DATA 250)--> accepted            (terminal)
--     delivering --(transient/connection/4xx)--> pending  (attempt++, next_attempt_at)
--     delivering --(5xx RCPT / 5xx post-DATA / no-MX / ceiling)--> failed (terminal)
--     delivering --(lease expired, crashed process)--> pending (same attempt)
--
-- Acceptance is written ONLY on the post-DATA 250 path. `accepted_at` and the
-- serialized `acceptance_record` are the evidence a repeated `send_unit`
-- returns; a `pending`/`delivering` row can never be mistaken for acceptance.
--
-- Additive: one new table plus its indexes; no existing table or row changes.
-- =============================================================================

CREATE TABLE IF NOT EXISTS outbound_relay_ledger (
    -- Stable logical send unit forwarded by the submitting worker
    -- (`sa-send:{step_execution_id}` or `email_queue:{id}:{recipient}`).
    -- PRIMARY KEY is what makes submission idempotent: a concurrent or
    -- repeated submission inserts nothing.
    send_unit            TEXT PRIMARY KEY,
    tenant_id            TEXT,
    queue_id             UUID,
    state                TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'delivering', 'accepted', 'failed')),
    -- NULL = SMTP null reverse-path (MAIL FROM:<>). A null-return-path
    -- message must never produce a DSN (RFC 3464 §3), so the relay checks
    -- this column before enqueueing a bounce.
    envelope_from        TEXT,
    -- JSON array of envelope recipients (RCPT TO), in submission order.
    recipients           JSONB NOT NULL,
    -- The raw RFC 5322 message. Durable queueing means the relay must be
    -- able to retry a delivery after a restart without the worker re-sending.
    message              BYTEA NOT NULL,
    -- The dedicated source IP the submission requested; NULL = shared pool.
    requested_source_ip  INET,
    -- What the socket was actually bound to. Recorded for every accepted
    -- send, not only dedicated ones: the worker's contract counts warmup
    -- capacity only when actual == requested.
    actual_source_ip     INET,
    remote_mx            TEXT,
    tls_used             BOOLEAN NOT NULL DEFAULT FALSE,
    -- Delivery attempts started (1 = the inline submission attempt).
    attempt              INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    max_attempts         INTEGER NOT NULL DEFAULT 12 CHECK (max_attempts > 0),
    next_attempt_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- A live delivery holds a lease; a crashed process is reclaimed by
    -- clearing it after expiry, never by trusting the process's exit.
    lease_until          TIMESTAMPTZ,
    -- Serialized AcceptanceRecord (post-DATA 250 only). NULL until accepted.
    acceptance_record    JSONB,
    last_error           TEXT,
    accepted_at          TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Acceptance is evidence of a post-DATA 250: a row cannot claim
    -- `accepted` without the timestamp that came with that reply.
    CONSTRAINT outbound_relay_ledger_accepted_has_timestamp
        CHECK (state <> 'accepted' OR accepted_at IS NOT NULL)
);

-- The daemon's due-queue scan: only `pending` rows are candidates.
CREATE INDEX IF NOT EXISTS idx_outbound_relay_ledger_due
    ON outbound_relay_ledger (next_attempt_at)
    WHERE state = 'pending';

-- Crash recovery: expired `delivering` leases are returned to `pending`.
CREATE INDEX IF NOT EXISTS idx_outbound_relay_ledger_expired_lease
    ON outbound_relay_ledger (lease_until)
    WHERE state = 'delivering';

CREATE INDEX IF NOT EXISTS idx_outbound_relay_ledger_tenant
    ON outbound_relay_ledger (tenant_id, created_at DESC);

COMMENT ON TABLE outbound_relay_ledger IS
    'Durable outbound queue + idempotent acceptance ledger owned by crates/outbound-mta. One row per stable send_unit: message bytes, envelope, requested/actual source IP, retry schedule, and the post-DATA-250 AcceptanceRecord. A repeated submit of the same send_unit returns the stored acceptance and never delivers twice.';

COMMENT ON COLUMN outbound_relay_ledger.state IS
    'pending = queued/due for delivery; delivering = lease held by one attempt; accepted = remote post-DATA 250 recorded; failed = terminal permanent failure (see last_error).';
