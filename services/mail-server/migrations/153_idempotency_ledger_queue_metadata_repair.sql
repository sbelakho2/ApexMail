-- Migration 153: durable idempotency ledger, email_queue metadata repair,
-- and webhook_queue claim fencing.
--
-- Audit findings covered:
--   * F19/F20/F21 — Idempotency was Redis-only (best-effort): a lost HTTP
--     response or a Redis failure made batch replays double-send, and the
--     in-flight claim had no owner identity (no fencing). This adds the
--     durable Postgres ledger `idempotency_records` that is committed in the
--     SAME transaction as the messages/email_queue writes it describes. Redis
--     remains a read-through accelerator; the ledger is authoritative.
--   * F44 — Historical caller metadata was stored verbatim into
--     email_queue.metadata. Scalar/array JSONB values there break every
--     `jsonb_set(COALESCE(metadata, '{}'::jsonb), ...)` worker write with
--     SQLSTATE 22023 ("cannot delete from scalar/array"), wedging whole claim
--     batches. The worker now object-guards every write; this repair
--     quarantines the historical poison rows so healthy batches un-wedge.
--   * F10 — webhook_queue completion writes (retry reschedule, DELETE) can
--     outlive their visibility lease and hit a row a new worker re-claimed.
--     The claim now mints an owner token into `claim_token`; every completion
--     write is fenced on it.

-- ── 1. Durable idempotency ledger (F19/F20/F21) ──────────────────────────

CREATE TABLE IF NOT EXISTS idempotency_records (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           VARCHAR(26) NOT NULL,
    idempotency_key     VARCHAR(255) NOT NULL,
    -- request method + route path the key was first used on
    request_method      VARCHAR(16) NOT NULL,
    request_route       VARCHAR(512) NOT NULL,
    -- canonical SHA-256 of the request body (hex); '' when the body exceeded
    -- the hashing budget and no payload binding is enforced
    payload_hash        VARCHAR(64) NOT NULL,
    -- authenticated principal that created the record
    principal_id        VARCHAR(255) NOT NULL,
    -- random owner token of the creator; completion updates are fenced on it
    owner_token         VARCHAR(64) NOT NULL,
    -- 'in_flight' while the creator executes, 'complete' once the stored
    -- response is durable
    status              VARCHAR(20) NOT NULL DEFAULT 'in_flight',
    response_status     INTEGER,
    -- the serialized handler response (per-item results for batch sends)
    response_body       TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at        TIMESTAMPTZ,
    CONSTRAINT uq_idempotency_records_tenant_key UNIQUE (tenant_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_idempotency_records_tenant
    ON idempotency_records(tenant_id, created_at);

-- ── 2. Repair/quarantine poisoned email_queue metadata (F44) ─────────────
--
-- Scalar and array metadata values can never be merged with operational
-- queue state (pending_recipients / lease_token / ...). The worker now
-- treats non-object metadata as absent; drop the poison so historical rows
-- stop failing every jsonb_set in a claim batch (SQLSTATE 22023).

UPDATE email_queue
SET metadata = NULL,
    updated_at = NOW()
WHERE metadata IS NOT NULL
  AND jsonb_typeof(metadata) <> 'object';

-- ── 3. Webhook claim fencing (F10) ───────────────────────────────────────

ALTER TABLE webhook_queue
    ADD COLUMN IF NOT EXISTS claim_token VARCHAR(64);
