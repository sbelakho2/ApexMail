-- Migration 179: canonical logical usage-operation ledger (audit F71).
--
-- Generic metering deduplicated with a check-then-insert race: the
-- existence pre-check keys on metering_events.id, but that table is
-- RANGE-partitioned with PRIMARY KEY (id, timestamp) — the same logical
-- operation arriving twice at different timestamps counts twice. Redis
-- dedup keys only fence what Redis still remembers and coordinate none of
-- the DB retry stages.
--
-- This table claims each logical usage operation EXACTLY ONCE, durably,
-- before any quota/billing effect:
--
--   * operation_key is globally unique (tenant + kind + logical event id);
--   * payload_hash binds tenant/kind/quantity/metadata content — reuse of
--     the same logical id with DIFFERENT content is rejected upstream,
--     never silently re-counted;
--   * original_timestamp is IMMUTABLE (first claim wins) and is the
--     timestamp every durable re-recording of the operation must use, so a
--     partitioned-table replay cannot mint a second row.

CREATE TABLE IF NOT EXISTS usage_operations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_key       VARCHAR(160) NOT NULL UNIQUE,
    tenant_id           VARCHAR(26) NOT NULL,
    event_kind          VARCHAR(32) NOT NULL,
    event_id            UUID NOT NULL,
    payload_hash        VARCHAR(64) NOT NULL,
    original_timestamp  TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_usage_operations_tenant
    ON usage_operations (tenant_id, event_kind, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_operations_event
    ON usage_operations (event_id);
