-- Migration 138: invoice collection outbox (audit F33).
--
-- Collection of a usage invoice (wallet application, Stripe invoice item,
-- dunning transition) previously ran as best-effort inline code with
-- ignored commit errors: a crash after invoice creation left a `draft`
-- invoice that the idempotency marker would never revisit — stranded
-- forever, never collected. The sweep now writes a collection operation
-- in the SAME transaction as the invoice; a resumable worker (and the
-- sweep itself) drives it through the ladder, one committed step at a
-- time. UNIQUE (invoice_id, operation) makes retries idempotent.

CREATE TABLE IF NOT EXISTS invoice_collection_outbox (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        VARCHAR(26) NOT NULL,
    invoice_id       UUID NOT NULL,
    operation        VARCHAR(32) NOT NULL
        CHECK (operation IN ('collect_usage_invoice')),
    status           VARCHAR(16) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'in_progress', 'done', 'failed')),
    attempts         INTEGER NOT NULL DEFAULT 0,
    last_error       TEXT,
    payload          JSONB NOT NULL DEFAULT '{}',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (invoice_id, operation)
);

CREATE INDEX IF NOT EXISTS idx_invoice_collection_outbox_pending
    ON invoice_collection_outbox (created_at)
    WHERE status IN ('pending', 'in_progress');
