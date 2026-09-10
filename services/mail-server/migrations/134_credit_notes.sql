-- Migration 134: canonical credit_notes persistence (audit F60).
--
-- credit_notes.rs has always read/written a `credit_notes` table that no
-- migration ever created — every credit-note operation failed with 42P01.
-- Canonical shape per the audit:
--   * invoice/tenant ownership (tenant must own the invoice it credits);
--   * positive amounts only;
--   * currency recorded (credits must reconcile in the invoice currency);
--   * idempotency scoped to the TENANT: UNIQUE (tenant_id, idempotency_key)
--     so one tenant's key can never replay another tenant's credit;
--   * audited at the application layer in the same transaction.

CREATE TABLE IF NOT EXISTS credit_notes (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    invoice_id       UUID NOT NULL,
    tenant_id        VARCHAR(26) NOT NULL,
    amount           BIGINT NOT NULL CHECK (amount > 0),
    currency         VARCHAR(3) NOT NULL DEFAULT 'EUR',
    reason           TEXT NOT NULL DEFAULT '',
    idempotency_key  VARCHAR(128) NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_credit_notes_invoice
    ON credit_notes (invoice_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_credit_notes_tenant
    ON credit_notes (tenant_id, created_at DESC);
