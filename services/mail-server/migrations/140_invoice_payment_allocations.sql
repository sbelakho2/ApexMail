-- 140: durable invoice payment allocations (audit F35).
--
-- Wallet deductions settled usage invoices by writing a wallet_transactions
-- row only — nothing tied the payment to the invoice, so outstanding
-- amounts could not be derived (paid? partially paid? refunded?), and UI,
-- dunning and refunds each improvised their own answer. Allocations are
-- immutable, carry a unique operation id (idempotent retries), and the
-- outstanding balance is derived:
--
--     outstanding = total − confirmed allocations − valid credit notes
--
-- (credit_notes are the credit side; migration 134.)

CREATE TABLE IF NOT EXISTS invoice_payment_allocations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           VARCHAR(26) NOT NULL,
    invoice_id          UUID NOT NULL,
    operation_id        VARCHAR(160) NOT NULL UNIQUE,
    source              VARCHAR(16) NOT NULL
        CHECK (source IN ('wallet', 'stripe', 'manual', 'credit_note')),
    amount_cents        BIGINT NOT NULL CHECK (amount_cents > 0),
    currency            VARCHAR(3) NOT NULL DEFAULT 'EUR',
    wallet_transaction_id UUID,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_invoice_payment_allocations_invoice
    ON invoice_payment_allocations (invoice_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_invoice_payment_allocations_tenant
    ON invoice_payment_allocations (tenant_id, created_at DESC);
