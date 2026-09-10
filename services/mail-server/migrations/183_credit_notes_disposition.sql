-- 183: credit-note disposition split (audit F60).
--
-- Crediting an unpaid invoice both reduced the debt (the outstanding
-- calculation subtracted the credit) AND minted spendable wallet value —
-- double benefit. Credits are now split at creation into:
--
--   * debt_reduction_cents — the part that reduces the UNPAID obligation
--     (what the outstanding derivation subtracts);
--   * refunded_cents — the part refunding value that was ACTUALLY PAID
--     (the only part that may mint wallet balance / issue a refund).
--
-- debt_reduction + refunded = amount. A unique operation id links each
-- credit note to its wallet/allocation effects idempotently. Legacy rows
-- (created before the split) are conservatively treated as pure debt
-- reductions: they already reduced outstanding, so the outstanding
-- derivation is unchanged for them.

ALTER TABLE credit_notes
    ADD COLUMN IF NOT EXISTS operation_id VARCHAR(160);
ALTER TABLE credit_notes
    ADD COLUMN IF NOT EXISTS debt_reduction_cents BIGINT;
ALTER TABLE credit_notes
    ADD COLUMN IF NOT EXISTS refunded_cents BIGINT;

-- Legacy backfill: whole amount was subtracted from outstanding by the
-- old derivation, so debt_reduction = amount keeps the balance identical.
UPDATE credit_notes
SET debt_reduction_cents = amount,
    refunded_cents = 0
WHERE debt_reduction_cents IS NULL;

ALTER TABLE credit_notes
    ALTER COLUMN debt_reduction_cents SET NOT NULL,
    ALTER COLUMN refunded_cents SET NOT NULL;

-- Operation identity: one durable operation per credit note. Populated by
-- the writer; backfilled deterministically from the existing idempotency
-- key so the unique index can exist.
UPDATE credit_notes
SET operation_id = 'credit_note:' || tenant_id || ':' || idempotency_key
WHERE operation_id IS NULL;

ALTER TABLE credit_notes
    ALTER COLUMN operation_id SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_credit_notes_operation_id
    ON credit_notes (operation_id);
