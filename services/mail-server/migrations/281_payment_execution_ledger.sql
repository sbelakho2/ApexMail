-- Migration 281: Payment provider neutrality, stage 2 - the execution
-- ledger and the provider dimension.
--
-- External audit, seventh pass, P0-A, steps 5-7 of the mandated order.
-- Migration 279 created the neutral tables and backfilled them; this
-- migration makes two of them LIVE:
--
--   1. payment_attempts becomes the EXECUTION ledger (audit step 7):
--      * provider_payment_id becomes NULLable - a CLAIMED attempt is
--        written BEFORE the provider call and confirmed after, and a lost
--        response (timeout after a successful provider charge) leaves the
--        claim open with NO payment id;
--      * idempotency_key + obligation_ref columns. The UNIQUE index on
--        (provider, idempotency_key) IS the audit's exactly-once gate:
--        the charge path claims by INSERT, a concurrent scheduler tick or
--        a retry while an attempt is unresolved hits the index and is
--        refused ("scheduler race -> one payment attempt").
--   2. Accounting neutralized (audit step 5, debt N-12): the statutory
--      ledger gains a PROVIDER DIMENSION and generic processor roles.
--      Historical values are NEVER rewritten (the migration-269 lesson):
--      the existing allowlists keep every current value and ACCEPT the
--      generic ones ('processor_clearing', 'processor_fees',
--      'processor_settlement', source 'processor'); existing rows are
--      stamped with the provider that owns them.
--
-- Additive and guarded throughout: a re-run, a partially migrated database
-- and a fresh database all converge. No table or column renames, no drops
-- of data; the one constraint relaxation (DROP NOT NULL on
-- payment_attempts.provider_payment_id) is a widening: every existing row
-- keeps its value.

-- ---------------------------------------------------------------------------
-- 1. payment_attempts: the execution ledger (audit step 7)
-- ---------------------------------------------------------------------------

-- A claimed attempt is written BEFORE the provider call, so the payment id
-- must be nullable (the widening is guarded on current nullability).
DO $$
BEGIN
    -- No idempotency_key precondition: on a FRESH chain the key column is
    -- added further below, and the widening must run NOW (279 creates the
    -- column NOT NULL; a guard keyed on the new column would never fire).
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'payment_attempts'
                 AND column_name = 'provider_payment_id'
                 AND is_nullable = 'NO') THEN
        ALTER TABLE payment_attempts ALTER COLUMN provider_payment_id DROP NOT NULL;
    END IF;
END $$;

ALTER TABLE payment_attempts ADD COLUMN IF NOT EXISTS idempotency_key TEXT;
ALTER TABLE payment_attempts ADD COLUMN IF NOT EXISTS obligation_ref TEXT;

-- The exactly-once claim gate: one attempt row per operation key per
-- provider. Partial (the 279 backfill rows carry no keys).
CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_attempts_idem
    ON payment_attempts (provider, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- Open-attempt probes by obligation and by provider state.
CREATE INDEX IF NOT EXISTS idx_payment_attempts_obligation
    ON payment_attempts (obligation_ref, state);
CREATE INDEX IF NOT EXISTS idx_payment_attempts_open
    ON payment_attempts (provider, updated_at)
    WHERE state IN ('pending', 'processing');

-- Obligation references for the 279 backfill rows: every attempt that
-- already binds an invoice payment names its obligation.
UPDATE payment_attempts
SET obligation_ref = 'invoice:' || i.id::text
FROM invoices i
WHERE i.mollie_payment_id IS NOT NULL
  AND i.mollie_payment_id <> ''
  AND payment_attempts.provider_payment_id = i.mollie_payment_id
  AND payment_attempts.obligation_ref IS NULL;

COMMENT ON COLUMN payment_attempts.idempotency_key IS
    'The charge operation id the caller claimed (UNIQUE per provider with a partial index): the audit exactly-once gate, INSERT-claim -> provider call -> confirm.';
COMMENT ON COLUMN payment_attempts.obligation_ref IS
    'The local obligation this attempt executes (invoice:{uuid}); open claims are matched to provider callbacks by this reference.';

-- ---------------------------------------------------------------------------
-- 2. Accounting neutralized: the provider dimension (audit step 5, N-12)
-- ---------------------------------------------------------------------------

ALTER TABLE chart_of_accounts          ADD COLUMN IF NOT EXISTS provider VARCHAR(32);
ALTER TABLE invoice_payment_allocations ADD COLUMN IF NOT EXISTS provider VARCHAR(32);
ALTER TABLE accounting_source_documents ADD COLUMN IF NOT EXISTS provider VARCHAR(32);
ALTER TABLE processor_clearing_accounts ADD COLUMN IF NOT EXISTS provider VARCHAR(32);

-- Stamp the provider that owns every existing processor-shaped row.
-- Historical VALUES stay exactly as they are; the dimension carries the
-- processor identity going forward.
UPDATE chart_of_accounts SET provider = 'mollie'
WHERE provider IS NULL AND account_role IN ('mollie_clearing', 'mollie_fees');
UPDATE chart_of_accounts SET provider = 'stripe'
WHERE provider IS NULL AND account_role IN ('stripe_clearing', 'stripe_fees');
UPDATE invoice_payment_allocations SET provider = source
WHERE provider IS NULL AND source IN ('mollie', 'stripe');
UPDATE accounting_source_documents SET provider = 'mollie'
WHERE provider IS NULL AND source_type = 'mollie_settlement';
UPDATE accounting_source_documents SET provider = 'stripe'
WHERE provider IS NULL AND source_type = 'stripe_settlement';
UPDATE processor_clearing_accounts SET provider = processor
WHERE provider IS NULL AND processor IN ('mollie', 'stripe');

CREATE INDEX IF NOT EXISTS idx_invoice_payment_allocations_provider
    ON invoice_payment_allocations (provider, created_at DESC)
    WHERE provider IS NOT NULL;

-- The allowlists: every historical value stays, the generic processor
-- roles become accepted. Drop-and-re-add guarded by constraint name (the
-- migration-269 pattern).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chart_of_accounts_account_role_check') THEN
        ALTER TABLE chart_of_accounts DROP CONSTRAINT chart_of_accounts_account_role_check;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chart_of_accounts_account_role_check') THEN
        ALTER TABLE chart_of_accounts ADD CONSTRAINT chart_of_accounts_account_role_check
            CHECK (account_role IS NULL OR account_role = ANY (ARRAY[
                'ar','ap','revenue','refunds','vat_output','vat_input','bank',
                'bank_clearing','stripe_clearing','stripe_fees','mollie_clearing',
                'mollie_fees','processor_clearing','processor_fees','wallet_liability',
                'expense_default','payroll_expense','net_wages_payable','income_tax_payable',
                'social_tax_payable','unemployment_payable','pension_payable','fx_gain',
                'fx_loss','depreciation_expense','accumulated_depreciation','retained_earnings',
                'suspense','other_income']));
    END IF;

    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'invoice_payment_allocations_source_check') THEN
        ALTER TABLE invoice_payment_allocations DROP CONSTRAINT invoice_payment_allocations_source_check;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'invoice_payment_allocations_source_check') THEN
        ALTER TABLE invoice_payment_allocations ADD CONSTRAINT invoice_payment_allocations_source_check
            CHECK (source = ANY (ARRAY['wallet','stripe','mollie','processor','manual','credit_note']));
    END IF;

    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'accounting_source_documents_source_type_check') THEN
        ALTER TABLE accounting_source_documents DROP CONSTRAINT accounting_source_documents_source_type_check;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'accounting_source_documents_source_type_check') THEN
        ALTER TABLE accounting_source_documents ADD CONSTRAINT accounting_source_documents_source_type_check
            CHECK (source_type = ANY (ARRAY[
                'invoice','credit_note','credit_note_refund','stripe_settlement',
                'mollie_settlement','processor_settlement','wallet_settlement',
                'manual_settlement','expense','bank_statement_line','payroll','tax',
                'manual','opening_balance','depreciation','fx_revaluation','reversal',
                'closing']));
    END IF;
END $$;

COMMENT ON COLUMN chart_of_accounts.provider IS
    'The payment processor this account clears/fees for; the role vocabulary is generic (processor_clearing/processor_fees) with the provider carried by this dimension (migration 281).';
COMMENT ON COLUMN invoice_payment_allocations.provider IS
    'The payment processor that moved this allocation''s money (dimension added by migration 281; historical rows are stamped from their source).';

-- ---------------------------------------------------------------------------
-- 3. Proof
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    unstamped INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'invoice_payment_allocations') THEN
        SELECT count(*) INTO unstamped
        FROM invoice_payment_allocations
        WHERE source IN ('mollie', 'stripe') AND provider IS NULL;
        IF unstamped > 0 THEN
            RAISE EXCEPTION 'migration 281: % processor allocation row(s) carry no provider dimension', unstamped;
        END IF;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'payment_attempts'
                 AND column_name = 'provider_payment_id' AND is_nullable = 'NO') THEN
        RAISE EXCEPTION 'migration 281: payment_attempts.provider_payment_id must be nullable for claim-before-charge';
    END IF;
END $$;
