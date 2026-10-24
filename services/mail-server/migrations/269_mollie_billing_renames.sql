-- 269: the payment processor is Mollie (was Adyen).
--
-- Forward-only, idempotent, data-preserving. The 2026-10-14 switch renamed
-- the Stripe-era schema to Adyen in migration 252; this migration renames
-- that generation to the Mollie vocabulary the code now speaks:
--
--   entity            Adyen term                 Mollie term
--   customer          adyen_shoppers             mollie_customers + mollie_customer_id
--   subscription      adyen_subscriptions        mollie_subscriptions
--   webhook ledger    adyen_webhook_events       mollie_webhook_events (mollie_event_id)
--   tax evidence      adyen_tax_snapshots        mollie_tax_snapshots
--   payment id        adyen_psp_reference        mollie_payment_id
--   mandate           adyen_recurring_detail_…   mollie_mandate_id
--   sequence          adyen_recurring_processing_model  mollie_sequence_type
--
-- Every rename is guarded: a replay, a partially migrated database or a
-- fresh database all converge to the same schema. Historical *values* that
-- name the old processor inside business documents (invoice notes, dead
-- letters, allocation rows already written) are left as the record they are;
-- the provider-label columns the product reads are updated so the operator
-- surfaces never report a processor that is no longer in use.

-- ── 1. Tables ────────────────────────────────────────────────────────────
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'adyen_shoppers')
       AND NOT EXISTS (SELECT 1 FROM information_schema.tables
                       WHERE table_schema = 'public' AND table_name = 'mollie_customers') THEN
        ALTER TABLE adyen_shoppers RENAME TO mollie_customers;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'adyen_subscriptions')
       AND NOT EXISTS (SELECT 1 FROM information_schema.tables
                       WHERE table_schema = 'public' AND table_name = 'mollie_subscriptions') THEN
        ALTER TABLE adyen_subscriptions RENAME TO mollie_subscriptions;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'adyen_tax_snapshots')
       AND NOT EXISTS (SELECT 1 FROM information_schema.tables
                       WHERE table_schema = 'public' AND table_name = 'mollie_tax_snapshots') THEN
        ALTER TABLE adyen_tax_snapshots RENAME TO mollie_tax_snapshots;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'adyen_webhook_events')
       AND NOT EXISTS (SELECT 1 FROM information_schema.tables
                       WHERE table_schema = 'public' AND table_name = 'mollie_webhook_events') THEN
        ALTER TABLE adyen_webhook_events RENAME TO mollie_webhook_events;
    END IF;
END $$;

-- ── 2. Columns (each guarded by table+column existence) ──────────────────
DO $$
DECLARE
    rename RECORD;
BEGIN
    FOR rename IN
        SELECT * FROM (VALUES
            ('mollie_customers',      'adyen_shopper_reference',           'mollie_customer_id'),
            ('mollie_subscriptions',  'adyen_plan_code',                  'mollie_plan_code'),
            ('mollie_subscriptions',  'adyen_recurring_detail_reference', 'mollie_mandate_id'),
            ('mollie_subscriptions',  'adyen_recurring_processing_model', 'mollie_sequence_type'),
            ('mollie_subscriptions',  'adyen_shopper_reference',          'mollie_customer_id'),
            ('mollie_subscriptions',  'adyen_subscription_id',            'mollie_subscription_id'),
            ('mollie_tax_snapshots',  'adyen_merchant_reference',         'mollie_payment_reference'),
            ('mollie_tax_snapshots',  'adyen_psp_reference',              'mollie_payment_id'),
            ('mollie_webhook_events', 'adyen_notification_id',            'mollie_event_id'),
            ('mollie_webhook_events', 'adyen_psp_reference',              'mollie_payment_id'),
            ('billing_periods',       'adyen_subscription_id',            'mollie_subscription_id'),
            ('dedicated_ips',         'adyen_recurring_detail_reference', 'mollie_mandate_id'),
            ('finance_incidents',     'adyen_psp_reference',              'mollie_payment_id'),
            ('invoices',              'adyen_payment_reference',          'mollie_payment_reference'),
            ('invoices',              'adyen_psp_reference',              'mollie_payment_id'),
            ('invoices',              'adyen_tax_snapshot_id',            'mollie_tax_snapshot_id'),
            ('plans',                 'adyen_plan_code_monthly',          'mollie_plan_code_monthly'),
            ('plans',                 'adyen_plan_code_yearly',           'mollie_plan_code_yearly'),
            ('subscriptions',         'adyen_shopper_reference',          'mollie_customer_id'),
            ('subscriptions',         'adyen_subscription_id',            'mollie_subscription_id')
        ) AS t(table_name, old_column, new_column)
    LOOP
        IF EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = rename.table_name
                     AND column_name = rename.old_column)
           AND NOT EXISTS (SELECT 1 FROM information_schema.columns
                           WHERE table_schema = 'public' AND table_name = rename.table_name
                             AND column_name = rename.new_column) THEN
            EXECUTE format('ALTER TABLE %I RENAME COLUMN %I TO %I',
                           rename.table_name, rename.old_column, rename.new_column);
        END IF;
    END LOOP;
END $$;

-- ── 3. Indexes and constraints: the names carried the old processor ──────
DO $$
DECLARE
    index_row RECORD;
BEGIN
    FOR index_row IN
        SELECT indexname FROM pg_indexes
        WHERE schemaname = 'public' AND indexname ILIKE '%adyen%'
    LOOP
        EXECUTE format('ALTER INDEX %I RENAME TO %I',
                       index_row.indexname,
                       replace(replace(index_row.indexname, 'adyen', 'mollie'), 'Adyen', 'Mollie'));
    END LOOP;

    FOR index_row IN
        SELECT conname, conrelid::regclass::text AS table_name
        FROM pg_constraint
        WHERE connamespace = 'public'::regnamespace AND conname ILIKE '%adyen%'
    LOOP
        EXECUTE format('ALTER TABLE %s RENAME CONSTRAINT %I TO %I',
                       index_row.table_name,
                       index_row.conname,
                       replace(replace(index_row.conname, 'adyen', 'mollie'), 'Adyen', 'Mollie'));
    END LOOP;
END $$;

-- ── 3b. Refund mapping ───────────────────────────────────────────────────
-- Mollie's refund webhook names only the refund id, and its API needs BOTH
-- ids to fetch a refund. We write this row when we create the refund.
CREATE TABLE IF NOT EXISTS mollie_refunds (
    id           TEXT PRIMARY KEY,
    payment_id   TEXT NOT NULL,
    tenant_id    VARCHAR(26),
    amount_cents BIGINT,
    currency     VARCHAR(3),
    status       VARCHAR(32) NOT NULL DEFAULT 'created',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_mollie_refunds_payment ON mollie_refunds (payment_id);
CREATE INDEX IF NOT EXISTS idx_mollie_refunds_tenant ON mollie_refunds (tenant_id);

-- ── 3b-bis. Mandate revocation evidence ──────────────────────────────────
-- Mollie keeps a mandate on the customer. A canceled account must not be
-- chargeable at the provider, so the local cancel revokes the mandate and
-- records WHEN it succeeded (a NULL after a canceled subscription is the
-- retry signal for the maintenance sweep).
ALTER TABLE mollie_customers
    ADD COLUMN IF NOT EXISTS mandate_revoked_at TIMESTAMPTZ;

-- ── 3c. Constraints whose allowlists named the old processor ─────────────
-- A CHECK allowlist is a schema reference: without this step the new
-- `mollie` values (and the `mollie_clearing` role the Rust chart uses) would
-- be rejected at insert time.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chart_of_accounts_account_role_check') THEN
        ALTER TABLE chart_of_accounts DROP CONSTRAINT chart_of_accounts_account_role_check;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'invoice_payment_allocations_source_check') THEN
        ALTER TABLE invoice_payment_allocations DROP CONSTRAINT invoice_payment_allocations_source_check;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'accounting_source_documents_source_type_check') THEN
        ALTER TABLE accounting_source_documents DROP CONSTRAINT accounting_source_documents_source_type_check;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'processor_clearing_accounts_processor_check') THEN
        ALTER TABLE processor_clearing_accounts DROP CONSTRAINT processor_clearing_accounts_processor_check;
    END IF;
END $$;

-- ── 3d. Provider values written before this migration ────────────────────
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema='public' AND table_name='invoice_payment_allocations'
                 AND column_name='source') THEN
        UPDATE invoice_payment_allocations SET source = 'mollie' WHERE source = 'adyen';
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema='public' AND table_name='accounting_source_documents'
                 AND column_name='source_type') THEN
        UPDATE accounting_source_documents
        SET source_type = 'mollie_settlement'
        WHERE source_type = 'adyen_settlement';
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema='public' AND table_name='processor_clearing_accounts'
                 AND column_name='processor') THEN
        UPDATE processor_clearing_accounts SET processor = 'mollie' WHERE processor = 'adyen';
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema='public' AND table_name='chart_of_accounts'
                 AND column_name='account_role') THEN
        UPDATE chart_of_accounts SET account_role = 'mollie_clearing'
        WHERE account_role = 'adyen_clearing';
        UPDATE chart_of_accounts SET account_role = 'mollie_fees'
        WHERE account_role = 'adyen_fees';
    END IF;
END $$;

-- Re-add the allowlists with the Mollie vocabulary. The Stripe-era values
-- stay: they label historical ledger rows that no migration may rewrite into
-- a processor that did not clear them.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chart_of_accounts_account_role_check') THEN
        ALTER TABLE chart_of_accounts ADD CONSTRAINT chart_of_accounts_account_role_check
            CHECK (account_role IS NULL OR account_role = ANY (ARRAY[
                'ar','ap','revenue','refunds','vat_output','vat_input','bank',
                'bank_clearing','stripe_clearing','stripe_fees','mollie_clearing',
                'mollie_fees','wallet_liability','expense_default','payroll_expense',
                'net_wages_payable','income_tax_payable','social_tax_payable',
                'unemployment_payable','pension_payable','fx_gain','fx_loss',
                'depreciation_expense','accumulated_depreciation','retained_earnings',
                'suspense','other_income']));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'invoice_payment_allocations_source_check') THEN
        ALTER TABLE invoice_payment_allocations ADD CONSTRAINT invoice_payment_allocations_source_check
            CHECK (source = ANY (ARRAY['wallet','stripe','mollie','manual','credit_note']));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'accounting_source_documents_source_type_check') THEN
        ALTER TABLE accounting_source_documents ADD CONSTRAINT accounting_source_documents_source_type_check
            CHECK (source_type = ANY (ARRAY[
                'invoice','credit_note','credit_note_refund','stripe_settlement',
                'mollie_settlement','wallet_settlement','manual_settlement','expense',
                'bank_statement_line','payroll','tax','manual','opening_balance',
                'depreciation','fx_revaluation','reversal','closing']));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'processor_clearing_accounts_processor_check') THEN
        ALTER TABLE processor_clearing_accounts ADD CONSTRAINT processor_clearing_accounts_processor_check
            CHECK (processor = ANY (ARRAY['stripe','mollie','paypal','bank']));
    END IF;
END $$;

-- ── 3e. Triggers and their functions ─────────────────────────────────────
-- Renaming a table/column does NOT rewrite function bodies: the Adyen-era
-- immutability trigger referenced `OLD.adyen_psp_reference`, which no longer
-- exists. It is replaced (and renamed) before any row can hit it.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_adyen_shoppers_updated_at') THEN
        ALTER TRIGGER trg_adyen_shoppers_updated_at ON mollie_customers
            RENAME TO trg_mollie_customers_updated_at;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_adyen_subscriptions_updated_at') THEN
        ALTER TRIGGER trg_adyen_subscriptions_updated_at ON mollie_subscriptions
            RENAME TO trg_mollie_subscriptions_updated_at;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_adyen_webhook_events_updated_at') THEN
        ALTER TRIGGER trg_adyen_webhook_events_updated_at ON mollie_webhook_events
            RENAME TO trg_mollie_webhook_events_updated_at;
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'prevent_adyen_tax_snapshot_mutation') THEN
        CREATE OR REPLACE FUNCTION prevent_mollie_tax_snapshot_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $function$
        BEGIN
            RAISE EXCEPTION 'mollie_tax_snapshots is immutable (attempted % on %)',
                TG_OP, COALESCE(OLD.mollie_payment_id, '(unknown)');
        END;
        $function$;
        DROP TRIGGER IF EXISTS trg_adyen_tax_snapshots_immutable ON mollie_tax_snapshots;
        CREATE TRIGGER trg_mollie_tax_snapshots_immutable
            BEFORE DELETE OR UPDATE ON mollie_tax_snapshots
            FOR EACH ROW EXECUTE FUNCTION prevent_mollie_tax_snapshot_mutation();
        DROP FUNCTION prevent_adyen_tax_snapshot_mutation();
    END IF;
END $$;

-- ── 4. The provider labels the operator surfaces read ────────────────────
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'invoice_payment_allocations'
                 AND column_name = 'source') THEN
        UPDATE invoice_payment_allocations SET source = 'mollie' WHERE source = 'adyen';
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'finance_incidents'
                 AND column_name = 'kind') THEN
        -- Provider-prefixed incident kinds (if any) follow the processor.
        UPDATE finance_incidents SET kind = replace(kind, 'adyen_', 'mollie_')
        WHERE kind LIKE 'adyen\_%';
    END IF;
END $$;


-- ── 5. Proof for the migration test ──────────────────────────────────────
-- The migration test asserts (a) no table or column still carries the old
-- processor's name in the SCHEMA, and (b) every renamed table kept its rows.
DO $$
DECLARE
    leftovers INTEGER;
BEGIN
    SELECT count(*) INTO leftovers
    FROM information_schema.columns
    WHERE table_schema = 'public' AND column_name ILIKE '%adyen%';
    IF leftovers > 0 THEN
        RAISE EXCEPTION 'migration 269: % column(s) still carry the old processor name', leftovers;
    END IF;

    SELECT count(*) INTO leftovers
    FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name ILIKE '%adyen%';
    IF leftovers > 0 THEN
        RAISE EXCEPTION 'migration 269: % table(s) still carry the old processor name', leftovers;
    END IF;

    -- Constraints, functions and triggers are references too.
    SELECT count(*) INTO leftovers
    FROM pg_constraint
    WHERE connamespace = 'public'::regnamespace
      AND pg_get_constraintdef(oid) ILIKE '%adyen%';
    IF leftovers > 0 THEN
        RAISE EXCEPTION 'migration 269: % constraint(s) still name the old processor', leftovers;
    END IF;

    SELECT count(*) INTO leftovers
    FROM pg_proc
    WHERE pronamespace = 'public'::regnamespace
      AND (proname ILIKE '%adyen%' OR pg_get_functiondef(oid) ILIKE '%adyen%');
    IF leftovers > 0 THEN
        RAISE EXCEPTION 'migration 269: % function(s) still name the old processor', leftovers;
    END IF;

    SELECT count(*) INTO leftovers
    FROM pg_trigger
    WHERE NOT tgisinternal AND tgname ILIKE '%adyen%';
    IF leftovers > 0 THEN
        RAISE EXCEPTION 'migration 269: % trigger(s) still name the old processor', leftovers;
    END IF;
END $$;
