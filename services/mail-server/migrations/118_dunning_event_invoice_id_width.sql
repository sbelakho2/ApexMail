-- 118_dunning_event_invoice_id_width.sql
--
-- =============================================================================
-- dunning_events.invoice_id was VARCHAR(26), sized for local 26-char ids,
-- but record_failed_payment() binds the STRIPE invoice id ("in_" + 24-25
-- chars = 27-28 total). Postgres rejects the whole payment-failure
-- transaction with 22001 value-too-long on every contemporary failed
-- invoice: the event deadletters, dunning never escalates, and tenants are
-- never suspended for non-payment. Widen to VARCHAR(64) — wide enough for
-- any current or foreseeable Stripe invoice id shape.
-- Idempotent: safe to re-run.
-- =============================================================================

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'dunning_events'
          AND column_name = 'invoice_id'
          AND character_maximum_length = 26
    ) THEN
        ALTER TABLE dunning_events ALTER COLUMN invoice_id TYPE VARCHAR(64);
        RAISE NOTICE '118: dunning_events.invoice_id widened VARCHAR(26) -> VARCHAR(64)';
    ELSE
        RAISE NOTICE '118: dunning_events.invoice_id already wide enough — nothing to do';
    END IF;
END $$;

-- ── dunning_records: 087/093 IF NOT EXISTS collision repair ────────────────
-- 087 created dunning_records in the OLD shape; 093's CREATE TABLE IF NOT
-- EXISTS with the full writer shape therefore NO-OPED on every chain that
-- ran 087 first (i.e. all of them). The result is missing every column
-- record_failed_payment() inserts (42703 on the first failed payment) and
-- missing the UNIQUE(tenant_id) its ON CONFLICT targets. Reconcile to the
-- 093/code contract.
DO $$
BEGIN
    IF to_regclass('public.dunning_records') IS NOT NULL THEN
        ALTER TABLE dunning_records ADD COLUMN IF NOT EXISTS failed_payment_count INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE dunning_records ADD COLUMN IF NOT EXISTS first_failed_at TIMESTAMPTZ;
        ALTER TABLE dunning_records ADD COLUMN IF NOT EXISTS last_failed_at TIMESTAMPTZ;
        ALTER TABLE dunning_records ADD COLUMN IF NOT EXISTS next_retry_at TIMESTAMPTZ;
        ALTER TABLE dunning_records ADD COLUMN IF NOT EXISTS grace_period_ends_at TIMESTAMPTZ;
        ALTER TABLE dunning_records ADD COLUMN IF NOT EXISTS suspended_at TIMESTAMPTZ;
        -- One dunning record per tenant: the upsert target. Adding the
        -- unique index fails if pre-existing duplicates exist — collapse
        -- them first, keeping the most recently updated row per tenant.
        IF EXISTS (
            SELECT 1 FROM dunning_records GROUP BY tenant_id HAVING count(*) > 1
        ) THEN
            DELETE FROM dunning_records a
            USING dunning_records b
            WHERE a.tenant_id = b.tenant_id
              AND (a.updated_at, a.id) < (b.updated_at, b.id);
            RAISE NOTICE '118: collapsed duplicate dunning_records per tenant';
        END IF;
        CREATE UNIQUE INDEX IF NOT EXISTS idx_dunning_records_tenant_unique
            ON dunning_records (tenant_id);
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = 'dunning_records'
              AND column_name = 'invoice_id' AND character_maximum_length = 26
        ) THEN
            ALTER TABLE dunning_records ALTER COLUMN invoice_id TYPE VARCHAR(64);
        END IF;
        RAISE NOTICE '118: dunning_records reconciled to the writer shape';
    END IF;
END $$;
