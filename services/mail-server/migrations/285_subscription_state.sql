-- Migration 285: the local subscription state table loses the provider tag
-- (payment-neutrality step 10, NEUTRALITY_DEBT row N-03).
--
-- The LOCAL subscription state machine has been renamed twice already
-- (stripe_subscriptions → adyen_subscriptions in 252 → mollie_subscriptions
-- in 269) while its OWNER stayed the same: ApexMail. Since the beta
-- authority inversion (migration 284) the provider owns no schedule object
-- at all — renewal is the local worker, the contract id on new rows is a
-- locally-minted `local_…` sentinel — so the physical name is pure legacy
-- vocabulary. This migration renames the table to what it IS and renames
-- every provider-tagged column inside to the neutral names the rest of the
-- ledger already speaks (migration 279's payment_credentials /
-- subscription_payment_bindings vocabulary):
--
--   entity            old (provider-tagged)      new (neutral)
--   table             mollie_subscriptions       subscription_state
--   contract id       mollie_subscription_id     provider_contract_id
--                     (holds legacy `sub_…` provider contracts and the
--                     locally-minted `local_…` sentinels; aligns with
--                     subscription_payment_bindings.provider_contract_id)
--   customer id       mollie_customer_id         provider_customer_id
--                     (aligns with payment_credentials /
--                     subscription_payment_bindings.provider_customer_id)
--   stored method     mollie_mandate_id          provider_method_id
--                     (aligns with payment_credentials.provider_method_id)
--   processing model  mollie_sequence_type       provider_sequence_type
--                     (write-only provider-era fact; kept for history)
--   plan price code   mollie_plan_code           snapshot_plan_code
--                     (frozen since the 252 backfill, no writers: a
--                     historical snapshot the churn report prices from)
--
-- Forward-only, idempotent, data-preserving — the migration-269 pattern:
-- a replay, a partially migrated database or a fresh database all converge
-- to the same schema. Historical *values* are preserved byte-for-byte; this
-- is a RENAME, not a rewrite. Consumers outside billing-service
-- (api-server admin surfaces, subscription routes, churn report,
-- compliance entitlements) are updated by a coordinated follow-up against
-- the mapping pinned in NEUTRALITY_DEBT.md row N-03.

-- ── 1. The table ─────────────────────────────────────────────────────────
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'mollie_subscriptions')
       AND NOT EXISTS (SELECT 1 FROM information_schema.tables
                       WHERE table_schema = 'public' AND table_name = 'subscription_state') THEN
        ALTER TABLE mollie_subscriptions RENAME TO subscription_state;
    END IF;
END $$;

-- ── 2. Columns (each guarded by table+column existence) ──────────────────
DO $$
DECLARE
    rename RECORD;
BEGIN
    FOR rename IN
        SELECT * FROM (VALUES
            ('provider_contract_id',  'mollie_subscription_id'),
            ('provider_customer_id',  'mollie_customer_id'),
            ('provider_method_id',    'mollie_mandate_id'),
            ('provider_sequence_type','mollie_sequence_type'),
            ('snapshot_plan_code',    'mollie_plan_code')
        ) AS t(new_column, old_column)
    LOOP
        IF EXISTS (SELECT 1 FROM information_schema.tables
                   WHERE table_schema = 'public' AND table_name = 'subscription_state')
           AND EXISTS (SELECT 1 FROM information_schema.columns
                       WHERE table_schema = 'public' AND table_name = 'subscription_state'
                         AND column_name = rename.old_column)
           AND NOT EXISTS (SELECT 1 FROM information_schema.columns
                           WHERE table_schema = 'public' AND table_name = 'subscription_state'
                             AND column_name = rename.new_column) THEN
            EXECUTE format('ALTER TABLE subscription_state RENAME COLUMN %I TO %I',
                           rename.old_column, rename.new_column);
        END IF;
    END LOOP;
END $$;

-- ── 3. Indexes, constraints and the trigger carry the old name too ───────
DO $$
DECLARE
    index_row RECORD;
BEGIN
    FOR index_row IN
        SELECT indexname FROM pg_indexes
        WHERE schemaname = 'public'
          AND tablename = 'subscription_state'
          AND indexname LIKE '%mollie_subscriptions%'
    LOOP
        EXECUTE format('ALTER INDEX %I RENAME TO %I',
                       index_row.indexname,
                       replace(index_row.indexname, 'mollie_subscriptions', 'subscription_state'));
    END LOOP;

    -- The tenant index predates the subscription-suffix naming (252 era
    -- `idx_stripe_sub_tenant` → `idx_mollie_sub_tenant`); give it the
    -- canonical new prefix exactly once.
    IF EXISTS (SELECT 1 FROM pg_indexes
               WHERE schemaname = 'public'
                 AND tablename = 'subscription_state'
                 AND indexname = 'idx_mollie_sub_tenant')
       AND NOT EXISTS (SELECT 1 FROM pg_indexes
                       WHERE schemaname = 'public'
                         AND tablename = 'subscription_state'
                         AND indexname = 'idx_subscription_state_tenant') THEN
        ALTER INDEX idx_mollie_sub_tenant RENAME TO idx_subscription_state_tenant;
    END IF;

    FOR index_row IN
        SELECT conname, conrelid::regclass::text AS table_name
        FROM pg_constraint
        WHERE connamespace = 'public'::regnamespace
          AND conrelid = 'subscription_state'::regclass
          AND conname LIKE '%mollie_subscriptions%'
    LOOP
        EXECUTE format('ALTER TABLE %s RENAME CONSTRAINT %I TO %I',
                       index_row.table_name,
                       index_row.conname,
                       replace(index_row.conname, 'mollie_subscriptions', 'subscription_state'));
    END LOOP;

    IF EXISTS (SELECT 1 FROM pg_trigger
               WHERE tgname = 'trg_mollie_subscriptions_updated_at'
                 AND tgrelid = 'subscription_state'::regclass) THEN
        ALTER TRIGGER trg_mollie_subscriptions_updated_at ON subscription_state
            RENAME TO trg_subscription_state_updated_at;
    END IF;
END $$;

-- ── 4. Comments: the operator-facing descriptions lose the provider tag ──
COMMENT ON TABLE subscription_state IS
    'The LOCAL subscription state machine (billing cycles, cancellation authority, renewal worker gate, admin overrides). Physically renamed from the provider-era mollie_subscriptions by migration 285 (NEUTRALITY-DEBT N-03); provider_contract_id holds legacy provider contracts and locally-minted local_… sentinels alike.';
COMMENT ON COLUMN subscription_state.provider_contract_id IS
    'The subscription''s external contract reference: a legacy provider schedule id (sub_…) for rows bound before the local-renewal authority, a locally-minted local_… sentinel since (migration 284). Renamed from mollie_subscription_id by migration 285; the neutral binding lives on subscription_payment_bindings.provider_contract_id.';
COMMENT ON COLUMN subscription_state.provider_customer_id IS
    'The provider customer object the subscription''s stored method belongs to (renamed from mollie_customer_id by migration 285).';
COMMENT ON COLUMN subscription_state.provider_method_id IS
    'The stored-payment method the local renewal worker charges (renamed from mollie_mandate_id by migration 285); the charging authority is the neutral payment_credentials row keyed by this id.';
COMMENT ON COLUMN subscription_state.provider_sequence_type IS
    'Provider-era processing model (first/recurring) carried for history; the renewal schedule is LOCAL since migration 284 and nothing reads this for scheduling. Renamed from mollie_sequence_type by migration 285.';
COMMENT ON COLUMN subscription_state.snapshot_plan_code IS
    'Historical plan price-code snapshot (frozen by the migration-252 backfill, no writers since); the churn report prices legacy churned rows from it. Renamed from mollie_plan_code by migration 285.';

-- ── 5. Proof ─────────────────────────────────────────────────────────────
DO $$
DECLARE
    leftovers INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'mollie_subscriptions') THEN
        RAISE EXCEPTION 'migration 285: the provider-tagged subscription table still exists';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables
                   WHERE table_schema = 'public' AND table_name = 'subscription_state') THEN
        RAISE EXCEPTION 'migration 285: subscription_state must exist';
    END IF;

    SELECT count(*) INTO leftovers
    FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'subscription_state'
      AND column_name LIKE 'mollie%';
    IF leftovers > 0 THEN
        RAISE EXCEPTION 'migration 285: % provider-tagged column(s) remain on subscription_state', leftovers;
    END IF;

    FOR leftovers IN
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'subscription_state'
          AND column_name IN ('provider_contract_id', 'provider_customer_id',
                              'provider_method_id', 'provider_sequence_type',
                              'snapshot_plan_code')
        HAVING count(*) <> 5
    LOOP
        RAISE EXCEPTION 'migration 285: the neutral column set is incomplete';
    END LOOP;

    SELECT count(*) INTO leftovers
    FROM pg_indexes
    WHERE schemaname = 'public' AND tablename = 'subscription_state'
      AND indexname LIKE '%mollie%';
    IF leftovers > 0 THEN
        RAISE EXCEPTION 'migration 285: % index(es) still carry the provider tag', leftovers;
    END IF;
END $$;
