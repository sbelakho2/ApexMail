-- Migration 282: Payment attempt semantics — immutable attempts with
-- attempt_no, the strict exact-amount obligation gate, the `unresolved`
-- attempt state, and the provider contract binding.
--
-- External audit, eighth pass, P0 (payments engine financial correctness):
--
--   1. payment_attempts.attempt_no: a dunning retry is a NEW immutable
--      attempt row (attempt_no = max+1 per (provider, obligation_ref)),
--      never a mutation of the failed row. Transport retries of the SAME
--      attempt keep the SAME idempotency key (the unique claim index);
--      business retries claim `payment:{obligation_ref}:{attempt_no}`.
--      The backfill numbers the historical rows in created_at order.
--   2. The `unresolved` attempt state: a stale keyless claim whose
--      provider-side search cannot PROVE absence (lost webhooks, truncated
--      listings) must never be blindly closed failed nor auto-retried; it
--      waits for human reconciliation. The state CHECK constraint is
--      dropped and recreated with the new value (guarded, name-pinned:
--      `payment_attempts_state_check`, the auto name of migration 279's
--      inline CHECK).
--   3. invoices.allow_partial: the exact-amount gate. Default FALSE —
--      verify-then-settle requires EXACT equality between the charge and
--      the outstanding obligation; an over- or under-charge is a
--      reconciliation incident, never a silent min() cap. The flag is the
--      ONLY obligation-level escape back to the capped allocation.
--   4. subscription_payment_bindings.provider_schedule_id becomes
--      provider_contract_id and NULLable (a binding may exist before the
--      provider object is minted). Migration 279 is applied and its
--      checksums are frozen, so the rename happens HERE: the 279 UNIQUE
--      constraint is dropped by its exact name and recreated over the new
--      column.
--
-- Guarded and re-run safe throughout (the migration-269 lesson): no data
-- drops, every existing row keeps its value, fresh and partially migrated
-- databases converge to the same schema.

-- ---------------------------------------------------------------------------
-- 1. payment_attempts.attempt_no (immutable attempts, dunning ladder)
-- ---------------------------------------------------------------------------

ALTER TABLE payment_attempts ADD COLUMN IF NOT EXISTS attempt_no INT NOT NULL DEFAULT 1;

-- Backfill: number each (provider, obligation_ref) attempt chain in
-- created_at order (id as the deterministic tie-break). Rows without an
-- obligation reference keep the default (each is a standalone historical
-- attempt keyed by its provider payment id).
WITH ranked AS (
    SELECT id,
           ROW_NUMBER() OVER (
               PARTITION BY provider, obligation_ref
               ORDER BY created_at ASC, id ASC
           ) AS attempt_no
    FROM payment_attempts
    WHERE obligation_ref IS NOT NULL
)
UPDATE payment_attempts pa
SET attempt_no = ranked.attempt_no
FROM ranked
WHERE pa.id = ranked.id
  AND pa.attempt_no <> ranked.attempt_no;

CREATE INDEX IF NOT EXISTS idx_payment_attempts_attempt_chain
    ON payment_attempts (provider, obligation_ref, attempt_no);

COMMENT ON COLUMN payment_attempts.attempt_no IS
    'The 1-based attempt ordinal per (provider, obligation_ref): attempts are IMMUTABLE rows — a dunning retry opens attempt N+1 under the payment:{obligation_ref}:{N} idempotency key, a transport retry reuses the same key and row (migration 282).';
COMMENT ON COLUMN payment_attempts.state IS
    'Attempt state; `unresolved` (migration 282) marks a stale claim whose provider-side search could not prove the charge absent — it requires manual reconciliation and is NEVER auto-retried.';

-- The `unresolved` state must be legal: drop and recreate the 279 state
-- CHECK by its exact (auto-generated) name, guarded like migration 281.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'payment_attempts_state_check') THEN
        ALTER TABLE payment_attempts DROP CONSTRAINT payment_attempts_state_check;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'payment_attempts_state_check') THEN
        ALTER TABLE payment_attempts ADD CONSTRAINT payment_attempts_state_check
            CHECK (state IN ('pending', 'requiresAction', 'processing',
                             'succeeded', 'failed', 'canceled', 'unresolved'));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 2. invoices.allow_partial (the exact-amount gate's only escape hatch)
-- ---------------------------------------------------------------------------

-- The obligation row verify_against_obligation reads IS the invoices table.
-- Default FALSE: the strict world. Nothing in the codebase sets it true.
ALTER TABLE invoices ADD COLUMN IF NOT EXISTS allow_partial BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN invoices.allow_partial IS
    'Obligation-level escape from the exact-amount settlement gate (migration 282): false (default) requires the charge to equal the outstanding obligation exactly — any mismatch is a reconciliation incident; true restores the legacy capped (min) allocation. No code path sets it true today.';

-- ---------------------------------------------------------------------------
-- 3. subscription_payment_bindings: provider_schedule_id ->
--    provider_contract_id, NULLable, UNIQUE constraint recreated by name
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint
               WHERE conname = 'subscription_payment_bindings_provider_provider_schedule_id_key') THEN
        ALTER TABLE subscription_payment_bindings
            DROP CONSTRAINT subscription_payment_bindings_provider_provider_schedule_id_key;
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'subscription_payment_bindings'
                 AND column_name = 'provider_schedule_id')
       AND NOT EXISTS (SELECT 1 FROM information_schema.columns
                       WHERE table_schema = 'public' AND table_name = 'subscription_payment_bindings'
                         AND column_name = 'provider_contract_id') THEN
        ALTER TABLE subscription_payment_bindings
            RENAME COLUMN provider_schedule_id TO provider_contract_id;
    END IF;
END $$;

-- A binding may exist before the provider contract object does (the
-- schedule/contract id arrives with activation). Widening, guarded.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'subscription_payment_bindings'
                 AND column_name = 'provider_contract_id'
                 AND is_nullable = 'YES') THEN
        NULL; -- already nullable
    ELSE
        ALTER TABLE subscription_payment_bindings
            ALTER COLUMN provider_contract_id DROP NOT NULL;
    END IF;
END $$;

-- Recreate the uniqueness over the new column (same shape as 279: one
-- binding per provider contract object; NULLs are distinct so pre-activation
-- rows never collide).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'subscription_payment_bindings'
                 AND column_name = 'provider_contract_id')
       AND NOT EXISTS (SELECT 1 FROM pg_constraint
                       WHERE conname = 'subscription_payment_bindings_provider_provider_contract_id_key') THEN
        ALTER TABLE subscription_payment_bindings
            ADD CONSTRAINT subscription_payment_bindings_provider_provider_contract_id_key
            UNIQUE (provider, provider_contract_id);
    END IF;
END $$;

COMMENT ON COLUMN subscription_payment_bindings.provider_contract_id IS
    'The provider recurring-contract object this local subscription is bound to (renamed from provider_schedule_id by migration 282); NULL until the provider object exists.';

-- ---------------------------------------------------------------------------
-- 4. Proof
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    bad_state_check TEXT;
    stale_attempts INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'payment_attempts') THEN
        SELECT pg_get_constraintdef(oid) INTO bad_state_check
        FROM pg_constraint
        WHERE conname = 'payment_attempts_state_check';
        IF bad_state_check IS NULL OR position('unresolved' in bad_state_check) = 0 THEN
            RAISE EXCEPTION 'migration 282: payment_attempts state CHECK must accept unresolved';
        END IF;

        -- The backfill must leave no chain with a gap or a zero.
        SELECT count(*) INTO stale_attempts
        FROM payment_attempts
        WHERE obligation_ref IS NOT NULL
          AND (attempt_no < 1
               OR attempt_no > (SELECT count(*) FROM payment_attempts p2
                                WHERE p2.provider = payment_attempts.provider
                                  AND p2.obligation_ref = payment_attempts.obligation_ref));
        IF stale_attempts > 0 THEN
            RAISE EXCEPTION 'migration 282: % attempt chain(s) not backfilled correctly', stale_attempts;
        END IF;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'subscription_payment_bindings'
                 AND column_name = 'provider_schedule_id') THEN
        RAISE EXCEPTION 'migration 282: subscription_payment_bindings.provider_schedule_id must be renamed to provider_contract_id';
    END IF;
END $$;
