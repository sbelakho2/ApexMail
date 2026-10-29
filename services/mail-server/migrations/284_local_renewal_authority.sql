-- Migration 284: the local renewal authority (beta authority inversion,
-- external audit #8 sections 1-3, 11).
--
-- ApexMail owns subscription renewal. The provider-owned recurring schedule
-- is gone from the core model: the renewal worker
-- (billing-service/src/plan_billing.rs `renew_due_subscriptions`) creates
-- the NEXT period's invoice BEFORE any charge, claims the payment attempt
-- through the engine (`claim_next_attempt` / `payment:{ref}:{N}`), charges
-- the stored credential, and settles against the local obligation with the
-- strict exact-amount gate. The provider never decides when the next charge
-- exists.
--
-- What the schema still lacked for that worker:
--
--   1. mollie_subscriptions.renewal_attempts — the dunning counter. A
--      definitively failed renewal charge opens the NEXT attempt (a new
--      immutable payment_attempts row) on a later tick; after
--      MAX_DUNNING_ATTEMPTS the subscription moves to `past_due` (the
--      crate's existing dunning vocabulary). Successful renewal resets it.
--   2. mollie_subscriptions.renewal_locked_at — the per-row renewal gate:
--      stamped when a renewal attempt for the row is in flight or was just
--      attempted, so concurrent ticks and back-to-back dunning retries
--      cannot hammer the same row. NULL when the row is idle/renewed.
--
-- `cancel_at_period_end` ALREADY exists on mollie_subscriptions (migrations
-- 071/076): the local flag is the cancellation authority and needed no new
-- column. `subscription_payment_bindings.provider_contract_id` is already
-- NULLable (migration 282): a binding WITHOUT a provider contract is the
-- legal, normal shape for a locally-renewed subscription.
--
-- The physical table/column names still carrying the provider tag
-- (`mollie_subscriptions`, `mollie_subscription_id`, ...) are the local
-- subscription STATE table since the Stripe-era schema; renaming them is
-- the owner-gated step-10 legacy-table retirement, not this migration.
--
-- Guarded and re-run safe (the migration-269 lesson): additive-only,
-- every statement idempotent, fresh and partially migrated databases
-- converge to the same schema.

-- ---------------------------------------------------------------------------
-- 1. The renewal worker's per-row state
-- ---------------------------------------------------------------------------

ALTER TABLE mollie_subscriptions
    ADD COLUMN IF NOT EXISTS renewal_attempts INT NOT NULL DEFAULT 0;

ALTER TABLE mollie_subscriptions
    ADD COLUMN IF NOT EXISTS renewal_locked_at TIMESTAMPTZ;

COMMENT ON COLUMN mollie_subscriptions.renewal_attempts IS
    'Dunning counter of the LOCAL renewal worker (migration 284): incremented per definitively failed renewal charge, reset on a successful one; at MAX_DUNNING_ATTEMPTS the subscription moves to past_due. The provider owns no retry schedule.';
COMMENT ON COLUMN mollie_subscriptions.renewal_locked_at IS
    'The renewal worker''s per-row gate (migration 284): stamped while a renewal attempt is in flight or just attempted (the dunning backoff); NULL when the row is idle. Concurrent ticks and back-to-back retries skip a stamped row.';

-- The worker's due-set scan: active rows at/after their period end that are
-- neither canceled-at-period-end nor mid-dunning-backoff.
CREATE INDEX IF NOT EXISTS idx_mollie_subscriptions_renewal_due
    ON mollie_subscriptions (billing_cycle_end)
    WHERE status = 'active'
      AND cancel_at_period_end = false;

-- ---------------------------------------------------------------------------
-- 2. The binding shape for locally-renewed subscriptions
-- ---------------------------------------------------------------------------

-- Stamp (documentation only; 282 made the column NULLable) that a binding
-- without a provider contract is the LEGAL shape for a locally-renewed
-- subscription: the contract id is legacy-reconciliation provenance, never
-- a requirement for an ACTIVE local subscription.
COMMENT ON COLUMN subscription_payment_bindings.provider_contract_id IS
    'The provider recurring-contract object this local subscription is bound to (renamed from provider_schedule_id by migration 282). NULL is the LEGAL shape for a locally-renewed subscription (migration 284): the local row is the renewal authority, a contract id survives only as legacy reconciliation provenance.';

-- ---------------------------------------------------------------------------
-- 3. Proof
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'mollie_subscriptions'
          AND column_name = 'renewal_attempts'
    ) THEN
        RAISE EXCEPTION 'migration 284: mollie_subscriptions.renewal_attempts must exist';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'mollie_subscriptions'
          AND column_name = 'renewal_locked_at'
    ) THEN
        RAISE EXCEPTION 'migration 284: mollie_subscriptions.renewal_locked_at must exist';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'mollie_subscriptions'
          AND column_name = 'cancel_at_period_end'
    ) THEN
        RAISE EXCEPTION 'migration 284: the local cancel_at_period_end authority column must exist';
    END IF;
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'subscription_payment_bindings'
          AND column_name = 'provider_contract_id'
          AND is_nullable = 'NO'
    ) THEN
        RAISE EXCEPTION
            'migration 284: subscription_payment_bindings.provider_contract_id must stay NULLable for locally-renewed subscriptions';
    END IF;
END $$;
