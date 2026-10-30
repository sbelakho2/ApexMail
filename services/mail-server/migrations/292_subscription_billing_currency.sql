-- Migration 292: the subscription's billing currency is LOCAL state (audit
-- item 11).
-- =============================================================================
-- The renewal worker inferred the tenant's billing currency from the tenant's
-- most recent invoice (`ORDER BY created_at DESC LIMIT 1`). That made an
-- unrelated invoice — a USD support/adjustment document issued after an EUR
-- subscription — re-denominate the next renewal, and it let invoice history
-- (a DERIVED record) overrule the subscription (the authority).
--
-- The currency is part of the subscription arrangement: this migration makes
-- it an explicit column on the local subscription authority.
--
--   * New rows: the checkout activation writes the currency the customer
--     actually paid in (the quote's currency).
--   * Existing rows: a SAFE, one-time backfill from the tenant's most recent
--     invoice (the rule the worker used to apply per tick), defaulting to the
--     catalog default EUR when the tenant has no invoice yet. This preserves
--     today's observable behaviour for every existing subscription instead of
--     inventing a currency.
--
-- After this migration the column is the ONLY source of a renewal's currency.
-- It is changed only through an explicit billing transition; today the only
-- writer besides this backfill is the checkout activation (a new checkout is
-- the explicit "bill me in X" act). A future plan/currency change must be its
-- own audited transition, never an inference from invoice rows.
--
-- Idempotent: ADD COLUMN IF NOT EXISTS, the UPDATE only touches NULL rows, the
-- constraint is dropped-then-added. Fresh, replayed and partially migrated
-- databases converge.
-- =============================================================================

ALTER TABLE subscription_state
    ADD COLUMN IF NOT EXISTS billing_currency VARCHAR(3);

-- The one-time backfill (the worker's historical rule, frozen once).
UPDATE subscription_state s
SET billing_currency = COALESCE(
        (
            SELECT i.currency
            FROM invoices i
            WHERE i.tenant_id = s.tenant_id
              AND i.currency IN ('EUR', 'USD')
            ORDER BY i.created_at DESC, i.id DESC
            LIMIT 1
        ),
        'EUR'
    ),
    updated_at = NOW()
WHERE s.billing_currency IS NULL;

ALTER TABLE subscription_state
    ALTER COLUMN billing_currency SET DEFAULT 'EUR';

ALTER TABLE subscription_state
    ALTER COLUMN billing_currency SET NOT NULL;

ALTER TABLE subscription_state
    DROP CONSTRAINT IF EXISTS chk_subscription_state_billing_currency;

ALTER TABLE subscription_state
    ADD CONSTRAINT chk_subscription_state_billing_currency
    CHECK (billing_currency IN ('EUR', 'USD'));

COMMENT ON COLUMN subscription_state.billing_currency IS
    'The currency this subscription is billed in (migration 292): LOCAL authoritative state, frozen at activation, read by every renewal. Never inferred from invoice history; changed only by an explicit billing transition (today: a new checkout activation).';

-- ── Proof ────────────────────────────────────────────────────────────────
DO $$
DECLARE
    nulls INTEGER;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'subscription_state'
          AND column_name = 'billing_currency'
    ) THEN
        RAISE EXCEPTION 'migration 292: subscription_state.billing_currency must exist';
    END IF;

    SELECT count(*) INTO nulls FROM subscription_state WHERE billing_currency IS NULL;
    IF nulls > 0 THEN
        RAISE EXCEPTION 'migration 292: % subscription row(s) carry no billing_currency', nulls;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_subscription_state_billing_currency'
    ) THEN
        RAISE EXCEPTION 'migration 292: the billing_currency check constraint is missing';
    END IF;
END $$;
