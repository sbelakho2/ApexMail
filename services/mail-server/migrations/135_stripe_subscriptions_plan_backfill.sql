-- Migration 135: backfill stripe_subscriptions.plan from the authoritative price
-- mapping (audit F27).
--
-- The subscription upsert never persisted `plan` (it stayed NULL on insert
-- and stale on update) even though the webhook handler resolves the plan
-- from the Stripe price via the plans table. Consumers that key on
-- ss.plan (overage entitlement, dedicated-IP provisioning, the paid-sub
-- gate) silently mis-resolved. Backfill every NULL/stale plan from
-- stripe_price_id via the plans mapping; rows whose price resolves to no
-- active plan keep plan = NULL — NULL is the "unresolved" flag the
-- webhook handler and sweeps warn on.

UPDATE stripe_subscriptions ss
SET plan = resolved.plan_name,
    updated_at = NOW()
FROM (
    SELECT DISTINCT ON (ss2.id) ss2.id, p.name AS plan_name
    FROM stripe_subscriptions ss2
    JOIN plans p
      ON p.is_active = true
     AND (p.stripe_price_id_monthly = ss2.stripe_price_id
          OR p.stripe_price_id_yearly = ss2.stripe_price_id)
    WHERE ss2.stripe_price_id IS NOT NULL
    ORDER BY ss2.id, p.name
) resolved
WHERE ss.id = resolved.id
  AND ss.plan IS DISTINCT FROM resolved.plan_name;

DO $$
DECLARE
    unresolved INT;
BEGIN
    SELECT COUNT(*) INTO unresolved FROM stripe_subscriptions
    WHERE stripe_price_id IS NOT NULL AND plan IS NULL;
    IF unresolved > 0 THEN
        RAISE NOTICE '135: % subscription row(s) have a Stripe price that maps to no active plan — left NULL (unresolved flag)', unresolved;
    END IF;
END
$$;

-- Fast lookup for the unresolved set (sweeps warn on these).
CREATE INDEX IF NOT EXISTS idx_stripe_subscriptions_plan_unresolved
    ON stripe_subscriptions (tenant_id)
    WHERE plan IS NULL AND stripe_price_id IS NOT NULL;
