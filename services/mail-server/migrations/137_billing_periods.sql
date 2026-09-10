-- Migration 137: immutable billing-period records (audit F30).
--
-- The overage sweep read its billing periods straight off the MUTABLE
-- stripe_subscriptions.billing_cycle_start/end columns. A renewal webhook
-- could overwrite the period bounds before the sweep read them — the
-- just-ended period vanished and its accrued overage was never invoiced
-- (or was priced against the NEW period's plan). Periods now live in an
-- append-only table written by the subscription webhook at every period
-- transition, keyed uniquely per (tenant, usage kind, period start):
--
--   * tenant/subscription ownership and period bounds are immutable;
--   * currency, plan, overage rate and email allowance are snapshotted at
--     write time (the period is priced with the plan in force THEN, never
--     today's plan — audit F32);
--   * metered_emails records the usage watermark at billing time;
--   * invoice_state is the billing state machine:
--       unbilled -> invoiced -> collected
--                -> skipped   (no overage / not billable)
--     terminal states are never revisited by the sweep (audit F31).

CREATE TABLE IF NOT EXISTS billing_periods (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               VARCHAR(26) NOT NULL,
    stripe_subscription_id  VARCHAR(128),
    usage_kind              VARCHAR(16) NOT NULL DEFAULT 'subscription'
        CHECK (usage_kind IN ('subscription', 'payg')),
    period_start            TIMESTAMPTZ NOT NULL,
    period_end              TIMESTAMPTZ NOT NULL,
    currency                VARCHAR(3) NOT NULL DEFAULT 'EUR',
    plan_name               VARCHAR(64),
    overage_rate_millicents INTEGER,
    email_allowance         BIGINT,
    metered_emails          BIGINT,
    invoice_state           VARCHAR(16) NOT NULL DEFAULT 'unbilled'
        CHECK (invoice_state IN ('unbilled', 'invoiced', 'collected', 'skipped')),
    invoice_id              UUID,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (period_end > period_start),
    UNIQUE (tenant_id, usage_kind, period_start)
);

CREATE INDEX IF NOT EXISTS idx_billing_periods_unbilled
    ON billing_periods (period_end, tenant_id)
    WHERE invoice_state = 'unbilled';
CREATE INDEX IF NOT EXISTS idx_billing_periods_subscription
    ON billing_periods (stripe_subscription_id, period_start);

-- Seed the CURRENT cycle of every subscription so the first sweep after
-- this migration has period records to work from. Historical cycles are
-- already gone from stripe_subscriptions (only the current bounds are
-- stored) and the metering TTL is 40 days — cycles that ended before the
-- seed keep flowing through the legacy stripe_subscriptions read inside
-- the sweep until they age out of the TTL.
INSERT INTO billing_periods (
    tenant_id, stripe_subscription_id, usage_kind,
    period_start, period_end, currency, plan_name
)
SELECT
    ss.tenant_id,
    ss.stripe_subscription_id,
    'subscription',
    ss.billing_cycle_start,
    ss.billing_cycle_end,
    'EUR',
    ss.plan
FROM stripe_subscriptions ss
WHERE ss.billing_cycle_start IS NOT NULL
  AND ss.billing_cycle_end IS NOT NULL
  AND ss.billing_cycle_end > ss.billing_cycle_start
ON CONFLICT (tenant_id, usage_kind, period_start) DO NOTHING;
