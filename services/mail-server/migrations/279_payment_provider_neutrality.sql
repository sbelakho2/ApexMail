-- Migration 279: Payment provider neutrality - the staged neutral ledger.
--
-- External audit (seventh pass, P0-A): the billing engine becomes
-- processor-independent with Mollie as the first adapter. The Rust side
-- gains the `PaymentProvider` boundary (billing-service/src/payments/);
-- this migration stages the NEUTRAL persistence layer it will move onto.
--
-- THE STAGED PLAN (each later step is its own migration round):
--
--   stage 1 (THIS migration): create the neutral tables ADDITIVE-ONLY and
--     BACKFILL them from the existing provider tables, tagging every row
--     with the provider that owns it ('mollie'; 'adyen' for legacy rows
--     that predate the Mollie era, i.e. ids without Mollie's grammar).
--   stage 2: the adapter READS AND WRITES the neutral tables (legacy
--     tables keep receiving their writes too).
--   stage 3: PARITY - dual-write verification, counts and money equality.
--   stage 4: MOVE the domain code onto the neutral tables.
--   stage 5: RETIRE the legacy columns/tables LATER, in a dedicated
--     drop-round after at least one full billing cycle on parity.
--
-- The migration-269 lesson, applied: NO renames, NO drops, NO type
-- changes to existing objects. The legacy `mollie_*` tables are untouched
-- (the backfill only READS them). Everything below is guarded so a
-- re-run, a partially migrated database or a fresh database all converge
-- to the same schema and the same backfilled rows.
--
-- Legacy-shape notes the backfills rely on:
--   * `mollie_customers.mollie_customer_id` holds Mollie `cst_…` ids for
--     the Mollie era and pre-Mollie (Adyen-rename-era) references that
--     were seeded equal to the tenant id (migration 252); ids WITHOUT the
--     Mollie grammar are tagged 'adyen'.
--   * `mollie_subscriptions.mollie_subscription_id` holds `sub_…` ids
--     (live provider schedules) or legacy sentinels; only `sub_…`-shaped
--     rows are provider schedules and backfill the binding table, all
--     tagged by the same grammar test.
--   * `mollie_refunds`, `mollie_webhook_events` and `mollie_tax_snapshots`
--     follow the same rule on `re_…`, `tr_…` payment ids.

-- ---------------------------------------------------------------------------
-- 1. Neutral tables (additive, idempotent)
-- ---------------------------------------------------------------------------

-- Tenant <-> provider customer object mapping, one row per provider
-- customer; the UNIQUE constraint is the neutrality gate: the same
-- provider object can never be claimed twice.
CREATE TABLE IF NOT EXISTS payment_provider_customers (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            VARCHAR(26) NOT NULL,
    provider             VARCHAR(32) NOT NULL,
    provider_customer_id VARCHAR(128) NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider, provider_customer_id)
);
CREATE INDEX IF NOT EXISTS idx_payment_provider_customers_tenant
    ON payment_provider_customers (tenant_id, provider);

-- Stored payment credentials (the neutral mandate): what the engine may
-- charge, and the revocation evidence for canceled accounts.
CREATE TABLE IF NOT EXISTS payment_credentials (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            VARCHAR(26) NOT NULL,
    provider             VARCHAR(32) NOT NULL,
    provider_customer_id VARCHAR(128) NOT NULL,
    provider_method_id   VARCHAR(128) NOT NULL,
    state                VARCHAR(24) NOT NULL
                         CHECK (state IN ('active', 'expired', 'failed')),
    method_kind          VARCHAR(32),
    revoked_at           TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider, provider_method_id)
);
CREATE INDEX IF NOT EXISTS idx_payment_credentials_tenant
    ON payment_credentials (tenant_id, state);

-- One charge attempt per provider payment id, with the normalized state
-- machine the Rust boundary defines (serde camelCase enum values).
CREATE TABLE IF NOT EXISTS payment_attempts (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           VARCHAR(26) NOT NULL,
    provider            VARCHAR(32) NOT NULL,
    provider_payment_id VARCHAR(128) NOT NULL,
    state               VARCHAR(24) NOT NULL
                        CHECK (state IN ('pending', 'requiresAction', 'processing',
                                         'succeeded', 'failed', 'canceled')),
    amount_minor        BIGINT NOT NULL,
    currency            VARCHAR(3) NOT NULL,
    purpose             VARCHAR(64),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider, provider_payment_id)
);
CREATE INDEX IF NOT EXISTS idx_payment_attempts_tenant
    ON payment_attempts (tenant_id, created_at DESC);

-- The neutral provider event ledger (the promotion target of the webhook
-- normalizer): one row per deduplicated provider fact. Status stays
-- uncheck-constrained so legacy webhook statuses copy 1:1.
CREATE TABLE IF NOT EXISTS payment_provider_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider            VARCHAR(32) NOT NULL,
    provider_event_id   VARCHAR(255) NOT NULL,
    event_kind          VARCHAR(64) NOT NULL,
    provider_payment_id VARCHAR(128),
    provider_refund_id  VARCHAR(128),
    payload             JSONB NOT NULL DEFAULT '{}'::jsonb,
    status              VARCHAR(20) NOT NULL DEFAULT 'pending',
    error               TEXT,
    processed_at        TIMESTAMPTZ,
    received_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider, provider_event_id)
);
CREATE INDEX IF NOT EXISTS idx_payment_provider_events_payment
    ON payment_provider_events (provider, provider_payment_id);

-- Neutral refund facts.
CREATE TABLE IF NOT EXISTS payment_provider_refunds (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          VARCHAR(26),
    provider           VARCHAR(32) NOT NULL,
    provider_refund_id VARCHAR(128) NOT NULL,
    provider_payment_id VARCHAR(128) NOT NULL,
    state              VARCHAR(24) NOT NULL
                       CHECK (state IN ('pending', 'processing', 'succeeded', 'failed')),
    amount_minor       BIGINT NOT NULL,
    currency           VARCHAR(3) NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider, provider_refund_id)
);
CREATE INDEX IF NOT EXISTS idx_payment_provider_refunds_payment
    ON payment_provider_refunds (provider, provider_payment_id);

-- Dispute (chargeback) facts. No legacy table exists to backfill: the
-- Mollie era recorded chargebacks as payment statuses; rows begin when
-- the adapter starts emitting dispute facts.
CREATE TABLE IF NOT EXISTS payment_disputes (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           VARCHAR(26),
    provider            VARCHAR(32) NOT NULL,
    provider_dispute_id VARCHAR(128) NOT NULL,
    provider_payment_id VARCHAR(128) NOT NULL,
    state               VARCHAR(24) NOT NULL DEFAULT 'opened',
    reason              VARCHAR(64),
    amount_minor        BIGINT NOT NULL,
    currency            VARCHAR(3) NOT NULL,
    opened_at           TIMESTAMPTZ,
    resolved_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider, provider_dispute_id)
);
CREATE INDEX IF NOT EXISTS idx_payment_disputes_payment
    ON payment_disputes (provider, provider_payment_id);

-- Tax evidence per provider payment (the neutral successor of the
-- immutable provider tax snapshots; the snapshot table is NOT touched).
CREATE TABLE IF NOT EXISTS payment_tax_evidence (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           VARCHAR(26),
    provider            VARCHAR(32) NOT NULL,
    provider_payment_id VARCHAR(128) NOT NULL,
    local_invoice_id    UUID REFERENCES invoices(id) ON DELETE SET NULL,
    currency            VARCHAR(8) NOT NULL,
    subtotal_minor      BIGINT NOT NULL,
    tax_minor           BIGINT NOT NULL,
    total_minor         BIGINT NOT NULL,
    authority           VARCHAR(32),
    jurisdiction        VARCHAR(64),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider, provider_payment_id)
);
CREATE INDEX IF NOT EXISTS idx_payment_tax_evidence_invoice
    ON payment_tax_evidence (local_invoice_id);

-- Local subscription row <-> provider recurring schedule binding. No FK to
-- the legacy table on purpose: this binding must outlive the legacy
-- column's retirement (stage 5).
CREATE TABLE IF NOT EXISTS subscription_payment_bindings (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            VARCHAR(26) NOT NULL,
    provider             VARCHAR(32) NOT NULL,
    local_subscription_id UUID NOT NULL,
    provider_schedule_id VARCHAR(128) NOT NULL,
    provider_customer_id VARCHAR(128),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider, provider_schedule_id)
);
CREATE INDEX IF NOT EXISTS idx_subscription_payment_bindings_local
    ON subscription_payment_bindings (local_subscription_id);

-- The neutral plan catalog mapping (retires `plans.mollie_plan_code_*` in
-- stage 4): one row per provider price code the checkout may quote.
CREATE TABLE IF NOT EXISTS provider_catalog_mappings (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider            VARCHAR(32) NOT NULL,
    catalog_key         VARCHAR(128) NOT NULL,
    provider_price_code VARCHAR(128),
    currency            VARCHAR(3) NOT NULL DEFAULT 'EUR',
    billing_interval    VARCHAR(16) NOT NULL DEFAULT 'monthly',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider, catalog_key, currency, billing_interval)
);

COMMENT ON TABLE payment_provider_customers IS
    'Neutral tenant-to-provider-customer mapping (migration 279, stage 1 of the payment neutrality plan; see src/payments/NEUTRALITY_DEBT.md).';
COMMENT ON TABLE payment_credentials IS
    'Neutral stored payment credentials with revocation evidence; succeeds the mollie mandate columns in stage 4.';
COMMENT ON TABLE payment_attempts IS
    'One neutral charge attempt per provider payment id; state values are the serde camelCase enum of payments::PaymentState.';
COMMENT ON TABLE payment_provider_events IS
    'Neutral provider event ledger; promotion target of the webhook normalizer (mollie_webhooks ProviderNotification).';
COMMENT ON TABLE subscription_payment_bindings IS
    'Local subscription row to provider recurring schedule binding; replaces the SQL id-grammar probes in stage 4.';

-- ---------------------------------------------------------------------------
-- 2. Backfill from the legacy provider tables (READ-ONLY on the legacy
--    side; every statement guarded and re-run safe)
-- ---------------------------------------------------------------------------

-- 2a. Provider customers.
INSERT INTO payment_provider_customers (tenant_id, provider, provider_customer_id, created_at)
SELECT mc.tenant_id,
       CASE WHEN mc.mollie_customer_id LIKE 'cst\_%' THEN 'mollie' ELSE 'adyen' END,
       mc.mollie_customer_id,
       mc.created_at
FROM mollie_customers mc
WHERE mc.mollie_customer_id IS NOT NULL
  AND mc.mollie_customer_id <> ''
  AND NOT EXISTS (
        SELECT 1 FROM payment_provider_customers existing
        WHERE existing.provider = CASE WHEN mc.mollie_customer_id LIKE 'cst\_%'
                                       THEN 'mollie' ELSE 'adyen' END
          AND existing.provider_customer_id = mc.mollie_customer_id);

-- 2b. Stored credentials from the subscription mandates. State 'active'
-- is what every charge decision already assumes for these rows (the
-- engine charges them); a revoked/expired mandate is distinguished in
-- stage 2 when the adapter starts writing here.
INSERT INTO payment_credentials
        (tenant_id, provider, provider_customer_id, provider_method_id, state, created_at)
SELECT DISTINCT ON (ms.mollie_mandate_id)
       ms.tenant_id,
       CASE WHEN ms.mollie_mandate_id LIKE 'mdt\_%' THEN 'mollie' ELSE 'adyen' END,
       COALESCE(ms.mollie_customer_id, ms.tenant_id),
       ms.mollie_mandate_id,
       'active',
       ms.created_at
FROM mollie_subscriptions ms
WHERE ms.mollie_mandate_id IS NOT NULL
  AND ms.mollie_mandate_id <> ''
  AND NOT EXISTS (
        SELECT 1 FROM payment_credentials existing
        WHERE existing.provider = CASE WHEN ms.mollie_mandate_id LIKE 'mdt\_%'
                                       THEN 'mollie' ELSE 'adyen' END
          AND existing.provider_method_id = ms.mollie_mandate_id)
ORDER BY ms.mollie_mandate_id, ms.created_at DESC;

-- 2c. Charge attempts from bound invoices. The invoice status maps onto
-- the neutral payment state machine; the amount is the invoice's own
-- total in its currency (minor units).
INSERT INTO payment_attempts
        (tenant_id, provider, provider_payment_id, state, amount_minor, currency,
         purpose, created_at)
SELECT i.tenant_id,
       CASE WHEN i.mollie_payment_id LIKE 'tr\_%' THEN 'mollie' ELSE 'adyen' END,
       i.mollie_payment_id,
       CASE i.status
            WHEN 'paid' THEN 'succeeded'
            WHEN 'pending' THEN 'pending'
            WHEN 'draft' THEN 'pending'
            WHEN 'void' THEN 'canceled'
            WHEN 'uncollectible' THEN 'failed'
            ELSE 'failed'
       END,
       COALESCE(i.total, i.amount, 0)::bigint,
       i.currency,
       'invoice',
       i.created_at
FROM invoices i
WHERE i.mollie_payment_id IS NOT NULL
  AND i.mollie_payment_id <> ''
  AND NOT EXISTS (
        SELECT 1 FROM payment_attempts existing
        WHERE existing.provider = CASE WHEN i.mollie_payment_id LIKE 'tr\_%'
                                       THEN 'mollie' ELSE 'adyen' END
          AND existing.provider_payment_id = i.mollie_payment_id);

-- 2d. Refunds.
INSERT INTO payment_provider_refunds
        (tenant_id, provider, provider_refund_id, provider_payment_id, state,
         amount_minor, currency, created_at)
SELECT mr.tenant_id,
       CASE WHEN mr.id LIKE 're\_%' THEN 'mollie' ELSE 'adyen' END,
       mr.id,
       mr.payment_id,
       CASE mr.status
            WHEN 'refunded' THEN 'succeeded'
            WHEN 'processing' THEN 'processing'
            WHEN 'failed' THEN 'failed'
            WHEN 'canceled' THEN 'failed'
            ELSE 'pending'
       END,
       COALESCE(mr.amount_cents, 0),
       COALESCE(mr.currency, 'EUR'),
       mr.created_at
FROM mollie_refunds mr
WHERE mr.id <> ''
  AND NOT EXISTS (
        SELECT 1 FROM payment_provider_refunds existing
        WHERE existing.provider = CASE WHEN mr.id LIKE 're\_%'
                                       THEN 'mollie' ELSE 'adyen' END
          AND existing.provider_refund_id = mr.id);

-- 2e. Tax evidence (the snapshot table is read-only and stays untouched).
INSERT INTO payment_tax_evidence
        (tenant_id, provider, provider_payment_id, local_invoice_id, currency,
         subtotal_minor, tax_minor, total_minor, authority, jurisdiction, created_at)
SELECT ts.tenant_id,
       CASE WHEN ts.mollie_payment_id LIKE 'tr\_%' THEN 'mollie' ELSE 'adyen' END,
       ts.mollie_payment_id,
       ts.local_invoice_id,
       ts.currency,
       ts.subtotal_cents,
       ts.tax_cents,
       ts.total_cents,
       ts.authority,
       ts.jurisdiction,
       COALESCE(ts.created_at, NOW())
FROM mollie_tax_snapshots ts
WHERE ts.mollie_payment_id IS NOT NULL
  AND ts.mollie_payment_id <> ''
  AND NOT EXISTS (
        SELECT 1 FROM payment_tax_evidence existing
        WHERE existing.provider = CASE WHEN ts.mollie_payment_id LIKE 'tr\_%'
                                       THEN 'mollie' ELSE 'adyen' END
          AND existing.provider_payment_id = ts.mollie_payment_id);

-- 2f. Subscription <-> schedule bindings, for live provider schedules
-- only (legacy sentinels are not provider objects).
INSERT INTO subscription_payment_bindings
        (tenant_id, provider, local_subscription_id, provider_schedule_id,
         provider_customer_id, created_at)
SELECT ms.tenant_id,
       'mollie',
       ms.id,
       ms.mollie_subscription_id,
       ms.mollie_customer_id,
       ms.created_at
FROM mollie_subscriptions ms
WHERE ms.mollie_subscription_id LIKE 'sub\_%'
  AND NOT EXISTS (
        SELECT 1 FROM subscription_payment_bindings existing
        WHERE existing.provider = 'mollie'
          AND existing.provider_schedule_id = ms.mollie_subscription_id);

-- 2g. Plan catalog price codes.
INSERT INTO provider_catalog_mappings
        (provider, catalog_key, provider_price_code, currency, billing_interval)
SELECT 'mollie', p.name, p.mollie_plan_code_monthly, 'EUR', 'monthly'
FROM plans p
WHERE p.mollie_plan_code_monthly IS NOT NULL
  AND p.mollie_plan_code_monthly <> ''
  AND NOT EXISTS (
        SELECT 1 FROM provider_catalog_mappings existing
        WHERE existing.provider = 'mollie'
          AND existing.catalog_key = p.name
          AND existing.currency = 'EUR'
          AND existing.billing_interval = 'monthly');

INSERT INTO provider_catalog_mappings
        (provider, catalog_key, provider_price_code, currency, billing_interval)
SELECT 'mollie', p.name, p.mollie_plan_code_yearly, 'EUR', 'yearly'
FROM plans p
WHERE p.mollie_plan_code_yearly IS NOT NULL
  AND p.mollie_plan_code_yearly <> ''
  AND NOT EXISTS (
        SELECT 1 FROM provider_catalog_mappings existing
        WHERE existing.provider = 'mollie'
          AND existing.catalog_key = p.name
          AND existing.currency = 'EUR'
          AND existing.billing_interval = 'yearly');

-- 2h. Webhook event ledger (legacy statuses copy 1:1; the payload keeps
-- the event type so nothing is lost before the normalizer promotion).
INSERT INTO payment_provider_events
        (provider, provider_event_id, event_kind, provider_payment_id,
         payload, status, error, processed_at, received_at)
SELECT CASE WHEN we.mollie_payment_id LIKE 'tr\_%' THEN 'mollie' ELSE 'adyen' END,
       we.mollie_event_id,
       we.event_type,
       we.mollie_payment_id,
       jsonb_build_object('event_type', we.event_type),
       we.status,
       we.error,
       we.processed_at,
       we.created_at
FROM mollie_webhook_events we
WHERE we.mollie_event_id IS NOT NULL
  AND we.mollie_event_id <> ''
  AND NOT EXISTS (
        SELECT 1 FROM payment_provider_events existing
        WHERE existing.provider = CASE WHEN we.mollie_payment_id LIKE 'tr\_%'
                                       THEN 'mollie' ELSE 'adyen' END
          AND existing.provider_event_id = we.mollie_event_id);

-- ---------------------------------------------------------------------------
-- 3. Proof (fail the migration if the backfill lost a row)
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    missing INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'mollie_customers') THEN
        SELECT count(*) INTO missing
        FROM mollie_customers mc
        WHERE mc.mollie_customer_id IS NOT NULL AND mc.mollie_customer_id <> ''
          AND NOT EXISTS (
                SELECT 1 FROM payment_provider_customers existing
                WHERE existing.provider_customer_id = mc.mollie_customer_id);
        IF missing > 0 THEN
            RAISE EXCEPTION 'migration 279: % provider customer row(s) not backfilled', missing;
        END IF;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'mollie_refunds') THEN
        SELECT count(*) INTO missing
        FROM mollie_refunds mr
        WHERE NOT EXISTS (
                SELECT 1 FROM payment_provider_refunds existing
                WHERE existing.provider_refund_id = mr.id);
        IF missing > 0 THEN
            RAISE EXCEPTION 'migration 279: % refund row(s) not backfilled', missing;
        END IF;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'mollie_subscriptions') THEN
        SELECT count(*) INTO missing
        FROM mollie_subscriptions ms
        WHERE ms.mollie_subscription_id LIKE 'sub\_%'
          AND NOT EXISTS (
                SELECT 1 FROM subscription_payment_bindings existing
                WHERE existing.provider_schedule_id = ms.mollie_subscription_id);
        IF missing > 0 THEN
            RAISE EXCEPTION 'migration 279: % live schedule row(s) not bound', missing;
        END IF;
    END IF;
END $$;
