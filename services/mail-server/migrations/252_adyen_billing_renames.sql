-- Migration 252: the billing processor switch, schema wave — Stripe-era
-- objects are renamed to their Adyen-era names. Forward-only: no applied
-- migration is edited; this file renames the objects that migrations
-- 074/135/139/184/218 and friends created. See
-- docs/architecture/adyen-billing-migration.md for the concept mapping.
--
-- Value provenance (documented, not hidden): identity/reference columns keep
-- their historical values (rows created before the cutover carry the former
-- provider's ids — `sub_…`, `in_…`, `evt_…`); rows created after the cutover
-- carry Adyen-era values (`adyen_psp_reference` = Adyen pspReference, etc.).
-- Pure Stripe-object references that cannot mean anything under Adyen are
-- preserved under `legacy_stripe_*` names, and the Adyen-meaning column is
-- backfilled from data we control (shopper reference = tenant id).
--
-- Re-run safety: every rename is guarded (the 232 idiom) so a partially
-- applied run can be repeated; the migrator's ledger still treats the file
-- as applied exactly once.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. Tables: stripe_customers → adyen_shoppers
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'stripe_customers')
       AND NOT EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'adyen_shoppers') THEN
        ALTER TABLE stripe_customers RENAME TO adyen_shoppers;
    END IF;
END $$;

-- The provider customer id (cus_…) has no Adyen meaning; keep it as legacy
-- provenance, and make the Adyen shopper reference authoritative: it is the
-- tenant id, chosen by us (see the migration doc §2).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'adyen_shoppers'
                 AND column_name = 'stripe_customer_id')
       AND NOT EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'adyen_shoppers'
                 AND column_name = 'legacy_stripe_customer_id') THEN
        ALTER TABLE adyen_shoppers RENAME COLUMN stripe_customer_id TO legacy_stripe_customer_id;
    END IF;
END $$;

ALTER TABLE adyen_shoppers ADD COLUMN IF NOT EXISTS shopper_reference VARCHAR(128);
UPDATE adyen_shoppers SET shopper_reference = tenant_id WHERE shopper_reference IS NULL;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'adyen_shoppers'
                 AND column_name = 'shopper_reference' AND is_nullable = 'YES') THEN
        ALTER TABLE adyen_shoppers ALTER COLUMN shopper_reference SET NOT NULL;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 2. Tables: stripe_subscriptions → adyen_subscriptions
--    (this table is OUR subscription state machine — billing cycles, dunning
--    watermarks, admin overrides — not a provider mirror; only the provider
--    identity columns change meaning)
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'stripe_subscriptions')
       AND NOT EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'adyen_subscriptions') THEN
        ALTER TABLE stripe_subscriptions RENAME TO adyen_subscriptions;
    END IF;
END $$;

-- The subscription id stays the row identity: pre-cutover rows keep the
-- former provider's `sub_…` value (referenced by billing_periods and
-- subscriptions — rewriting identities would break those joins); post-cutover
-- rows carry our own id. Documented in the header.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'adyen_subscriptions'
                 AND column_name = 'stripe_subscription_id') THEN
        ALTER TABLE adyen_subscriptions RENAME COLUMN stripe_subscription_id TO adyen_subscription_id;
    END IF;
END $$;

-- The provider price id has no Adyen meaning; the provider-facing plan
-- reference (sent as the charge `reference`) takes its place, and the plan
-- code we already store is the truthful backfill.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'adyen_subscriptions'
                 AND column_name = 'stripe_price_id')
       AND NOT EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'adyen_subscriptions'
                 AND column_name = 'legacy_stripe_price_id') THEN
        ALTER TABLE adyen_subscriptions RENAME COLUMN stripe_price_id TO legacy_stripe_price_id;
    END IF;
END $$;
ALTER TABLE adyen_subscriptions ADD COLUMN IF NOT EXISTS adyen_plan_code VARCHAR(128);
UPDATE adyen_subscriptions SET adyen_plan_code = plan
    WHERE adyen_plan_code IS NULL AND plan IS NOT NULL;

-- Shopper reference: preserved legacy customer id + backfilled tenant id.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'adyen_subscriptions'
                 AND column_name = 'stripe_customer_id')
       AND NOT EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'adyen_subscriptions'
                 AND column_name = 'legacy_stripe_customer_id') THEN
        ALTER TABLE adyen_subscriptions RENAME COLUMN stripe_customer_id TO legacy_stripe_customer_id;
    END IF;
END $$;
ALTER TABLE adyen_subscriptions ADD COLUMN IF NOT EXISTS adyen_shopper_reference VARCHAR(128);
UPDATE adyen_subscriptions SET adyen_shopper_reference = tenant_id
    WHERE adyen_shopper_reference IS NULL;

-- The stored recurring token (Adyen recurringDetailReference) and the
-- recurring processing model are new provider-side identity; empty until the
-- customer re-tokenizes at cutover (owner decision, migration doc §9.4).
ALTER TABLE adyen_subscriptions
    ADD COLUMN IF NOT EXISTS adyen_recurring_detail_reference VARCHAR(128),
    ADD COLUMN IF NOT EXISTS adyen_recurring_processing_model VARCHAR(32);

-- ---------------------------------------------------------------------------
-- 3. Tables: stripe_webhook_events → adyen_webhook_events
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'stripe_webhook_events')
       AND NOT EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'adyen_webhook_events') THEN
        ALTER TABLE stripe_webhook_events RENAME TO adyen_webhook_events;
    END IF;
END $$;

-- The dedupe id column: Adyen retries the same notification, so the id is a
-- deterministic digest over (eventCode, pspReference, success, eventDate,
-- merchantReference) computed by the ingest. Historical rows keep the former
-- provider's `evt_…` ids (documented provenance).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'adyen_webhook_events'
                 AND column_name = 'stripe_event_id') THEN
        ALTER TABLE adyen_webhook_events RENAME COLUMN stripe_event_id TO adyen_notification_id;
    END IF;
END $$;

-- Operational column: the notification's pspReference, stored for support
-- queries (the dedupe id is a digest and cannot be looked up from a
-- customer report).
ALTER TABLE adyen_webhook_events ADD COLUMN IF NOT EXISTS adyen_psp_reference VARCHAR(64);

-- ---------------------------------------------------------------------------
-- 4. Tables: stripe_tax_snapshots → adyen_tax_snapshots
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'stripe_tax_snapshots')
       AND NOT EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'adyen_tax_snapshots') THEN
        ALTER TABLE stripe_tax_snapshots RENAME TO adyen_tax_snapshots;
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'adyen_tax_snapshots'
                 AND column_name = 'stripe_invoice_id') THEN
        ALTER TABLE adyen_tax_snapshots RENAME COLUMN stripe_invoice_id TO adyen_psp_reference;
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'adyen_tax_snapshots'
                 AND column_name = 'stripe_invoice_number') THEN
        ALTER TABLE adyen_tax_snapshots RENAME COLUMN stripe_invoice_number TO adyen_merchant_reference;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 5. Columns on other tables
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    -- billing_periods: joins adyen_subscriptions.adyen_subscription_id (same
    -- values, renamed in lockstep).
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'billing_periods'
                 AND column_name = 'stripe_subscription_id') THEN
        ALTER TABLE billing_periods RENAME COLUMN stripe_subscription_id TO adyen_subscription_id;
    END IF;

    -- finance_incidents / invoices: the provider-side reference becomes the
    -- Adyen pspReference (historical values documented in the header).
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'finance_incidents'
                 AND column_name = 'stripe_invoice_id') THEN
        ALTER TABLE finance_incidents RENAME COLUMN stripe_invoice_id TO adyen_psp_reference;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'invoices'
                 AND column_name = 'stripe_invoice_id') THEN
        ALTER TABLE invoices RENAME COLUMN stripe_invoice_id TO adyen_psp_reference;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'invoices'
                 AND column_name = 'stripe_invoice_item_id') THEN
        ALTER TABLE invoices RENAME COLUMN stripe_invoice_item_id TO adyen_payment_reference;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'invoices'
                 AND column_name = 'stripe_tax_snapshot_id') THEN
        ALTER TABLE invoices RENAME COLUMN stripe_tax_snapshot_id TO adyen_tax_snapshot_id;
    END IF;

    -- plans: the provider-facing plan reference per interval (Adyen takes
    -- amounts inline; the reference is what the charge carries).
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'plans'
                 AND column_name = 'stripe_price_id_monthly') THEN
        ALTER TABLE plans RENAME COLUMN stripe_price_id_monthly TO adyen_plan_code_monthly;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'plans'
                 AND column_name = 'stripe_price_id_yearly') THEN
        ALTER TABLE plans RENAME COLUMN stripe_price_id_yearly TO adyen_plan_code_yearly;
    END IF;
END $$;

-- legacy `subscriptions` table: same treatment as adyen_subscriptions.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'subscriptions'
                 AND column_name = 'stripe_subscription_id') THEN
        ALTER TABLE subscriptions RENAME COLUMN stripe_subscription_id TO adyen_subscription_id;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'subscriptions'
                 AND column_name = 'stripe_customer_id')
       AND NOT EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'subscriptions'
                 AND column_name = 'legacy_stripe_customer_id') THEN
        ALTER TABLE subscriptions RENAME COLUMN stripe_customer_id TO legacy_stripe_customer_id;
    END IF;
END $$;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS adyen_shopper_reference VARCHAR(128);
UPDATE subscriptions SET adyen_shopper_reference = tenant_id
    WHERE adyen_shopper_reference IS NULL AND tenant_id IS NOT NULL;

-- dedicated_ips: the Stripe subscription-item id is NOT an Adyen token —
-- preserve it as legacy provenance and leave the Adyen recurring reference
-- empty until the dedicated-IP subscriber re-tokenizes.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'dedicated_ips'
                 AND column_name = 'stripe_subscription_item_id')
       AND NOT EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'dedicated_ips'
                 AND column_name = 'legacy_stripe_subscription_item_id') THEN
        ALTER TABLE dedicated_ips RENAME COLUMN stripe_subscription_item_id TO legacy_stripe_subscription_item_id;
    END IF;
END $$;
ALTER TABLE dedicated_ips ADD COLUMN IF NOT EXISTS adyen_recurring_detail_reference VARCHAR(128);

-- ---------------------------------------------------------------------------
-- 6. Indexes, constraints, triggers, functions
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    -- tables renamed above keep their auto-generated names otherwise
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'stripe_customers_pkey') THEN
        ALTER INDEX stripe_customers_pkey RENAME TO adyen_shoppers_pkey;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'stripe_customers_tenant_id_key') THEN
        ALTER INDEX stripe_customers_tenant_id_key RENAME TO adyen_shoppers_tenant_id_key;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'stripe_subscriptions_pkey') THEN
        ALTER INDEX stripe_subscriptions_pkey RENAME TO adyen_subscriptions_pkey;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'stripe_webhook_events_pkey') THEN
        ALTER INDEX stripe_webhook_events_pkey RENAME TO adyen_webhook_events_pkey;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'stripe_tax_snapshots_pkey') THEN
        ALTER INDEX stripe_tax_snapshots_pkey RENAME TO adyen_tax_snapshots_pkey;
    END IF;

    -- explicit indexes
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_invoices_stripe') THEN
        ALTER INDEX idx_invoices_stripe RENAME TO idx_invoices_adyen;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_invoices_stripe_item') THEN
        ALTER INDEX idx_invoices_stripe_item RENAME TO idx_invoices_adyen_payment;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'uq_invoices_stripe_invoice_id') THEN
        ALTER INDEX uq_invoices_stripe_invoice_id RENAME TO uq_invoices_adyen_psp_reference;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_stripe_sub_tenant') THEN
        ALTER INDEX idx_stripe_sub_tenant RENAME TO idx_adyen_sub_tenant;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_stripe_subscriptions_plan_unresolved') THEN
        ALTER INDEX idx_stripe_subscriptions_plan_unresolved RENAME TO idx_adyen_subscriptions_plan_unresolved;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_stripe_subscriptions_watermark') THEN
        ALTER INDEX idx_stripe_subscriptions_watermark RENAME TO idx_adyen_subscriptions_watermark;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_stripe_tax_snapshots_tenant') THEN
        ALTER INDEX idx_stripe_tax_snapshots_tenant RENAME TO idx_adyen_tax_snapshots_tenant;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_stripe_webhook_events_status') THEN
        ALTER INDEX idx_stripe_webhook_events_status RENAME TO idx_adyen_webhook_events_status;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_stripe_customers_customer_id') THEN
        ALTER INDEX idx_stripe_customers_customer_id RENAME TO idx_adyen_shoppers_legacy_stripe_customer_id;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_stripe_subscriptions_sub_id') THEN
        ALTER INDEX idx_stripe_subscriptions_sub_id RENAME TO idx_adyen_subscriptions_sub_id;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_stripe_webhook_events_event_id') THEN
        ALTER INDEX idx_stripe_webhook_events_event_id RENAME TO idx_adyen_webhook_events_notification_id;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'uq_stripe_subscriptions_tenant') THEN
        ALTER INDEX uq_stripe_subscriptions_tenant RENAME TO uq_adyen_subscriptions_tenant;
    END IF;

    -- check + fk + unique constraints
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'stripe_tax_snapshots_authority_check') THEN
        ALTER TABLE adyen_tax_snapshots RENAME CONSTRAINT stripe_tax_snapshots_authority_check
            TO adyen_tax_snapshots_authority_check;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'stripe_tax_snapshots_local_invoice_id_fkey') THEN
        ALTER TABLE adyen_tax_snapshots RENAME CONSTRAINT stripe_tax_snapshots_local_invoice_id_fkey
            TO adyen_tax_snapshots_local_invoice_id_fkey;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'stripe_tax_snapshots_one_per_invoice') THEN
        ALTER TABLE adyen_tax_snapshots RENAME CONSTRAINT stripe_tax_snapshots_one_per_invoice
            TO adyen_tax_snapshots_one_per_invoice;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'stripe_tax_snapshots_validation_status_check') THEN
        ALTER TABLE adyen_tax_snapshots RENAME CONSTRAINT stripe_tax_snapshots_validation_status_check
            TO adyen_tax_snapshots_validation_status_check;
    END IF;

    -- triggers (+ the immutability function, whose name follows the trigger)
    IF EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_stripe_customers_updated_at') THEN
        ALTER TRIGGER trg_stripe_customers_updated_at ON adyen_shoppers
            RENAME TO trg_adyen_shoppers_updated_at;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_stripe_subscriptions_updated_at') THEN
        ALTER TRIGGER trg_stripe_subscriptions_updated_at ON adyen_subscriptions
            RENAME TO trg_adyen_subscriptions_updated_at;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_stripe_webhook_events_updated_at') THEN
        ALTER TRIGGER trg_stripe_webhook_events_updated_at ON adyen_webhook_events
            RENAME TO trg_adyen_webhook_events_updated_at;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_stripe_tax_snapshots_immutable') THEN
        ALTER TRIGGER trg_stripe_tax_snapshots_immutable ON adyen_tax_snapshots
            RENAME TO trg_adyen_tax_snapshots_immutable;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'prevent_stripe_tax_snapshot_mutation') THEN
        ALTER FUNCTION prevent_stripe_tax_snapshot_mutation() RENAME TO prevent_adyen_tax_snapshot_mutation;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 7. Table comments follow the rename (operator-facing truth)
-- ---------------------------------------------------------------------------
COMMENT ON TABLE adyen_shoppers IS
    'Billing shopper identity: shopper_reference = tenant id (the Adyen shopperReference); legacy_stripe_customer_id preserves the pre-cutover provider id.';
COMMENT ON TABLE adyen_subscriptions IS
    'Our subscription state machine (billing cycles, dunning watermark, admin overrides). adyen_recurring_detail_reference carries the Adyen stored-payment token once the customer re-tokenizes at cutover.';
COMMENT ON TABLE adyen_webhook_events IS
    'Adyen notification ledger. adyen_notification_id is the deterministic dedupe digest over (eventCode, pspReference, success, eventDate, merchantReference); Adyen retries the same notification, so this is the idempotency key.';
COMMENT ON TABLE adyen_tax_snapshots IS
    'Immutable record of the finalized payment tax decision (amounts, jurisdiction, tax-ID status, hash), enforced by trigger.';
COMMENT ON COLUMN adyen_webhook_events.adyen_psp_reference IS
    'Adyen pspReference of the notification item (support lookups; the dedupe id is a digest).';

-- Legacy comments that named Stripe on columns we renamed are updated so the
-- catalog carries no stale processor claim.
COMMENT ON COLUMN invoices.adyen_psp_reference IS
    'Provider payment reference settling this invoice: an Adyen pspReference post-cutover; pre-cutover rows carry the former provider invoice id (documented provenance).';
COMMENT ON COLUMN plans.adyen_plan_code_monthly IS
    'Provider-facing plan reference for monthly charges (sent as the Adyen charge reference). Amounts come inline from platform-catalog.';
COMMENT ON COLUMN plans.adyen_plan_code_yearly IS
    'Provider-facing plan reference for yearly charges (sent as the Adyen charge reference). Amounts come inline from platform-catalog.';
