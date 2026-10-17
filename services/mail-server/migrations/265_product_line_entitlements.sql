-- Migration 265: the Compliance, Inbox Placement Monitoring and EU-only
-- Routing lines become recordable, billable and enforceable product lines.
--
-- Migration 256 created `product_line_contracts` for the two lines billing
-- already knew about (Platform, Mailboxes) and constrained
-- `product_line_contracts.product_line` and
-- `billing_periods.usage_kind` to exactly those values. Three sold lines had
-- no storage at all:
--
--   * Compliance (990 EUR / 1,090 USD per month) — "EU-only routing
--     included" on the owner's price table, but its contract could not be
--     recorded and it granted no entitlement;
--   * Inbox Placement Monitoring (99 EUR / 109 USD per month) — sold as an
--     add-on, but the placement engine ran for every tenant because no
--     purchase record or entitlement existed;
--   * EU-only Routing (149 EUR / 165 USD per month) — only a test ever
--     wrote `tenants.settings.addons.euOnlyRouting`; there was no purchase
--     path.
--
-- This migration widens the two closed vocabularies and adds the columns the
-- CP purchase writer needs. It is deliberately additive:
--
--   1. `product_line_contracts.product_line` admits 'compliance',
--      'placement' and 'eu_only_routing'. The old CHECK is dropped by BOTH
--      names it can carry (the inline 256 name and the canonical name a
--      previous run of this file would have added) and re-added, so a
--      re-run no-ops cleanly.
--   2. `billing_periods.usage_kind` admits the same three values: the
--      monthly sweep writes one period row per (tenant, line, month) and
--      reuses the migration-137 uniqueness as its idempotency backstop.
--   3. `product_line_contracts.billing_interval` records the interval the
--      line was purchased on ('monthly' or 'yearly'). The sweep stays
--      MONTHLY (the 12-month annual contract is billed monthly, exactly as
--      the existing lines are); the column is the purchase term, not a
--      second billing cadence.
--   4. `product_line_contracts.contracted_units` records the seats/units
--      purchased (1 for the flat lines; the Mailboxes line still bills the
--      seats actually provisioned, never this column).
--   5. `product_line_contracts.purchase_key` — the CP writer's
--      idempotency key. A replay with the same key and line returns the
--      recorded contract; a key reused for a different line is refused. The
--      partial unique index makes a silent second contract impossible.
--
-- No DML, no backfill: every existing row stays valid (defaults fill the new
-- columns), so a re-run on a current database no-ops cleanly.

-- ---------------------------------------------------------------------------
-- 1. product_line_contracts.product_line — the three new lines.
-- ---------------------------------------------------------------------------
ALTER TABLE product_line_contracts
    DROP CONSTRAINT IF EXISTS product_line_contracts_product_line_check;
ALTER TABLE product_line_contracts
    DROP CONSTRAINT IF EXISTS chk_product_line_contracts_product_line;

ALTER TABLE product_line_contracts
    ADD CONSTRAINT chk_product_line_contracts_product_line
    CHECK (product_line IN (
        'platform',
        'mailboxes',
        'compliance',
        'placement',
        'eu_only_routing'
    ));

-- ---------------------------------------------------------------------------
-- 2. billing_periods.usage_kind — one period kind per billable line.
-- ---------------------------------------------------------------------------
ALTER TABLE billing_periods
    DROP CONSTRAINT IF EXISTS billing_periods_usage_kind_check;
ALTER TABLE billing_periods
    DROP CONSTRAINT IF EXISTS chk_billing_periods_usage_kind;

ALTER TABLE billing_periods
    ADD CONSTRAINT chk_billing_periods_usage_kind
    CHECK (usage_kind IN (
        'subscription',
        'payg',
        'platform',
        'mailboxes',
        'compliance',
        'placement',
        'eu_only_routing'
    ));

-- ---------------------------------------------------------------------------
-- 3. Contract purchase metadata: interval, units, idempotency key.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'product_line_contracts'
                     AND column_name = 'billing_interval') THEN
        ALTER TABLE product_line_contracts
            ADD COLUMN billing_interval VARCHAR(16) NOT NULL DEFAULT 'monthly';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'product_line_contracts'
                     AND column_name = 'contracted_units') THEN
        ALTER TABLE product_line_contracts
            ADD COLUMN contracted_units INTEGER NOT NULL DEFAULT 1;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'product_line_contracts'
                     AND column_name = 'purchase_key') THEN
        ALTER TABLE product_line_contracts ADD COLUMN purchase_key TEXT;
    END IF;
END
$$;

ALTER TABLE product_line_contracts
    DROP CONSTRAINT IF EXISTS chk_product_line_contracts_billing_interval;
ALTER TABLE product_line_contracts
    ADD CONSTRAINT chk_product_line_contracts_billing_interval
    CHECK (billing_interval IN ('monthly', 'yearly'));

ALTER TABLE product_line_contracts
    DROP CONSTRAINT IF EXISTS chk_product_line_contracts_contracted_units;
ALTER TABLE product_line_contracts
    ADD CONSTRAINT chk_product_line_contracts_contracted_units
    CHECK (contracted_units >= 1);

-- A purchase key identifies one purchase request within a tenant. The
-- partial index permits legacy/operator rows without a key while making a
-- replayed request unable to mint a second contract row.
CREATE UNIQUE INDEX IF NOT EXISTS uq_product_line_contracts_purchase_key
    ON product_line_contracts (tenant_id, purchase_key)
    WHERE purchase_key IS NOT NULL;

-- Entitlement resolution reads the tenant dimension (the existing 256 index
-- leads with product_line). Partial on active rows: a suspended/terminated
-- contract is not an entitlement.
CREATE INDEX IF NOT EXISTS idx_product_line_contracts_tenant_active
    ON product_line_contracts (tenant_id, product_line)
    WHERE status = 'active';
