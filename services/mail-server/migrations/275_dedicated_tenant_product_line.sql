-- Migration 275: Dedicated Tenant becomes a first-class contract line.
--
-- Fifth external audit (item 14, P1 for the 100-customer architecture):
-- Dedicated Tenant is the flagship contract product (from EUR 4,000/month,
-- 12-month minimum, EUR 10k-40k setup) and the canonical catalog already
-- carries its monthly list (`platform-catalog` PRODUCT_LINES row, EUR and
-- USD) and its setup range. But the financial control plane could not
-- represent it: migration 256 created `product_line_contracts` for Platform
-- and Mailboxes, migration 265 widened the `product_line` CHECK to exactly
-- platform|mailboxes|compliance|placement|eu_only_routing, and
-- `billing-service::product_lines` deliberately excluded `dedicated_tenant`.
-- The flagship line could therefore only be invoiced manually.
--
-- This migration makes the line representable in the SAME control plane:
--
--   1. `product_line_contracts.product_line` admits 'dedicated_tenant'. The
--      CHECK is dropped by BOTH names it can carry (the inline 256 name and
--      the canonical name migration 265 added) and re-added, so a re-run
--      no-ops cleanly.
--   2. `billing_periods.usage_kind` admits 'dedicated_tenant' (VARCHAR(16)
--      fits exactly): the monthly sweep writes one period row per
--      (tenant, line, month) and reuses the migration-137 uniqueness as its
--      idempotency backstop, exactly as for the other lines.
--   3. `product_line_contracts.setup_fee_cents` / `minimum_term_months`:
--      the catalog publishes a setup RANGE (EUR 10k-40k) and a 12-month
--      minimum, so the CONTRACTED figures must live on the contract row.
--      `setup_fee_cents` is the one-time fee billed with the contract's
--      first billed period (the sweep freezes it in that period's pricing
--      snapshot; later periods carry month only).
--   4. `product_line_contracts.setup_fee_period_start`: the durable
--      exactly-once marker for that setup fee. The first period row the
--      sweep creates CLAIMS it with a conditional UPDATE on the contract
--      row, so overlapping sweep runs can never bill the one-time fee
--      twice (row-level locking serializes the claim).
--      All three columns are NULL for the other lines, enforced by a shape
--      CHECK so a setup fee or a minimum term can never be attached to a
--      line that does not sell one.
--
-- No DML, no backfill: every existing row stays valid (the new columns are
-- nullable), so a re-run on a current database no-ops cleanly.

-- ---------------------------------------------------------------------------
-- 1. product_line_contracts.product_line — the Dedicated Tenant line.
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
        'eu_only_routing',
        'dedicated_tenant'
    ));

-- ---------------------------------------------------------------------------
-- 2. billing_periods.usage_kind — the Dedicated Tenant period kind.
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
        'eu_only_routing',
        'dedicated_tenant'
    ));

-- ---------------------------------------------------------------------------
-- 3. The contracted Dedicated Tenant terms (NULL for every other line).
-- ---------------------------------------------------------------------------
ALTER TABLE product_line_contracts
    ADD COLUMN IF NOT EXISTS setup_fee_cents BIGINT;
ALTER TABLE product_line_contracts
    ADD COLUMN IF NOT EXISTS minimum_term_months BIGINT;
ALTER TABLE product_line_contracts
    ADD COLUMN IF NOT EXISTS setup_fee_period_start TIMESTAMPTZ;

ALTER TABLE product_line_contracts
    DROP CONSTRAINT IF EXISTS chk_product_line_contracts_setup_fee;
ALTER TABLE product_line_contracts
    ADD CONSTRAINT chk_product_line_contracts_setup_fee
    CHECK (setup_fee_cents IS NULL OR setup_fee_cents >= 0);

ALTER TABLE product_line_contracts
    DROP CONSTRAINT IF EXISTS chk_product_line_contracts_minimum_term;
ALTER TABLE product_line_contracts
    ADD CONSTRAINT chk_product_line_contracts_minimum_term
    CHECK (minimum_term_months IS NULL OR minimum_term_months >= 1);

-- The shape: only the Dedicated Tenant line carries a one-time setup fee, a
-- minimum term or the exactly-once setup marker. Existing rows are NULL on
-- all three columns, so this validates immediately; a re-run drops and
-- re-adds the same constraint.
ALTER TABLE product_line_contracts
    DROP CONSTRAINT IF EXISTS chk_product_line_contracts_dedicated_tenant_terms;
ALTER TABLE product_line_contracts
    ADD CONSTRAINT chk_product_line_contracts_dedicated_tenant_terms
    CHECK (
        product_line = 'dedicated_tenant'
        OR (
            setup_fee_cents IS NULL
            AND minimum_term_months IS NULL
            AND setup_fee_period_start IS NULL
        )
    );

COMMENT ON COLUMN product_line_contracts.setup_fee_cents IS
    'Dedicated Tenant one-time setup fee in billing cents; billed once, with the contract''s first billed period. NULL on every other product line.';
COMMENT ON COLUMN product_line_contracts.minimum_term_months IS
    'Dedicated Tenant contracted minimum term in months (never below the platform-catalog minimum). NULL on every other product line.';
COMMENT ON COLUMN product_line_contracts.setup_fee_period_start IS
    'The billing period that claimed the Dedicated Tenant one-time setup fee (exactly-once marker, claimed under a row lock by the monthly sweep). NULL until the first billed period, and NULL on every other product line.';
