-- Migration 256: the Platform and Mailboxes contract lines become billable.
--
-- The 2026-10-15 price table put both lines in the catalog
-- (`platform-catalog` `PRODUCT_LINES` rows + `PLATFORM_*` constants +
-- the `mailboxes` / `mailbox_archive_journaling` add-on rows) but nothing
-- billed them: subaccounts exist as an enterprise feature, mailboxes exist
-- as receiving accounts, and neither had a monthly charge. This migration
-- lands the storage the billing-service sweep (and the Mailboxes
-- provisioning gate) needs:
--
--   1. `billing_periods.usage_kind` gains 'platform' and 'mailboxes' — the
--      per-(tenant, kind, period) idempotency the existing sweeps use
--      (migration 137 UNIQUE) is reused verbatim for the two new lines.
--   2. `product_line_contracts` — the record that a tenant HODLS a contract
--      product line ('platform' or 'mailboxes'). It is both the sweep's
--      truth source (which tenants are billed) and the Mailboxes
--      provisioning entitlement (the add-on purchase record). No such
--      record existed: the catalog rows were display-only.
--   3. `mail_accounts.tenant_id` — seats are counted per tenant, and no
--      tenant column existed anywhere in the mail plane (`mail_accounts` /
--      `mail_mailboxes` carry no tenant dimension). NO backfill: a legacy
--      operator-created row has no recorded owner, and guessing one from
--      the domain (a domain can be shared, and the system tenant owns the
--      platform's own domain) would bill the wrong tenant. Unbound legacy
--      rows stay unbilled; the provisioning path now records the owner on
--      every new row. `archive_enabled` / `archive_enabled_at` are the
--      per-mailbox archive add-on flag and the retention marker it starts.
--   4. `invoices.product_lines_period` — the product-line invoice identity.
--      Deliberately NOT `overage_period`: a PAYG tenant may also hold a
--      contract line, and both would then claim the same
--      (tenant_id, overage_period = month start) identity — the second
--      charge would be silently swallowed by the uniqueness backstop. The
--      new column carries its own partial unique index.
--
-- Idempotent by construction (guarded DDL, IF NOT EXISTS, no DML) so a
-- re-run no-ops cleanly.

-- ---------------------------------------------------------------------------
-- 1. billing_periods.usage_kind: add the two contract-line kinds.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'billing_periods_usage_kind_check'
          AND conrelid = 'billing_periods'::regclass
    ) THEN
        ALTER TABLE billing_periods DROP CONSTRAINT billing_periods_usage_kind_check;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_billing_periods_usage_kind'
          AND conrelid = 'billing_periods'::regclass
    ) THEN
        ALTER TABLE billing_periods
            ADD CONSTRAINT chk_billing_periods_usage_kind
            CHECK (usage_kind IN ('subscription', 'payg', 'platform', 'mailboxes'));
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- 2. product_line_contracts — the contract records the sweep bills from.
--
-- One row per (tenant, product line). `active_from` is when the contract
-- took effect: the sweep bills a completed calendar month only when the
-- period START is on/after it (a partially contracted first month is not
-- billed — no proration exists; see `billing_service::product_lines`).
-- `contracted_seats` is deliberately ABSENT: seats bill from the mailboxes
-- actually provisioned for the tenant (the entitlement-gated provisioning
-- path is the purchase act), so a contracted-but-unprovisioned seat count
-- would be a second, unhooked source of truth.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS product_line_contracts (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    VARCHAR(26) NOT NULL,
    product_line VARCHAR(20) NOT NULL
        CHECK (product_line IN ('platform', 'mailboxes')),
    status       VARCHAR(16) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'terminated')),
    active_from  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at     TIMESTAMPTZ,
    notes        TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, product_line)
);

CREATE INDEX IF NOT EXISTS idx_product_line_contracts_active
    ON product_line_contracts (product_line, tenant_id)
    WHERE status = 'active';

-- ---------------------------------------------------------------------------
-- 3. mail_accounts: the tenant binding + the per-mailbox archive flag.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'mail_accounts'
                     AND column_name = 'tenant_id') THEN
        ALTER TABLE mail_accounts ADD COLUMN tenant_id VARCHAR(26);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'mail_accounts'
                     AND column_name = 'archive_enabled') THEN
        ALTER TABLE mail_accounts ADD COLUMN archive_enabled BOOLEAN NOT NULL DEFAULT false;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'mail_accounts'
                     AND column_name = 'archive_enabled_at') THEN
        ALTER TABLE mail_accounts ADD COLUMN archive_enabled_at TIMESTAMPTZ;
    END IF;
END
$$;

-- Seat counting reads (tenant_id, is_active) for every billed tenant.
CREATE INDEX IF NOT EXISTS idx_mail_accounts_tenant
    ON mail_accounts (tenant_id)
    WHERE tenant_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 4. invoices.product_lines_period — the contract-line invoice identity.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'invoices'
                     AND column_name = 'product_lines_period') THEN
        ALTER TABLE invoices ADD COLUMN product_lines_period TIMESTAMPTZ;
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_invoices_product_lines_period
    ON invoices (tenant_id, product_lines_period)
    WHERE product_lines_period IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_invoices_tenant_product_lines_period
    ON invoices (tenant_id, product_lines_period)
    WHERE product_lines_period IS NOT NULL;
