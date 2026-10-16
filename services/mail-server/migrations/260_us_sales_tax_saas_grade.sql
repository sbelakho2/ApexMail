-- Migration 260: US sales tax — SaaS-grade collection (taxability, either-
-- criterion nexus, customer exemptions, early warning).
--
-- Migration 257 landed the first US sales-tax half: a per-state nexus status
-- row plus the stamped tax pair on invoices, for operator-registered states
-- only. This migration lands the storage for the SaaS-grade upgrade of the
-- same module (`billing-service/src/us_tax.rs`):
--
--   1. `us_tax_nexus_states` gains the second nexus criterion and the early
--      warning state:
--        `criteria`              which statutory test(s) the state's row
--                                declares: `sales` | `transactions` |
--                                `either` (whichever the operator's data-file
--                                row declares is what the sweep evaluates);
--        `transaction_threshold` the transaction-count threshold (NULL for a
--                                sales-only state, and vice versa);
--        `observed_count`        transactions counted in the window (kept
--                                regardless of which criterion alerts — both
--                                measures are always tracked);
--        `observed_exempt_cents` sales dollars under a customer exemption
--                                certificate in the window, tracked separately
--                                (exempt sales still count toward the gross-
--                                sales nexus test, which is why the total is
--                                also stored);
--        `warned_at` /
--        `warned_window_start`   the once-per-window early warning (raised at
--                                the configured fraction of the threshold, so
--                                registration/filing has lead time). The
--                                crossing alert stays its own exactly-once
--                                record (`crossed_at`/`crossed_window_start`).
--      `threshold_cents` relaxes to nullable: a `transactions`-criteria state
--      declares no sales threshold, and inventing one would fabricate the
--      figure the sweep compares against.
--
--   2. `us_tax_customer_exemptions` — the B2B exemption certificates. One row
--      per (tenant, state, certificate): a certificate may cover many states
--      (several rows share the certificate id). `expires_at` NULL means the
--      certificate states no expiry date (recorded deliberately, never
--      guessed); a certificate whose `expires_at` is before the invoice date
--      never exempts. The certificate is applied at invoice time by the
--      canonical writer and recorded on the invoice's tax snapshot.
--
--   3. `invoices` provenance CHECK widens: an EXEMPT sale carries amount 0
--      WITH a snapshot (`{"exempt":true,…}`), so the pair stays atomic in
--      both directions — money requires provenance, and a zero amount can
--      only carry a snapshot when that snapshot is the exemption record.
--
-- Idempotent by construction (guarded DDL, IF NOT EXISTS, no DML) so a
-- re-run no-ops cleanly.

-- ---------------------------------------------------------------------------
-- 1. us_tax_nexus_states — the second criterion, both measures, the warning.
-- ---------------------------------------------------------------------------
ALTER TABLE us_tax_nexus_states
    ADD COLUMN IF NOT EXISTS criteria VARCHAR(16) NOT NULL DEFAULT 'sales';
ALTER TABLE us_tax_nexus_states
    ADD COLUMN IF NOT EXISTS transaction_threshold BIGINT;
ALTER TABLE us_tax_nexus_states
    ADD COLUMN IF NOT EXISTS observed_count BIGINT NOT NULL DEFAULT 0;
ALTER TABLE us_tax_nexus_states
    ADD COLUMN IF NOT EXISTS observed_exempt_cents BIGINT NOT NULL DEFAULT 0;
ALTER TABLE us_tax_nexus_states
    ADD COLUMN IF NOT EXISTS warned_at TIMESTAMPTZ;
ALTER TABLE us_tax_nexus_states
    ADD COLUMN IF NOT EXISTS warned_window_start TIMESTAMPTZ;

-- A `transactions`-criteria state declares no sales threshold at all.
ALTER TABLE us_tax_nexus_states
    ALTER COLUMN threshold_cents DROP NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'chk_us_tax_nexus_states_criteria'
                     AND conrelid = 'us_tax_nexus_states'::regclass) THEN
        ALTER TABLE us_tax_nexus_states
            ADD CONSTRAINT chk_us_tax_nexus_states_criteria
            CHECK (criteria IN ('sales', 'transactions', 'either'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'chk_us_tax_nexus_states_thresholds'
                     AND conrelid = 'us_tax_nexus_states'::regclass) THEN
        ALTER TABLE us_tax_nexus_states
            ADD CONSTRAINT chk_us_tax_nexus_states_thresholds
            CHECK (
                (threshold_cents IS NULL OR threshold_cents > 0)
                AND (transaction_threshold IS NULL OR transaction_threshold > 0)
                AND observed_cents >= 0
                AND observed_count >= 0
                AND observed_exempt_cents >= 0
            );
    END IF;
END
$$;

COMMENT ON COLUMN us_tax_nexus_states.criteria IS
    'Nexus test(s) the state row declares: sales | transactions | either. '
    'The sweep alerts on the FIRST crossing of whichever declared criterion '
    'is reached.';
COMMENT ON COLUMN us_tax_nexus_states.transaction_threshold IS
    'Transaction-count threshold when the declared criteria include '
    'transactions; NULL when the row is sales-only.';
COMMENT ON COLUMN us_tax_nexus_states.observed_count IS
    'Non-void US invoices in the window (all currencies — a transaction '
    'needs no FX conversion). Always stored, whichever criterion alerts.';
COMMENT ON COLUMN us_tax_nexus_states.observed_exempt_cents IS
    'USD sales under a customer exemption certificate in the window. These '
    'sales still count toward the gross-sales/transaction nexus tests (the '
    'common statutory rule counts exempt sales); the figure is kept separate '
    'for reporting.';
COMMENT ON COLUMN us_tax_nexus_states.warned_at IS
    'When the once-per-window early warning (US_TAX_WARN_FRACTION of the '
    'threshold) was raised. Cleared by a new calendar-year window instance, '
    'like the crossing record.';
COMMENT ON COLUMN us_tax_nexus_states.warned_window_start IS
    'The window instance the warning belongs to (exactly-once per window).';

-- ---------------------------------------------------------------------------
-- 2. us_tax_customer_exemptions — B2B resale/exemption certificates.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS us_tax_customer_exemptions (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      VARCHAR(26) NOT NULL CHECK (btrim(tenant_id) <> ''),
    -- ISO 3166-2:US style two-letter code, upper-case: one row per covered
    -- state (a multi-state certificate shares its certificate_id across rows).
    state_code     VARCHAR(2) NOT NULL CHECK (state_code ~ '^[A-Z]{2}$'),
    certificate_id TEXT NOT NULL CHECK (btrim(certificate_id) <> ''),
    -- NULL = the certificate states no expiry date (recorded as such). A
    -- certificate whose expiry is before the invoice date never exempts.
    expires_at     DATE,
    note           TEXT,
    created_by     TEXT,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, state_code, certificate_id)
);

CREATE INDEX IF NOT EXISTS idx_us_tax_customer_exemptions_tenant
    ON us_tax_customer_exemptions (tenant_id, state_code);

COMMENT ON TABLE us_tax_customer_exemptions IS
    'Customer sales-tax exemption certificates (billing-service us_tax): '
    'applied per (tenant, state) at invoice time; the certificate is recorded '
    'on the invoice tax snapshot and the exempt sale is still counted toward '
    'nexus/reporting (exempt_cents). Expired/absent certificate → taxable.';

-- ---------------------------------------------------------------------------
-- 3. invoices — the exemption arm of the provenance CHECK.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint
               WHERE conname = 'chk_invoices_us_sales_tax_provenance'
                 AND conrelid = 'invoices'::regclass) THEN
        ALTER TABLE invoices DROP CONSTRAINT chk_invoices_us_sales_tax_provenance;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'chk_invoices_us_sales_tax_provenance'
                     AND conrelid = 'invoices'::regclass) THEN
        ALTER TABLE invoices
            ADD CONSTRAINT chk_invoices_us_sales_tax_provenance
            CHECK (
                us_sales_tax_cents >= 0
                AND (
                    (us_sales_tax_cents = 0
                     AND (us_sales_tax_snapshot IS NULL
                          OR us_sales_tax_snapshot ->> 'exempt' = 'true'))
                    OR (us_sales_tax_cents > 0 AND us_sales_tax_snapshot IS NOT NULL)
                )
            );
    END IF;
END
$$;

COMMENT ON COLUMN invoices.us_sales_tax_snapshot IS
    'Provenance stamp for us_sales_tax_cents. Taxed: {snapshotVersion, state, '
    'rateBps, rateKind (state|combined), …source, retrieved}. Exempt: '
    '{snapshotVersion, state, exempt:true, certificateId, '
    'certificateExpiresAt, amountCents:0}.';
