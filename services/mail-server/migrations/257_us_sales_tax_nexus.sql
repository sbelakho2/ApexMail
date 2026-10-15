-- Migration 257: US sales tax — economic-nexus tracking + the stamped tax
-- columns on invoices (plan WP C2).
--
-- Before this migration the platform had ZERO US sales-tax code: the whole
-- tax stack is EU (`vat_*` modules, invoices carry vat_rate/vat_amount). This
-- migration lands the storage for the two halves of WP C2:
--
--   1. `us_tax_nexus_states` — one row per US state the platform sells into.
--      It is the operator-facing state machine:
--        `below`             the trailing/calendar window of taxable US sales
--                            is under the state's economic-nexus threshold;
--        `threshold_crossed` the window reached/exceeded the threshold — the
--                            periodic sweep raises ONE operator alert (a
--                            `finance_incidents` row) per window and flips
--                            the row here. It NEVER registers and NEVER
--                            charges: registration is a legal act by the
--                            owner/accounting, not a computed transition;
--        `registered`        the operator registered with the state (admin
--                            surface, audited). Only then is sales tax
--                            computed on new invoices for that state.
--      `threshold_cents` / `nexus_window` mirror the committed rate file
--      (`billing-service/data/us_sales_tax.json`) row actually USED for the
--      evaluation — the file is the truth for rates and thresholds, the row
--      records what was compared against.
--   2. `invoices.us_sales_tax_cents` + `invoices.us_sales_tax_snapshot` —
--      the stamped sales-tax amount and its provenance (state, rate in basis
--      points, source URL, retrieved date). Both are written ONLY by the
--      canonical invoice writer, and only for a US customer whose billing
--      address state is `registered` AND whose rate row is fresh; a stale
--      rate row fails closed (the invoice is refused, never computed from a
--      stale rate). The pair is atomic by CHECK: money without provenance
--      can never exist, provenance without money can never exist.
--
-- `total` keeps its meaning as the amount to collect and now equals
-- `subtotal + vat_total + us_sales_tax_cents`. The VAT columns are
-- deliberately NOT reused for US sales tax: `vat_total` feeds the Estonian
-- KMD return (migration 218's recognition ledger), and filing US state tax
-- as Estonian VAT would be a false return.
--
-- Idempotent by construction (guarded DDL, IF NOT EXISTS, no DML) so a
-- re-run no-ops cleanly.

-- ---------------------------------------------------------------------------
-- 1. us_tax_nexus_states — the per-state nexus status row.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS us_tax_nexus_states (
    -- ISO 3166-2:US style two-letter code (50 states, DC and the inhabited
    -- territories the rate file may carry).
    state_code            VARCHAR(2) PRIMARY KEY
                              CHECK (state_code ~ '^[A-Z]{2}$'),
    status                VARCHAR(24) NOT NULL DEFAULT 'below'
                              CHECK (status IN ('below', 'threshold_crossed', 'registered')),
    -- The threshold/window the LAST evaluation compared against, read from
    -- the committed rate file (the file is the truth; the row records it).
    nexus_window          VARCHAR(20) NOT NULL
                              CHECK (nexus_window IN ('calendar', 'trailing_12m')),
    threshold_cents       BIGINT NOT NULL CHECK (threshold_cents > 0),
    -- Taxable US sales (USD invoice subtotals, voided invoices excluded) in
    -- the evaluated window, in integer cents.
    observed_cents        BIGINT NOT NULL DEFAULT 0 CHECK (observed_cents >= 0),
    window_start          TIMESTAMPTZ NOT NULL,
    window_end            TIMESTAMPTZ NOT NULL,
    -- The crossing record. `crossed_window_start` is the window the alert
    -- belongs to, so a calendar-year state alerts at most ONCE per year and
    -- a trailing-12m crossing stays sticky (a rolling window has no new
    -- window to re-alert for).
    crossed_at            TIMESTAMPTZ,
    crossed_window_start  TIMESTAMPTZ,
    -- The operator registration record (admin surface only; the sweep never
    -- writes these).
    registered_at         TIMESTAMPTZ,
    registered_by         TEXT,
    registration_note     TEXT,
    -- Evaluation bookkeeping: when the sweep last looked at this row, and
    -- why it could not evaluate it (e.g. the rate file has no row for the
    -- state, or the row is stale) — a named reason, never a silent skip.
    last_evaluated_at     TIMESTAMPTZ,
    last_evaluation_error TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The admin read surface lists by status; the sweep reads every row.
CREATE INDEX IF NOT EXISTS idx_us_tax_nexus_states_status
    ON us_tax_nexus_states (status, state_code);

-- ---------------------------------------------------------------------------
-- 2. invoices: the stamped US sales tax (amount + provenance, atomic pair).
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'invoices'
                     AND column_name = 'us_sales_tax_cents') THEN
        ALTER TABLE invoices ADD COLUMN us_sales_tax_cents BIGINT NOT NULL DEFAULT 0;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'invoices'
                     AND column_name = 'us_sales_tax_snapshot') THEN
        ALTER TABLE invoices ADD COLUMN us_sales_tax_snapshot JSONB;
    END IF;
END
$$;

-- 0 / NULL is the "no US sales tax on this invoice" state (every historic
-- row, and every non-US invoice). A non-zero amount REQUIRES the provenance
-- snapshot and vice versa: a US tax line whose rate/source/retrieved date is
-- unknown must not be able to exist.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'chk_invoices_us_sales_tax_provenance'
                     AND conrelid = 'invoices'::regclass) THEN
        ALTER TABLE invoices
            ADD CONSTRAINT chk_invoices_us_sales_tax_provenance
            CHECK ((us_sales_tax_cents = 0 AND us_sales_tax_snapshot IS NULL)
                   OR (us_sales_tax_cents > 0 AND us_sales_tax_snapshot IS NOT NULL));
    END IF;
END
$$;

COMMENT ON TABLE us_tax_nexus_states IS
    'US economic-nexus status per state (billing-service WP C2): taxable '
    'sales tracked per window; crossings alert ONCE per window; registration '
    'is an operator action (admin surface) and is the ONLY thing that makes '
    'sales tax compute on invoices.';
COMMENT ON COLUMN invoices.us_sales_tax_cents IS
    'US state sales tax on this invoice, integer cents (billing-service '
    'us_tax module). 0 = none. Included in `total`.';
COMMENT ON COLUMN invoices.us_sales_tax_snapshot IS
    'Provenance stamp for us_sales_tax_cents: {snapshotVersion, state, '
    'rateBps, amountCents, source, retrieved} from the committed rate file.';
