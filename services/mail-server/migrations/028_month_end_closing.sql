-- Month-end closing for accounting period finalisation
-- =============================================================================
-- Adds closed_at to invoices so we can track which invoices have been through
-- month-end closing (critical for audit & accounting finalisation).
-- The month_end_closings table records each closing event with summary stats.
-- =============================================================================

-- Add closed_at column to invoices (NULL = not yet closed through month-end)
-- C-04: Guard against missing invoices table (created later in migration 052).
DO $$
BEGIN
    IF to_regclass('public.invoices') IS NOT NULL THEN
        EXECUTE 'ALTER TABLE invoices ADD COLUMN IF NOT EXISTS closed_at TIMESTAMPTZ';
    ELSE
        RAISE WARNING 'Migration 028: invoices table does not exist — skipping ALTER TABLE.';
    END IF;
END $$;

-- Month-end closing tracking table
CREATE TABLE IF NOT EXISTS month_end_closings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The tax period being closed (year and month, e.g. 2026-04 for April 2026)
    tax_year INT NOT NULL,
    tax_month INT NOT NULL CHECK (tax_month BETWEEN 1 AND 12),
    -- Closing timestamp
    closed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Summary statistics
    total_invoices INT NOT NULL DEFAULT 0,
    total_revenue_cents BIGINT NOT NULL DEFAULT 0,
    total_vat_cents BIGINT NOT NULL DEFAULT 0,
    -- Status of the closing operation
    status TEXT NOT NULL DEFAULT 'completed'
        CHECK (status IN ('pending', 'completed', 'failed')),
    -- Error message if the closing operation failed
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Unique constraint: one closing per tax period
CREATE UNIQUE INDEX IF NOT EXISTS idx_month_end_closings_period
    ON month_end_closings(tax_year, tax_month);

CREATE INDEX IF NOT EXISTS idx_month_end_closings_closed_at
    ON month_end_closings(closed_at DESC);

-- Index for finding invoices by period that need closing
DO $$
BEGIN
    IF to_regclass('public.invoices') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS idx_invoices_month_issued
            ON invoices(EXTRACT(YEAR FROM issued_at), EXTRACT(MONTH FROM issued_at))
            WHERE closed_at IS NULL';
    END IF;
END $$;

-- Index for finding unpaid invoices
DO $$
BEGIN
    IF to_regclass('public.invoices') IS NOT NULL THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS idx_invoices_closed_at
            ON invoices(closed_at)
            WHERE closed_at IS NULL';
    END IF;
END $$;
