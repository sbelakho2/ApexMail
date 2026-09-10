-- Migration 126: Overage period marker
--
-- =============================================================================
-- 1. invoices.overage_period — explicit idempotency marker for the usage
--    sweeps.
--
--    The overage sweep's per-period idempotency used to gate on
--    `line_items::text LIKE '%Overage:%'` — a content scrape that breaks on
--    any wording change, cannot cover PAYG invoices (whose lines say "PAYG
--    usage"), and gave concurrent sweeps only a racy check-then-insert (the
--    sibling SLA sweep got an advisory lock for exactly this). The sweep
--    now serializes on pg_advisory_xact_lock(tenant, period) and gates on
--    this column: overage invoices store their billing_cycle_start, PAYG
--    invoices their calendar-month start, written atomically with the
--    invoice row.
--
--    Backfill: historical invoices whose line items carry the "Overage:"
--    marker inherit period_start as their marker, so the first run of the
--    new sweep cannot re-invoice an already-billed period.
--
-- 2. vat_kmd_returns UNIQUE (tax_year, tax_month) — one return per period.
--
--    KMD generation had no concurrency guard: two maintenance replicas (or
--    a backfill racing the 6-hour generator) could double-generate the
--    same period, producing two draft returns for one filing deadline.
--    The generator now also takes a pg_advisory_xact_lock per period; the
--    unique index is the schema-level backstop. Pre-existing duplicates
--    are collapsed to the latest row before the index is added.
-- =============================================================================

-- ── 1a. Marker column + lookup index ────────────────────────────────────────

ALTER TABLE invoices ADD COLUMN IF NOT EXISTS overage_period TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_invoices_overage_period
    ON invoices(tenant_id, overage_period)
    WHERE overage_period IS NOT NULL;

-- ── 1b. Backfill the marker for historical overage invoices ─────────────────
-- Idempotent: only NULL markers are touched, and the LIKE predicate is
-- evaluated against the SAME line-item text shape the old sweep wrote.

UPDATE invoices
SET overage_period = period_start
WHERE overage_period IS NULL
  AND period_start IS NOT NULL
  AND line_items::text LIKE '%Overage:%';

DO $$
DECLARE
    marked INT;
BEGIN
    SELECT COUNT(*) INTO marked FROM invoices
    WHERE overage_period IS NOT NULL;
    RAISE NOTICE '126: overage_period marker present on % invoice(s)', marked;
END
$$;

-- ── 2. One KMD return per (tax_year, tax_month) ─────────────────────────────

DO $$
DECLARE
    dup RECORD;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE indexname = 'uq_vat_kmd_returns_period'
    ) THEN
        -- Drop EARLIER duplicates for each period, keeping the most
        -- recently generated row (the one an operator most likely acted
        -- on). Rows already filed are kept preferentially.
        FOR dup IN
            SELECT id,
                   ROW_NUMBER() OVER (
                       PARTITION BY tax_year, tax_month
                       ORDER BY filed_at IS NULL, generated_at DESC, id
                   ) AS dup_rank
            FROM vat_kmd_returns
        LOOP
            IF dup.dup_rank > 1 THEN
                DELETE FROM vat_kmd_returns WHERE id = dup.id;
                RAISE NOTICE '126: removed duplicate KMD return % (rank %)', dup.id, dup.dup_rank;
            END IF;
        END LOOP;
    END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_vat_kmd_returns_period
    ON vat_kmd_returns(tax_year, tax_month);
