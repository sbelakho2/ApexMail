-- 101: Billing revenue-integrity fixes (audit items A / I4).
--
--   1. invoices.stripe_invoice_id needs a UNIQUE constraint so the
--      invoice.paid webhook handler can upsert idempotently with
--      ON CONFLICT (stripe_invoice_id). Existing duplicates (if any) are
--      collapsed to the newest row per stripe_invoice_id before the index
--      is created; the older duplicates are deleted.
--   2. KMD VAT buckets must be derived from the rate/country actually
--      charged on the invoice, not from the tenant's *current* billing
--      address (which may change after issuance). Capture both at creation.
--
-- All statements are idempotent and safe to re-run.

-- 1a. Collapse duplicate invoice rows per stripe_invoice_id, keeping the
--     most recent (largest issued_at, then created_at, then id).
DO $$
BEGIN
    IF to_regclass('public.invoices') IS NOT NULL THEN
        DELETE FROM invoices older
        USING invoices newer
        WHERE older.stripe_invoice_id = newer.stripe_invoice_id
          AND older.stripe_invoice_id IS NOT NULL
          AND (newer.issued_at, newer.created_at, newer.id)
              > (older.issued_at, older.created_at, older.id);
    END IF;
END $$;

-- 1b. Unique partial index (NULL stripe_invoice_id rows stay unconstrained).
CREATE UNIQUE INDEX IF NOT EXISTS uq_invoices_stripe_invoice_id
    ON invoices (stripe_invoice_id)
    WHERE stripe_invoice_id IS NOT NULL;

-- 2. Country + VAT rate captured at invoice creation time.
--    TODO(vat-history): rows created before this migration have NULL here;
--    vat_kmd falls back to the billing-address join for those.
ALTER TABLE invoices ADD COLUMN IF NOT EXISTS billing_country VARCHAR(2);
ALTER TABLE invoices ADD COLUMN IF NOT EXISTS vat_rate INTEGER;

-- 3. Fix I12 — BIGINT-safe wallet reservation release. The maintenance
--    sweeper previously computed `reserved - total_amount::integer`, which
--    overflows when the summed released reservations exceed INT range.
CREATE OR REPLACE FUNCTION release_reserved_cents(
    reserved bigint,
    released_total bigint
) RETURNS integer
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT GREATEST(0, reserved - released_total)::integer
$$;
