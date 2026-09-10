-- Migration 122: invoices.vat_rate must hold fractional statutory VAT rates.
--
-- Finland's standard VAT rate is 25.5 % (since 1 September 2024). The
-- INTEGER column could not represent it, so Finnish B2C invoices were
-- rounded to 26 % — a statutory overcharge. Widen the column; existing
-- whole-number values convert losslessly.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'invoices' AND column_name = 'vat_rate'
          AND data_type = 'integer'
    ) THEN
        ALTER TABLE invoices ALTER COLUMN vat_rate TYPE DOUBLE PRECISION
            USING vat_rate::double precision;
    END IF;
END
$$;
