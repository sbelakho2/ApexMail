-- Migration 273: the billing books are EUR/USD only.
--
-- Fifth external audit Tier-0 (P1): `billing-service::product_lines`
-- normalized `settings.billingCurrency` by accepting ANY syntactically valid
-- three-letter uppercase code, then priced USD tenants from the USD list and
-- everyone else from the EUR list. A `GBP` tenant therefore kept GBP on the
-- period row while the invoice line items carried the EUR numbers, i.e. GBP
-- invoices that were numerically EUR.
--
-- The application now normalizes/validates to exactly EUR|USD at every
-- product-line entry point (contract creation, period creation, invoice
-- generation, catalog price lookup) and refuses anything else with
-- `ProductLineCurrencyError::UnsupportedCurrency`. These constraints are the
-- schema backstop for every writer, including paths outside the product-line
-- module. Case-insensitive on purpose: legacy rows/invoices were written
-- lowercase (`eur`/`usd`) by `create_invoice_in_tx`, and the application
-- canonicalizes to uppercase before it stores a new period.
--
-- NOT VALID + conditional VALIDATE: a deployment carrying a pre-fix GBP row
-- must not fail the whole migration chain. New and updated rows are enforced
-- immediately; a clean table is validated inline, a dirty one raises a
-- WARNING naming the reconciliation step.

DO $$
DECLARE
    -- NOT `table_name`: that identifier collides with
    -- information_schema.columns' own output name and PL/pgSQL refuses the
    -- ambiguous reference (proven by applying this file on a live cluster).
    tbl TEXT;
    cname TEXT;
BEGIN
    FOREACH tbl IN ARRAY ARRAY['billing_periods', 'invoices', 'wallets']::text[]
    LOOP
        IF to_regclass('public.' || tbl) IS NULL THEN
            CONTINUE;
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns AS cols
            WHERE cols.table_schema = 'public'
              AND cols.table_name = tbl
              AND cols.column_name = 'currency'
        ) THEN
            CONTINUE;
        END IF;

        cname := 'chk_' || tbl || '_currency_books';
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conname = cname
              AND conrelid = ('public.' || tbl)::regclass
        ) THEN
            EXECUTE format(
                'ALTER TABLE %I ADD CONSTRAINT %I CHECK (currency IS NOT NULL AND UPPER(currency) IN (''EUR'', ''USD'')) NOT VALID',
                tbl,
                cname
            );
        END IF;

        BEGIN
            EXECUTE format(
                'SELECT 1 FROM %I WHERE currency IS NULL OR UPPER(currency) NOT IN (''EUR'', ''USD'') LIMIT 1',
                tbl
            );
            IF NOT FOUND THEN
                EXECUTE format(
                    'ALTER TABLE %I VALIDATE CONSTRAINT %I',
                    tbl,
                    cname
                );
            ELSE
                RAISE WARNING '% contains currency values outside EUR/USD; % left NOT VALID, reconcile the rows and run ALTER TABLE % VALIDATE CONSTRAINT %',
                    tbl, cname, tbl, cname;
            END IF;
        EXCEPTION
            WHEN OTHERS THEN
                RAISE WARNING 'could not validate % on %: %', cname, tbl, SQLERRM;
        END;
    END LOOP;
END
$$;
