-- Migration 098: Billing-service schema fixes.
--
-- Closes the gap between the billing-service Rust code and the database
-- schema. Every statement below is idempotent and safe to re-run.
--
--   1. invoices.rs generate_invoice_number() reads nextval('invoice_number_seq')
--      but no migration ever created the sequence — every invoice creation
--      failed with "relation invoice_number_seq does not exist".
--   2. invoices.rs generate_invoice_pdf() updates invoices.pdf_url, which
--      no migration had added (42703 undefined_column).
--   3. stripe_webhooks.rs auto-provisioning updates
--      dedicated_ip_provisioning_requests.success_count / failure_count,
--      which did not exist (42703 undefined_column).
--   4. maintenance.rs attempt_emta_filing() stores status = 'failed' when
--      EMTA rejects a KMD return, violating the CHECK constraint from
--      migration 027 (only draft/final/filed/acknowledged were allowed).
--   5. plans.rs get_plan_for_tenant() honours admin plan overrides; the
--      active flag lets an override be disabled without deleting the row.

-- 1. Invoice numbering sequence (invoice numbers are rendered as YYYY-NNNNNN).
CREATE SEQUENCE IF NOT EXISTS invoice_number_seq START 1000;

-- 2. Public URL of the generated invoice PDF (object storage).
ALTER TABLE invoices ADD COLUMN IF NOT EXISTS pdf_url TEXT;

-- 3. Dedicated IP auto-provisioning outcome counters.
ALTER TABLE dedicated_ip_provisioning_requests
    ADD COLUMN IF NOT EXISTS success_count INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS failure_count INT NOT NULL DEFAULT 0;

-- 4. KMD return status: allow 'failed' (EMTA rejection). The original CHECK
--    from migration 027 is unnamed inline, so Postgres assigned it the
--    default name vat_kmd_returns_status_check.
ALTER TABLE vat_kmd_returns
    DROP CONSTRAINT IF EXISTS vat_kmd_returns_status_check;
ALTER TABLE vat_kmd_returns
    ADD CONSTRAINT vat_kmd_returns_status_check
    CHECK (status IN ('draft', 'final', 'filed', 'acknowledged', 'failed'));

-- 5. Plan overrides: active flag (expires_at already exists via migration 093).
ALTER TABLE plan_overrides
    ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT true;
