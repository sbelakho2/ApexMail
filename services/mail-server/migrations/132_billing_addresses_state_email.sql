-- Migration 132: billing_addresses.state / .email (audit F08).
--
-- Consumers (api-server admin invoice creation, the accounting CSV export)
-- select `state` and `email` from billing_addresses, but migration 069's
-- canonical table never had them — both consumers failed with 42703. Add
-- the nullable columns with light validation: state is free-form region
-- text (bounded length), email must look like an address when present.

ALTER TABLE billing_addresses ADD COLUMN IF NOT EXISTS state VARCHAR(128);

ALTER TABLE billing_addresses ADD COLUMN IF NOT EXISTS email VARCHAR(320);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_billing_addresses_email_shape'
    ) THEN
        ALTER TABLE billing_addresses
            ADD CONSTRAINT chk_billing_addresses_email_shape
            CHECK (
                email IS NULL
                OR email ~* '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$'
            );
    END IF;
END
$$;
