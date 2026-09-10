-- 185: freeze the export-relevant buyer registry identity at issue time
-- (audit F08).
--
-- The accounting export's Registrikood column was sourced from mutable
-- tenant state (and in practice never populated), so a historical invoice
-- could change buyer identity after the account was edited. The full
-- billing address is already snapshotted in invoices.billing_address;
-- this adds the missing registry-code identity field, frozen at issue
-- time with the same contract. Legacy rows keep NULL and the export falls
-- back to the current tenant setting, explicitly labelled legacy.

ALTER TABLE invoices
    ADD COLUMN IF NOT EXISTS billing_registry_code VARCHAR(64);

-- Backfill from the tenant's current registry setting: for ALREADY-ISSUED
-- invoices this is the best available historical record (the field was
-- never captured before); new invoices freeze it in the writer.
UPDATE invoices i
SET billing_registry_code = t.settings->>'registryCode'
FROM tenants t
WHERE i.billing_registry_code IS NULL
  AND t.id = i.tenant_id
  AND t.settings->>'registryCode' IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_invoices_tenant_issued
    ON invoices (tenant_id, issued_at DESC);
