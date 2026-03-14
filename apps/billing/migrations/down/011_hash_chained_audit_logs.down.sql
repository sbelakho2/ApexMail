DROP TRIGGER IF EXISTS trg_billing_audit_logs_immutable ON audit_logs;
DROP TRIGGER IF EXISTS trg_billing_audit_logs_before_insert ON audit_logs;

DROP FUNCTION IF EXISTS billing_prevent_audit_log_mutation();
DROP FUNCTION IF EXISTS billing_audit_logs_before_insert();
DROP FUNCTION IF EXISTS billing_compute_audit_log_hash(UUID, VARCHAR, VARCHAR, VARCHAR, UUID, JSONB, VARCHAR, TIMESTAMPTZ);

DROP INDEX IF EXISTS idx_audit_logs_hash;
DROP INDEX IF EXISTS idx_audit_logs_tenant_created_hash;

ALTER TABLE audit_logs
    DROP COLUMN IF EXISTS hash,
    DROP COLUMN IF EXISTS previous_hash,
    DROP COLUMN IF EXISTS resource_id;