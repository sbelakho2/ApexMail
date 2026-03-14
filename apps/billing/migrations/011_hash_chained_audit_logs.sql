-- Migration 011: Make billing audit logs append-only and tamper-evident

CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS resource_id UUID,
    ADD COLUMN IF NOT EXISTS previous_hash VARCHAR(64),
    ADD COLUMN IF NOT EXISTS hash VARCHAR(64);

CREATE OR REPLACE FUNCTION billing_compute_audit_log_hash(
    p_id UUID,
    p_tenant_id VARCHAR(26),
    p_action VARCHAR(100),
    p_resource_type VARCHAR(50),
    p_resource_id UUID,
    p_metadata JSONB,
    p_previous_hash VARCHAR(64),
    p_created_at TIMESTAMPTZ
) RETURNS VARCHAR(64)
LANGUAGE SQL
AS $$
    SELECT encode(
        digest(
            concat_ws(
                '|',
                p_id::text,
                p_tenant_id,
                COALESCE(p_action, ''),
                COALESCE(p_resource_type, ''),
                COALESCE(p_resource_id::text, ''),
                COALESCE(p_metadata::text, '{}'::text),
                COALESCE(p_previous_hash, ''),
                p_created_at::text
            ),
            'sha256'
        ),
        'hex'
    );
$$;

CREATE OR REPLACE FUNCTION billing_audit_logs_before_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    prev_hash_value VARCHAR(64);
BEGIN
    IF NEW.created_at IS NULL THEN
        NEW.created_at := NOW();
    END IF;

    PERFORM pg_advisory_xact_lock(hashtext('billing_audit_logs'), hashtext(NEW.tenant_id));

    SELECT hash
      INTO prev_hash_value
      FROM audit_logs
     WHERE tenant_id = NEW.tenant_id
     ORDER BY created_at DESC, id DESC
     LIMIT 1;

    NEW.previous_hash := prev_hash_value;
    NEW.hash := billing_compute_audit_log_hash(
        NEW.id,
        NEW.tenant_id,
        NEW.action,
        NEW.resource_type,
        NEW.resource_id,
        NEW.metadata,
        prev_hash_value,
        NEW.created_at
    );

    RETURN NEW;
END;
$$;

DO $$
DECLARE
    tenant_record RECORD;
    audit_record RECORD;
    prev_hash_value VARCHAR(64);
    computed_hash VARCHAR(64);
BEGIN
    FOR tenant_record IN
        SELECT DISTINCT tenant_id
          FROM audit_logs
         ORDER BY tenant_id
    LOOP
        prev_hash_value := NULL;

        FOR audit_record IN
            SELECT id, tenant_id, action, resource_type, resource_id, metadata, created_at
              FROM audit_logs
             WHERE tenant_id = tenant_record.tenant_id
             ORDER BY created_at ASC, id ASC
        LOOP
            computed_hash := billing_compute_audit_log_hash(
                audit_record.id,
                audit_record.tenant_id,
                audit_record.action,
                audit_record.resource_type,
                audit_record.resource_id,
                audit_record.metadata,
                prev_hash_value,
                audit_record.created_at
            );

            UPDATE audit_logs
               SET previous_hash = prev_hash_value,
                   hash = computed_hash
             WHERE id = audit_record.id;

            prev_hash_value := computed_hash;
        END LOOP;
    END LOOP;
END;
$$;

ALTER TABLE audit_logs
    ALTER COLUMN hash SET NOT NULL;

CREATE OR REPLACE FUNCTION billing_prevent_audit_log_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only and cannot be modified';
END;
$$;

DROP TRIGGER IF EXISTS trg_billing_audit_logs_before_insert ON audit_logs;
CREATE TRIGGER trg_billing_audit_logs_before_insert
BEFORE INSERT ON audit_logs
FOR EACH ROW
EXECUTE FUNCTION billing_audit_logs_before_insert();

DROP TRIGGER IF EXISTS trg_billing_audit_logs_immutable ON audit_logs;
CREATE TRIGGER trg_billing_audit_logs_immutable
BEFORE UPDATE OR DELETE ON audit_logs
FOR EACH ROW
EXECUTE FUNCTION billing_prevent_audit_log_mutation();

CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_created_hash
    ON audit_logs(tenant_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_hash
    ON audit_logs(hash);