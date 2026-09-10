-- Migration 081: Full-text search on audit_logs via tsvector column + GIN index.
--
-- Adds a generated tsvector column that combines action, resource, resource_id,
-- user_id, tenant_id, ip_address, and details fields for fast full-text queries.

DO $$
BEGIN
    IF to_regclass('public.audit_logs') IS NOT NULL
       -- resource/user_id/details are absent on runtime-provisioned
       -- (apexmail-db SCHEMA) audit_logs — skip FTS there.
       AND EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'audit_logs' AND column_name = 'resource')
       AND NOT EXISTS (
           SELECT 1 FROM information_schema.columns
           WHERE table_name = 'audit_logs' AND column_name = 'fts_vector'
       ) THEN
        EXECUTE 'ALTER TABLE audit_logs ADD COLUMN fts_vector tsvector';

        EXECUTE 'UPDATE audit_logs SET fts_vector =
            to_tsvector(''english'',
                coalesce(action, '''') || '' '' ||
                coalesce(resource, '''') || '' '' ||
                coalesce(resource_id, '''') || '' '' ||
                coalesce(user_id, '''') || '' '' ||
                coalesce(tenant_id, '''') || '' '' ||
                coalesce(ip_address, '''') || '' '' ||
                coalesce(details::text, '''')
            )';

        EXECUTE 'CREATE INDEX IF NOT EXISTS idx_audit_logs_fts
                 ON audit_logs USING GIN (fts_vector)';

        RAISE NOTICE '081: Added fts_vector column + GIN index to audit_logs';
    END IF;
END;
$$;
