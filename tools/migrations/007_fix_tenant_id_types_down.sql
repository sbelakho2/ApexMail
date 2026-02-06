-- Rollback FIX-083: Revert tenant_id types
BEGIN;

ALTER TABLE IF EXISTS sales_pipelines ALTER COLUMN tenant_id TYPE UUID USING tenant_id::uuid;
ALTER TABLE IF EXISTS sales_lead_activities ALTER COLUMN tenant_id TYPE UUID USING tenant_id::uuid;
ALTER TABLE IF EXISTS sales_lead_tasks ALTER COLUMN tenant_id TYPE UUID USING tenant_id::uuid;
ALTER TABLE IF EXISTS queue_jobs ALTER COLUMN tenant_id TYPE VARCHAR(255);

COMMIT;
