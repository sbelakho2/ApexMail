-- FIX-083: Fix tenant_id type consistency across migrations
-- tenants.id is VARCHAR(26) (ULID format), so all foreign keys must match.
-- This migration fixes tables that incorrectly declared tenant_id as UUID or VARCHAR(255).

BEGIN;

DO $$
DECLARE
  invalid_count BIGINT;
BEGIN
  SELECT COUNT(*) INTO invalid_count FROM sales_pipelines WHERE tenant_id IS NOT NULL AND length(tenant_id::text) > 26;
  IF invalid_count > 0 THEN
    RAISE EXCEPTION 'sales_pipelines contains % tenant_id values longer than 26 chars', invalid_count;
  END IF;

  SELECT COUNT(*) INTO invalid_count FROM sales_lead_activities WHERE tenant_id IS NOT NULL AND length(tenant_id::text) > 26;
  IF invalid_count > 0 THEN
    RAISE EXCEPTION 'sales_lead_activities contains % tenant_id values longer than 26 chars', invalid_count;
  END IF;

  SELECT COUNT(*) INTO invalid_count FROM sales_lead_tasks WHERE tenant_id IS NOT NULL AND length(tenant_id::text) > 26;
  IF invalid_count > 0 THEN
    RAISE EXCEPTION 'sales_lead_tasks contains % tenant_id values longer than 26 chars', invalid_count;
  END IF;

  SELECT COUNT(*) INTO invalid_count FROM queue_jobs WHERE tenant_id IS NOT NULL AND length(tenant_id::text) > 26;
  IF invalid_count > 0 THEN
    RAISE EXCEPTION 'queue_jobs contains % tenant_id values longer than 26 chars', invalid_count;
  END IF;
END $$;

-- sales_pipelines: UUID → VARCHAR(26)
ALTER TABLE IF EXISTS sales_pipelines
  ALTER COLUMN tenant_id TYPE VARCHAR(26);

-- sales_lead_activities: UUID → VARCHAR(26)
ALTER TABLE IF EXISTS sales_lead_activities
  ALTER COLUMN tenant_id TYPE VARCHAR(26);

-- sales_lead_tasks: UUID → VARCHAR(26)
ALTER TABLE IF EXISTS sales_lead_tasks
  ALTER COLUMN tenant_id TYPE VARCHAR(26);

-- queue_jobs: VARCHAR(255) → VARCHAR(26) (with null allowed since it was nullable)
ALTER TABLE IF EXISTS queue_jobs
  ALTER COLUMN tenant_id TYPE VARCHAR(26);

COMMIT;
