-- FIX-083: Fix tenant_id type consistency across migrations
-- tenants.id is VARCHAR(26) (ULID format), so all foreign keys must match.
-- This migration fixes tables that incorrectly declared tenant_id as UUID or VARCHAR(255).

BEGIN;

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
