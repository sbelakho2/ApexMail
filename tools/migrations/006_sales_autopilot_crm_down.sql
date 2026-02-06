-- Sales Autopilot CRM Persistence (Rollback)

DROP INDEX IF EXISTS idx_sales_lead_tasks_due;
DROP INDEX IF EXISTS idx_sales_lead_tasks_lead;
DROP TABLE IF EXISTS sales_lead_tasks;

DROP INDEX IF EXISTS idx_sales_lead_activities_lead;
DROP TABLE IF EXISTS sales_lead_activities;

DROP INDEX IF EXISTS idx_sales_pipelines_tenant;
DROP TABLE IF EXISTS sales_pipelines;

-- Columns removal (non-destructive in practice; keep data if rollbacks needed)
ALTER TABLE sales_leads DROP COLUMN IF EXISTS website;
ALTER TABLE sales_leads DROP COLUMN IF EXISTS email;
ALTER TABLE sales_leads DROP COLUMN IF EXISTS email_verified;
ALTER TABLE sales_leads DROP COLUMN IF EXISTS phone;
ALTER TABLE sales_leads DROP COLUMN IF EXISTS employee_count;
ALTER TABLE sales_leads DROP COLUMN IF EXISTS revenue;
ALTER TABLE sales_leads DROP COLUMN IF EXISTS technologies;
ALTER TABLE sales_leads DROP COLUMN IF EXISTS social_profiles;
ALTER TABLE sales_leads DROP COLUMN IF EXISTS location;
ALTER TABLE sales_leads DROP COLUMN IF EXISTS source_url;
ALTER TABLE sales_leads DROP COLUMN IF EXISTS stage;
ALTER TABLE sales_leads DROP COLUMN IF EXISTS tags_json;
ALTER TABLE sales_leads DROP COLUMN IF EXISTS custom_fields;
ALTER TABLE sales_leads DROP COLUMN IF EXISTS mx_records;
ALTER TABLE sales_leads DROP COLUMN IF EXISTS email_provider;
ALTER TABLE sales_leads DROP COLUMN IF EXISTS last_contacted_at;
ALTER TABLE sales_leads DROP COLUMN IF EXISTS next_follow_up_at;
