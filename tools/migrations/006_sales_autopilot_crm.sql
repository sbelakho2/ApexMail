-- Sales Autopilot CRM Persistence
-- Adds persistent storage for pipelines, leads, activities, and tasks

-- Pipelines stored per tenant
CREATE TABLE IF NOT EXISTS sales_pipelines (
  id VARCHAR(64) PRIMARY KEY,
  tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name VARCHAR(255) NOT NULL,
  stages JSONB NOT NULL DEFAULT '[]',
  default_stage VARCHAR(64) NOT NULL,
  won_stage VARCHAR(64) NOT NULL,
  lost_stage VARCHAR(64) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_sales_pipelines_tenant ON sales_pipelines(tenant_id);

-- Leads base table (was missing — required before ALTER statements below)
CREATE TABLE IF NOT EXISTS sales_leads (
  id VARCHAR(64) PRIMARY KEY,
  tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  company_name VARCHAR(255) NOT NULL,
  domain VARCHAR(255) NOT NULL,
  status VARCHAR(64) NOT NULL DEFAULT 'new',
  source VARCHAR(255),
  industry VARCHAR(255),
  notes TEXT,
  score INTEGER,
  contact_email VARCHAR(255),
  contact_name VARCHAR(255),
  title TEXT NOT NULL DEFAULT '',
  tags JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sales_leads_tenant ON sales_leads(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sales_leads_status ON sales_leads(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_sales_leads_created ON sales_leads(created_at DESC);

-- Leads table alignment (add missing columns)
ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS website VARCHAR(255);
ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS email VARCHAR(255);
ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS phone VARCHAR(50);
ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS title TEXT NOT NULL DEFAULT '';
ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS employee_count VARCHAR(50);
ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS revenue VARCHAR(50);
ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS technologies JSONB NOT NULL DEFAULT '[]';
ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS social_profiles JSONB NOT NULL DEFAULT '[]';
ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS location JSONB;
ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS source_url TEXT;
ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS stage VARCHAR(64) NOT NULL DEFAULT 'prospect';
ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS tags_json JSONB NOT NULL DEFAULT '[]';
ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS custom_fields JSONB NOT NULL DEFAULT '{}';
ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS mx_records JSONB NOT NULL DEFAULT '[]';
ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS email_provider VARCHAR(100);
ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS last_contacted_at TIMESTAMPTZ;
ALTER TABLE sales_leads ADD COLUMN IF NOT EXISTS next_follow_up_at TIMESTAMPTZ;

-- Activities
CREATE TABLE IF NOT EXISTS sales_lead_activities (
  id VARCHAR(64) PRIMARY KEY,
  lead_id VARCHAR(64) NOT NULL REFERENCES sales_leads(id) ON DELETE CASCADE,
  tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  type VARCHAR(64) NOT NULL,
  description TEXT NOT NULL,
  data JSONB NOT NULL DEFAULT '{}',
  user_id VARCHAR(64),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sales_lead_activities_lead ON sales_lead_activities(lead_id, created_at DESC);

-- Tasks
CREATE TABLE IF NOT EXISTS sales_lead_tasks (
  id VARCHAR(64) PRIMARY KEY,
  lead_id VARCHAR(64) NOT NULL REFERENCES sales_leads(id) ON DELETE CASCADE,
  tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  type VARCHAR(64) NOT NULL,
  priority VARCHAR(32) NOT NULL,
  status VARCHAR(32) NOT NULL,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  due_at TIMESTAMPTZ,
  assigned_to VARCHAR(64),
  completed_by VARCHAR(64),
  created_by VARCHAR(64),
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sales_lead_tasks_lead ON sales_lead_tasks(lead_id, status);
CREATE INDEX IF NOT EXISTS idx_sales_lead_tasks_due ON sales_lead_tasks(due_at) WHERE status != 'completed';
