-- ApexMail Load Test Database Initialisation
-- Creates minimal schema needed for load test operations

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create basic schema for load test compatibility
CREATE SCHEMA IF NOT EXISTS apexmail;

-- Create a minimal tenants table if it doesn't exist (needed by many FK refs)
CREATE TABLE IF NOT EXISTS apexmail.tenants (
  id VARCHAR(26) PRIMARY KEY,
  name VARCHAR(255) NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create a minimal email_queue table for SMTP tests
CREATE TABLE IF NOT EXISTS apexmail.email_queue (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id VARCHAR(26) NOT NULL,
  from_email VARCHAR(255) NOT NULL,
  to_emails JSONB NOT NULL DEFAULT '[]',
  subject TEXT NOT NULL,
  text_body TEXT,
  html_body TEXT,
  raw_headers TEXT,
  status VARCHAR(50) NOT NULL DEFAULT 'pending',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_tenant FOREIGN KEY (tenant_id) REFERENCES apexmail.tenants(id)
);

-- Insert test tenant
INSERT INTO apexmail.tenants (id, name) VALUES
  ('tenant-loadtest-001', 'Load Test Tenant Alpha'),
  ('tenant-loadtest-002', 'Load Test Tenant Beta'),
  ('tenant-loadtest-003', 'Load Test Tenant Gamma')
ON CONFLICT (id) DO NOTHING;
