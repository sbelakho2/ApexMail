-- Migration 072: Seed system tenant and domain for email queue operations
-- The auth routes (signup, forgot-password) insert verification/reset emails
-- into the messages + email_queue tables using a SYSTEM_TENANT_ID.
-- These rows FK to tenants and domains, so the system tenant + domain must exist.

INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at)
VALUES ('system_internal_tenant01', 'ApexMail System', 'system', 'enterprise', 'active', '{}'::jsonb, '{}'::jsonb, NOW(), NOW())
ON CONFLICT (id) DO NOTHING;

INSERT INTO domains (id, tenant_id, name, status, created_at, updated_at)
VALUES ('dom_system_apexmail', 'system_internal_tenant01', 'apexmail.ee', 'verified', NOW(), NOW())
ON CONFLICT DO NOTHING;
