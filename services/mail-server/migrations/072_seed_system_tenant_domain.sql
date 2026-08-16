-- Migration 072: Seed system tenant and domain for email queue operations
-- The auth routes (signup, forgot-password) insert verification/reset emails
-- into the messages + email_queue tables using a SYSTEM_TENANT_ID.
-- These rows FK to tenants and domains, so the system tenant + domain must exist.

INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at)
VALUES ('system_internal_tenant01', 'ApexMail System', 'system', 'enterprise', 'active', '{}'::jsonb, '{}'::jsonb, NOW(), NOW())
ON CONFLICT (id) DO NOTHING;

-- domains.id is UUID (052/056); a non-UUID literal aborts the insert.
-- Seed with a stable derived UUID and conflict on the (tenant_id, name) shape.
INSERT INTO domains (id, tenant_id, name, status, created_at, updated_at)
VALUES (
    '00000000-0000-0000-0000-0000000000d1'::uuid,
    'system_internal_tenant01',
    'apexmail.ee',
    'verified',
    NOW(),
    NOW()
)
ON CONFLICT DO NOTHING;
