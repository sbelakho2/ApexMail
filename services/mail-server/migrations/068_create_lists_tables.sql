-- Migration 068: Create lists and list_subscribers tables
-- These tables are referenced by the api-server lists.rs routes but were
-- never created by any prior migration.

CREATE TABLE IF NOT EXISTS lists (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    VARCHAR(26) NOT NULL,
    name         VARCHAR(255) NOT NULL,
    description  TEXT,
    opt_in_mode  VARCHAR(20) NOT NULL DEFAULT 'double_opt_in',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_lists_tenant_name ON lists(tenant_id, name);
CREATE INDEX IF NOT EXISTS idx_lists_tenant ON lists(tenant_id);

CREATE TABLE IF NOT EXISTS list_subscribers (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    list_id      UUID NOT NULL REFERENCES lists(id) ON DELETE CASCADE,
    contact_id   UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    status       VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(list_id, contact_id)
);

CREATE INDEX IF NOT EXISTS idx_list_subscribers_list ON list_subscribers(list_id);
CREATE INDEX IF NOT EXISTS idx_list_subscribers_contact ON list_subscribers(contact_id);
CREATE INDEX IF NOT EXISTS idx_list_subscribers_status ON list_subscribers(list_id, status);
