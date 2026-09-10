-- Migration 087: Create scim_users and dunning_records tables.
-- These tables are queried by routes/scim.rs (SCIM user provisioning) and
-- routes/billing.rs (dunning management) but were never created by a migration,
-- causing runtime 42703 (undefined_table) errors.

-- SCIM user provisioning target table (used by routes/scim.rs SCIM user ops).
CREATE TABLE IF NOT EXISTS scim_users (
    id           VARCHAR(26) PRIMARY KEY,
    tenant_id    VARCHAR(26) NOT NULL,
    external_id  VARCHAR(255),
    email        VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    active       BOOLEAN NOT NULL DEFAULT true,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_scim_users_tenant ON scim_users (tenant_id);
CREATE INDEX IF NOT EXISTS idx_scim_users_external ON scim_users (tenant_id, external_id);

-- Dunning records table (used by routes/billing.rs dunning GET/UPDATE endpoints).
CREATE TABLE IF NOT EXISTS dunning_records (
    id             VARCHAR(26) PRIMARY KEY,
    tenant_id      VARCHAR(26) NOT NULL,
    invoice_id     VARCHAR(26),
    attempt_number INTEGER NOT NULL DEFAULT 0,
    status         VARCHAR(50) NOT NULL DEFAULT 'pending',
    amount_cents   BIGINT NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_dunning_records_tenant ON dunning_records (tenant_id);
CREATE INDEX IF NOT EXISTS idx_dunning_records_status ON dunning_records (tenant_id, status);
