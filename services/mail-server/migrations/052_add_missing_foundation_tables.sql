-- 052_add_missing_foundation_tables.sql
--
-- Foundation tables required by earlier migrations but never created.
-- This migration fills 9 missing-table gaps identified by the comprehensive
-- migration audit (C-02 through C-06, C-10 through C-13).
--
-- Tables created (all with IF NOT EXISTS for idempotency):
--   1. tenants           — referenced by FKs in 021, 022, 023, 024
--   2. users             — ALTERed in 025
--   3. invoices          — FK reference in 022, ALTERed in 028
--   4. messages          — FK reference in 021
--   5. metering_events   — indexed in 026, 029, 051
--   6. domains           — indexed in 029
--   7. api_keys          — indexed in 029, 051
--   8. webhook_events    — indexed in 029, 051
--   9. dead_letter_queue — created at runtime; now in migrations
--
-- IMPORTANT: This migration is designed to run AFTER migrations 001-051.
-- For fresh deployments, earlier migrations that reference these tables via
-- inline FK constraints must also be modified (see migration 021-024 fixes).

BEGIN;

-- =============================================================================
-- 0. Column additions to existing tables
-- =============================================================================

-- C-01/C-08: Add raw_headers to email_queue (needed by session.rs:510 INSERT).
-- Handles existing deployments where migration 050 may have already run
-- without the raw_headers column in the partitioned table definition.
ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS raw_headers TEXT;

-- =============================================================================
-- 1. Tenants table
-- =============================================================================
-- Provides the core tenant record that every FK in the system references.
-- Uses UUID PK to match the UUID type used in migration 001, 020, 021, etc.
-- Also provides a VARCHAR(26) slug for ULID-based lookups used by the API.

CREATE TABLE IF NOT EXISTS tenants (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(255) NOT NULL,
    slug        VARCHAR(255) UNIQUE,
    settings    JSONB DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants(slug) WHERE slug IS NOT NULL;

-- =============================================================================
-- 2. Users table
-- =============================================================================
-- Maps to the users referenced by migration 025 and the broader auth system.

CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID REFERENCES tenants(id),
    email           VARCHAR(255) UNIQUE NOT NULL,
    password_hash   TEXT,
    role            VARCHAR(50),
    mfa_enabled     BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- =============================================================================
-- 3. Invoices table
-- =============================================================================
-- Referenced by sla_credits FK (migration 022) and ALTER TABLE (migration 028).

CREATE TABLE IF NOT EXISTS invoices (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID REFERENCES tenants(id),
    stripe_invoice_id   VARCHAR(255),
    amount              BIGINT NOT NULL DEFAULT 0,
    currency            VARCHAR(3) NOT NULL DEFAULT 'USD',
    status              VARCHAR(50) NOT NULL DEFAULT 'pending',
    due_date            TIMESTAMPTZ,
    paid_at             TIMESTAMPTZ,
    closed_at           TIMESTAMPTZ,
    issued_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_invoices_tenant ON invoices(tenant_id);
CREATE INDEX IF NOT EXISTS idx_invoices_stripe ON invoices(stripe_invoice_id);

-- =============================================================================
-- 4. Messages table
-- =============================================================================
-- Referenced by self_hosted_bounces.message_id and
-- self_hosted_complaints.message_id FKs in migration 021.
-- NOTE: This is distinct from mail_messages (which stores received mail).
-- This table tracks outbound message send metadata.

CREATE TABLE IF NOT EXISTS messages (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID REFERENCES tenants(id),
    from_address    TEXT NOT NULL,
    to_addresses    TEXT[] NOT NULL DEFAULT '{}',
    subject         TEXT,
    body            TEXT,
    status          VARCHAR(50) NOT NULL DEFAULT 'pending',
    transport       VARCHAR(10),
    source_ip       INET,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_messages_tenant ON messages(tenant_id, created_at DESC);

-- =============================================================================
-- 5. Metering Events table
-- =============================================================================
-- Indexed by migrations 026, 029, 051 for billing aggregation queries.

CREATE TABLE IF NOT EXISTS metering_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    quantity    BIGINT NOT NULL DEFAULT 1,
    metadata    JSONB DEFAULT '{}'::jsonb,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_metering_events_tenant_type_ts
    ON metering_events (tenant_id, event_type, timestamp);
CREATE INDEX IF NOT EXISTS idx_metering_events_tenant_type
    ON metering_events (tenant_id, event_type);
CREATE INDEX IF NOT EXISTS idx_metering_events_tenant_type_ts_desc
    ON metering_events (tenant_id, event_type, timestamp DESC);

-- =============================================================================
-- 6. Domains table
-- =============================================================================
-- Indexed by migration 029 for domain validation and lookup queries.

CREATE TABLE IF NOT EXISTS domains (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID REFERENCES tenants(id),
    domain          TEXT NOT NULL,
    verified        BOOLEAN NOT NULL DEFAULT false,
    dkim_enabled    BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_domains_domain ON domains(domain);
CREATE INDEX IF NOT EXISTS idx_domains_tenant ON domains(tenant_id);

-- =============================================================================
-- 7. API Keys table
-- =============================================================================
-- Indexed by migrations 029 and 051 for tenant-scoped key lookups.

CREATE TABLE IF NOT EXISTS api_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   TEXT NOT NULL,
    name        TEXT NOT NULL,
    key_hash    TEXT NOT NULL,
    key_prefix  VARCHAR(8) NOT NULL,
    scopes      JSONB DEFAULT '[]'::jsonb,
    revoked_at  TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_id ON api_keys (tenant_id, id);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_revoked
    ON api_keys (tenant_id, revoked_at)
    WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys (key_prefix);

-- =============================================================================
-- 8. Webhook Events table
-- =============================================================================
-- Indexed by migrations 029 and 051 for webhook delivery tracking.

CREATE TABLE IF NOT EXISTS webhook_events (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         TEXT NOT NULL,
    event_type        TEXT NOT NULL,
    message_id        TEXT,
    payload           JSONB NOT NULL DEFAULT '{}'::jsonb,
    delivery_status   TEXT NOT NULL DEFAULT 'pending',
    delivery_attempts INT NOT NULL DEFAULT 0,
    last_http_status  INT,
    last_error        TEXT,
    next_retry_at     TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhook_events_message_id
    ON webhook_events (message_id);
CREATE INDEX IF NOT EXISTS idx_webhook_events_tenant_delivery
    ON webhook_events (tenant_id, delivery_status, created_at);
CREATE INDEX IF NOT EXISTS idx_webhook_events_retry
    ON webhook_events (next_retry_at)
    WHERE delivery_status = 'failed' AND next_retry_at IS NOT NULL;

-- =============================================================================
-- 9. Dead Letter Queue table
-- =============================================================================
-- Previously created at runtime by application code; now explicitly managed
-- by migrations. Schema matches the CREATE TABLE IF NOT EXISTS in
-- crates/outbound-queue/src/queue.rs:380-396.

CREATE TABLE IF NOT EXISTS dead_letter_queue (
    id                  UUID PRIMARY KEY,
    original_email_id   UUID,
    from_address        TEXT NOT NULL,
    to_addresses        TEXT[] NOT NULL,
    subject             TEXT NOT NULL,
    text_body           TEXT,
    html_body           TEXT,
    headers             JSONB DEFAULT '{}'::jsonb,
    attempts            INT NOT NULL DEFAULT 0,
    max_attempts        INT NOT NULL DEFAULT 5,
    last_error          TEXT NOT NULL,
    bounce_type         TEXT,
    tenant_id           TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    dead_lettered_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dead_letter_created
    ON dead_letter_queue(dead_lettered_at);
CREATE INDEX IF NOT EXISTS idx_dead_letter_tenant
    ON dead_letter_queue(tenant_id)
    WHERE tenant_id IS NOT NULL;

-- =============================================================================
-- Add updated_at triggers for all new tables that have updated_at columns
-- =============================================================================

DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'tenants', 'users', 'invoices', 'messages',
        'api_keys', 'webhook_events'
    ]
    LOOP
        EXECUTE format('
            DROP TRIGGER IF EXISTS update_%I_updated_at ON %I;
            CREATE TRIGGER update_%I_updated_at
            BEFORE UPDATE ON %I
            FOR EACH ROW
            EXECUTE FUNCTION update_updated_at_column();
        ', t, t, t, t);
    END LOOP;
END;
$$;

COMMIT;
