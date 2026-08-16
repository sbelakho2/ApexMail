-- Enterprise support and SSO tables required by the Rust enterprise service.
-- These tables replace the legacy TS-owned schema assumptions with live Rust-owned backing tables.

BEGIN;

-- H-12: Own the sequence to the number column so it's cleaned up if the
-- table is dropped.
CREATE SEQUENCE IF NOT EXISTS ent_support_ticket_number_seq START WITH 1000;

CREATE TABLE IF NOT EXISTS ent_support_agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(320) NOT NULL,
    team VARCHAR(100),
    role VARCHAR(100),
    max_tickets INTEGER NOT NULL DEFAULT 10 CHECK (max_tickets >= 0),
    current_ticket_count INTEGER NOT NULL DEFAULT 0 CHECK (current_ticket_count >= 0),
    specialties TEXT[],
    available BOOLEAN NOT NULL DEFAULT TRUE,
    last_assignment_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id),
    UNIQUE (email)
);

CREATE INDEX IF NOT EXISTS idx_ent_support_agents_available_load
    ON ent_support_agents(available, current_ticket_count ASC);
CREATE INDEX IF NOT EXISTS idx_ent_support_agents_specialties
    ON ent_support_agents USING GIN(specialties);

CREATE TABLE IF NOT EXISTS ent_support_tickets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL,
    number INTEGER NOT NULL UNIQUE DEFAULT nextval('ent_support_ticket_number_seq'),
    subject VARCHAR(500) NOT NULL,
    description TEXT NOT NULL,
    category VARCHAR(100) NOT NULL,
    priority VARCHAR(50) NOT NULL DEFAULT 'medium'
        CHECK (priority IN ('critical', 'high', 'medium', 'low')),
    status VARCHAR(50) NOT NULL DEFAULT 'new'
        CHECK (status IN ('new', 'open', 'pending', 'on_hold', 'waiting_customer', 'escalated', 'resolved', 'closed')),
    assigned_to UUID REFERENCES ent_support_agents(id) ON DELETE SET NULL,
    team VARCHAR(100),
    sla_first_response_due TIMESTAMPTZ,
    sla_resolution_due TIMESTAMPTZ,
    sla_breached BOOLEAN NOT NULL DEFAULT FALSE,
    first_response_at TIMESTAMPTZ,
    escalation_level INTEGER NOT NULL DEFAULT 0 CHECK (escalation_level >= 0),
    escalated_at TIMESTAMPTZ,
    escalation_reason TEXT,
    escalated_by UUID,
    created_by VARCHAR(255) NOT NULL DEFAULT 'system',
    contact_email VARCHAR(320),
    satisfaction_rating INTEGER CHECK (satisfaction_rating BETWEEN 1 AND 5),
    satisfaction_feedback TEXT,
    tags TEXT[],
    custom_fields JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER SEQUENCE ent_support_ticket_number_seq OWNED BY ent_support_tickets.number;

CREATE INDEX IF NOT EXISTS idx_ent_support_tickets_tenant_created
    ON ent_support_tickets(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ent_support_tickets_status
    ON ent_support_tickets(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ent_support_tickets_priority
    ON ent_support_tickets(priority, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ent_support_tickets_assigned_to
    ON ent_support_tickets(assigned_to, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ent_support_tickets_sla_due
    ON ent_support_tickets(sla_first_response_due, sla_resolution_due)
    WHERE status NOT IN ('resolved', 'closed');

CREATE TABLE IF NOT EXISTS ent_ticket_comments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id UUID NOT NULL REFERENCES ent_support_tickets(id) ON DELETE CASCADE,
    author_id VARCHAR(255) NOT NULL,
    author_name VARCHAR(255) NOT NULL,
    author_type VARCHAR(50) NOT NULL,
    content TEXT NOT NULL,
    is_internal BOOLEAN NOT NULL DEFAULT FALSE,
    attachments JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_ticket_comments_ticket_created
    ON ent_ticket_comments(ticket_id, created_at ASC);

CREATE TABLE IF NOT EXISTS ent_sso_configurations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL,
    provider_type VARCHAR(50) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    domain VARCHAR(255) NOT NULL,
    metadata_url TEXT,
    entity_id TEXT,
    sso_url TEXT,
    slo_url TEXT,
    certificate TEXT,
    private_key_encrypted TEXT,
    oidc_client_id VARCHAR(255),
    oidc_client_secret_encrypted TEXT,
    oidc_issuer TEXT,
    oidc_redirect_uri TEXT,
    oidc_scopes TEXT,
    attribute_mapping JSONB,
    enforce_sso BOOLEAN NOT NULL DEFAULT FALSE,
    allow_idp_initiated BOOLEAN NOT NULL DEFAULT FALSE,
    session_duration_hours INTEGER NOT NULL DEFAULT 8 CHECK (session_duration_hours > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, domain),
    UNIQUE (domain)
);

CREATE INDEX IF NOT EXISTS idx_ent_sso_configurations_tenant
    ON ent_sso_configurations(tenant_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_ent_sso_configurations_enabled_domain
    ON ent_sso_configurations(domain)
    WHERE enabled = TRUE;

CREATE TABLE IF NOT EXISTS ent_sso_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(26) NOT NULL,
    user_id VARCHAR(255),
    provider_type VARCHAR(50) NOT NULL,
    external_user_id VARCHAR(255) NOT NULL,
    email VARCHAR(320) NOT NULL,
    display_name VARCHAR(255),
    groups JSONB,
    attributes JSONB,
    session_token VARCHAR(255) NOT NULL UNIQUE,
    access_token_encrypted TEXT,
    refresh_token_encrypted TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    last_activity_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ent_sso_sessions_tenant_external_user
    ON ent_sso_sessions(tenant_id, external_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ent_sso_sessions_expires_at
    ON ent_sso_sessions(expires_at);

CREATE TABLE IF NOT EXISTS sso_oidc_state (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    state VARCHAR(255) NOT NULL UNIQUE,
    code_verifier VARCHAR(255) NOT NULL,
    domain VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(26) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '10 minutes'
);

CREATE INDEX IF NOT EXISTS idx_sso_oidc_state_expires
    ON sso_oidc_state(expires_at);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'sso_oidc_state'
          AND column_name = 'tenant_id'
          AND udt_name = 'uuid'
    ) THEN
        -- L-05: Only truncate rows older than 5 minutes to avoid disrupting
        -- active OIDC login sessions during deployment.
        DELETE FROM sso_oidc_state WHERE created_at < NOW() - INTERVAL '5 minutes';
        ALTER TABLE sso_oidc_state
            ALTER COLUMN tenant_id TYPE VARCHAR(26) USING tenant_id::text;
    END IF;
END;
$$;

ALTER TABLE sso_oidc_state
    ADD COLUMN IF NOT EXISTS domain VARCHAR(255);

ALTER TABLE sso_oidc_state
    DROP COLUMN IF EXISTS redirect_uri;

UPDATE sso_oidc_state
SET domain = ''
WHERE domain IS NULL;

ALTER TABLE sso_oidc_state
    ALTER COLUMN domain SET NOT NULL;

DO $$
BEGIN
    IF to_regclass('public.tenants') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1
            FROM pg_constraint
            WHERE conname = 'sso_oidc_state_tenant_id_fkey'
              AND conrelid = 'public.sso_oidc_state'::regclass
        ) THEN
            ALTER TABLE sso_oidc_state
                ADD CONSTRAINT sso_oidc_state_tenant_id_fkey
                FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
        END IF;
    ELSE
        RAISE WARNING 'Migration 023: tenants table does not exist — skipping FK on sso_oidc_state.';
    END IF;
END;
$$;

DO $$
DECLARE
    table_name TEXT;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'ent_support_agents',
        'ent_support_tickets',
        'ent_sso_configurations'
    ] LOOP
        IF NOT EXISTS (
            SELECT 1
            FROM pg_trigger
            WHERE tgname = 'trg_' || table_name || '_updated_at'
        ) THEN
            EXECUTE format(
                'CREATE TRIGGER trg_%1$s_updated_at BEFORE UPDATE ON %1$s FOR EACH ROW EXECUTE FUNCTION enterprise_billing_update_updated_at_column()',
                table_name
            );
        END IF;
    END LOOP;
END;
$$;

-- ─── Additional conditional FK constraints ───────────────────
-- C-02: Add FK REFERENCES tenants(id) for tables that expected it inline.

DO $$
BEGIN
    IF to_regclass('public.tenants') IS NOT NULL THEN
        -- ent_support_tickets
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ent_support_tickets_tenant_id_fkey') THEN
            BEGIN
                EXECUTE 'ALTER TABLE ent_support_tickets ADD CONSTRAINT ent_support_tickets_tenant_id_fkey
                FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE';
            EXCEPTION WHEN OTHERS THEN
                RAISE NOTICE 'FK ent_support_tickets_tenant_id_fkey skipped (%)', SQLERRM;
            END;
        END IF;
        -- ent_sso_configurations
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ent_sso_configurations_tenant_id_fkey') THEN
            BEGIN
                EXECUTE 'ALTER TABLE ent_sso_configurations ADD CONSTRAINT ent_sso_configurations_tenant_id_fkey
                FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE';
            EXCEPTION WHEN OTHERS THEN
                RAISE NOTICE 'FK ent_sso_configurations_tenant_id_fkey skipped (%)', SQLERRM;
            END;
        END IF;
        -- ent_sso_sessions
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ent_sso_sessions_tenant_id_fkey') THEN
            BEGIN
                EXECUTE 'ALTER TABLE ent_sso_sessions ADD CONSTRAINT ent_sso_sessions_tenant_id_fkey
                FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE';
            EXCEPTION WHEN OTHERS THEN
                RAISE NOTICE 'FK ent_sso_sessions_tenant_id_fkey skipped (%)', SQLERRM;
            END;
        END IF;
    ELSE
        RAISE WARNING 'Migration 023: tenants table does not exist — skipping FK constraints.';
    END IF;
END $$;

COMMIT;