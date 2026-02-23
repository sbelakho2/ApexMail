//! SQL schema constants for all ApexMail tables.
//!
//! These can be executed sequentially via `sqlx::query(SQL).execute(pool)` to
//! bootstrap a fresh database. For production use run proper migrations; these
//! constants serve as a single-file reference and for integration-test setup.

/// Complete DDL for all tables, executed in dependency order.
pub const SCHEMA: &str = r#"
-- ── Tenants ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tenants (
    id          UUID PRIMARY KEY,
    name        TEXT        NOT NULL,
    slug        TEXT        NOT NULL UNIQUE,
    plan        TEXT        NOT NULL DEFAULT 'free',
    status      TEXT        NOT NULL DEFAULT 'active',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Users ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY,
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email           TEXT        NOT NULL UNIQUE,
    name            TEXT,
    password_hash   TEXT        NOT NULL,
    role            TEXT        NOT NULL DEFAULT 'member',
    status          TEXT        NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_email  ON users(email);

-- ── API Keys ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS api_keys (
    id              UUID PRIMARY KEY,
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            TEXT        NOT NULL,
    key_hash        TEXT        NOT NULL UNIQUE,
    key_prefix      TEXT        NOT NULL,
    scopes          JSONB       NOT NULL DEFAULT '[]'::jsonb,
    last_used_at    TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash   ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);

-- ── Domains ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS domains (
    id                      UUID PRIMARY KEY,
    tenant_id               UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                    TEXT        NOT NULL,
    status                  TEXT        NOT NULL DEFAULT 'pending',
    spf_verified            BOOLEAN     NOT NULL DEFAULT FALSE,
    dkim_verified           BOOLEAN     NOT NULL DEFAULT FALSE,
    dmarc_verified          BOOLEAN     NOT NULL DEFAULT FALSE,
    return_path_verified    BOOLEAN     NOT NULL DEFAULT FALSE,
    mta_sts_verified        BOOLEAN     NOT NULL DEFAULT FALSE,
    bimi_verified           BOOLEAN     NOT NULL DEFAULT FALSE,
    tlsrpt_verified         BOOLEAN     NOT NULL DEFAULT FALSE,
    dkim_selector           TEXT,
    dkim_public_key         TEXT,
    dkim_private_key        TEXT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, name)
);
CREATE INDEX IF NOT EXISTS idx_domains_tenant ON domains(tenant_id);
CREATE INDEX IF NOT EXISTS idx_domains_name   ON domains(name);

-- ── Messages ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS messages (
    id              UUID PRIMARY KEY,
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    from_email      TEXT        NOT NULL,
    to_emails       JSONB       NOT NULL,
    cc_emails       JSONB,
    bcc_emails      JSONB,
    subject         TEXT        NOT NULL,
    html_body       TEXT,
    text_body       TEXT,
    status          TEXT        NOT NULL DEFAULT 'queued',
    tags            JSONB,
    metadata        JSONB,
    scheduled_at    TIMESTAMPTZ,
    sent_at         TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_messages_tenant        ON messages(tenant_id);
CREATE INDEX IF NOT EXISTS idx_messages_status        ON messages(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_messages_created       ON messages(created_at DESC);

-- ── Events ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS events (
    id              UUID PRIMARY KEY,
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    message_id      UUID        REFERENCES messages(id) ON DELETE SET NULL,
    event_type      TEXT        NOT NULL,
    recipient       TEXT,
    metadata        JSONB,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_events_tenant     ON events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_events_message    ON events(message_id);
CREATE INDEX IF NOT EXISTS idx_events_type       ON events(tenant_id, event_type);
CREATE INDEX IF NOT EXISTS idx_events_timestamp  ON events(timestamp DESC);

-- ── Templates ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS templates (
    id              UUID PRIMARY KEY,
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            TEXT        NOT NULL,
    subject         TEXT        NOT NULL,
    html_body       TEXT        NOT NULL,
    text_body       TEXT,
    version         INT         NOT NULL DEFAULT 1,
    status          TEXT        NOT NULL DEFAULT 'draft',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, name)
);
CREATE INDEX IF NOT EXISTS idx_templates_tenant ON templates(tenant_id);

-- ── Suppressions ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS suppressions (
    id              UUID PRIMARY KEY,
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email           TEXT        NOT NULL,
    reason          TEXT        NOT NULL,
    source          TEXT        NOT NULL DEFAULT 'system',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, email)
);
CREATE INDEX IF NOT EXISTS idx_suppressions_tenant ON suppressions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_suppressions_email  ON suppressions(tenant_id, email);

-- ── Webhooks ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS webhooks (
    id              UUID PRIMARY KEY,
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    url             TEXT        NOT NULL,
    events          JSONB       NOT NULL DEFAULT '[]'::jsonb,
    secret          TEXT        NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_webhooks_tenant ON webhooks(tenant_id);

-- ── Audit Logs ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_logs (
    id              UUID PRIMARY KEY,
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    actor_id        UUID,
    action          TEXT        NOT NULL,
    resource_type   TEXT        NOT NULL,
    resource_id     TEXT,
    metadata        JSONB,
    ip_address      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant ON audit_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_time   ON audit_logs(created_at DESC);

-- ── Contacts ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS contacts (
    id              UUID PRIMARY KEY,
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email           TEXT        NOT NULL,
    name            TEXT,
    tags            JSONB,
    metadata        JSONB,
    status          TEXT        NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, email)
);
CREATE INDEX IF NOT EXISTS idx_contacts_tenant ON contacts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_contacts_email  ON contacts(tenant_id, email);

-- ── Campaigns ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS campaigns (
    id              UUID PRIMARY KEY,
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            TEXT        NOT NULL,
    subject         TEXT        NOT NULL,
    template_id     UUID        REFERENCES templates(id) ON DELETE SET NULL,
    status          TEXT        NOT NULL DEFAULT 'draft',
    scheduled_at    TIMESTAMPTZ,
    sent_count      BIGINT      NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_campaigns_tenant ON campaigns(tenant_id);
CREATE INDEX IF NOT EXISTS idx_campaigns_status ON campaigns(tenant_id, status);

-- ── Support Tickets ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS support_tickets (
    id              UUID PRIMARY KEY,
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subject         TEXT        NOT NULL,
    description     TEXT        NOT NULL,
    priority        TEXT        NOT NULL DEFAULT 'medium',
    status          TEXT        NOT NULL DEFAULT 'open',
    assigned_to     UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_support_tickets_tenant ON support_tickets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_support_tickets_status ON support_tickets(tenant_id, status);
"#;

/// Individual table DDL constants (for selective setup in tests).
pub const CREATE_TENANTS: &str = r#"
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY, name TEXT NOT NULL, slug TEXT NOT NULL UNIQUE,
    plan TEXT NOT NULL DEFAULT 'free', status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

pub const CREATE_USERS: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email TEXT NOT NULL UNIQUE, name TEXT, password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member', status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

pub const CREATE_API_KEYS: &str = r#"
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE, key_prefix TEXT NOT NULL,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb, last_used_at TIMESTAMPTZ, expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

pub const CREATE_DOMAINS: &str = r#"
CREATE TABLE IF NOT EXISTS domains (
    id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
    spf_verified BOOLEAN NOT NULL DEFAULT FALSE, dkim_verified BOOLEAN NOT NULL DEFAULT FALSE,
    dmarc_verified BOOLEAN NOT NULL DEFAULT FALSE, return_path_verified BOOLEAN NOT NULL DEFAULT FALSE,
    mta_sts_verified BOOLEAN NOT NULL DEFAULT FALSE, bimi_verified BOOLEAN NOT NULL DEFAULT FALSE,
    tlsrpt_verified BOOLEAN NOT NULL DEFAULT FALSE,
    dkim_selector TEXT, dkim_public_key TEXT, dkim_private_key TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, name)
);
"#;

pub const CREATE_MESSAGES: &str = r#"
CREATE TABLE IF NOT EXISTS messages (
    id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    from_email TEXT NOT NULL, to_emails JSONB NOT NULL, cc_emails JSONB, bcc_emails JSONB,
    subject TEXT NOT NULL, html_body TEXT, text_body TEXT,
    status TEXT NOT NULL DEFAULT 'queued', tags JSONB, metadata JSONB,
    scheduled_at TIMESTAMPTZ, sent_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

pub const CREATE_EVENTS: &str = r#"
CREATE TABLE IF NOT EXISTS events (
    id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    message_id UUID REFERENCES messages(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL, recipient TEXT, metadata JSONB,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

pub const CREATE_TEMPLATES: &str = r#"
CREATE TABLE IF NOT EXISTS templates (
    id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL, subject TEXT NOT NULL, html_body TEXT NOT NULL, text_body TEXT,
    version INT NOT NULL DEFAULT 1, status TEXT NOT NULL DEFAULT 'draft',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, name)
);
"#;

pub const CREATE_SUPPRESSIONS: &str = r#"
CREATE TABLE IF NOT EXISTS suppressions (
    id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email TEXT NOT NULL, reason TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'system',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, email)
);
"#;

pub const CREATE_WEBHOOKS: &str = r#"
CREATE TABLE IF NOT EXISTS webhooks (
    id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    url TEXT NOT NULL, events JSONB NOT NULL DEFAULT '[]'::jsonb,
    secret TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

pub const CREATE_AUDIT_LOGS: &str = r#"
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    actor_id UUID, action TEXT NOT NULL, resource_type TEXT NOT NULL, resource_id TEXT,
    metadata JSONB, ip_address TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

pub const CREATE_CONTACTS: &str = r#"
CREATE TABLE IF NOT EXISTS contacts (
    id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email TEXT NOT NULL, name TEXT, tags JSONB, metadata JSONB,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, email)
);
"#;

pub const CREATE_CAMPAIGNS: &str = r#"
CREATE TABLE IF NOT EXISTS campaigns (
    id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL, subject TEXT NOT NULL,
    template_id UUID REFERENCES templates(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'draft', scheduled_at TIMESTAMPTZ,
    sent_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

pub const CREATE_SUPPORT_TICKETS: &str = r#"
CREATE TABLE IF NOT EXISTS support_tickets (
    id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subject TEXT NOT NULL, description TEXT NOT NULL,
    priority TEXT NOT NULL DEFAULT 'medium', status TEXT NOT NULL DEFAULT 'open',
    assigned_to UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

/// Run the full schema against a pool (idempotent thanks to IF NOT EXISTS).
pub async fn run_migrations(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(SCHEMA).execute(pool).await?;
    tracing::info!("Database schema applied successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_contains_all_tables() {
        let tables = [
            "tenants", "users", "api_keys", "domains", "messages", "events",
            "templates", "suppressions", "webhooks", "audit_logs", "contacts",
            "campaigns", "support_tickets",
        ];
        for table in &tables {
            assert!(
                SCHEMA.contains(&format!("CREATE TABLE IF NOT EXISTS {}", table)),
                "Missing table: {}",
                table
            );
        }
    }

    #[test]
    fn test_individual_ddl_constants() {
        assert!(CREATE_TENANTS.contains("tenants"));
        assert!(CREATE_USERS.contains("users"));
        assert!(CREATE_API_KEYS.contains("api_keys"));
        assert!(CREATE_DOMAINS.contains("domains"));
        assert!(CREATE_MESSAGES.contains("messages"));
        assert!(CREATE_EVENTS.contains("events"));
        assert!(CREATE_TEMPLATES.contains("templates"));
        assert!(CREATE_SUPPRESSIONS.contains("suppressions"));
        assert!(CREATE_WEBHOOKS.contains("webhooks"));
        assert!(CREATE_AUDIT_LOGS.contains("audit_logs"));
        assert!(CREATE_CONTACTS.contains("contacts"));
        assert!(CREATE_CAMPAIGNS.contains("campaigns"));
        assert!(CREATE_SUPPORT_TICKETS.contains("support_tickets"));
    }

    #[test]
    fn test_schema_has_indexes() {
        assert!(SCHEMA.contains("idx_messages_tenant"));
        assert!(SCHEMA.contains("idx_events_timestamp"));
        assert!(SCHEMA.contains("idx_api_keys_hash"));
    }
}
