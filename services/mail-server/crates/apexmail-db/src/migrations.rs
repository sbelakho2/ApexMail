//! Individual table DDL constants (for selective setup in tests).
//!
//! # Bootstrapping a database
//!
//! There is deliberately NO monolithic `SCHEMA` constant or `run_migrations`
//! helper here anymore (audit F6): the old single-file "reference schema"
//! drifted from the canonical migration chain — it declared
//! `campaigns.template_id UUID REFERENCES templates(id)` while `templates.id`
//! is `VARCHAR(26)` (migrations 064/075), a foreign key PostgreSQL rejects
//! between incompatible types. `run_migrations` therefore could never execute
//! successfully against a fresh database, and its string-`contains` tests
//! passed despite the broken DDL.
//!
//! The single source of truth is the canonical migration chain in
//! `services/mail-server/migrations/`, applied by the `migrator` crate. For
//! tests use `migrator::test_support::fresh_canonical_pool` (or
//! `apply_canonical_migrations`) so a green test means the code works against
//! the byte-for-byte deploy-time schema.
//!
//! The per-table `CREATE_*` constants below remain only for tests that need
//! to stand up ONE table in isolation. Several reference sibling tables and
//! therefore require those parents to exist first — they are not a schema
//! reference and MUST NOT be used to provision a database.

/// Individual table DDL constant (for selective setup in tests).
pub const CREATE_TENANTS: &str = r#"
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY, name TEXT NOT NULL, slug TEXT NOT NULL UNIQUE,
    plan TEXT NOT NULL DEFAULT 'free', status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

/// Individual table DDL constant (for selective setup in tests).
pub const CREATE_USERS: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY, tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email TEXT NOT NULL UNIQUE, name TEXT, password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member', status TEXT NOT NULL DEFAULT 'active',
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE, mfa_secret TEXT,
    mfa_recovery_hashes JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

/// Individual table DDL constant (for selective setup in tests).
pub const CREATE_API_KEYS: &str = r#"
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY, tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE, key_prefix TEXT NOT NULL,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb, last_used_at TIMESTAMPTZ, expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

/// Individual table DDL constant (for selective setup in tests).
pub const CREATE_DOMAINS: &str = r#"
CREATE TABLE IF NOT EXISTS domains (
    id UUID PRIMARY KEY, tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
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

/// Individual table DDL constant (for selective setup in tests).
pub const CREATE_MESSAGES: &str = r#"
CREATE TABLE IF NOT EXISTS messages (
    id UUID PRIMARY KEY, tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    from_email TEXT NOT NULL, to_emails JSONB NOT NULL, cc_emails JSONB, bcc_emails JSONB,
    subject TEXT NOT NULL, html_body TEXT, text_body TEXT,
    status TEXT NOT NULL DEFAULT 'queued', tags JSONB, metadata JSONB,
    scheduled_at TIMESTAMPTZ, sent_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

/// Individual table DDL constant (for selective setup in tests).
pub const CREATE_EVENTS: &str = r#"
CREATE TABLE IF NOT EXISTS events (
    id VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(26) NOT NULL,
    message_id VARCHAR(64), domain_id TEXT, campaign_id TEXT,
    event_type VARCHAR(50) NOT NULL, recipient VARCHAR(255), metadata JSONB DEFAULT '{}',
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

/// Individual table DDL constant (for selective setup in tests).
pub const CREATE_TEMPLATES: &str = r#"
CREATE TABLE IF NOT EXISTS templates (
    id VARCHAR(26) PRIMARY KEY, tenant_id VARCHAR(26) NOT NULL,
    name VARCHAR(255) NOT NULL, subject VARCHAR(255) NOT NULL,
    html_body TEXT NOT NULL, text_body TEXT,
    version INTEGER NOT NULL DEFAULT 1, status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

/// Individual table DDL constant (for selective setup in tests).
pub const CREATE_SUPPRESSIONS: &str = r#"
CREATE TABLE IF NOT EXISTS suppressions (
    id VARCHAR(26) PRIMARY KEY, tenant_id VARCHAR(26) NOT NULL,
    email VARCHAR(255) NOT NULL, reason VARCHAR(50) NOT NULL, subtype VARCHAR(100),
    source VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ,
    UNIQUE (tenant_id, email)
);
"#;

/// Individual table DDL constant (for selective setup in tests).
pub const CREATE_WEBHOOKS: &str = r#"
CREATE TABLE IF NOT EXISTS webhooks (
    id VARCHAR(26) PRIMARY KEY, tenant_id VARCHAR(26) NOT NULL,
    url VARCHAR(2048) NOT NULL, events JSONB NOT NULL DEFAULT '["*"]'::jsonb,
    secret VARCHAR(255) NOT NULL, previous_secret VARCHAR(255),
    status VARCHAR(20) NOT NULL DEFAULT 'active', enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

/// Individual table DDL constant (for selective setup in tests).
pub const CREATE_AUDIT_LOGS: &str = r#"
CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY, tenant_id TEXT, user_id TEXT, session_id TEXT,
    action TEXT NOT NULL, resource TEXT NOT NULL, resource_id TEXT,
    details JSONB NOT NULL DEFAULT '{}'::jsonb, ip_address TEXT, user_agent TEXT,
    outcome TEXT NOT NULL, error_message TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hash TEXT NOT NULL, previous_hash TEXT, signature TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS audit_logs_archive (LIKE audit_logs INCLUDING ALL);
"#;

/// Individual table DDL constant (for selective setup in tests).
pub const CREATE_CONTACTS: &str = r#"
CREATE TABLE IF NOT EXISTS contacts (
    id UUID PRIMARY KEY, tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email TEXT NOT NULL, name TEXT, tags JSONB, metadata JSONB,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, email)
);
"#;

/// Individual table DDL constant (for selective setup in tests).
///
/// `template_id` is a bare `UUID`, exactly as canonical migration 075
/// declares it — the former `REFERENCES templates(id)` here was the SAME
/// type-incompatible foreign key audit F6 removed with `SCHEMA`
/// (`templates.id` is `VARCHAR(26)`), and no FK exists in canonical either.
pub const CREATE_CAMPAIGNS: &str = r#"
CREATE TABLE IF NOT EXISTS campaigns (
    id UUID PRIMARY KEY, tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL, subject TEXT NOT NULL,
    template_id UUID,
    status TEXT NOT NULL DEFAULT 'draft', scheduled_at TIMESTAMPTZ,
    sent_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

/// Individual table DDL constant (for selective setup in tests).
pub const CREATE_SUPPORT_TICKETS: &str = r#"
CREATE TABLE IF NOT EXISTS support_tickets (
    id VARCHAR(26) PRIMARY KEY, tenant_id VARCHAR(26),
    subject VARCHAR(500) NOT NULL, description TEXT NOT NULL DEFAULT '',
    tenant_name VARCHAR(255), tenant_email VARCHAR(255),
    status VARCHAR(30) NOT NULL DEFAULT 'open', priority VARCHAR(20) NOT NULL DEFAULT 'normal',
    category VARCHAR(50), assigned_to VARCHAR(26), assignee VARCHAR(255), resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

#[cfg(test)]
mod tests {
    use super::*;

    /// The per-table constants stay compile-checked and shape-checked; the
    /// monolithic `SCHEMA` (and its string-`contains` suite) was DELETED in
    /// audit F6 — it could never execute against a fresh database
    /// (`campaigns.template_id UUID` → `templates.id` VARCHAR(26) FK) and
    /// its presence invited drift from the canonical migration chain.
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

    /// F6 contract: every constant is a SINGLE self-contained CREATE TABLE
    /// statement (tests may apply one table in isolation) — never a chained
    /// bootstrap script pretending to be a schema.
    #[test]
    fn constants_are_single_table_ddl() {
        for (name, ddl) in [
            ("tenants", CREATE_TENANTS),
            ("users", CREATE_USERS),
            ("api_keys", CREATE_API_KEYS),
            ("domains", CREATE_DOMAINS),
            ("messages", CREATE_MESSAGES),
            ("events", CREATE_EVENTS),
            ("templates", CREATE_TEMPLATES),
            ("suppressions", CREATE_SUPPRESSIONS),
            ("webhooks", CREATE_WEBHOOKS),
            ("audit_logs", CREATE_AUDIT_LOGS),
            ("contacts", CREATE_CONTACTS),
            ("campaigns", CREATE_CAMPAIGNS),
            ("support_tickets", CREATE_SUPPORT_TICKETS),
        ] {
            let creates = ddl.matches("CREATE TABLE").count();
            assert!(
                creates == 1 || name == "audit_logs",
                "{name} must declare exactly one CREATE TABLE (audit_logs carries its archive twin), got {creates}"
            );
            // F6 re-check: no constant may re-introduce the type-incompatible
            // `UUID → VARCHAR(26)` foreign key to `templates(id)` that made
            // the old monolithic SCHEMA unexecutable (canonical 075 declares
            // campaigns.template_id as a bare UUID with no FK).
            assert!(
                !ddl.contains("REFERENCES templates"),
                "{name} must not declare a foreign key to templates(id): the canonical \
                 templates.id is VARCHAR(26) and no UUID→VARCHAR FK exists in canonical"
            );
        }
    }
}
