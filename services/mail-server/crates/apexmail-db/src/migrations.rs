//! SQL schema constants for all ApexMail tables.
//!
//! These can be executed sequentially via `sqlx::query(SQL).execute(pool)` to
//! bootstrap a fresh database. For production use run proper migrations; these
//! constants serve as a single-file reference and for integration-test setup.
//!
//! # ⚠ O-18.2 — Sequential DDL Lock Risk
//!
//! All DDL statements (`CREATE TABLE`, `CREATE INDEX`, `ALTER TABLE`) acquire
//! `ACCESS EXCLUSIVE` locks on the target table while they execute. When the
//! full schema is applied inside a **single transaction** (as `run_migrations`
//! does), every table is locked until the entire transaction commits — which
//! means concurrent readers and writers queue behind the migration transaction.
//!
//! ## Mitigation strategies
//!
//! | Strategy | Description |
//! |----------|-------------|
//! | **Lock-avoiding DDL** | Use `CREATE INDEX CONCURRENTLY` for indexes and `SET statement_timeout` per statement so a single DDL hang does not stall the entire transaction. |
//! | **Per-object transactions** | Run each `CREATE TABLE` / `CREATE INDEX` in its own transaction (separate `sqlx::query().execute()` calls) so locks are released after each statement. |
//! | **Statement timeouts** | Set `lock_timeout` (e.g. `SET lock_timeout = '5s'`) before each DDL statement so a lock-wait does not block the migration indefinitely. |
//! | **Off-peak migrations** | Schedule schema changes during maintenance windows when write traffic is minimal. |
//! | **Retry on deadlock** | In production, use a migration framework (e.g. `sqlx::migrate!`) that can retry transactions that fail due to deadlock detection. |
//!
//! The current single-transaction approach (`run_migrations`) is suitable for
//! fresh databases (integration tests, CI). For production schema changes,
//! break DDL into per-statement transactions and use `CREATE INDEX CONCURRENTLY`.
//!
//! ## Example: concurrent index creation
//! ```ignore
//! // Each index in its own transaction with non-blocking CREATE INDEX CONCURRENTLY
//! sqlx::query("CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_tenant ON users(tenant_id)")
//!     .execute(&pool)  // no BEGIN/COMMIT needed — CONCURRENTLY requires its own tx
//!     .await?;
//! ```

/// Complete DDL for all tables, executed in dependency order.
pub const SCHEMA: &str = r#"
-- ── Tenants ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tenants (
    id          VARCHAR(26) PRIMARY KEY,
    name        TEXT        NOT NULL,
    slug        TEXT        UNIQUE,
    plan        TEXT        NOT NULL DEFAULT 'free',
    status      TEXT        NOT NULL DEFAULT 'active',
    -- settings/metadata match the canonical chain (migration 052/064): the
    -- api-server writes settings JSONB and metadata JSONB NOT NULL on every
    -- tenant insert; a SCHEMA without them broke the DB-backed test suite
    -- the moment CI_TEST_DB=ephemeral started applying this bootstrap.
    settings    JSONB,
    metadata    JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Users ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id                  UUID PRIMARY KEY,
    tenant_id           VARCHAR(26)        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email               TEXT        NOT NULL UNIQUE,
    name                TEXT,
    password_hash       TEXT        NOT NULL,
    role                TEXT        NOT NULL DEFAULT 'member',
    status              TEXT        NOT NULL DEFAULT 'active',
    mfa_enabled         BOOLEAN     NOT NULL DEFAULT FALSE,
    mfa_secret          TEXT,
    mfa_recovery_hashes JSONB       NOT NULL DEFAULT '[]'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_email  ON users(email);

-- ── API Keys ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS api_keys (
    id              UUID PRIMARY KEY,
    tenant_id       VARCHAR(26)        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
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
    tenant_id               VARCHAR(26)        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
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
    tenant_id       VARCHAR(26)        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
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
    tenant_id       VARCHAR(26)        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
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
    tenant_id       VARCHAR(26)        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
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
    tenant_id       VARCHAR(26)        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
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
    tenant_id       VARCHAR(26)        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
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
    tenant_id       VARCHAR(26)        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
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
    tenant_id       VARCHAR(26)        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
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
    tenant_id       VARCHAR(26)        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
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
    tenant_id       VARCHAR(26)        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
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

-- ── Status Page Incidents ───────────────────────────────────────
-- #211:Missing tables that repos query
CREATE TABLE IF NOT EXISTS status_page_incidents (
    id              TEXT PRIMARY KEY,
    title           TEXT        NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'investigating',
    impact          TEXT        NOT NULL DEFAULT 'minor',
    affected_components TEXT[]  NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON status_page_incidents(status);

-- ── Status Page Incident Updates ────────────────────────────────
CREATE TABLE IF NOT EXISTS status_page_incident_updates (
    id              TEXT PRIMARY KEY,
    incident_id     TEXT        NOT NULL REFERENCES status_page_incidents(id) ON DELETE CASCADE,
    status          TEXT        NOT NULL,
    body            TEXT        NOT NULL,
    author          TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_incident_updates_incident ON status_page_incident_updates(incident_id);

-- ── ISP Warmup Schedules ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS isp_warmup_schedules (
    id              TEXT PRIMARY KEY,
    isp_name        TEXT        NOT NULL,
    mx_patterns     JSONB       NOT NULL DEFAULT '[]'::jsonb,
    warmup_schedule JSONB       NOT NULL DEFAULT '{}'::jsonb,
    notes           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_warmup_isp ON isp_warmup_schedules(isp_name);
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
    id UUID PRIMARY KEY, tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email TEXT NOT NULL UNIQUE, name TEXT, password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member', status TEXT NOT NULL DEFAULT 'active',
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE, mfa_secret TEXT,
    mfa_recovery_hashes JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

pub const CREATE_API_KEYS: &str = r#"
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY, tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE, key_prefix TEXT NOT NULL,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb, last_used_at TIMESTAMPTZ, expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

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

pub const CREATE_EVENTS: &str = r#"
CREATE TABLE IF NOT EXISTS events (
    id UUID PRIMARY KEY, tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    message_id UUID REFERENCES messages(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL, recipient TEXT, metadata JSONB,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

pub const CREATE_TEMPLATES: &str = r#"
CREATE TABLE IF NOT EXISTS templates (
    id UUID PRIMARY KEY, tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL, subject TEXT NOT NULL, html_body TEXT NOT NULL, text_body TEXT,
    version INT NOT NULL DEFAULT 1, status TEXT NOT NULL DEFAULT 'draft',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, name)
);
"#;

pub const CREATE_SUPPRESSIONS: &str = r#"
CREATE TABLE IF NOT EXISTS suppressions (
    id UUID PRIMARY KEY, tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email TEXT NOT NULL, reason TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'system',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, email)
);
"#;

pub const CREATE_WEBHOOKS: &str = r#"
CREATE TABLE IF NOT EXISTS webhooks (
    id UUID PRIMARY KEY, tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    url TEXT NOT NULL, events JSONB NOT NULL DEFAULT '[]'::jsonb,
    secret TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

pub const CREATE_AUDIT_LOGS: &str = r#"
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY, tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    actor_id UUID, action TEXT NOT NULL, resource_type TEXT NOT NULL, resource_id TEXT,
    metadata JSONB, ip_address TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

pub const CREATE_CONTACTS: &str = r#"
CREATE TABLE IF NOT EXISTS contacts (
    id UUID PRIMARY KEY, tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email TEXT NOT NULL, name TEXT, tags JSONB, metadata JSONB,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, email)
);
"#;

pub const CREATE_CAMPAIGNS: &str = r#"
CREATE TABLE IF NOT EXISTS campaigns (
    id UUID PRIMARY KEY, tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL, subject TEXT NOT NULL,
    template_id UUID REFERENCES templates(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'draft', scheduled_at TIMESTAMPTZ,
    sent_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

pub const CREATE_SUPPORT_TICKETS: &str = r#"
CREATE TABLE IF NOT EXISTS support_tickets (
    id UUID PRIMARY KEY, tenant_id VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subject TEXT NOT NULL, description TEXT NOT NULL,
    priority TEXT NOT NULL DEFAULT 'medium', status TEXT NOT NULL DEFAULT 'open',
    assigned_to UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

/// Run the full schema against a pool (idempotent thanks to IF NOT EXISTS).
/// DI-002: Wrapped in a transaction so a failure rolls back all changes.
pub async fn run_migrations(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(SCHEMA).execute(&mut *tx).await?;
    tx.commit().await?;
    tracing::info!("Database schema applied successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_contains_all_tables() {
        let tables = [
            "tenants",
            "users",
            "api_keys",
            "domains",
            "messages",
            "events",
            "templates",
            "suppressions",
            "webhooks",
            "audit_logs",
            "contacts",
            "campaigns",
            "support_tickets",
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

    /// Canonical-type contract: the runtime SCHEMA must agree with the
    /// migrated schema (migration 064 made every tenant id VARCHAR(26); the
    /// pre-fix SCHEMA declared tenants.id UUID and tenant_id UUID, so a
    /// runtime-provisioned database could never interoperate with a migrated
    /// one — inserts failed with type mismatches and lookups matched zero
    /// rows). Pin the shapes so the drift cannot silently return.
    #[test]
    fn schema_matches_canonical_tenant_id_types() {
        let tenants_block = SCHEMA.split("-- ── Users").next().unwrap();
        assert!(
            tenants_block.contains("id          VARCHAR(26) PRIMARY KEY"),
            "tenants.id must be VARCHAR(26) (migration 064 canonical type)"
        );
        assert!(
            !SCHEMA.contains("tenant_id           UUID"),
            "no table may declare tenant_id UUID — canonical type is VARCHAR(26)"
        );
        assert!(
            SCHEMA.contains("UNIQUE(tenant_id, email)")
                || SCHEMA.contains("UNIQUE (tenant_id, email)"),
            "suppressions must enforce UNIQUE(tenant_id, email) like migration 088"
        );
        // The ephemeral CI database is provisioned from THIS constant; the
        // api-server writes settings + metadata on every tenant insert, so a
        // bootstrap missing either column broke the whole DB-backed suite.
        assert!(
            tenants_block.contains("settings    JSONB"),
            "SCHEMA tenants must carry the canonical settings JSONB column"
        );
        assert!(
            tenants_block.contains("metadata    JSONB"),
            "SCHEMA tenants must carry the canonical metadata JSONB column"
        );
    }
}
