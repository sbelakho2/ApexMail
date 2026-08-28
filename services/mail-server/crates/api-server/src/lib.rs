#![deny(unsafe_code)]
#![allow(
    clippy::type_complexity,
    clippy::too_many_arguments,
    clippy::result_large_err
)]
pub mod app;
pub mod audit_log;
pub mod config;
pub mod error;
pub mod ip_provider;
pub mod middleware;
pub mod presentation;
pub mod resilience;
pub mod routes;
pub mod ses_provider;
pub mod state;

#[cfg(test)]
pub(crate) mod test_db {
    use sqlx::{postgres::PgPoolOptions, PgPool};
    use std::time::Duration;
    use tokio::sync::OnceCell;

    /// Serialises tests that mutate the `DKIM_PRIVATE_KEY_ENCRYPTION_KEY`
    /// process env var (env access is process-global; `cargo test` runs
    /// tests in parallel threads). Shared so route-level tests (admin
    /// domains rebind/transfer) and the signup fixtures cannot flip the
    /// key under each other mid-flight.
    pub(crate) static DKIM_ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// api-server unit tests apply `tools/migrations` against the test DB.
    /// Other test binaries (e.g. `integration-tests::integration_routes`) use
    /// runtime `CREATE TABLE IF NOT EXISTS` schemas (e.g. `sales_leads.id UUID`)
    /// that are MUTUALLY INCOMPATIBLE with those migrations
    /// (`sales_leads.id VARCHAR(64)`). To prevent cross-binary pollution of
    /// `TEST_DATABASE_URL` we route api-server tests to a dedicated database
    /// derived by appending `_api` to the dbname segment of the URL.
    ///
    /// Concurrency contract (57P01 flake fix): `cargo nextest` runs EVERY test
    /// in its own process, so a "drop + recreate once per test-binary run"
    /// bootstrap would `DROP DATABASE ... WITH (FORCE)` the shared `<db>_api`
    /// database while other concurrently-running test processes hold open
    /// connections to it — those connections are terminated with
    /// `57P01 terminating connection due to administrator command`, which
    /// used to fail a rotating handful of admin tests under parallel load.
    /// The bootstrap instead:
    ///   1. takes a session-level `pg_advisory_lock` on the admin database,
    ///      keyed by the isolated db name, so only ONE process bootstrap at a
    ///      time (the lock releases when the admin connection closes);
    ///   2. REUSES an existing healthy `<db>_api` database instead of
    ///      dropping it (tests seed unique rows and scope assertions to them,
    ///      exactly as they already do under `cargo test`'s parallel threads);
    ///   3. only drops + recreates when the database is missing, carries no
    ///      api-server marker table (a name collision with a foreign
    ///      database), or has a dirty `_sqlx_migrations` row (a previously
    ///      crashed/failed migration apply that would poison every
    ///      subsequent `Migrator::run` with `Dirty(version)`).
    pub(crate) async fn optional_pg_pool(test_name: &str) -> Option<PgPool> {
        static INIT_DB: OnceCell<()> = OnceCell::const_new();

        let database_url = match std::env::var("TEST_DATABASE_URL") {
            Ok(value) if !value.trim().is_empty() => value,
            _ => {
                eprintln!("skipping {test_name}: set TEST_DATABASE_URL to run DB-backed test");
                return None;
            }
        };

        let (server_part, db_part) = match database_url.rsplit_once('/') {
            Some((s, d)) => (s, d),
            None => {
                eprintln!("skipping {test_name}: TEST_DATABASE_URL has no database segment");
                return None;
            }
        };
        let db_only = db_part.split('?').next().unwrap_or(db_part);
        let isolated_db = format!("{db_only}_api");
        let isolated_url = format!("{server_part}/{isolated_db}");
        let admin_url = format!("{server_part}/postgres");

        INIT_DB
            .get_or_init(|| async {
                let admin = match PgPoolOptions::new()
                    .max_connections(1)
                    .acquire_timeout(Duration::from_secs(30))
                    .connect(&admin_url)
                    .await
                {
                    Ok(p) => p,
                    Err(error) => {
                        eprintln!(
                            "api-server test DB bootstrap: cannot connect to admin URL: {error}"
                        );
                        return;
                    }
                };

                // Cross-process mutex: a session advisory lock on the admin
                // database, held until `admin` (and its connection) drops.
                // The key is derived from the isolated db name so different
                // TEST_DATABASE_URL targets never contend with each other.
                if let Err(error) = sqlx::query("SELECT pg_advisory_lock(hashtext($1))")
                    .bind(&isolated_db)
                    .execute(&admin)
                    .await
                {
                    eprintln!("api-server test DB bootstrap: advisory lock failed: {error}");
                    return;
                }

                let exists: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)",
                )
                .bind(&isolated_db)
                .fetch_one(&admin)
                .await
                .unwrap_or(false);

                // Health verdict for an EXISTING database. Only POSITIVE
                // proof of an unusable database (foreign/unmarked schema, or
                // a committed dirty migration row) justifies a drop; a
                // failed probe (e.g. transient connection exhaustion under
                // a parallel nextest run) must NOT — dropping on it is what
                // massacred concurrent test processes with 57P01.
                //
                // Both checks consult pg_catalog only until the guard
                // passes: referencing `_sqlx_migrations` in SQL PARSES the
                // table even in an untaken CASE branch, which would error
                // (42P01) on a fresh database that simply has not applied
                // migrations yet — and misclassify it as unhealthy.
                // sqlx applies each migration inside a transaction, so a
                // CONCURRENT apply by another process is invisible here.
                let mut healthy = false;
                if exists {
                    for attempt in 0..3 {
                        match PgPoolOptions::new()
                            .max_connections(1)
                            .acquire_timeout(Duration::from_secs(5))
                            .connect(&isolated_url)
                            .await
                        {
                            Ok(pool) => {
                                let check_test_db_marker = || async {
                                    let marked: bool = sqlx::query_scalar(
                                        "SELECT EXISTS(SELECT 1 FROM pg_tables \
                                         WHERE schemaname = 'public' \
                                           AND tablename = '_apexmail_api_test_db')",
                                    )
                                    .fetch_one(&pool)
                                    .await
                                    .ok()?;
                                    if !marked {
                                        // Never created by this bootstrap — a
                                        // foreign database on our name.
                                        return Some(false);
                                    }
                                    let migrations_table: bool = sqlx::query_scalar(
                                        "SELECT EXISTS(SELECT 1 FROM pg_tables \
                                         WHERE schemaname = 'public' \
                                           AND tablename = '_sqlx_migrations')",
                                    )
                                    .fetch_one(&pool)
                                    .await
                                    .ok()?;
                                    if !migrations_table {
                                        // Fresh database, migrations not
                                        // applied yet — healthy.
                                        return Some(true);
                                    }
                                    // sqlx 0.8 records a failed apply as
                                    // `success = false` (there is no `dirty`
                                    // column — the pre-0.7 layout persists).
                                    let dirty: bool = sqlx::query_scalar(
                                        "SELECT EXISTS(SELECT 1 FROM _sqlx_migrations \
                                         WHERE success = false)",
                                    )
                                    .fetch_one(&pool)
                                    .await
                                    .ok()?;
                                    Some(!dirty)
                                };
                                let verdict: Option<bool> = check_test_db_marker().await;
                                pool.close().await;
                                if let Some(is_healthy) = verdict {
                                    healthy = is_healthy;
                                    break;
                                }
                            }
                            Err(_) => {
                                if attempt == 2 {
                                    // Unreachable right now — do NOT drop; the
                                    // caller's own connect below retries and
                                    // fails loudly if the database is truly
                                    // gone.
                                    healthy = true;
                                } else {
                                    tokio::time::sleep(Duration::from_millis(500)).await;
                                }
                            }
                        }
                    }
                }

                if !healthy {
                    eprintln!(
                        "api-server test DB bootstrap: creating fresh {isolated_db} \
                         (exists={exists}; missing, foreign, or poison-marked)"
                    );
                    let _ = sqlx::query(&format!(
                        "DROP DATABASE IF EXISTS \"{isolated_db}\" WITH (FORCE)"
                    ))
                    .execute(&admin)
                    .await;
                    let _ = sqlx::query(&format!("CREATE DATABASE \"{isolated_db}\""))
                        .execute(&admin)
                        .await;
                    if let Ok(pool) = PgPoolOptions::new()
                        .max_connections(1)
                        .acquire_timeout(Duration::from_secs(5))
                        .connect(&isolated_url)
                        .await
                    {
                        // Marker: identifies the database as api-server test
                        // infrastructure (guards against reusing a name-colliding
                        // foreign database forever).
                        let _ = sqlx::query(
                            "CREATE TABLE IF NOT EXISTS _apexmail_api_test_db \
                             (marker TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())",
                        )
                        .execute(&pool)
                        .await;
                        let _ = sqlx::query(
                            "INSERT INTO _apexmail_api_test_db (marker) VALUES ('api-server')",
                        )
                        .execute(&pool)
                        .await;
                        pool.close().await;
                    }
                }
                // Dropping the admin pool releases the advisory lock.
                admin.close().await;
            })
            .await;

        Some(
            PgPoolOptions::new()
                .max_connections(4)
                .acquire_timeout(Duration::from_secs(5))
                .connect(&isolated_url)
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "api-server isolated test DB ({isolated_url}) could not connect for \
                         {test_name}: {error}"
                    )
                }),
        )
    }

    /// Canonical-shape test fixture DDL (the production lineage).
    ///
    /// The `<db>_api` database used by `optional_pg_pool` carries the
    /// tools/migrations lineage, whose `users.id` is VARCHAR(26) — the
    /// OPPOSITE of production. The canonical production lineage
    /// (services/mail-server/migrations, embedded at build time by the
    /// `migrator` crate and applied before every deploy) has:
    ///
    ///   * `users.id` UUID (migration 052) — user ids are UUIDs;
    ///   * `tenants.id` / every `*_tenant_id`/`tenant_id` column
    ///     VARCHAR(26) (migration 064 standardization) — tenant ids are
    ///     26-char ULID-style text;
    ///   * campaigns/lists/domains/contacts/messages/email_queue/
    ///     system_alerts ids UUID; templates/gdpr_requests/ip_pools ids
    ///     VARCHAR(26).
    ///
    /// Handler tests that prove id-binding correctness (signup, the
    /// `WHERE id = $n` family) run against THIS shape so a green test
    /// means the bind works against production, not against the legacy
    /// test-only lineage.
    pub(crate) const CANONICAL_TEST_DDL: &str = r#"
        CREATE TABLE IF NOT EXISTS tenants (
            id          VARCHAR(26) PRIMARY KEY,
            name        TEXT        NOT NULL,
            slug        TEXT        NOT NULL UNIQUE,
            plan        TEXT        NOT NULL DEFAULT 'free',
            status      TEXT        NOT NULL DEFAULT 'active',
            settings    JSONB       NOT NULL DEFAULT '{}'::jsonb,
            metadata    JSONB       NOT NULL DEFAULT '{}'::jsonb,
            legal_hold  BOOLEAN     NOT NULL DEFAULT false,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS users (
            id                  UUID PRIMARY KEY,
            tenant_id           VARCHAR(26),
            email               VARCHAR(255) NOT NULL UNIQUE,
            password_hash       TEXT,
            name                VARCHAR(255),
            role                VARCHAR(50)  NOT NULL DEFAULT 'member',
            status              VARCHAR(20)  NOT NULL DEFAULT 'active',
            email_verified      BOOLEAN      NOT NULL DEFAULT false,
            mfa_enabled         BOOLEAN      NOT NULL DEFAULT false,
            mfa_secret          TEXT,
            mfa_recovery_hashes JSONB       NOT NULL DEFAULT '[]'::jsonb,
            username            VARCHAR(255),
            metadata            JSONB       NOT NULL DEFAULT '{}'::jsonb,
            created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_users_email  ON users(email);

        CREATE TABLE IF NOT EXISTS domains (
            id                   UUID PRIMARY KEY,
            tenant_id            VARCHAR(26),
            name                 TEXT        NOT NULL,
            status               VARCHAR(20) NOT NULL DEFAULT 'pending',
            verified             BOOLEAN     NOT NULL DEFAULT false,
            ses_verified         BOOLEAN     NOT NULL DEFAULT false,
            dkim_enabled         BOOLEAN     NOT NULL DEFAULT false,
            spf_verified         BOOLEAN,
            dkim_verified        BOOLEAN,
            dmarc_verified       BOOLEAN,
            return_path_verified BOOLEAN,
            mta_sts_verified     BOOLEAN,
            bimi_verified        BOOLEAN,
            tlsrpt_verified      BOOLEAN,
            dkim_selector        TEXT,
            dkim_public_key      TEXT,
            dkim_private_key     TEXT,
            created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(tenant_id, name)
        );

        CREATE TABLE IF NOT EXISTS messages (
            id          UUID PRIMARY KEY,
            tenant_id   VARCHAR(26),
            from_email  TEXT        NOT NULL,
            to_emails   JSONB       NOT NULL,
            cc_emails   JSONB,
            bcc_emails  JSONB,
            subject     TEXT,
            html_body   TEXT,
            text_body   TEXT,
            status      VARCHAR(50) NOT NULL DEFAULT 'queued',
            tags        JSONB,
            metadata    JSONB,
            scheduled_at TIMESTAMPTZ,
            sent_at     TIMESTAMPTZ,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_messages_status ON messages(tenant_id, status);
        CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at DESC);
        -- Migration 096: dedicated idempotency column + unique index so the
        -- send path's ON CONFLICT (tenant_id, idempotency_key) infers it.
        ALTER TABLE messages ADD COLUMN IF NOT EXISTS idempotency_key VARCHAR(255);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_tenant_idempotency_key
            ON messages (tenant_id, idempotency_key);

        -- Runtime api_keys shape (apexmail-db CREATE_API_KEYS): UUID ids,
        -- hashed secrets, prefix column for display. tenant_id follows the
        -- migration-064 VARCHAR(26) standardization like every other table.
        CREATE TABLE IF NOT EXISTS api_keys (
            id           UUID PRIMARY KEY,
            tenant_id    VARCHAR(26),
            name         TEXT        NOT NULL,
            key_hash     TEXT        NOT NULL,
            key_prefix   TEXT        NOT NULL,
            scopes       JSONB       NOT NULL DEFAULT '[]'::jsonb,
            last_used_at TIMESTAMPTZ,
            expires_at   TIMESTAMPTZ,
            created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);

        CREATE TABLE IF NOT EXISTS email_queue (
            id            UUID PRIMARY KEY,
            message_id    UUID,
            tenant_id     VARCHAR(26),
            domain_id     UUID,
            from_address  TEXT   NOT NULL,
            to_addresses  TEXT[] NOT NULL,
            subject       TEXT   NOT NULL,
            "from"        TEXT,
            "to"          TEXT,
            html          TEXT,
            text          TEXT,
            tags          TEXT[],
            metadata      JSONB  DEFAULT '{}'::jsonb,
            scheduled_at  TIMESTAMPTZ,
            priority      INTEGER NOT NULL DEFAULT 0,
            status        TEXT   NOT NULL DEFAULT 'pending',
            created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS lists (
            id          UUID PRIMARY KEY,
            tenant_id   VARCHAR(26),
            name        TEXT        NOT NULL,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS campaigns (
            id            UUID PRIMARY KEY,
            tenant_id     VARCHAR(26),
            name          TEXT        NOT NULL,
            subject       TEXT,
            status        TEXT        NOT NULL DEFAULT 'draft',
            scheduled_at  TIMESTAMPTZ,
            created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS system_alerts (
            id              UUID PRIMARY KEY,
            tenant_id       VARCHAR(26),
            severity        TEXT NOT NULL,
            alert_type      TEXT NOT NULL,
            message         TEXT NOT NULL,
            acknowledged    BOOLEAN NOT NULL DEFAULT false,
            acknowledged_by TEXT,
            acknowledged_at TIMESTAMPTZ,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    "#;

    /// A per-test isolated database carrying the CANONICAL production shape
    /// (see [`CANONICAL_TEST_DDL`]). The suffix must be unique per test so
    /// parallel tests never share it. Soft-skips without
    /// `TEST_DATABASE_URL` (workspace convention).
    pub(crate) async fn canonical_pool(db_suffix: &str) -> Option<PgPool> {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())?;
        let (server_part, db_part) = database_url.rsplit_once('/')?;
        let db_only = db_part.split('?').next().unwrap_or(db_part);
        let isolated_db = format!("{db_only}_api_canon_{db_suffix}");
        let isolated_url = format!("{server_part}/{isolated_db}");
        let admin_url = format!("{server_part}/postgres");

        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(30))
            .connect(&admin_url)
            .await
            .ok()?;
        let _ = sqlx::query(&format!(
            r#"DROP DATABASE IF EXISTS "{isolated_db}" WITH (FORCE)"#
        ))
        .execute(&admin)
        .await;
        let created = sqlx::query(&format!(r#"CREATE DATABASE "{isolated_db}""#))
            .execute(&admin)
            .await;
        admin.close().await;
        created.ok()?;

        let pool = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&isolated_url)
            .await
            .ok()?;
        sqlx::raw_sql(CANONICAL_TEST_DDL)
            .execute(&pool)
            .await
            .expect("canonical test DDL must apply");
        Some(pool)
    }
}
