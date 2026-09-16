//! Shared in-crate adversarial-test harness (unit-test only).
//!
//! Mirrors the provisioning convention of `tests/coverage_adversarial.rs`:
//! every test clones its OWN canonical database from the migrator template
//! for the pinned chain, so schema-level fault injection (renaming tables to
//! force SQL failures) can never affect any shared database. `TEST_DATABASE_URL`
//! unset → soft-skip (the `env_test!` macro's `if let` makes the skip arm
//! coverable). A configured provisioning failure panics.
//!
//! Fault injection:
//! * [`TestEnv::break_table`] renames a table inside the PRIVATE clone so SQL
//!   error arms (map_err/savepoint/dead-letter compensation) can be driven.
//! * [`dead_redis_pool`] returns a pool pointed at a closed local port so
//!   Redis-unavailable arms fail fast without any real network.

use std::time::Duration;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;

use crate::config::BillingConfig;
use crate::AppState;

type HmacSha256 = Hmac<Sha256>;

const MAX_DB_NAME_LEN: usize = 63;

/// Install a process-wide TRACE subscriber exactly once. Tracing macros only
/// evaluate their field expressions (`x = %expr`) when the callsite is
/// enabled; without a subscriber every dynamic field line would be an
/// uncoverable region. The formatted output goes to the sink — the point is
/// evaluating the expressions, not reading logs.
pub(crate) fn ensure_trace_subscriber() {
    static INSTALLED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if INSTALLED.set(()).is_ok() {
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(std::io::sink)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    }
}

/// The Stripe signing secret baked into every provisioned [`AppState`].
pub(crate) const TEST_STRIPE_SECRET: &str = "whsec_adversarial";

/// Serializes canonical-template clones process-wide: PostgreSQL rejects a
/// `CREATE DATABASE ... TEMPLATE x` while any other session (including a
/// concurrent cloner) touches the template (error 55006).
pub(crate) static CLONE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub(crate) struct TestEnv {
    pub state: Arc<AppState>,
    pub pool: PgPool,
    db_name: String,
    admin_url: String,
}

impl TestEnv {
    /// Drop the private database clone. Must run before the test returns.
    pub(crate) async fn finish(self) {
        self.pool.close().await;
        self.state.redis.close();
        if let Ok(admin) = PgPoolOptions::new()
            .max_connections(1)
            .connect(&self.admin_url)
            .await
        {
            let _ = sqlx::query(&format!(
                r#"DROP DATABASE IF EXISTS "{}" WITH (FORCE)"#,
                self.db_name
            ))
            .execute(&admin)
            .await;
            admin.close().await;
        }
    }

    // Schema-level fault injection (break/restore table) lives on the
    // maintenance Env (the only suites that use it); this harness kept a
    // second, unused copy.
}

fn admin_database_url(server_part: &str) -> String {
    std::env::var("TEST_DATABASE_ADMIN_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("{server_part}/postgres"))
}

fn canonical_chain_shape() -> (usize, i64) {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
    let mut count = 0_usize;
    let mut newest = 0_i64;
    for entry in std::fs::read_dir(&dir).expect("read migrations dir") {
        let name = entry.expect("migrations dir entry").file_name();
        let name = name.to_string_lossy().to_string();
        if let Some(prefix) = name.split('_').next() {
            if let Ok(version) = prefix.parse::<i64>() {
                count += 1;
                newest = newest.max(version);
            }
        }
    }
    (count, newest)
}

/// Provision a private canonical-schema database clone + Redis pool + the
/// AppState every in-crate adversarial test drives. `None` soft-skips.
pub(crate) async fn provision(tag: &str) -> Option<TestEnv> {
    ensure_trace_subscriber();
    let url = std::env::var("TEST_DATABASE_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())?;
    let (server_part, db_part) = url
        .rsplit_once('/')
        .expect("TEST_DATABASE_URL has a database segment");
    let db_only = db_part.split('?').next().unwrap_or(db_part);
    // Postgres caps identifiers at 63 bytes: derive a short deterministic
    // suffix from the (unique) test tag.
    let mut digest: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in tag.bytes() {
        digest ^= u64::from(byte);
        digest = digest.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let db_name = format!("{db_only}_tcov_{:08x}", digest & 0xffff_ffff);
    assert!(db_name.len() <= MAX_DB_NAME_LEN, "test db name too long");

    let admin_url = admin_database_url(server_part);
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(30))
        .connect(&admin_url)
        .await
        .unwrap_or_else(|error| panic!("connect admin {admin_url}: {error}"));

    let (count, newest) = canonical_chain_shape();
    let prefix = format!("apexmail_canonical_tpl_{count}_{newest}_");
    let template: String = sqlx::query_scalar(
        "SELECT datname FROM pg_database WHERE datname LIKE $1 ORDER BY datname DESC LIMIT 1",
    )
    .bind(format!("{prefix}%"))
    .fetch_optional(&admin)
    .await
    .expect("list canonical templates")
    .unwrap_or_else(|| {
        panic!(
            "no canonical template for chain ({count} migrations, newest {newest}); \
             provision by running a DB-backed test in a crate that uses migrator::test_support"
        )
    });

    sqlx::query(&format!(
        r#"DROP DATABASE IF EXISTS "{}" WITH (FORCE)"#,
        db_name
    ))
    .execute(&admin)
    .await
    .unwrap_or_else(|error| panic!("drop {db_name}: {error}"));
    // Concurrent `CREATE DATABASE ... TEMPLATE` calls see each other's
    // internal session on the template (PG 55006): serialize the clone step
    // process-wide and retry once on the transient collision.
    {
        // Bounded retry: transient holders of the template (a concurrent
        // cloner's internal session, autovacuum) release it within
        // milliseconds; 5 x 50ms is plenty and stays deterministic.
        let mut last_error = None;
        for _ in 0..5 {
            match sqlx::query(&format!(
                r#"CREATE DATABASE "{}" TEMPLATE "{}""#,
                db_name, template
            ))
            .execute(&admin)
            .await
            {
                Ok(_) => {
                    last_error = None;
                    break;
                }
                Err(error) => {
                    last_error = Some(error);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
        if let Some(error) = last_error {
            panic!("clone {db_name} from {template}: {error}");
        }
    }
    admin.close().await;

    let pool = PgPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&format!("{server_part}/{db_name}"))
        .await
        .unwrap_or_else(|error| panic!("connect {db_name}: {error}"));

    let redis_url = std::env::var("TEST_REDIS_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "redis://127.0.0.1:6379".to_string());
    let redis = deadpool_redis::Config::from_url(redis_url)
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .expect("create redis pool");

    let config = BillingConfig {
        database_url: format!("{server_part}/{db_name}"),
        redis_url: "redis://127.0.0.1:6379".to_string(),
        service_auth_token: "adversarial-service-token".to_string(),
        stripe_webhook_secret: TEST_STRIPE_SECRET.to_string(),
        api_base_url: "http://127.0.0.1:9".to_string(),
        ..BillingConfig::default()
    };
    let state = AppState::new(pool.clone(), redis.clone(), config);

    Some(TestEnv {
        state,
        pool,
        db_name,
        admin_url,
    })
}

/// A Redis pool pointed at a closed LOCAL port: every acquisition fails with
/// connection-refused immediately (no external network, deterministic).
pub(crate) fn dead_redis_pool() -> deadpool_redis::Pool {
    deadpool_redis::Config::from_url("redis://127.0.0.1:1")
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .expect("create dead pool")
}

/// A private, throwaway `redis-server` on an ephemeral LOCAL port. Tests that
/// poison shared index keys (WRONGTYPE faults, retry-ladder state) get full
/// isolation from every other test in the binary — the process-local server
/// is killed on drop.
pub(crate) struct IsolatedRedis {
    pub pool: deadpool_redis::Pool,
    child: std::process::Child,
}

impl Drop for IsolatedRedis {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub(crate) fn spawn_isolated_redis() -> IsolatedRedis {
    use std::io::BufRead;
    // redis-server has no "ephemeral port" mode (--port 0 disables the
    // listener): reserve a free port via a throwaway TCP bind, then start
    // the server on it and wait for its readiness banner.
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve a port");
        listener.local_addr().expect("local addr").port()
    };
    let mut child = std::process::Command::new("redis-server")
        .args([
            "--port",
            &port.to_string(),
            "--save",
            "",
            "--appendonly",
            "no",
            "--daemonize",
            "no",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn local redis-server");
    let stdout = child.stdout.take().expect("redis stdout");
    let mut ready = false;
    for line in std::io::BufReader::new(stdout).lines() {
        let line = line.expect("redis log line");
        if line.contains("Ready to accept connections") {
            ready = true;
            break;
        }
    }
    assert!(ready, "redis-server never became ready on port {port}");
    let pool = deadpool_redis::Config::from_url(format!("redis://127.0.0.1:{port}"))
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .expect("isolated redis pool");
    IsolatedRedis { pool, child }
}

/// Build a real Stripe-style `Stripe-Signature` header over `payload`.
pub(crate) fn sign_stripe(secret: &str, payload: &[u8], timestamp: i64) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(payload);
    format!(
        "t={timestamp},v1={}",
        hex::encode(mac.finalize().into_bytes())
    )
}

/// A lazy pool that fails on first acquire (nonexistent database): drives
/// `begin()`-failure arms deterministically without touching real servers.
pub(crate) fn broken_db_pool() -> PgPool {
    PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(500))
        .connect_lazy("postgresql://127.0.0.1:5432/apexmail_no_such_database_cov")
        .expect("lazy pool")
}

/// An AppState whose database pool fails on acquire (drives `begin()`
/// failure arms deterministically).
pub(crate) fn state_with_broken_db() -> Arc<AppState> {
    AppState::new(
        broken_db_pool(),
        dead_redis_pool(),
        BillingConfig {
            database_url: "postgresql://127.0.0.1:5432/apexmail_no_such_database_cov".to_string(),
            redis_url: "redis://127.0.0.1:6379".to_string(),
            service_auth_token: "adversarial-service-token".to_string(),
            stripe_webhook_secret: TEST_STRIPE_SECRET.to_string(),
            api_base_url: "http://127.0.0.1:9".to_string(),
            ..BillingConfig::default()
        },
    )
}

/// An AppState over `pool` with a dead Redis pool (connection refused).
pub(crate) fn state_with_dead_redis(pool: &PgPool) -> Arc<AppState> {
    AppState::new(
        pool.clone(),
        dead_redis_pool(),
        BillingConfig {
            database_url: "postgresql://127.0.0.1:5432/apexmail_no_such_database_cov".to_string(),
            redis_url: "redis://127.0.0.1:1".to_string(),
            service_auth_token: "adversarial-service-token".to_string(),
            stripe_webhook_secret: TEST_STRIPE_SECRET.to_string(),
            api_base_url: "http://127.0.0.1:9".to_string(),
            ..BillingConfig::default()
        },
    )
}

/// An AppState over `pool`/`redis` with an empty Stripe webhook secret.
pub(crate) fn state_with_empty_stripe_secret(
    pool: &PgPool,
    redis: &deadpool_redis::Pool,
    config: &BillingConfig,
) -> Arc<AppState> {
    let mut config = config.clone();
    config.stripe_webhook_secret = String::new();
    AppState::new(pool.clone(), redis.clone(), config)
}

/// Common seeding: an active tenant (unique tag prefix keeps Redis counters
/// from colliding across tests).
pub(crate) async fn seed_tenant(pool: &PgPool, tenant: &str, plan: &str) {
    sqlx::query(
        "INSERT INTO tenants (id, name, plan, status) VALUES ($1, $2, $3, 'active')
         ON CONFLICT (id) DO UPDATE SET plan = EXCLUDED.plan",
    )
    .bind(tenant)
    .bind(format!("Adversarial {tenant}"))
    .bind(plan)
    .execute(pool)
    .await
    .expect("seed tenant");
}

pub(crate) async fn seed_plan(pool: &PgPool, name: &str, price_id: &str) {
    sqlx::query(
        "INSERT INTO plans (id, name, display_name, price_cents, email_limit, api_call_limit,
                            stripe_price_id_monthly, is_active)
         VALUES ($1, $2, $2, 4900, 100000, 100000, $3, true)
         ON CONFLICT (name) DO UPDATE SET stripe_price_id_monthly = EXCLUDED.stripe_price_id_monthly,
             is_active = true",
    )
    .bind(format!("plan_{name}"))
    .bind(name)
    .bind(price_id)
    .execute(pool)
    .await
    .expect("seed plan");
}

/// Cross-process serialization for tests whose Redis keyspace is SHARED by
/// the whole suite (pending metering events, Stripe deadletters): a drain or
/// a clear-and-scan in one process otherwise races another's. A session-level
/// Postgres advisory lock on the admin database; released when the pool drops.
pub(crate) async fn redis_keys_guard(admin_url: &str, lock_name: &str) -> Option<sqlx::PgPool> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .connect(admin_url)
        .await
        .ok()?;
    sqlx::query("SELECT pg_advisory_lock(hashtext($1))")
        .bind(format!("billing-shared-redis:{lock_name}"))
        .execute(&pool)
        .await
        .ok()?;
    Some(pool)
}
