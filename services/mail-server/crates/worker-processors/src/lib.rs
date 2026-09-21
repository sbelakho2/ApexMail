//! ApexMail Worker Processors — Rust implementation of queue-based background workers.
//!
//! This crate provides high-performance Rust implementations of the worker processors
//! that handle background tasks:analytics aggregation, email sending, reply classification,
//! and webhook delivery.
//!
//! ## Modules
//!
//! - [`analytics`] — Event aggregation and real-time stats (Redis counters + Postgres rollups)
//! - [`email`] — Email sending pipeline (SMTP/SES, DKIM, tracking, warmup)
//! - [`reply_handler`] — Pattern-based reply classification with Aho-Corasick
//! - [`webhook`] — Webhook delivery with SSRF protection and circuit breakers
//! - [`common`] — Shared types, database pools, circuit breakers, error handling

#![deny(unsafe_code)]
pub mod analytics;
pub mod common;
pub mod email;
pub mod reply_handler;
pub mod webhook;

// Re-export main processor types
pub use analytics::AnalyticsProcessor;
pub use common::{ProcessorConfig, ProcessorError, ProcessorResult};
pub use email::EmailProcessor;
pub use reply_handler::{classify, ReplyClassification, ReplyHandler};
pub use webhook::WebhookProcessor;

/// Single crate-wide lock serializing env-mutating tests.
///
/// `std::env` is process-global, and `cargo test` runs every test of this
/// crate's binary in ONE process on parallel threads. Per-module locks do not
/// exclude each other: `email::tracking` and `email::processor` both mutate
/// `TRACKING_SECRET_KEY`, so a module-local lock let one test re-set the
/// variable while another asserted its absence (ci/README.md §9 F10 — flaky
/// under `cargo test`, invisible under nextest's process isolation). Every
/// `#[cfg(test)]` module that calls `std::env::set_var`/`remove_var` must take
/// this lock for the duration of the mutation AND the assertion.
#[cfg(test)]
pub(crate) mod test_support {
    pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Cross-process guard for tests that touch SHARED Redis keyspaces
    /// (`rl:send:*` admission buckets, warmup counters keyed on real IPs):
    /// nextest runs each test in its own process, so only a Postgres advisory
    /// lock on the shared admin database can serialize them. Hold the
    /// returned pool for the test's lifetime (the lock is session-scoped).
    pub(crate) async fn redis_keys_guard(admin_url: &str, lock_name: &str) -> Option<sqlx::PgPool> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(30))
            .connect(admin_url)
            .await
            .ok()?;
        sqlx::query("SELECT pg_advisory_lock(hashtext($1))")
            .bind(format!("worker-shared-redis:{lock_name}"))
            .execute(&pool)
            .await
            .ok()?;
        Some(pool)
    }

    /// THE one provisioning gate for every DB-backed test in this crate:
    /// per-test canonical databases (`migrator::test_support::
    /// fresh_canonical_pool`). `TEST_DATABASE_URL` unset/blank soft-skips
    /// (returns `None` — callers early-return through their one-line
    /// `let ... else { return }` guard); a configured-but-broken server is
    /// `Err` and PANICS (audit F01: infrastructure failure must fail the
    /// suite, never silently skip it).
    pub(crate) async fn canonical_pool(test_name: &str, db_suffix: &str) -> Option<sqlx::PgPool> {
        let pool = migrator::test_support::fresh_canonical_pool(test_name, db_suffix).await;
        unwrap_provisioned(pool, test_name)
    }

    /// The shared gate's Err arm: a CONFIGURED provisioning failure panics —
    /// it must fail the suite, never degrade into a silent skip. A public
    /// seam so the probe test can pin the contract without mutating
    /// `TEST_DATABASE_URL` or reaching for a dead server.
    pub(crate) fn unwrap_provisioned(
        pool: Result<Option<sqlx::PgPool>, migrator::test_support::ProvisionError>,
        label: &str,
    ) -> Option<sqlx::PgPool> {
        match pool {
            Ok(pool) => pool,
            Err(error) => panic!(
                "canonical test-database provisioning failed for {label}: {}",
                error.panic_message()
            ),
        }
    }

    /// Deterministic per-statement fault injection for the DB-backed suites:
    /// a flag table plus a BEFORE <event> trigger on `table` whose function
    /// raises while the flag row exists. Handlers span several statements, so
    /// flipping the flag between them targets the Nth statement of a handler.
    pub(crate) async fn install_fault_trigger(
        pool: &sqlx::PgPool,
        flag: &str,
        table: &str,
        event: &str,
    ) {
        sqlx::query("CREATE TABLE IF NOT EXISTS fault_injection (flag TEXT PRIMARY KEY)")
            .execute(pool)
            .await
            .expect("fault table");
        let ret = if event == "DELETE" { "OLD" } else { "NEW" };
        let fname = format!("wpf_{flag}_{event}");
        let tname = format!("wpt_{flag}_{event}");
        let create_fn = format!(
            "CREATE OR REPLACE FUNCTION {fname}() RETURNS trigger AS $$ \
             BEGIN \
               IF EXISTS (SELECT 1 FROM fault_injection WHERE flag = '{flag}') THEN \
                 RAISE EXCEPTION 'injected fault {flag}'; \
               END IF; \
               RETURN {ret}; \
             END; \
             $$ LANGUAGE plpgsql"
        );
        sqlx::query(&create_fn)
            .execute(pool)
            .await
            .expect("fault fn");
        sqlx::query(&format!("DROP TRIGGER IF EXISTS {tname} ON {table}"))
            .execute(pool)
            .await
            .expect("drop old fault trigger");
        sqlx::query(&format!(
            "CREATE TRIGGER {tname} BEFORE {event} ON {table} \
             FOR EACH ROW EXECUTE FUNCTION {fname}()"
        ))
        .execute(pool)
        .await
        .expect("fault trigger");
    }

    /// Arm / disarm a fault flag previously installed with
    /// [`install_fault_trigger`].
    pub(crate) async fn set_fault(pool: &sqlx::PgPool, flag: &str, on: bool) {
        if on {
            sqlx::query("INSERT INTO fault_injection (flag) VALUES ($1) ON CONFLICT DO NOTHING")
                .bind(flag)
                .execute(pool)
                .await
                .expect("arm fault");
        } else {
            sqlx::query("DELETE FROM fault_injection WHERE flag = $1")
                .bind(flag)
                .execute(pool)
                .await
                .expect("disarm fault");
        }
    }

    /// Pins the gate's fail-hard contract: a CONFIGURED provisioning failure
    /// (constructed here — the panic arm is the behaviour under test) must
    /// PANIC, never degrade into a silent skip (audit F01).
    #[test]
    #[should_panic(expected = "canonical test-database provisioning failed")]
    fn configured_provisioning_failure_fails_the_suite() {
        let injected = migrator::test_support::ProvisionError::new(
            "admin-connect",
            "injected probe failure — behaviour under test, not infrastructure",
        );
        let _ = unwrap_provisioned(Err(injected), "gate_probe");
    }

    /// Install a process-wide tracing subscriber for tests (idempotent).
    ///
    /// Without a subscriber the `tracing` macros short-circuit before their
    /// formatting regions run, so every `warn!`/`info!`/`error!`/`debug!`
    /// arm inside a production code path reports as never-executed even when
    /// the path itself is exercised. Installing a DEBUG-level subscriber
    /// makes those arms genuinely run (and count) while keeping `TRACE`
    /// noise (sqlx statement logs) filtered. Tests that exercise log-bearing
    /// paths call this first; `call_once` makes repeats a no-op, and the
    /// `Err` from a lost race with another thread's first install is
    /// intentionally ignored.
    pub(crate) fn install_test_tracing() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            use tracing_subscriber::EnvFilter;
            let _ = tracing_subscriber::fmt()
                .with_env_filter(
                    EnvFilter::try_new("debug").unwrap_or_else(|_| EnvFilter::new("debug")),
                )
                .with_test_writer()
                .try_init();
        });
    }
}
