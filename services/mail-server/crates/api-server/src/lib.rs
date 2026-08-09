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

    /// API-server unit tests apply `tools/migrations` against the test DB.
    /// Other test binaries (e.g. `integration-tests::integration_routes`) use
    /// runtime `CREATE TABLE IF NOT EXISTS` schemas (e.g. `sales_leads.id UUID`)
    /// that are MUTUALLY INCOMPATIBLE with those migrations
    /// (`sales_leads.id VARCHAR(64)`). To prevent cross-binary pollution of
    /// `TEST_DATABASE_URL` we route api-server tests to a dedicated database
    /// derived by appending `_api` to the dbname segment of the URL. The
    /// dedicated database is dropped + recreated once per test-binary run.
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
                    .acquire_timeout(Duration::from_secs(3))
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
                let _ = sqlx::query(&format!(
                    "DROP DATABASE IF EXISTS \"{isolated_db}\" WITH (FORCE)"
                ))
                .execute(&admin)
                .await;
                let _ = sqlx::query(&format!("CREATE DATABASE \"{isolated_db}\""))
                    .execute(&admin)
                    .await;
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
}
