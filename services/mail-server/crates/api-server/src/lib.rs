pub mod app;
pub mod config;
pub mod error;
pub mod ip_provider;
pub mod middleware;
pub mod presentation;
pub mod routes;
pub mod ses_provider;
pub mod state;

#[cfg(test)]
pub(crate) mod test_db {
    use sqlx::{postgres::PgPoolOptions, PgPool};
    use std::time::Duration;

    pub(crate) async fn optional_pg_pool(test_name: &str) -> Option<PgPool> {
        let database_url = match std::env::var("TEST_DATABASE_URL") {
            Ok(value) if !value.trim().is_empty() => value,
            _ => {
                eprintln!("skipping {test_name}: set TEST_DATABASE_URL to run DB-backed test");
                return None;
            }
        };

        Some(
            PgPoolOptions::new()
                .max_connections(2)
                .acquire_timeout(Duration::from_secs(3))
                .connect(&database_url)
                .await
                .unwrap_or_else(|error| {
                    panic!("TEST_DATABASE_URL is set but {test_name} could not connect: {error}")
                }),
        )
    }
}
