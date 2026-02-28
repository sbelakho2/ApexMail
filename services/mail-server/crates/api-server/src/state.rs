//! Shared application state passed into every handler via Axum's `State` extractor.

use std::sync::Arc;

use deadpool_redis::Pool as RedisPool;
use reqwest::Client;
use sqlx::PgPool;

use crate::config::Config;
use crate::ses_provider::SesIpProvider;

/// Cheaply-cloneable handle shared across all request handlers.
pub type AppState = Arc<AppStateInner>;

/// Inner struct holding the database pool, Redis pool, config, and SES provider.
pub struct AppStateInner {
    pub db: PgPool,
    pub redis: RedisPool,
    pub config: Config,
    pub http_client: Client,
    pub ses_provider: SesIpProvider,
}

impl AppStateInner {
    pub fn new(
        db: PgPool,
        redis: RedisPool,
        config: Config,
        http_client: Client,
        ses_provider: SesIpProvider,
    ) -> AppState {
        Arc::new(Self {
            db,
            redis,
            config,
            http_client,
            ses_provider,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_state_is_send_sync() {
        // AppState must be Send + Sync for axum handlers.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AppState>();
    }
}
