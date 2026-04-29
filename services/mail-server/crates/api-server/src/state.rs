//! Shared application state passed into every handler via Axum's `State` extractor.

use std::sync::Arc;

use deadpool_redis::Pool as RedisPool;
use ddos_protection::{DdosProtector, ProtectorConfig};
use reqwest::Client;
use sqlx::PgPool;

use crate::config::Config;
use crate::ip_provider::DedicatedIpProvider;
use crate::ses_provider::SesIpProvider;

/// Cheaply-cloneable handle shared across all request handlers.
pub type AppState = Arc<AppStateInner>;

/// Inner struct holding the database pool, Redis pool, config, and providers.
pub struct AppStateInner {
    pub db: PgPool,
    pub redis: RedisPool,
    pub config: Config,
    pub http_client: Client,
/// SES provider — used for shared-pool sending only (no dedicated IPs).
    pub ses_provider: SesIpProvider,
/// Dedicated IP provider (Hetzner Cloud). `None` if HETZNER_API_TOKEN is unset.
    pub ip_provider: Option<DedicatedIpProvider>,
    pub ddos_protector: Arc<DdosProtector>,
}

impl AppStateInner {
    pub async fn new(
        db: PgPool,
        redis: RedisPool,
        config: Config,
        http_client: Client,
        ses_provider: SesIpProvider,
        ip_provider: Option<DedicatedIpProvider>,
    ) -> Result<AppState, ddos_protection::DdosError> {
        let ddos_protector = Arc::new(DdosProtector::new(ProtectorConfig::default()).await?);

        Ok(Self::with_ddos_protector(
            db,
            redis,
            config,
            http_client,
            ses_provider,
            ip_provider,
            ddos_protector,
        ))
    }

    pub fn with_ddos_protector(
        db: PgPool,
        redis: RedisPool,
        config: Config,
        http_client: Client,
        ses_provider: SesIpProvider,
        ip_provider: Option<DedicatedIpProvider>,
        ddos_protector: Arc<DdosProtector>,
    ) -> AppState {
        Arc::new(Self {
            db,
            redis,
            config,
            http_client,
            ses_provider,
            ip_provider,
            ddos_protector,
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
