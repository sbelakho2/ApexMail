//! Shared application state passed into every handler via Axum's `State` extractor.

use std::sync::Arc;

use apexmail_db::pool::{PoolPair, WriteTracker};
use ddos_protection::{DdosProtector, ProtectorConfig};
use deadpool_redis::Pool as RedisPool;
use email_grader::{GraderConfig, GraderEngine, GraderState};
use inbox_placement::PlacementState;
use reqwest::Client;
use sqlx::PgPool;
use threat_intel::domain_blocklist::DomainBlocklist;

use crate::config::Config;
use crate::ip_provider::DedicatedIpProvider;
use crate::resilience::ResilientClient;
use crate::ses_provider::SesIpProvider;

/// Cheaply-cloneable handle shared across all request handlers.
pub type AppState = Arc<AppStateInner>;

/// Inner struct holding the database pool, Redis pool, config, and providers.
pub struct AppStateInner {
    pub db: PgPool,
    /// Read/write connection pool pair for primary/replica routing.
    pub pools: PoolPair,
    /// Tracks the last write for read-after-write consistency.
    pub write_tracker: std::sync::Mutex<WriteTracker>,
    pub redis: RedisPool,
    pub config: Config,
    pub http_client: Client,
    /// SES provider — used for shared-pool sending only (no dedicated IPs).
    pub ses_provider: SesIpProvider,
    /// Dedicated IP provider (Hetzner Cloud). `None` if HETZNER_API_TOKEN is unset.
    pub ip_provider: Option<DedicatedIpProvider>,
    pub ddos_protector: Arc<DdosProtector>,
    /// Pre-built grader state (engine + config + db). `None` if grader is disabled.
    pub grader_state: Option<Arc<GraderState>>,
    /// Pre-built inbox-placement state (engine + db). `None` if placement is disabled.
    pub placement_state: Option<Arc<PlacementState>>,
    /// Circuit breakers and bulkheads for upstream dependency calls.
    pub resilient: ResilientClient,
}

impl AppStateInner {
    pub async fn new(
        db: PgPool,
        pools: PoolPair,
        redis: RedisPool,
        config: Config,
        http_client: Client,
        ses_provider: SesIpProvider,
        ip_provider: Option<DedicatedIpProvider>,
    ) -> Result<AppState, ddos_protection::DdosError> {
        let ddos_protector = Arc::new(DdosProtector::new(ProtectorConfig::default()).await?);

        let grader_state = if config.grader_enabled {
            let grader_cfg = GraderConfig {
                enabled: true,
                rate_limit_max: config.grader_rate_limit,
                rate_limit_window_seconds: config.grader_rate_window_seconds,
                cache_ttl_seconds: config.grader_cache_ttl_seconds,
                max_body_size: config.grader_max_body_size as u32,
                ..Default::default()
            };
            let blocklist = DomainBlocklist::new(1000);
            match GraderEngine::new(grader_cfg.clone(), Some(Arc::new(blocklist))) {
                Ok(engine) => match GraderState::new(Arc::new(engine), grader_cfg, db.clone()) {
                    Ok(gs) => Some(Arc::new(gs)),
                    Err(e) => {
                        tracing::warn!("GraderState init failed (grader disabled): {e}");
                        None
                    }
                },
                Err(e) => {
                    tracing::warn!("GraderEngine init failed (grader disabled): {e}");
                    None
                }
            }
        } else {
            None
        };

        let placement_state = if config.placement_enabled {
            let placement_cfg = inbox_placement::PlacementConfig {
                enabled: config.placement_enabled,
                polling_interval_secs: config.placement_polling_interval_secs,
                max_polling_attempts: config.placement_max_polling_attempts,
                max_seeds_per_test: config.placement_max_seeds_per_test as usize,
                max_tests_per_hour: config.placement_max_tests_per_hour,
                imap_connection_timeout_secs: config.placement_imap_timeout_secs,
                encrypt_stored_passwords: config.placement_encrypt_passwords,
                encryption_secret: if config.placement_encrypt_passwords
                    && !config.placement_encryption_secret.is_empty()
                {
                    Some(config.placement_encryption_secret.clone())
                } else {
                    None
                },
                ..Default::default()
            };

            let analytics_client = None; // analytics can be wired in separately

            let engine = inbox_placement::PlacementEngine::with_analytics(
                placement_cfg,
                db.clone(),
                analytics_client,
            );
            let placement_state = inbox_placement::PlacementState {
                engine: Arc::new(engine),
                db: db.clone(),
            };
            Some(Arc::new(placement_state))
        } else {
            None
        };

        let resilient = ResilientClient::new_from_config(&config);

        Ok(Self::with_ddos_protector(
            db,
            pools,
            redis,
            config,
            http_client,
            ses_provider,
            ip_provider,
            ddos_protector,
            grader_state,
            placement_state,
            resilient,
        ))
    }

    pub fn with_ddos_protector(
        db: PgPool,
        pools: PoolPair,
        redis: RedisPool,
        config: Config,
        http_client: Client,
        ses_provider: SesIpProvider,
        ip_provider: Option<DedicatedIpProvider>,
        ddos_protector: Arc<DdosProtector>,
        grader_state: Option<Arc<GraderState>>,
        placement_state: Option<Arc<PlacementState>>,
        resilient: ResilientClient,
    ) -> AppState {
        Arc::new(Self {
            db,
            pools,
            write_tracker: std::sync::Mutex::new(WriteTracker::new()),
            redis,
            config,
            http_client,
            ses_provider,
            ip_provider,
            ddos_protector,
            grader_state,
            placement_state,
            resilient,
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
