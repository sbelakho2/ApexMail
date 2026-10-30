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

/// The one billing provider handle the request handlers use.
///
/// Resolved through `billing_service::payments::registry` (fail closed:
/// `PAYMENTS_PROVIDER`, never empty in production), cached after the first
/// successful resolution, and installable by the test harness with a
/// scripted double so the checkout/activation/refund path can be exercised
/// end to end without a live processor. Handlers never construct an adapter.
#[derive(Clone, Default)]
pub struct PaymentProviderHandle {
    provider: Arc<std::sync::RwLock<Option<Arc<dyn billing_service::payments::PaymentProvider>>>>,
}

impl PaymentProviderHandle {
    /// Handle with no installed provider: resolves through the registry on
    /// first use.
    pub fn from_registry() -> Self {
        Self::default()
    }

    /// A handle pinned to one provider (tests, or an operator-pinned
    /// deployment).
    pub fn installed(provider: Arc<dyn billing_service::payments::PaymentProvider>) -> Self {
        Self {
            provider: Arc::new(std::sync::RwLock::new(Some(provider))),
        }
    }

    /// Pin the provider for this state (tests call this after construction).
    pub fn install(&self, provider: Arc<dyn billing_service::payments::PaymentProvider>) {
        *self.provider.write().expect("payment provider handle lock") = Some(provider);
    }

    /// The provider: the installed one (tests / operator pin), else the
    /// registry resolved per call. A registry refusal is returned verbatim
    /// (fail closed). Deliberately NOT cached: a rotated credential or a
    /// test's environment change takes effect on the next request, and the
    /// adapter construction is cheap compared with the payment itself.
    pub fn resolve(
        &self,
    ) -> Result<
        Arc<dyn billing_service::payments::PaymentProvider>,
        billing_service::payments::RegistryError,
    > {
        if let Some(provider) = self
            .provider
            .read()
            .expect("payment provider handle lock")
            .clone()
        {
            return Ok(provider);
        }
        billing_service::payments::registry::from_env()
    }
}

impl std::fmt::Debug for PaymentProviderHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let installed = self
            .provider
            .read()
            .map(|provider| provider.is_some())
            .unwrap_or(false);
        formatter
            .debug_struct("PaymentProviderHandle")
            .field("installed", &installed)
            .finish()
    }
}

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
    /// SES provider, used for shared-pool sending only (no dedicated IPs).
    pub ses_provider: SesIpProvider,
    /// Dedicated IP provider (Hetzner Cloud). `None` if HETZNER_API_TOKEN is unset.
    pub ip_provider: Option<DedicatedIpProvider>,
    pub ddos_protector: Arc<DdosProtector>,
    /// WAF screening engine (audit F-WIRING-1 wiring). `None` when the WAF
    /// is disabled by config, the middleware is then a pass-through.
    pub waf_engine: Option<Arc<waf_engine::WafEngine>>,
    /// Pre-built grader state (engine + config + db). `None` if grader is disabled.
    pub grader_state: Option<Arc<GraderState>>,
    /// Pre-built inbox-placement state (engine + db). `None` if placement is disabled.
    pub placement_state: Option<Arc<PlacementState>>,
    /// Circuit breakers and bulkheads for upstream dependency calls.
    pub resilient: ResilientClient,
    /// Runtime feature-flag evaluation (tenant override → global row →
    /// default), with a bounded TTL cache invalidated by admin writes.
    pub feature_flags: crate::feature_flags::FeatureFlagService,
    /// The configured payment provider (registry-resolved, test-installable).
    pub payments: PaymentProviderHandle,
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

        // ONE blocklist instance shared by the grader and the feed loader,
        // regardless of whether the grader is enabled.
        let threat_blocklist = Arc::new(DomainBlocklist::new(1000));
        let grader_state = if config.grader_enabled {
            let grader_cfg = GraderConfig {
                enabled: true,
                rate_limit_max: config.grader_rate_limit,
                rate_limit_window_seconds: config.grader_rate_window_seconds,
                cache_ttl_seconds: config.grader_cache_ttl_seconds,
                max_body_size: config.grader_max_body_size as u32,
                ..Default::default()
            };
            match GraderEngine::new(grader_cfg.clone(), Some(threat_blocklist.clone())) {
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

            // Wave G: the analytics client is the placement report's summary
            // reader (`PlacementEngine::placement_summary` → measured seed
            // placement + SMTP delivery counts + recommendations). It is the
            // engine's own analytics service, so the report no longer carries
            // a stored-but-unread field.
            let analytics_client = Some(Arc::new(
                apexmail_analytics::inbox_placement::InboxPlacementService::new(db.clone()),
            ));

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

        let state = Self::with_ddos_protector(
            db,
            pools,
            redis,
            config,
            http_client.clone(),
            ses_provider,
            ip_provider,
            ddos_protector,
            grader_state,
            placement_state,
            resilient,
        );
        // Use-all audit: the grader's blocklist was constructed empty and no
        // refresh task existed. Spawn the feed loop only when feeds are
        // configured (no-op otherwise).
        crate::threat_feeds::spawn_if_configured(http_client, threat_blocklist);
        Ok(state)
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
        let waf_engine = build_waf_engine(&config);
        // Built here (not as a constructor argument) so every production and
        // test AppState constructor gets the service without touching each
        // call site's signature.
        let feature_flags = crate::feature_flags::FeatureFlagService::new(db.clone());
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
            waf_engine,
            grader_state,
            placement_state,
            resilient,
            feature_flags,
            payments: PaymentProviderHandle::from_registry(),
        })
    }
}

/// Build the WAF engine from config. `None` = disabled (the middleware
/// passes every request through). The engine itself is cheap to construct
/// (rule tables are static); one instance lives in the shared state.
fn build_waf_engine(config: &Config) -> Option<Arc<waf_engine::WafEngine>> {
    if !config.waf_enabled {
        return None;
    }
    Some(Arc::new(waf_engine::WafEngine::new(
        waf_engine::WafConfig::default(),
    )))
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
