//! Shared application state threaded through every axum handler via `Extension`.
//!
//! All fields are wrapped in `Arc` so cloning the struct is cheap. The state
//! is constructed once in `main.rs` and then immutably shared across every
//! Tokio task and request handler.

use std::sync::Arc;

use moka::future::Cache;
use sqlx::PgPool;

use crate::bot::BotDetector;
use crate::codec::TrackingCodec;
use crate::config::Config;
use crate::processor::EventProcessor;

/// The single source-of-truth for shared resources passed to axum extractors.
/// Cloning is O(1) — every field is either `Arc<T>` or `Clone + Copy`.
#[derive(Clone)]
pub struct AppState {
    /// AES-128-GCM codec for encoding / decoding tracking tokens.
    pub codec: Arc<TrackingCodec>,

    /// PostgreSQL connection pool (sqlx, async).
    pub db: PgPool,

    /// Async Redis connection pool (deadpool-redis).
    pub redis: deadpool_redis::Pool,

    /// Background flush loop that drains the Redis WAL → Postgres.
    pub processor: Arc<EventProcessor>,

    /// AhoCorasick + CIDR bot detector (built once, shared everywhere).
    pub bot_detector: Arc<BotDetector>,

    /// Merged config used by route handlers.
    pub config: Arc<Config>,

    /// Per-tenant domain allow-list cache.
    /// Key :`"{tenant_id}:{domain}"`
    /// Value:`true` if the domain is allowed for that tenant,
    /// `false` otherwise.
    /// TTL = 60 s, max = 10 000 entries — matches `routes.ts` DOMAIN_CACHE_TTL_MS.
    pub domain_cache: Arc<Cache<String, bool>>,

    /// Per-tenant webhook-ID cache for unsubscribe event dispatching.
    /// Key :`"{tenant_id}"`
    /// Value:list of enabled webhook IDs for `recipient.unsubscribed`.
    /// TTL = 60 s, max = 5 000 entries — matches `routes.ts` WEBHOOK_CACHE_TTL_MS.
    pub webhook_cache: Arc<Cache<String, Vec<String>>>,
}

impl AppState {
    /// Construct from already-built components. Called once in `main.rs`.
    pub fn new(
        codec: TrackingCodec,
        db: PgPool,
        redis: deadpool_redis::Pool,
        // Pre-wrapped so the same Arc can be held by main.rs for shutdown.
        processor: Arc<EventProcessor>,
        bot_detector: BotDetector,
        config: Config,
    ) -> Self {
        let domain_cache = Cache::builder()
            .max_capacity(10_000)
            .time_to_live(std::time::Duration::from_secs(60))
            .build();

        let webhook_cache = Cache::builder()
            .max_capacity(5_000)
            .time_to_live(std::time::Duration::from_secs(60))
            .build();

        Self {
            codec: Arc::new(codec),
            db,
            redis,
            processor,
            bot_detector: Arc::new(bot_detector),
            config: Arc::new(config),
            domain_cache: Arc::new(domain_cache),
            webhook_cache: Arc::new(webhook_cache),
        }
    }
}
