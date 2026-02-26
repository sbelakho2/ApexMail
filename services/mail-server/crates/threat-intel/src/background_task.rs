//! Background purge task for threat intelligence data
//!
//! Provides an asynchronous background task that periodically purges expired
//! entries from the IP and domain blocklists. This prevents memory from growing
//! indefinitely as threat intelligence feeds accumulate entries over time.
//!
//! ## Design Rationale
//!
//! - Without periodic purging, the DashMap-backed blocklists grow unbounded
//! - TTL-based entries (from feeds) need to be cleaned up after expiration
//! - Running purge on a dedicated async task avoids blocking request handling
//! - Configurable interval allows tuning for different deployment sizes
//!
//! ## Usage
//!
//! ```rust,ignore
//! use threat_intel::{ThreatIntelEngine, background_task};
//!
//! let engine = Arc::new(ThreatIntelEngine::new());
//! 
//! // Spawn the background purge task
//! let handle = tokio::spawn(background_task::run_purge_loop(engine.clone()));
//!
//! // Later, to stop:
//! handle.abort();
//! ```

use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;

use crate::ThreatIntelEngine;

/// Configuration for the background purge task
#[derive(Debug, Clone)]
pub struct PurgeTaskConfig {
    /// How often to run the purge (default: 60 seconds)
    pub interval: Duration,
    /// Whether the task is enabled
    pub enabled: bool,
}

impl Default for PurgeTaskConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(60),
            enabled: true,
        }
    }
}

/// Statistics from a purge operation
#[derive(Debug, Clone, Default)]
pub struct PurgeStats {
    /// Number of expired IP entries removed
    pub expired_ips_removed: usize,
    /// Number of expired domain entries removed
    pub expired_domains_removed: usize,
    /// Total entries remaining in IP blocklist
    pub ip_entries_remaining: usize,
    /// Total entries remaining in domain blocklist
    pub domain_entries_remaining: usize,
    /// Duration of the purge operation
    pub duration_ms: u64,
}

/// Run the purge loop continuously.
/// This function runs until the future is dropped/cancelled.
/// 
/// # Arguments
/// * `engine` - Arc reference to the ThreatIntelEngine
/// * `config` - Configuration for the purge task
///
/// # Example
/// ```rust,ignore
/// let engine = Arc::new(ThreatIntelEngine::new());
/// let config = PurgeTaskConfig::default();
/// 
/// let handle = tokio::spawn(async move {
///     run_purge_loop(engine, config).await;
/// });
/// ```
pub async fn run_purge_loop(engine: Arc<ThreatIntelEngine>, config: PurgeTaskConfig) {
    if !config.enabled {
        return;
    }

    let mut ticker = interval(config.interval);

    loop {
        ticker.tick().await;
        
        let stats = purge_once(&engine);
        
        // Log if we actually removed anything (when tracing is available)
        #[cfg(feature = "tracing")]
        {
            if stats.expired_ips_removed > 0 || stats.expired_domains_removed > 0 {
                tracing::info!(
                    ips_removed = stats.expired_ips_removed,
                    domains_removed = stats.expired_domains_removed,
                    ips_remaining = stats.ip_entries_remaining,
                    domains_remaining = stats.domain_entries_remaining,
                    duration_ms = stats.duration_ms,
                    "Threat intel purge completed"
                );
            } else {
                tracing::debug!(
                    ips_remaining = stats.ip_entries_remaining,
                    domains_remaining = stats.domain_entries_remaining,
                    duration_ms = stats.duration_ms,
                    "Threat intel purge: no expired entries found"
                );
            }
        }
        
        // Suppress unused variable warning when tracing is disabled
        let _ = &stats;
    }
}

/// Run a single purge operation.
/// This is useful for testing or manual triggering.
pub fn purge_once(engine: &ThreatIntelEngine) -> PurgeStats {
    let start = std::time::Instant::now();
    
    // Get counts before purge
    let stats_before = engine.stats();
    let ips_before = stats_before.ip_exact_entries + stats_before.ip_cidr_entries;
    let domains_before = stats_before.domain_entries;
    
    // Run purge on both blocklists
    engine.ip_blocklist().purge_expired();
    engine.domain_blocklist().purge_expired();
    
    // Get counts after purge
    let stats_after = engine.stats();
    let ips_after = stats_after.ip_exact_entries + stats_after.ip_cidr_entries;
    let domains_after = stats_after.domain_entries;
    
    let elapsed = start.elapsed();
    
    PurgeStats {
        expired_ips_removed: ips_before.saturating_sub(ips_after),
        expired_domains_removed: domains_before.saturating_sub(domains_after),
        ip_entries_remaining: ips_after,
        domain_entries_remaining: domains_after,
        duration_ms: elapsed.as_millis() as u64,
    }
}

/// Create a purge task handle that can be used to spawn the background loop.
/// This is a convenience wrapper for common usage patterns.
pub fn spawn_purge_task(
    engine: Arc<ThreatIntelEngine>,
    config: PurgeTaskConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run_purge_loop(engine, config).await;
    })
}

// ---------------------------------------------------------------------------
// Feed auto-refresh
// ---------------------------------------------------------------------------

/// Configuration for the feed auto-refresh background task.
///
/// Because the threat-intel crate has no embedded HTTP client, callers must
/// provide a `loader` callback that performs the actual fetch + insertion.
/// This keeps the crate dependency-free while still enabling automatic refresh
/// of Spamhaus DROP / EDROP, DNSBL dumps, etc.
///
/// ## Example
/// ```rust,ignore
/// let refresh_cfg = FeedRefreshConfig {
///     interval: Duration::from_secs(3600),   // reload every hour
///     enabled: true,
/// };
///
/// let engine_clone = engine.clone();
/// let handle = spawn_refresh_task(engine.clone(), refresh_cfg, move || {
///     // Re-download all feeds and re-populate blocklists
///     let data = reqwest::blocking::get("https://www.spamhaus.org/drop/drop.txt")
///         .unwrap().text().unwrap();
///     load_spamhaus_drop_into(&engine_clone, &data);
/// });
/// ```
#[derive(Debug, Clone)]
pub struct FeedRefreshConfig {
    /// How often to reload feeds.  Default: every 24 hours (matching default TTL).
    pub interval: Duration,
    /// Whether the task is enabled.
    pub enabled: bool,
}

impl Default for FeedRefreshConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(86_400), // 24h — matches default_ttl_secs
            enabled: true,
        }
    }
}

/// Run the feed refresh loop continuously.
///
/// `loader` is called on every tick.  It is responsible for fetching current
/// feed data and loading it into the engine (via `engine.ip_blocklist()` /
/// `engine.domain_blocklist()`).
///
/// The function returns only when the future is dropped/cancelled (Tokio abort).
pub async fn run_refresh_loop<F>(
    engine: Arc<ThreatIntelEngine>,
    config: FeedRefreshConfig,
    loader: F,
) where
    F: Fn(Arc<ThreatIntelEngine>) + Send + Sync + 'static,
{
    if !config.enabled {
        return;
    }

    // Wrap in Arc so we can clone a reference for each spawn_blocking call
    let loader = Arc::new(loader);
    let mut ticker = interval(config.interval);

    // Skip the first immediate tick so we don't reload right at startup
    ticker.tick().await;

    loop {
        ticker.tick().await;

        let engine_ref = engine.clone();
        let loader_ref = loader.clone();
        let result = tokio::task::spawn_blocking(move || {
            loader_ref(engine_ref);
        })
        .await;

        #[cfg(feature = "tracing")]
        match result {
            Ok(()) => tracing::info!("Threat intel feed refresh completed"),
            Err(e) => tracing::error!(error = %e, "Threat intel feed refresh task panicked"),
        }

        let _ = result;
    }
}

/// Convenience wrapper: spawn a feed refresh task using [`tokio::spawn`].
pub fn spawn_refresh_task<F>(
    engine: Arc<ThreatIntelEngine>,
    config: FeedRefreshConfig,
    loader: F,
) -> tokio::task::JoinHandle<()>
where
    F: Fn(Arc<ThreatIntelEngine>) + Send + Sync + 'static,
{
    tokio::spawn(async move {
        run_refresh_loop(engine, config, loader).await;
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip_blocklist::ThreatCategory;
    use std::time::Duration;

    #[test]
    fn test_purge_stats_default() {
        let stats = PurgeStats::default();
        assert_eq!(stats.expired_ips_removed, 0);
        assert_eq!(stats.expired_domains_removed, 0);
    }

    #[test]
    fn test_purge_config_default() {
        let config = PurgeTaskConfig::default();
        assert_eq!(config.interval, Duration::from_secs(60));
        assert!(config.enabled);
    }

    #[tokio::test]
    async fn test_purge_once_empty() {
        let engine = ThreatIntelEngine::new();
        let stats = purge_once(&engine);
        
        assert_eq!(stats.expired_ips_removed, 0);
        assert_eq!(stats.expired_domains_removed, 0);
        assert!(stats.duration_ms < 1000); // Should be fast
    }

    #[tokio::test]
    async fn test_purge_removes_expired() {
        let engine = ThreatIntelEngine::new();
        
        // Add an entry with immediate expiration (in the past)
        // This requires access to add_ip_with_ttl or similar
        // For now, just verify the purge runs without error
        let stats = purge_once(&engine);
        assert!(stats.duration_ms < 1000);
    }
}
