//! ATO protection configuration

use serde::{Deserialize, Serialize};

/// Configuration for ATO protection
///
/// ## Known limitations
///
/// - **Device fingerprint uses IP /16 prefix:** This provides a better
///   experience behind NAT/CGNAT but means two users on the same /16 subnet
///   with the same User-Agent and TLS stack will share a fingerprint. Cloud
///   providers (AWS, GCP, Azure) often allocate /16 blocks, so cloud-hosted
///   bots may appear as the same "device" as legitimate users on that
///   provider.
///
/// - **Cross-node lockout remains a deployment concern:** This crate can share
///   lockout events across engine instances in the same process via a global
///   registry, but multi-node deployments still require an external shared
///   store (for example Redis) for perfect node-to-node consistency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtoConfig {
    /// Maximum plausible travel speed in km/h (default: 500).
    ///
    /// 900 km/h (commercial jet) causes false negatives for VPN hops that
    /// span continents in seconds. 500 km/h is fast enough for high-speed
    /// rail and nearly all legitimate travel while catching instant
    /// continent-jumps.
    pub max_travel_speed_kmh: f64,

    /// Risk score threshold to require step-up MFA (default: 5.0)
    pub mfa_threshold: f64,

    /// Risk score threshold to block login entirely (default: 9.0)
    pub block_threshold: f64,

    /// Maximum failed login attempts before lockout (default: 5)
    pub max_failed_attempts: u32,

    /// Lockout duration in seconds after max failures (default: 900 = 15 min)
    pub lockout_duration_secs: u64,

    /// Window (in seconds) to count failed attempts (default: 300 = 5 min)
    pub failed_attempt_window_secs: u64,

    /// Maximum login history entries per user (default: 100)
    pub max_history_per_user: usize,

    /// Weight for impossible travel risk component
    pub weight_geo: f64,

    /// Weight for new device/fingerprint risk component
    pub weight_device: f64,

    /// Weight for unusual time-of-day risk component
    pub weight_time: f64,

    /// Weight for failed attempt risk component
    pub weight_failures: f64,
    
    // ---- Lockout Escalation ----
    
    /// Number of lockout events within escalation_window before escalating to
    /// permanent lockout requiring CAPTCHA or admin unlock (default: 3)
    pub lockout_escalation_threshold: u32,
    
    /// Window (in seconds) to track lockout events for escalation (default: 86400 = 24h)
    pub lockout_escalation_window_secs: u64,

    // ---- Self-Protection ----

    /// Maximum `evaluate()` calls per second per IP before returning an early
    /// Block verdict.  Protects the engine itself from resource exhaustion
    /// when an attacker floods the auth endpoint.  0 = no limit (default: 50).
    pub rate_limit_rps: u32,

    /// Share lockout escalation state across all `AtoEngine` instances in the
    /// same process (default: true).
    pub use_process_global_lockout_registry: bool,

    // ---- Redis Shared Lockout ----

    /// Optional Redis URL for cross-node lockout state sharing.
    ///
    /// When set (e.g., `"redis://127.0.0.1:6379"`), lockout events are
    /// stored in Redis sorted sets keyed by user ID. This ensures that
    /// lockout escalation is consistent across all nodes in a cluster.
    ///
    /// Requires the `redis-lockout` feature flag for actual Redis I/O.
    /// Without the feature flag, setting this field creates a
    /// `RedisLockoutBackend` whose operations are no-ops (with warnings).
    pub redis_lockout_url: Option<String>,
}

impl Default for AtoConfig {
    fn default() -> Self {
        Self {
            max_travel_speed_kmh: 500.0,
            mfa_threshold: 5.0,
            block_threshold: 9.0,
            max_failed_attempts: 5,
            lockout_duration_secs: 900,
            failed_attempt_window_secs: 300,
            max_history_per_user: 100,
            weight_geo: 1.0,
            weight_device: 1.0,
            weight_time: 1.0,
            weight_failures: 1.0,
            lockout_escalation_threshold: 3,
            lockout_escalation_window_secs: 86400, // 24 hours
            rate_limit_rps: 50,
            use_process_global_lockout_registry: true,
            redis_lockout_url: None,
        }
    }
}
