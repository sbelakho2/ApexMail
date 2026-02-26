//! ATO protection configuration

use serde::{Deserialize, Serialize};

/// Configuration for ATO protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtoConfig {
    /// Maximum plausible travel speed in km/h (default: 900 — commercial jet)
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
}

impl Default for AtoConfig {
    fn default() -> Self {
        Self {
            max_travel_speed_kmh: 900.0,
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
        }
    }
}
