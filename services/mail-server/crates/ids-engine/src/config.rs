//! IDS/IPS configuration

use serde::{Deserialize, Serialize};

/// IDS engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsConfig {
    /// Enable inline prevention (IPS mode) vs detection-only (IDS mode)
    pub inline_mode: bool,
    /// Maximum number of tracked connections
    pub max_connections: usize,
    /// Connection tracking timeout (seconds)
    pub connection_timeout_secs: u64,
    /// Port scan detection: max unique ports per IP in window
    pub portscan_threshold: u32,
    /// Port scan detection window (seconds)
    pub portscan_window_secs: u64,
    /// SYN flood detection: max half-open connections per IP
    pub syn_flood_threshold: u32,
    /// Maximum payload size to inspect (bytes)
    pub max_payload_inspect: usize,
    /// Enable SMTP protocol validation
    pub enable_smtp_validation: bool,
    /// Enable DNS protocol validation
    pub enable_dns_validation: bool,
    /// Enable TLS protocol validation
    pub enable_tls_validation: bool,
    /// Alert rate limit (max alerts per IP per minute)
    pub alert_rate_limit: u32,
}

impl Default for IdsConfig {
    fn default() -> Self {
        Self {
            inline_mode: false,
            max_connections: 1_000_000,
            connection_timeout_secs: 300,
            portscan_threshold: 10,
            portscan_window_secs: 60,
            syn_flood_threshold: 100,
            max_payload_inspect: 65536,
            enable_smtp_validation: true,
            enable_dns_validation: true,
            enable_tls_validation: true,
            alert_rate_limit: 100,
        }
    }
}
