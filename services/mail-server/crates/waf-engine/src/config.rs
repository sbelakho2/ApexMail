//! WAF configuration

use crate::ParanoiaLevel;
use serde::{Deserialize, Serialize};

/// WAF engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WafConfig {
    /// Paranoia level (1-4)
    pub paranoia_level: u8,
    /// Anomaly score threshold for blocking
    pub blocking_threshold: u32,
    /// Anomaly score threshold for logging/monitoring
    pub detection_threshold: u32,
    /// Maximum request body size to inspect (bytes)
    pub max_body_size: usize,
    /// Maximum URL length
    pub max_url_length: usize,
    /// Maximum number of query parameters
    pub max_query_params: usize,
    /// Maximum header count
    pub max_headers: usize,
    /// Maximum individual header value length
    pub max_header_value_length: usize,
    /// Enable SQL injection detection
    pub enable_sqli: bool,
    /// Enable XSS detection
    pub enable_xss: bool,
    /// Enable path traversal detection
    pub enable_path_traversal: bool,
    /// Enable command injection detection
    pub enable_command_injection: bool,
    /// Enable protocol violation detection
    pub enable_protocol_checks: bool,
    /// Enable NoSQL injection detection (MongoDB, Redis, Elasticsearch)
    pub enable_nosqli: bool,
    /// Enable SSRF detection (internal IPs, dangerous URL schemes)
    pub enable_ssrf: bool,
    /// Enable HTTP request smuggling detection
    pub enable_smuggling: bool,
    /// IP allowlist (bypass WAF)
    pub allowlist_ips: Vec<String>,
    /// URL path allowlist (bypass WAF for specific paths)
    pub allowlist_paths: Vec<String>,
    /// Maximum recursion depth for decoders
    pub max_decode_depth: usize,
    /// Enable Unicode normalization and confusable folding during canonicalization
    pub enable_unicode_normalization: bool,
}

impl Default for WafConfig {
    fn default() -> Self {
        Self {
            paranoia_level: 2,
            blocking_threshold: 5,
            detection_threshold: 3,
            max_body_size: 1_048_576, // 1 MB
            max_url_length: 8192,
            max_query_params: 100,
            max_headers: 100,
            max_header_value_length: 8192,
            enable_sqli: true,
            enable_xss: true,
            enable_path_traversal: true,
            enable_command_injection: true,
            enable_protocol_checks: true,
            enable_nosqli: true,
            enable_ssrf: true,
            enable_smuggling: true,
            allowlist_ips: Vec::new(),
            allowlist_paths: Vec::new(),
            max_decode_depth: 5,
            enable_unicode_normalization: true,
        }
    }
}

impl WafConfig {
    /// Get the paranoia level enum
    pub fn paranoia(&self) -> ParanoiaLevel {
        match self.paranoia_level {
            1 => ParanoiaLevel::Low,
            2 => ParanoiaLevel::Medium,
            3 => ParanoiaLevel::High,
            _ => ParanoiaLevel::Paranoid,
        }
    }
}
