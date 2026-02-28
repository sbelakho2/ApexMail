//! Configuration for DDoS protection
//!
//! ## Security hardening (February 2026)
//!
//! - **Adaptive thresholds**: Added configuration for per-IP adaptive rate
//!   limiting using Z-score anomaly detection. Static thresholds are still
//!   available as fallback but adaptive mode is recommended for production.

use std::time::Duration;

/// Main configuration for DDoS protector
#[derive(Debug, Clone)]
pub struct ProtectorConfig {
    // ─── Rate Limiting ────────────────────────────────────────
    
    /// Default cost budget per tenant per minute
    pub default_cost_budget: u64,
    
    /// System-wide cost capacity
    pub system_cost_capacity: u64,
    
    // ─── Per-IP Adaptive Thresholds (Feb 2026) ────────────────
    
    /// Enable per-IP adaptive rate limiting (recommended for production).
    ///
    /// When enabled, the system tracks per-IP request patterns and
    /// automatically adjusts rate limits based on observed behavior.
    pub enable_per_ip_adaptive: bool,
    
    /// Per-IP adaptive Z-score threshold for anomaly detection.
    /// IPs exceeding this z-score from their baseline are flagged.
    pub per_ip_z_threshold: f64,
    
    /// Per-IP adaptive baseline window in seconds.
    pub per_ip_baseline_window_secs: u64,
    
    /// Per-IP minimum rate limit (requests per minute).
    pub per_ip_min_rpm: u64,
    
    /// Per-IP maximum rate limit (requests per minute).
    pub per_ip_max_rpm: u64,
    
    // ─── Reputation ───────────────────────────────────────────
    
    /// Score below which requests are blocked
    pub block_threshold: u8,
    
    /// Score below which challenges are issued
    pub challenge_threshold: u8,
    
    /// Initial reputation score for new IPs
    pub initial_reputation: u8,
    
    // ─── Session Tracking ─────────────────────────────────────
    
    /// Session tracking window
    pub session_window: Duration,
    
    /// Maximum sessions to track
    pub max_sessions: usize,
    
    // ─── Detection ────────────────────────────────────────────
    
    /// Enable behavioral analysis
    pub enable_behavioral: bool,
    
    /// Enable ML anomaly detection
    pub enable_ml: bool,
    
    /// Anomaly score threshold
    pub anomaly_threshold: f64,
    
    // ─── Challenges ───────────────────────────────────────────
    
    /// Enable challenge system
    pub enable_challenges: bool,
    
    /// PoW difficulty (bits)
    pub pow_difficulty: u8,
    
    // ─── Coordination ─────────────────────────────────────────
    
    /// Enable cross-region coordination
    pub enable_coordination: bool,
    
    /// Redis URL for coordination
    pub redis_url: Option<String>,
    
    /// Local region identifier
    pub local_region: String,
    
    // ─── Cleanup ──────────────────────────────────────────────
    
    /// Cleanup interval
    pub cleanup_interval: Duration,
    
    /// Block expiration for low reputation
    pub low_rep_block_duration: Duration,
}

impl Default for ProtectorConfig {
    fn default() -> Self {
        Self {
            // Rate limiting
            default_cost_budget: 100_000,
            system_cost_capacity: 10_000_000,
            
            // Per-IP adaptive thresholds (Feb 2026)
            enable_per_ip_adaptive: true, // Enabled by default for production safety
            per_ip_z_threshold: 3.0,
            per_ip_baseline_window_secs: 300, // 5 minutes
            per_ip_min_rpm: 10,
            per_ip_max_rpm: 10_000,
            
            // Reputation
            block_threshold: 10,
            challenge_threshold: 30,
            initial_reputation: 50,
            
            // Session tracking
            session_window: Duration::from_secs(300),
            max_sessions: 100_000,
            
            // Detection
            enable_behavioral: true,
            enable_ml: cfg!(feature = "ml"),
            anomaly_threshold: 0.7,
            
            // Challenges
            enable_challenges: cfg!(feature = "challenges"),
            pow_difficulty: 16,
            
            // Coordination
            enable_coordination: cfg!(feature = "coordinator"),
            redis_url: None,
            local_region: "default".to_string(),
            
            // Cleanup
            cleanup_interval: Duration::from_secs(60),
            low_rep_block_duration: Duration::from_secs(3600),
        }
    }
}

impl ProtectorConfig {
    /// Create a new configuration builder
    pub fn builder() -> ProtectorConfigBuilder {
        ProtectorConfigBuilder::default()
    }
    
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        let mut config = Self::default();
        
        if let Ok(val) = std::env::var("DDOS_COST_BUDGET") {
            if let Ok(v) = val.parse() {
                config.default_cost_budget = v;
            }
        }
        
        if let Ok(val) = std::env::var("DDOS_BLOCK_THRESHOLD") {
            if let Ok(v) = val.parse() {
                config.block_threshold = v;
            }
        }
        
        if let Ok(val) = std::env::var("DDOS_REDIS_URL") {
            config.redis_url = Some(val);
        }
        
        if let Ok(val) = std::env::var("DDOS_REGION") {
            config.local_region = val;
        }
        
        config
    }
}

/// Builder for ProtectorConfig
#[derive(Debug, Default)]
pub struct ProtectorConfigBuilder {
    config: ProtectorConfig,
}

impl ProtectorConfigBuilder {
    /// Set the default cost budget per tenant
    pub fn cost_budget(mut self, budget: u64) -> Self {
        self.config.default_cost_budget = budget;
        self
    }
    
    /// Set the system capacity
    pub fn system_capacity(mut self, capacity: u64) -> Self {
        self.config.system_cost_capacity = capacity;
        self
    }
    
    /// Set reputation thresholds
    pub fn reputation_thresholds(mut self, block: u8, challenge: u8) -> Self {
        self.config.block_threshold = block;
        self.config.challenge_threshold = challenge;
        self
    }
    
    /// Configure Redis for coordination
    pub fn redis(mut self, url: &str, region: &str) -> Self {
        self.config.redis_url = Some(url.to_string());
        self.config.local_region = region.to_string();
        self.config.enable_coordination = true;
        self
    }
    
    /// Enable ML detection
    pub fn enable_ml(mut self, enabled: bool) -> Self {
        self.config.enable_ml = enabled;
        self
    }
    
    /// Enable challenges
    pub fn enable_challenges(mut self, enabled: bool) -> Self {
        self.config.enable_challenges = enabled;
        self
    }
    
    /// Build the configuration
    pub fn build(self) -> ProtectorConfig {
        self.config
    }
}
