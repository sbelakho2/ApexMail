#![allow(clippy::doc_lazy_continuation)]

//! Configuration for DDoS protection
//!
//! ## Security hardening (February 2026)
//!
//! - **Adaptive thresholds**:Added configuration for per-IP adaptive rate
//! limiting using Z-score anomaly detection. Static thresholds are still
//! available as fallback but adaptive mode is recommended for production.

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

    /// Hard cap on the per-IP adaptive limiter table (audit SM5 F2): the
    /// number of distinct canonical client keys that get their own
    /// [`crate::adaptive::AdaptiveRateLimiter`]. Least-recently-seen
    /// entries are evicted when full. 0 disables the cap (not recommended).
    pub per_ip_adaptive_table_cap: usize,

    // ─── Reputation ───────────────────────────────────────────
    /// Score below which requests are blocked
    pub block_threshold: u8,

    /// Score below which challenges are issued
    pub challenge_threshold: u8,

    /// Initial reputation score for new IPs
    pub initial_reputation: u8,

    /// Hard cap on tracked reputation entries (memory bound against
    /// spoofed-IP floods). When the table reaches this size, the least
    /// valuable entries are evicted before new ones are inserted.
    /// 0 disables the cap (not recommended).
    pub max_reputation_entries: usize,

    /// Entries not seen for this long are evicted by the periodic cleanup
    /// regardless of their score. 0 uses the default (1 hour).
    pub reputation_stale_after: Duration,

    /// Hard cap on tracked blocklist entries (audit SM5 F10). When full,
    /// the entries expiring soonest are evicted before new blocks are
    /// inserted. 0 disables the cap (not recommended).
    pub max_blocklist_entries: usize,

    /// Hard cap on tracked cost-budget entries (audit SM5 F3); passed
    /// through to [`crate::cost_based::CostLimiterConfig`]. 0 disables.
    pub max_tracked_budgets: usize,

    /// Penalize requests that carry NO TLS fingerprint. Defaults to FALSE:
    /// no HTTP deployment in this repo populates `tls_fingerprint` (rustls
    /// does not expose the JA4 inputs), so a missing-fingerprint penalty
    /// drained EVERY client's reputation by 1 per request and false-blocked
    /// legitimate traffic within minutes of sustained use, with no
    /// redemption path in the compiled feature set. Enable only when a
    /// trusted proxy actually forwards fingerprints AND the challenge
    /// redemption route is wired; a PRESENT suspicious fingerprint is
    /// penalized regardless of this flag.
    pub penalize_missing_fingerprint: bool,

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

    // ─── Probe exemption ──────────────────────────────────────
    /// Paths that must ALWAYS be answered, whatever the client's rate or
    /// reputation: the liveness/readiness endpoints an orchestrator polls and
    /// the metrics endpoint a scraper polls.
    ///
    /// A refused probe is worse than no protection. The orchestrator reads a
    /// non-200 as "this instance is unhealthy" and restarts a healthy
    /// service, repeatedly, forever, because the restart does not change
    /// the client's rate. The same applies to a load balancer's health check
    /// and a Prometheus scrape. These endpoints do no database work and
    /// return a constant, so exempting them cannot be amplified into load.
    ///
    /// Live run 2026-10-22: `/health/live` answered 429 to all 250 polls of a
    /// liveness-probe cadence, and `/health/ready` to 150 of 250, the
    /// protector was throttling the endpoints whose only job is to say
    /// whether the process is alive. `DDOS_PROBE_PATHS` (comma-separated)
    /// overrides the list for deployments with different probe routes.
    pub probe_paths: Vec<String>,
}

impl Default for ProtectorConfig {
    fn default() -> Self {
        Self {
            // Rate limiting
            //
            // Per-client cost budget, per minute. Sized against the real
            // traffic shape of the browser console: one page load is a
            // document (~1 020 units) plus its API calls (~1 020 each) plus
            // ~30 sub-resource fetches (64 units each, see
            // `cost_based::SUBRESOURCE_COST`), roughly 11 200 units. The old
            // 100 000 was sized when "a request" meant one API call, so it
            // held only ~2 page loads per minute and 429'd an ordinary user
            // mid-session (live run 2026-10-22). 2 000 000 holds ~178 page
            // loads per minute, far above any human session, while a
            // single-client flood (thousands of requests per minute at
            // ~1 020 units) still exceeds it.
            default_cost_budget: 2_000_000,
            system_cost_capacity: 10_000_000,

            // Per-IP adaptive thresholds (Feb 2026)
            enable_per_ip_adaptive: true, // Enabled by default for production safety
            per_ip_z_threshold: 3.0,
            per_ip_baseline_window_secs: 300, // 5 minutes
            // The FLOOR of the adaptive threshold. It must sit above what a
            // legitimate browser generates, because a console page load is
            // one document plus ~20-40 sub-resource fetches (stylesheet,
            // scripts, fonts, images, then the page's own API calls), and
            // every one of those is a request this limiter counts. The old
            // floor of 10 RPM (1/6 rps) was below a single page load, so the
            // limiter's attack-mode threshold (baseline × 0.5) could collapse
            // under a normal user's traffic and 429 the page's own CSS (live
            // run 2026-10-22). 600 RPM is 10 rps sustained per IP: no human
            // browsing session reaches it, while a single-IP flood is still
            // caught long before the 10 000 RPM ceiling.
            per_ip_min_rpm: 600,
            per_ip_max_rpm: 10_000,
            per_ip_adaptive_table_cap: 100_000, // matches the session table

            // Reputation
            block_threshold: 10,
            challenge_threshold: 30,
            initial_reputation: 50,
            max_reputation_entries: 250_000,
            reputation_stale_after: Duration::from_secs(3600),
            max_blocklist_entries: 100_000, // audit SM5 F10
            max_tracked_budgets: 100_000,   // audit SM5 F3
            penalize_missing_fingerprint: false,

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

            // Probe exemption. Every name here is a route the service
            // actually serves (`routes::health`) plus the metrics scrape
            // port's path; the common aliases are included so a deployment
            // that mounts probes at the usual alternative paths is safe by
            // default rather than by configuration.
            probe_paths: vec![
                "/health".into(),
                "/health/live".into(),
                "/health/ready".into(),
                "/health/startup".into(),
                "/healthz".into(),
                "/livez".into(),
                "/readyz".into(),
                "/live".into(),
                "/ready".into(),
                "/metrics".into(),
            ],
        }
    }
}

impl ProtectorConfig {
    /// Is this request path a probe that must always be answered?
    ///
    /// Exact match on the configured list, plus any path nested beneath a
    /// configured probe path (`/health/live` also covers
    /// `/health/live/deep`), so a deeper probe route cannot slip back into
    /// the throttled set.
    pub fn is_probe_path(&self, path: &str) -> bool {
        self.probe_paths.iter().any(|probe| {
            path == probe
                || (path.len() > probe.len()
                    && path.starts_with(probe.as_str())
                    && path.as_bytes()[probe.len()] == b'/')
        })
    }

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

        // The probe list is deployment-shaped (an orchestrator's probe route
        // is an operator decision), so it is overridable, but only
        // wholesale: a deployment that adds its own routes must still list
        // the standard ones it relies on.
        if let Ok(val) = std::env::var("DDOS_PROBE_PATHS") {
            let paths: Vec<String> = val
                .split(',')
                .map(|entry| entry.trim().to_string())
                .filter(|entry| !entry.is_empty())
                .collect();
            if !paths.is_empty() {
                config.probe_paths = paths;
            }
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
