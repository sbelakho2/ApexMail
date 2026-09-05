//! # ApexMail DDoS Protection System
//!
//! Multi-layer DDoS protection providing://!
//! - **Layer 1**:Network edge protection (XDP/eBPF packet filtering)
//! - **Layer 2**:Protocol-level defense (TLS fingerprinting, protocol validation)
//! - **Layer 3**:Application-level protection (rate limiting, challenges)
//! - **Layer 4**:Behavioral analysis & ML (anomaly detection, adaptive thresholds)
//! - **Layer 5**:Coordination primitives (CRDTs, blocklists) — cross-process
//!   propagation is NOT implemented; see `coordinator` module docs
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use ddos_protection::{DdosProtector, ProtectorConfig};
//!
//! let config = ProtectorConfig::default;
//! let protector = DdosProtector::new(config).await?;
//!
//! // In your middleware
//! match protector.evaluate(&request_context).await {
//! ProtectionDecision::Allow => { /* proceed */ }
//! ProtectionDecision::Challenge(c) => { /* issue challenge */ }
//! ProtectionDecision::RateLimit { retry_after } => { /* 429 */ }
//! ProtectionDecision::Block => { /* 403 */ }
//! }
//! ```
//!
//! ## Feature Flags
//!
//! - `core` (default):Basic rate limiting and fingerprinting
//! - `ml`:Machine learning anomaly detection (Isolation Forest)
//! - `challenges`:Proof-of-work and JS challenges
//! - `coordinator`:In-process coordination primitives (CRDTs, blocklist
//!   hub). NOTE: cross-process/cross-region propagation is NOT
//!   implemented — the Redis knobs in `coordinator::CoordinatorConfig`
//!   are reserved placeholders.
//! - `full`:All features enabled

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![warn(missing_docs)]

pub mod adaptive;
pub mod bot_detection;
pub mod config;
pub mod cost_based;
pub mod decision;
pub mod metrics;
pub mod middleware;
pub mod reputation;
pub mod session;
pub mod smtp_protection;

#[cfg(feature = "challenges")]
pub mod challenges;

#[cfg(feature = "ml")]
pub mod ml;

#[cfg(feature = "ml")]
pub mod ml_cache;

#[cfg(feature = "coordinator")]
pub mod coordinator;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "ml")]
use chrono::Timelike;
use dashmap::DashMap;
use mail_common::{
    CorrelationContext, SecurityAction, SecurityEvent, SecuritySeverity, SecuritySystem,
};
use parking_lot::RwLock;
use tracing::{debug, info, warn};

pub use adaptive::AdaptiveRateLimiter;
pub use bot_detection::SessionBehavior;
pub use config::ProtectorConfig;
pub use cost_based::{CostBasedLimiter, RequestCost};
pub use decision::ProtectionDecision;
pub use middleware::{
    evaluate_request, extract_client_ip, extract_client_ip_trusted, MiddlewareAction,
    RequestContextBuilder, TrustedProxyList,
};
pub use reputation::ReputationScore;
pub use session::SessionTracker;
pub use smtp_protection::{SmtpConnectionProtection, SmtpConnectionTracker, SmtpProtectionConfig};

// Re-export from fingerprint crate
pub use fingerprint::{Http2Fingerprint, Ja4Fingerprint};

/// Main DDoS protection orchestrator
#[derive(Clone)]
pub struct DdosProtector {
    config: Arc<ProtectorConfig>,

    /// Per-IP reputation scores
    reputation_db: Arc<DashMap<IpAddr, ReputationScore>>,

    /// Session tracking for behavioral analysis
    session_tracker: Arc<SessionTracker>,

    /// Cost-based rate limiter
    cost_limiter: Arc<CostBasedLimiter>,

    /// Per-IP adaptive rate limiter (Layer 2b, audit F2c). Constructed when
    /// `enable_per_ip_adaptive` is set (the default); previously the flag and
    /// the [`AdaptiveRateLimiter`] type existed but were never wired into the
    /// decide path, so the configuration was inert.
    adaptive_limiter: Option<Arc<AdaptiveRateLimiter>>,

    /// IP blocklist with expiration
    blocklist: Arc<DashMap<IpAddr, BlockEntry>>,

    /// Attack state
    attack_state: Arc<RwLock<AttackState>>,

    #[cfg(feature = "ml")]
    /// Anomaly detector
    anomaly_detector: Option<Arc<ml::IsolationForest>>,

    #[cfg(feature = "challenges")]
    /// Challenge manager
    challenge_manager: Option<Arc<challenges::ChallengeManager>>,

    #[cfg(feature = "coordinator")]
    /// Threat intelligence service
    threat_intel: Option<Arc<coordinator::ThreatIntelService>>,
}

/// Block list entry
#[derive(Debug, Clone)]
pub struct BlockEntry {
    /// Reason for blocking
    pub reason: String,
    /// When this block expires
    pub expires_at: std::time::Instant,
    /// Source region (if from distributed intel)
    pub from_region: Option<String>,
}

/// Global attack state
#[derive(Debug, Clone, Default)]
pub struct AttackState {
    /// Is the system under active attack?
    pub is_under_attack: bool,
    /// When the attack started
    pub attack_started: Option<std::time::Instant>,
    /// Attack type (if identified)
    pub attack_type: Option<String>,
    /// Current mitigation level (0-5)
    pub mitigation_level: u8,
}

/// Context for evaluating a request
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// Client IP address
    pub ip: IpAddr,
    /// Request path/endpoint
    pub path: String,
    /// HTTP method
    pub method: String,
    /// TLS fingerprint (JA4)
    pub tls_fingerprint: Option<String>,
    /// HTTP/2 fingerprint
    pub h2_fingerprint: Option<String>,
    /// User-Agent header
    pub user_agent: Option<String>,
    /// Request body size
    pub body_size: usize,
    /// Tenant ID (if authenticated)
    pub tenant_id: Option<String>,
    /// API key ID (if authenticated)
    pub api_key_id: Option<String>,
    /// DDoS challenge id presented for redemption (audit F3c). Populated by
    /// the caller from the `X-DDoS-Challenge-Id` request header (or the body
    /// of a `POST /__ddos/verify`); see `middleware::evaluate_request`.
    pub challenge_id: Option<String>,
    /// Nonce presented as the challenge solution (audit F3c), from the
    /// `X-DDoS-Challenge-Solution` header.
    pub challenge_solution: Option<u64>,
}

impl DdosProtector {
    /// Create a new DDoS protector with the given configuration
    pub async fn new(config: ProtectorConfig) -> Result<Self, DdosError> {
        let config = Arc::new(config);

        let cost_limiter = Arc::new(CostBasedLimiter::new(cost_based::CostLimiterConfig {
            default_tenant_budget: config.default_cost_budget,
            system_capacity: config.system_cost_capacity,
        }));

        let session_tracker = Arc::new(SessionTracker::new(
            config.session_window,
            config.max_sessions,
        ));

        // Audit F2c: wire the per-IP adaptive rate limiter when
        // `enable_per_ip_adaptive` is enabled (previously inert config —
        // the limiter was never constructed nor consulted). Thresholds are
        // converted from the per-IP RPM knobs to requests/second, the unit
        // the limiter works in.
        let adaptive_min_rps = (config.per_ip_min_rpm / 60).max(1);
        let adaptive_max_rps = (config.per_ip_max_rpm / 60).max(adaptive_min_rps);
        let adaptive_limiter = config.enable_per_ip_adaptive.then(|| {
            Arc::new(AdaptiveRateLimiter::new(adaptive::AdaptiveConfig {
                baseline_window: if config.per_ip_baseline_window_secs == 0 {
                    Duration::from_secs(300)
                } else {
                    Duration::from_secs(config.per_ip_baseline_window_secs)
                },
                z_threshold: config.per_ip_z_threshold,
                min_threshold: adaptive_min_rps,
                max_threshold: adaptive_max_rps,
                ..adaptive::AdaptiveConfig::default()
            }))
        });

        let protector = Self {
            config,
            reputation_db: Arc::new(DashMap::new()),
            session_tracker,
            cost_limiter,
            adaptive_limiter,
            blocklist: Arc::new(DashMap::new()),
            attack_state: Arc::new(RwLock::new(AttackState::default())),
            #[cfg(feature = "ml")]
            // Audit F2a: construct the anomaly detector so the ML
            // anomaly/challenge block in `evaluate` actually runs. It was
            // previously hard-coded to `None`, making the whole Layer-3 ML
            // path dead code (an untrained forest returns a neutral 0.5
            // score and trains online from observed traffic).
            anomaly_detector: Some(Arc::new(ml::IsolationForest::new(
                ml::IsolationForestConfig::default(),
            ))),
            #[cfg(feature = "challenges")]
            // Fix I: initialize the ChallengeManager (random per-process
            // secret) so challenges are issued with fresh random data and
            // verified through the replay-cached implementation. It was
            // previously always `None`, making the manager dead code.
            challenge_manager: Some(Arc::new(challenges::ChallengeManager::new(
                generate_challenge_secret(),
            ))),
            #[cfg(feature = "coordinator")]
            threat_intel: None,
        };

        protector.start_background_tasks();

        Ok(protector)
    }

    fn start_background_tasks(&self) {
        let refill_limiter = Arc::clone(&self.cost_limiter);
        tokio::spawn(async move {
            refill_limiter.run_refill_loop().await;
        });

        let cleanup_interval = if self.config.cleanup_interval.is_zero() {
            Duration::from_secs(1)
        } else {
            self.config.cleanup_interval
        };
        let cleanup_protector = self.clone();
        tokio::spawn(async move {
            cleanup_protector.run_cleanup_loop(cleanup_interval).await;
        });
    }

    /// Evaluate a request and return protection decision
    pub async fn evaluate(&self, ctx: &RequestContext) -> ProtectionDecision {
        // Increment metrics
        if let Some(metric) = metrics::REQUESTS_TOTAL.as_ref() {
            metric.with_label_values(&["evaluated", "all"]).inc();
        }

        // Canonical client key (audit F2d): IPv6 addresses are truncated to
        // their /64 (and IPv4-mapped IPv6 mapped back to IPv4) for every
        // protection table — cost buckets, sessions, reputation and the
        // blocklist. Without this, an attacker rotating the interface ID of
        // a single /64 minted a fresh budget, session and reputation for
        // every request. The full address continues to be used in logs
        // (`evaluate_with_event` receives the original context).
        let canonical_ip = canonical_client_key(&ctx.ip);
        let canonical_ctx_storage;
        let ctx = if canonical_ip == ctx.ip {
            ctx
        } else {
            canonical_ctx_storage = RequestContext {
                ip: canonical_ip,
                ..ctx.clone()
            };
            &canonical_ctx_storage
        };

        // Layer 0:Check blocklist
        if self.is_blocked(&ctx.ip) {
            if let Some(metric) = metrics::REQUESTS_TOTAL.as_ref() {
                metric.with_label_values(&["blocked", "blocklist"]).inc();
            }
            return ProtectionDecision::Block;
        }

        // Layer 1:Fingerprint-based reputation penalty.
        //
        // Audit F2b: the full penalty requires `ctx.tls_fingerprint`, which
        // HTTP callers never set — Layer 1 could therefore never lower a
        // reputation from this arm. The missing-fingerprint penalty is
        // gated on `penalize_missing_fingerprint` (default OFF, audit
        // F-DDOS-1): with no fingerprint-populating proxy in this repo and
        // no compiled redemption path, the unconditional penalty drained
        // EVERY client's reputation by 1 per request and false-blocked
        // legitimate traffic. A PRESENT suspicious fingerprint is always
        // penalized regardless of the flag.
        match ctx.tls_fingerprint.as_deref() {
            Some(fp) if self.is_suspicious_fingerprint(fp) => {
                self.decrease_reputation(&ctx.ip, FINGERPRINT_PENALTY);
            }
            Some(_) => {}
            None if self.config.penalize_missing_fingerprint => {
                self.decrease_reputation(&ctx.ip, MISSING_FINGERPRINT_PENALTY);
            }
            None => {}
        }

        // Re-read reputation after potential fingerprint penalty so the
        // current request's decisions use the updated score.
        let reputation = self.get_or_create_reputation(&ctx.ip);

        // Layer 2:Cost-based rate limiting.
        // Fix #8: anonymous requests key their cost bucket by CLIENT IP.
        // All unauthenticated traffic previously shared ONE "" bucket, so
        // a single abusive client 429'd every other unauthenticated user.
        let bucket_key = cost_bucket_key(ctx.tenant_id.as_deref(), Some(&ctx.ip));
        let cost_decision = self.cost_limiter.check(&bucket_key, &ctx.path, None);

        match cost_decision {
            cost_based::CostDecision::SystemOverloaded { retry_after } => {
                if let Some(metric) = metrics::REQUESTS_TOTAL.as_ref() {
                    metric.with_label_values(&["limited", "system"]).inc();
                }
                return ProtectionDecision::RateLimit { retry_after };
            }
            cost_based::CostDecision::QuotaExceeded { retry_after, .. } => {
                if let Some(metric) = metrics::REQUESTS_TOTAL.as_ref() {
                    metric.with_label_values(&["limited", "tenant"]).inc();
                }
                return ProtectionDecision::RateLimit { retry_after };
            }
            cost_based::CostDecision::Allowed { .. } => {}
        }

        // Layer 3:Session tracking and behavioral analysis
        let session = self.session_tracker.track(ctx);
        #[cfg(not(feature = "ml"))]
        let _ = &session;

        // Layer 2b:Per-IP adaptive rate limiting (audit F2c). The adaptive
        // limiter learns a request-rate baseline and tightens the allowed
        // rate under attack; a client whose (damped) request rate exceeds
        // the current adaptive threshold is limited. Previously
        // `enable_per_ip_adaptive` never influenced any decision.
        if let Some(ref adaptive) = self.adaptive_limiter {
            let rate_rps = session_rate_per_sec(&session);
            adaptive.update(adaptive::TrafficObservation {
                timestamp: std::time::Instant::now(),
                requests_per_second: rate_rps,
                error_rate: session.error_rate,
                latency_p99_ms: 0.0,
                cpu_usage: 0.0,
            });
            if rate_rps > adaptive.current_threshold() as f64 {
                if let Some(metric) = metrics::REQUESTS_TOTAL.as_ref() {
                    metric.with_label_values(&["limited", "adaptive"]).inc();
                }
                return ProtectionDecision::RateLimit {
                    retry_after: Duration::from_secs(1),
                };
            }
        }

        // ML anomaly detection (uses anomaly_score, not a predict method)
        #[cfg(feature = "ml")]
        if let Some(ref detector) = self.anomaly_detector {
            // Build fully-populated feature vector from session and request context.
            // Previously several fields were left as 0.0 which degraded the
            // Isolation Forest's decision boundary — see security audit report.
            let iat_cov = session.inter_arrival_cov;
            // Estimate IAT mean from requests_per_minute:if RPM > 0 then
            // mean IAT (ms) ≈ 60_000 / RPM, else default to 1000 ms.
            let iat_mean_ms = if session.requests_per_minute > 0.0 {
                60_000.0 / session.requests_per_minute
            } else {
                1000.0
            };
            // Estimate IAT variance from CoV:variance = (CoV * mean)^2
            let iat_variance_ms = (iat_cov * iat_mean_ms).powi(2);

            // Estimate bytes_rate from body_size and request rate
            let bytes_rate = ctx.body_size as f64 * (session.requests_per_minute / 60.0);

            // Size variance:use CoV as a proxy (low CoV = uniform sizes = suspicious)
            let size_variance = iat_cov * ctx.body_size as f64;

            // Time-of-day factor:distance from business hours (9-17)
            let hour = chrono::Utc::now().hour() as f64;
            let time_factor = if (9.0..17.0).contains(&hour) {
                0.0 // Business hours — normal
            } else {
                ((hour - 13.0).abs() / 12.0).min(1.0) // Night — higher factor
            };

            let features = ml::FeatureVector {
                request_rate: session.requests_per_minute / 60.0, // Convert to RPS
                bytes_rate,
                connection_age: session.age_secs as f64,
                size_variance,
                iat_mean: iat_mean_ms,
                iat_variance: iat_variance_ms,
                endpoint_diversity: session.endpoint_diversity,
                error_rate: session.error_rate,
                geo_distance: 0.0, // Populated by GeoIP integration when available
                time_factor,
            };

            let anomaly_score = detector.anomaly_score(&features);

            if let Some(metric) = metrics::ANOMALY_SCORE.as_ref() {
                // Fix H: normalize the path into a bounded route class —
                // raw paths with attacker-controlled IDs/UUIDs created a
                // Prometheus cardinality bomb.
                metric
                    .with_label_values(&[&metrics::endpoint_label(&ctx.path)])
                    .observe(anomaly_score);
            }

            if anomaly_score > self.config.anomaly_threshold {
                self.decrease_reputation(&ctx.ip, 20);

                // Issue challenge for high anomaly scores with adaptive difficulty.
                // Under active attack (high anomaly volume), increase PoW difficulty
                // to make brute-force infeasible. During normal traffic, use the
                // configured baseline difficulty.
                #[cfg(feature = "challenges")]
                if let Some(ref cm) = self.challenge_manager {
                    // Adaptive PoW:Scale difficulty based on anomaly severity.
                    // Base difficulty from config (e.g. 16 bits). Under heavy
                    // attack (anomaly_score near 1.0), add up to 8 extra bits.
                    let attack_multiplier = ((anomaly_score - self.config.anomaly_threshold)
                        / (1.0 - self.config.anomaly_threshold))
                        .clamp(0.0, 1.0);
                    let extra_bits = (attack_multiplier * 8.0) as u8;
                    let adaptive_difficulty = self
                        .config
                        .pow_difficulty
                        .saturating_add(extra_bits)
                        .min(32); // Cap at 32 bits
                                  // Audit F3: issue through the server-side registry. The
                                  // challenge parameters (data, difficulty, expiry) are
                                  // stored server-side, clamped (difficulty ≥ 8) and
                                  // signed; verification consults the stored values and
                                  // NEVER client claims.
                    return ProtectionDecision::Challenge(crate::decision::Challenge::Pow(
                        cm.issue_server_pow(adaptive_difficulty),
                    ));
                }
            }
        }

        // Layer 4:Reputation-based decisions
        if reputation.score < self.config.block_threshold {
            self.block_ip(
                ctx.ip,
                Duration::from_secs(3600),
                "low_reputation".to_string(),
            );
            if let Some(metric) = metrics::REQUESTS_TOTAL.as_ref() {
                metric.with_label_values(&["blocked", "reputation"]).inc();
            }
            return ProtectionDecision::Block;
        }

        #[cfg(feature = "challenges")]
        if reputation.score < self.config.challenge_threshold {
            if let Some(ref cm) = self.challenge_manager {
                // Convert reputation to risk score (lower reputation = higher risk)
                let risk_score = 1.0 - (reputation.score as f64 / 100.0);
                if risk_score > 0.3 {
                    if let Some(metric) = metrics::REQUESTS_TOTAL.as_ref() {
                        metric
                            .with_label_values(&["challenged", "reputation"])
                            .inc();
                    }
                    // Audit F3: issue through the server-side registry
                    // (random per-issuance data, server-clamped difficulty
                    // and expiry, HMAC-signed parameters). The client
                    // receives the params to SOLVE the challenge, but
                    // verification only ever uses the stored values.
                    return ProtectionDecision::Challenge(crate::decision::Challenge::Pow(
                        cm.issue_server_pow(self.config.pow_difficulty),
                    ));
                }
            }
        }

        // Allowed
        if let Some(metric) = metrics::REQUESTS_TOTAL.as_ref() {
            metric.with_label_values(&["allowed", "ok"]).inc();
        }
        ProtectionDecision::Allow
    }

    /// Evaluate request and emit a normalized security event.
    pub async fn evaluate_with_event(
        &self,
        ctx: &RequestContext,
        correlation: Option<CorrelationContext>,
    ) -> (ProtectionDecision, SecurityEvent) {
        let decision = self.evaluate(ctx).await;
        let correlation = correlation.unwrap_or_else(CorrelationContext::generated);

        let (action, severity, risk_score) = match &decision {
            ProtectionDecision::Allow => (SecurityAction::Allow, SecuritySeverity::Info, 1.0),
            ProtectionDecision::Challenge(_) => {
                (SecurityAction::Challenge, SecuritySeverity::Medium, 7.0)
            }
            ProtectionDecision::RateLimit { .. } => {
                (SecurityAction::RateLimit, SecuritySeverity::Medium, 6.0)
            }
            ProtectionDecision::Block => (SecurityAction::Block, SecuritySeverity::High, 10.0),
        };

        let mut event = SecurityEvent::new(
            SecuritySystem::Ddos,
            action,
            severity,
            risk_score,
            format!(
                "DDoS decision={:?} ip={} path={}",
                decision, ctx.ip, ctx.path
            ),
            correlation,
        )
        .with_metadata("ip", ctx.ip.to_string())
        .with_metadata("src_ip", ctx.ip.to_string())
        .with_metadata("path", ctx.path.clone())
        .with_metadata("method", ctx.method.clone());

        if let Some(alert) = mail_common::ingest_security_event(event.clone()) {
            event
                .metadata
                .insert("composite_alert".to_string(), "true".to_string());
            event.metadata.insert(
                "composite_score".to_string(),
                format!("{:.2}", alert.composite_score),
            );
            event.metadata.insert(
                "composite_action".to_string(),
                format!("{:?}", alert.recommended_action),
            );
        }

        (decision, event)
    }

    /// Check if an IP is blocked
    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        if let Some(entry) = self.blocklist.get(ip) {
            if entry.expires_at > std::time::Instant::now() {
                return true;
            }
            // Expired, remove
            drop(entry);
            self.blocklist.remove(ip);
        }
        false
    }

    /// Block an IP address
    pub fn block_ip(&self, ip: IpAddr, duration: Duration, reason: String) {
        let entry = BlockEntry {
            reason,
            expires_at: std::time::Instant::now() + duration,
            from_region: None,
        };
        self.blocklist.insert(ip, entry);

        if let Some(metric) = metrics::BLOCKED_IPS.as_ref() {
            metric.with_label_values(&["local"]).inc();
        }
        warn!(%ip, "IP blocked");

        #[cfg(feature = "coordinator")]
        if let Some(ref intel) = self.threat_intel {
            // Async publish to other regions
            let intel = intel.clone();
            let ip_str = ip.to_string();
            tokio::spawn(async move {
                if let Err(error) = intel.publish_ip_block(&ip_str, duration).await {
                    warn!(ip = %ip_str, error = %error, "Failed to publish blocked IP to coordinator");
                }
            });
        }
    }

    /// Get or create reputation for an IP
    fn get_or_create_reputation(&self, ip: &IpAddr) -> ReputationScore {
        if !self.reputation_db.contains_key(ip) {
            self.enforce_reputation_capacity();
        }
        let mut entry = self.reputation_db.entry(*ip).or_default();
        entry.last_seen = std::time::Instant::now();
        entry.clone()
    }

    /// Decrease reputation score for an IP
    fn decrease_reputation(&self, ip: &IpAddr, amount: u8) {
        if !self.reputation_db.contains_key(ip) {
            self.enforce_reputation_capacity();
        }
        let mut entry = self.reputation_db.entry(*ip).or_default();
        entry.last_seen = std::time::Instant::now();
        entry.score = entry.score.saturating_sub(amount);
        debug!(%ip, new_score = entry.score, "Reputation decreased");
    }

    /// Number of tracked reputation entries (observability / tests).
    pub fn reputation_entry_count(&self) -> usize {
        self.reputation_db.len()
    }

    /// Enforce the hard capacity cap on the reputation table (fix G).
    ///
    /// The table previously grew without bound: entries with a non-neutral
    /// score were NEVER evicted, so a spoofed-IP flood (or a large botnet)
    /// allocated memory forever. When the cap is reached, the least valuable
    /// entries (non-trusted, oldest first) are evicted before a new insert;
    /// if everything is protected, arbitrary entries are dropped so the cap
    /// always holds.
    fn enforce_reputation_capacity(&self) {
        let cap = self.config.max_reputation_entries;
        if cap == 0 || self.reputation_db.len() < cap {
            return;
        }
        // Evict a 10% batch so the scan is amortized under floods.
        let target = cap.saturating_sub(cap / 10).max(1);
        let mut candidates: Vec<(IpAddr, std::time::Instant)> = self
            .reputation_db
            .iter()
            .filter(|entry| !entry.value().is_trusted)
            .map(|entry| (*entry.key(), entry.value().first_seen))
            .collect();
        candidates.sort_by_key(|(_, first_seen)| *first_seen);
        let excess = self.reputation_db.len().saturating_sub(target);
        for (ip, _) in candidates.into_iter().take(excess) {
            self.reputation_db.remove(&ip);
        }
        // Hard guarantee: even if every remaining entry is trusted, the
        // table must not exceed the cap.
        if self.reputation_db.len() > cap {
            let overflow: Vec<IpAddr> = self
                .reputation_db
                .iter()
                .take(self.reputation_db.len() - cap)
                .map(|entry| *entry.key())
                .collect();
            for ip in overflow {
                self.reputation_db.remove(&ip);
            }
        }
    }

    /// Check if a TLS fingerprint is suspicious.
    /// Parses the JA4 fingerprint and checks for anomalies:/// - Very few cipher suites (< 5)
    /// - Very few extensions (< 3)
    /// - Missing ALPN
    /// - Known-malicious fingerprint patterns
    fn is_suspicious_fingerprint(&self, fingerprint: &str) -> bool {
        // Parse the JA4 fingerprint
        if let Some(parsed) = fingerprint::Ja4Fingerprint::parse(fingerprint) {
            // Check for anomalous characteristics
            if parsed.is_anomalous() {
                return true;
            }
        }

        // Check for known-bad fingerprint patterns
        // Extremely short fingerprints are suspicious (custom/minimal TLS stacks)
        if fingerprint.len() < 15 {
            return true;
        }

        false
    }

    /// Check if currently under attack
    pub fn is_under_attack(&self) -> bool {
        self.attack_state.read().is_under_attack
    }

    /// Get current attack state
    pub fn attack_state(&self) -> AttackState {
        self.attack_state.read().clone()
    }

    /// Verify a proof-of-work solution against the SERVER-SIDE issuance
    /// registry (audit F3) with replay protection.
    ///
    /// Only the challenge id is taken from the client; the data, difficulty
    /// and expiry used for verification are the values the server stored
    /// when it ISSUED the challenge — client-supplied difficulty/expiry
    /// claims are never trusted. On success the challenge is marked solved
    /// in the registry (short allow-TTL) and the client IP's reputation is
    /// credited so the re-evaluated request is not immediately re-challenged.
    #[cfg(feature = "challenges")]
    pub fn verify_pow(
        &self,
        ip: &IpAddr,
        challenge_id: &str,
        nonce: u64,
    ) -> challenges::ChallengeVerifyResult {
        let result = match &self.challenge_manager {
            Some(cm) => cm.verify_pow_solution(challenge_id, nonce, Some(&ip.to_string())),
            None => challenges::ChallengeVerifyResult {
                valid: false,
                replayed: false,
                expired: true,
            },
        };
        if result.valid {
            self.record_challenge_passed(&canonical_client_key(ip));
        }
        result
    }

    /// Whether a solved challenge is still inside its redemption allow-TTL.
    #[cfg(feature = "challenges")]
    pub fn pow_allow_active(&self, challenge_id: &str) -> bool {
        match &self.challenge_manager {
            Some(cm) => cm.pow_solved_allow_active(challenge_id),
            None => false,
        }
    }

    /// Credit a client for passing a challenge (audit F3c redemption path):
    /// bumps `challenges_passed` and restores reputation so the follow-up
    /// request evaluation can pass.
    #[cfg(feature = "challenges")]
    fn record_challenge_passed(&self, ip: &IpAddr) {
        if !self.reputation_db.contains_key(ip) {
            self.enforce_reputation_capacity();
        }
        let mut entry = self.reputation_db.entry(*ip).or_default();
        entry.challenges_passed = entry.challenges_passed.saturating_add(1);
        entry.last_seen = std::time::Instant::now();
        entry.score = entry.score.saturating_add(CHALLENGE_PASS_CREDIT).min(100);
        debug!(%ip, new_score = entry.score, "Challenge passed; reputation credited");
    }

    /// Background cleanup task.
    ///
    /// Fix #7b: each iteration now also runs [`CostBasedLimiter::cleanup`]
    /// (Bug E-105) so the per-tenant budget map is bounded — previously
    /// only the refill loop ran and ephemeral tenants leaked entries
    /// forever.
    pub async fn run_cleanup_loop(&self, interval: Duration) {
        let mut ticker = tokio::time::interval(interval);

        loop {
            ticker.tick().await;
            self.run_cleanup_once();
        }
    }

    /// One cleanup pass: expired blocks, stale sessions, reputation
    /// decay/eviction, and stale per-tenant cost budgets.
    fn run_cleanup_once(&self) {
        let now = std::time::Instant::now();

        // Cleanup expired blocks
        let mut expired = Vec::new();
        for entry in self.blocklist.iter() {
            if entry.expires_at < now {
                expired.push(*entry.key());
            }
        }
        for ip in expired {
            self.blocklist.remove(&ip);
            if let Some(metric) = metrics::BLOCKED_IPS.as_ref() {
                metric.with_label_values(&["local"]).dec();
            }
        }

        // Cleanup old sessions
        self.session_tracker.cleanup(now);

        // Cleanup stale tenant cost budgets (fix #7b / Bug E-105).
        self.cost_limiter.cleanup();

        // Decay reputation scores toward neutral and evict stale entries.
        // Fix G: entries are ALSO evicted by last-seen regardless of
        // score — previously any IP with a non-neutral score was pinned
        // in the table forever (unbounded memory under IP floods).
        let eviction_threshold = if self.config.reputation_stale_after.is_zero() {
            Duration::from_secs(3600)
        } else {
            self.config.reputation_stale_after
        };
        self.reputation_db.retain(|_ip, entry| {
            // Decay toward neutral
            if entry.score < 50 {
                entry.score = (entry.score + 1).min(50);
            } else if entry.score > 50 {
                entry.score = (entry.score - 1).max(50);
            }

            // Evict if:not seen within the stale window (regardless of
            // score) OR neutral+inactive+old (previous policy).
            let is_stale = entry.last_seen.elapsed() > eviction_threshold;

            let is_neutral = entry.score == 50;
            let is_inactive = entry.total_requests < 10
                && entry.challenges_passed == 0
                && entry.challenges_failed == 0
                && entry.rate_limit_hits == 0
                && entry.blocked_requests == 0
                && !entry.is_trusted
                && !entry.is_flagged;
            let is_old = entry.first_seen.elapsed() > eviction_threshold;

            !(is_stale || is_neutral && is_inactive && is_old)
        });

        // Periodic enforcement of the hard capacity cap as well.
        self.enforce_reputation_capacity();

        info!(
            blocked_ips = self.blocklist.len(),
            active_sessions = self.session_tracker.active_count(),
            reputation_entries = self.reputation_db.len(),
            tracked_cost_tenants = self.cost_limiter.tracked_tenants(),
            "DDoS protection cleanup complete"
        );
    }
}

/// Generate a random per-process challenge signing secret (fix I).
#[cfg(feature = "challenges")]
fn generate_challenge_secret() -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(uuid::Uuid::new_v4().as_bytes());
    hasher.update(uuid::Uuid::new_v4().as_bytes());
    hasher.update(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos().to_le_bytes())
            .unwrap_or_default(),
    );
    let digest = hasher.finalize();
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&digest);
    secret
}

/// Cost-bucket key for a request (fix #8).
///
/// Authenticated requests are keyed by tenant ID as before. Anonymous
/// requests are keyed by CLIENT IP so one abusive client cannot exhaust
/// the budget of all unauthenticated traffic. Only when neither identity
/// nor address is available does the legacy shared bucket ("") apply.
fn cost_bucket_key(tenant_id: Option<&str>, ip: Option<&IpAddr>) -> String {
    match (tenant_id, ip) {
        (Some(tenant), _) => tenant.to_string(),
        (None, Some(ip)) => format!("anon:{ip}"),
        (None, None) => String::new(),
    }
}

/// Reputation penalty for a client presenting a SUSPICIOUS TLS
/// fingerprint (audit F2b).
const FINGERPRINT_PENALTY: u8 = 10;

/// Smaller fixed reputation penalty applied when NO TLS fingerprint is
/// available (audit F2b) — Layer 1 must still be able to lower reputation
/// for unattributed clients instead of being permanently inert.
const MISSING_FINGERPRINT_PENALTY: u8 = 1;

/// Reputation credit granted when a client solves a server-issued
/// challenge (audit F3c redemption path), so a redeemed client is not
/// immediately re-challenged.
#[cfg(feature = "challenges")]
const CHALLENGE_PASS_CREDIT: u8 = 25;

/// Canonicalize a client address for protection-table keying (audit F2d):
///
/// - IPv4-mapped IPv6 (`::ffff:a.b.c.d`) maps back to the IPv4 form, and
/// - IPv6 addresses are truncated to their /64 (host bits zeroed).
///
/// Cost buckets, sessions, reputation and the blocklist all key on the
/// canonical form, so rotating the interface ID inside one /64 cannot mint
/// fresh budgets/sessions/reputations. Logs keep the full address.
pub(crate) fn canonical_client_key(ip: &IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => *ip,
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return IpAddr::V4(v4);
            }
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
    }
}

/// Damped request rate (requests/second) for a session, used by the
/// adaptive limiter (audit F2c). Young sessions extrapolate wildly
/// (1 request in 40 ms projects to 1500 RPS), so the estimate never uses
/// a window shorter than 60 s — the per-IP floor in RPM terms.
fn session_rate_per_sec(session: &session::SessionInfo) -> f64 {
    session.request_count as f64 / session.age_secs.max(60) as f64
}

/// DDoS protection errors
#[derive(Debug, thiserror::Error)]
pub enum DdosError {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Redis connection error
    #[error("Redis error: {0}")]
    Redis(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_protection() {
        let config = ProtectorConfig::default();
        let protector = DdosProtector::new(config)
            .await
            .expect("test should succeed");

        let ctx = RequestContext {
            ip: "192.168.1.1".parse().expect("hardcoded test IP"),
            path: "/v1/health".to_string(),
            method: "GET".to_string(),
            tls_fingerprint: None,
            h2_fingerprint: None,
            user_agent: Some("Mozilla/5.0".to_string()),
            body_size: 0,
            tenant_id: None,
            api_key_id: None,
            challenge_id: None,
            challenge_solution: None,
        };

        let decision = protector.evaluate(&ctx).await;
        assert!(matches!(decision, ProtectionDecision::Allow));
    }

    #[tokio::test]
    async fn test_blocklist() {
        let config = ProtectorConfig::default();
        let protector = DdosProtector::new(config)
            .await
            .expect("test should succeed");

        let ip: IpAddr = "10.0.0.1".parse().expect("hardcoded test IP");
        protector.block_ip(ip, Duration::from_secs(300), "test".to_string());

        assert!(protector.is_blocked(&ip));

        let ctx = RequestContext {
            ip,
            path: "/".to_string(),
            method: "GET".to_string(),
            tls_fingerprint: None,
            h2_fingerprint: None,
            user_agent: None,
            body_size: 0,
            tenant_id: None,
            api_key_id: None,
            challenge_id: None,
            challenge_solution: None,
        };

        let decision = protector.evaluate(&ctx).await;
        assert!(matches!(decision, ProtectionDecision::Block));
    }

    #[tokio::test]
    async fn test_evaluate_with_event() {
        let config = ProtectorConfig::default();
        let protector = DdosProtector::new(config)
            .await
            .expect("test should succeed");

        let ctx = RequestContext {
            ip: "127.0.0.1".parse().expect("hardcoded test IP"),
            path: "/health".to_string(),
            method: "GET".to_string(),
            tls_fingerprint: None,
            h2_fingerprint: None,
            user_agent: None,
            body_size: 0,
            tenant_id: None,
            api_key_id: None,
            challenge_id: None,
            challenge_solution: None,
        };

        let (_decision, event) = protector.evaluate_with_event(&ctx, None).await;
        assert_eq!(event.system, SecuritySystem::Ddos);
        assert!(!event.correlation.correlation_id.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn test_new_starts_cost_refill_loop() {
        let config = ProtectorConfig {
            system_cost_capacity: 120,
            ..ProtectorConfig::default()
        };
        let protector = DdosProtector::new(config)
            .await
            .expect("test should succeed");

        let ctx = RequestContext {
            ip: "127.0.0.1".parse().expect("hardcoded test IP"),
            path: "/v1/health".to_string(),
            method: "GET".to_string(),
            tls_fingerprint: None,
            h2_fingerprint: None,
            user_agent: None,
            body_size: 0,
            tenant_id: None,
            api_key_id: None,
            challenge_id: None,
            challenge_solution: None,
        };

        for _ in 0..12 {
            assert!(matches!(
                protector.evaluate(&ctx).await,
                ProtectionDecision::Allow
            ));
        }
        assert_eq!(protector.cost_limiter.system_remaining(), 0);

        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;

        assert!(protector.cost_limiter.system_remaining() > 0);
    }

    #[tokio::test(start_paused = true)]
    async fn test_new_starts_cleanup_loop() {
        let config = ProtectorConfig {
            cleanup_interval: Duration::from_secs(1),
            ..ProtectorConfig::default()
        };
        let protector = DdosProtector::new(config)
            .await
            .expect("test should succeed");

        let ip: IpAddr = "10.10.10.10".parse().expect("hardcoded test IP");
        protector.blocklist.insert(
            ip,
            BlockEntry {
                reason: "expired".to_string(),
                expires_at: std::time::Instant::now() - Duration::from_secs(1),
                from_region: None,
            },
        );
        assert!(protector.blocklist.contains_key(&ip));

        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;

        assert!(!protector.blocklist.contains_key(&ip));
    }

    // ── Fix G:bounded tracking tables ─────────────────────────────

    #[tokio::test]
    async fn test_reputation_table_bounded_under_spoofed_ip_flood() {
        // Insert 2× cap distinct IPs through evaluate(); the reputation
        // table must never exceed the configured cap.
        let config = ProtectorConfig {
            max_reputation_entries: 100,
            max_sessions: 100,
            ..ProtectorConfig::default()
        };
        let protector = DdosProtector::new(config)
            .await
            .expect("test should succeed");

        for i in 0..250u32 {
            let ip: IpAddr = format!("198.18.{}.{}", (i >> 8) & 0xFF, i & 0xFF)
                .parse()
                .expect("valid IPv4");
            let ctx = RequestContext {
                ip,
                path: "/flood".to_string(),
                method: "GET".to_string(),
                tls_fingerprint: None,
                h2_fingerprint: None,
                user_agent: None,
                body_size: 0,
                tenant_id: None,
                api_key_id: None,
                challenge_id: None,
                challenge_solution: None,
            };
            let _ = protector.evaluate(&ctx).await;
            assert!(
                protector.reputation_entry_count() <= 100,
                "reputation table exceeded cap at iteration {i}: {}",
                protector.reputation_entry_count()
            );
        }
        assert!(protector.reputation_entry_count() <= 100);
        assert!(protector.session_tracker.active_count() <= 100);
    }

    #[tokio::test]
    async fn test_reputation_capacity_keeps_trusted_entries_longest() {
        // Trusted entries are evicted last when the cap is enforced.
        let config = ProtectorConfig {
            max_reputation_entries: 10,
            ..ProtectorConfig::default()
        };
        let protector = DdosProtector::new(config)
            .await
            .expect("test should succeed");

        let trusted_ip: IpAddr = "203.0.113.1".parse().expect("hardcoded test IP");
        {
            let mut entry = protector.reputation_db.entry(trusted_ip).or_default();
            entry.is_trusted = true;
            entry.score = 90;
        }

        for i in 0..50u32 {
            let ip: IpAddr = format!("198.19.0.{i}").parse().expect("valid IPv4");
            let ctx = RequestContext {
                ip,
                path: "/flood".to_string(),
                method: "GET".to_string(),
                tls_fingerprint: None,
                h2_fingerprint: None,
                user_agent: None,
                body_size: 0,
                tenant_id: None,
                api_key_id: None,
                challenge_id: None,
                challenge_solution: None,
            };
            let _ = protector.evaluate(&ctx).await;
        }

        assert!(
            protector.reputation_db.contains_key(&trusted_ip),
            "trusted entry must survive capacity eviction"
        );
        assert!(protector.reputation_entry_count() <= 10);
    }

    // ── Fix #7b:cost-budget map bounded by the cleanup loop ────────

    #[tokio::test]
    async fn test_cleanup_once_evicts_stale_cost_tenants() {
        let config = ProtectorConfig {
            default_cost_budget: 10_000,
            system_cost_capacity: 1_000_000,
            ..ProtectorConfig::default()
        };
        let protector = DdosProtector::new(config)
            .await
            .expect("test should succeed");

        let _ = protector.cost_limiter.check("active", "/v1/health", None);
        protector.cost_limiter.force_stale_for_test("stale");
        assert_eq!(protector.cost_limiter.tracked_tenants(), 2);

        // One pass of the (formerly loop-only) cleanup must evict the
        // stale tenant budget entry — before fix #7b the loop never called
        // CostBasedLimiter::cleanup and ephemeral tenants leaked forever.
        protector.run_cleanup_once();
        assert_eq!(
            protector.cost_limiter.tracked_tenants(),
            1,
            "stale tenant budget must be evicted by the cleanup pass"
        );
    }

    // ── Fix #8:anonymous cost buckets keyed by client IP ───────────

    #[test]
    fn test_cost_bucket_key_ip_vs_shared() {
        let ip1: IpAddr = "198.51.100.1".parse().expect("hardcoded test IP");
        let ip2: IpAddr = "198.51.100.2".parse().expect("hardcoded test IP");
        // Anonymous requests: per-IP keys, distinct.
        assert_eq!(cost_bucket_key(None, Some(&ip1)), "anon:198.51.100.1");
        assert_ne!(
            cost_bucket_key(None, Some(&ip1)),
            cost_bucket_key(None, Some(&ip2)),
            "distinct anonymous IPs must get distinct buckets"
        );
        // Authenticated requests: tenant wins even with an IP present.
        assert_eq!(cost_bucket_key(Some("tenant-7"), Some(&ip1)), "tenant-7");
        // No identity at all: legacy shared bucket.
        assert_eq!(cost_bucket_key(None, None), "");
    }

    #[tokio::test]
    async fn test_anonymous_cost_budgets_are_per_ip() {
        // Small budget so /v1/health (cost 10) exhausts after 3 hits.
        let config = ProtectorConfig {
            default_cost_budget: 30,
            system_cost_capacity: 10_000_000,
            ..ProtectorConfig::default()
        };
        let protector = DdosProtector::new(config)
            .await
            .expect("test should succeed");

        let anon_ctx = |ip: &str| RequestContext {
            ip: ip.parse().expect("hardcoded test IP"),
            path: "/v1/health".to_string(),
            method: "GET".to_string(),
            tls_fingerprint: None,
            h2_fingerprint: None,
            user_agent: None,
            body_size: 0,
            tenant_id: None,
            api_key_id: None,
            challenge_id: None,
            challenge_solution: None,
        };

        // Drain the budget of 198.51.100.10.
        for _ in 0..3 {
            assert!(matches!(
                protector.evaluate(&anon_ctx("198.51.100.10")).await,
                ProtectionDecision::Allow
            ));
        }
        assert!(
            matches!(
                protector.evaluate(&anon_ctx("198.51.100.10")).await,
                ProtectionDecision::RateLimit { .. }
            ),
            "the abusive IP must be limited"
        );

        // A different anonymous IP has its OWN budget and is unaffected —
        // previously all anonymous traffic shared one \"\" bucket and was
        // 429'd together.
        assert!(
            matches!(
                protector.evaluate(&anon_ctx("198.51.100.11")).await,
                ProtectionDecision::Allow
            ),
            "a different anonymous IP must not be collateral damage"
        );
    }

    // ── Fix I:challenge issuance/verification hardening ────────────
    #[cfg(feature = "challenges")]
    #[tokio::test]
    async fn test_verify_pow_replay_rejected_through_protector() {
        let protector = DdosProtector::new(ProtectorConfig::default())
            .await
            .expect("test should succeed");

        // Audit F3: verification goes through the server-side issuance
        // registry — a client-fabricated challenge (any id/data/difficulty
        // the client likes) must be rejected outright, and a replayed
        // solution to a REAL server-issued challenge must be rejected via
        // the replay cache.
        let ip: IpAddr = "203.0.113.4".parse().expect("hardcoded test IP");

        // Fabricated challenge id → rejected (never issued by this server).
        let forged = protector.verify_pow(&ip, "totally-forged-id", 7);
        assert!(!forged.valid, "forged challenge id must be rejected");

        // Real issuance: force the reputation-challenge path (90 threshold).
        let config = ProtectorConfig {
            challenge_threshold: 90,
            ..ProtectorConfig::default()
        };
        let protector = DdosProtector::new(config)
            .await
            .expect("test should succeed");
        let ctx = RequestContext {
            ip,
            path: "/".to_string(),
            method: "GET".to_string(),
            tls_fingerprint: None,
            h2_fingerprint: None,
            user_agent: None,
            body_size: 0,
            tenant_id: None,
            api_key_id: None,
            challenge_id: None,
            challenge_solution: None,
        };
        let challenge = match protector.evaluate(&ctx).await {
            ProtectionDecision::Challenge(crate::decision::Challenge::Pow(c)) => c,
            other => panic!("expected PoW challenge, got {other:?}"),
        };
        let nonce = solve_pow(&challenge.data, challenge.difficulty);

        let first = protector.verify_pow(&ip, &challenge.id, nonce);
        assert!(first.valid, "first submission must pass");
        let replay = protector.verify_pow(&ip, &challenge.id, nonce);
        assert!(
            !replay.valid && replay.replayed,
            "replayed nonce must be rejected via the replay cache"
        );
    }

    /// Brute-force a nonce satisfying sha256("<data>:<nonce>") having
    /// `difficulty` leading zero bits (test helper).
    #[cfg(feature = "challenges")]
    fn solve_pow(data: &str, difficulty: u8) -> u64 {
        use sha2::{Digest, Sha256};
        for nonce in 0..u64::MAX {
            let input = format!("{data}:{nonce}");
            let hash = Sha256::digest(input.as_bytes());
            let required_bytes = (difficulty / 8) as usize;
            let remaining_bits = difficulty % 8;
            if hash[..required_bytes].iter().all(|b| *b == 0)
                && (remaining_bits == 0 || hash[required_bytes] << remaining_bits == 0)
            {
                return nonce;
            }
        }
        unreachable!("a satisfying nonce always exists");
    }

    #[cfg(feature = "challenges")]
    #[tokio::test]
    async fn test_pow_challenges_differ_between_issuances() {
        use crate::decision::Challenge;

        // Force the reputation-challenge path (score 50 < threshold 90).
        let config = ProtectorConfig {
            challenge_threshold: 90,
            ..ProtectorConfig::default()
        };
        let protector = DdosProtector::new(config)
            .await
            .expect("test should succeed");

        let ctx = RequestContext {
            ip: "203.0.113.8".parse().expect("hardcoded test IP"),
            path: "/".to_string(),
            method: "GET".to_string(),
            tls_fingerprint: None,
            h2_fingerprint: None,
            user_agent: None,
            body_size: 0,
            tenant_id: None,
            api_key_id: None,
            challenge_id: None,
            challenge_solution: None,
        };

        let c1 = match protector.evaluate(&ctx).await {
            ProtectionDecision::Challenge(Challenge::Pow(c)) => c,
            other => panic!("expected PoW challenge, got {other:?}"),
        };
        let c2 = match protector.evaluate(&ctx).await {
            ProtectionDecision::Challenge(Challenge::Pow(c)) => c,
            other => panic!("expected PoW challenge, got {other:?}"),
        };
        assert_ne!(c1.data, c2.data, "each issuance must use fresh random data");
        assert_ne!(c1.id, c2.id);
        assert!(
            !c1.data.starts_with("rep_challenge:"),
            "per-IP constant prefixes are replayable and must not be used"
        );
        // Audit F3: issued challenges are signed and difficulty-clamped.
        assert!(!c1.signature.is_empty(), "issued challenge must be signed");
        assert!(c1.difficulty >= 8, "difficulty must be clamped to >= 8");
    }

    // ── Audit F2:Layer-1 penalty, adaptive wiring, /64 canonical keys ──

    #[test]
    fn test_canonical_client_key_slash64_and_v4_mapped() {
        let v4: IpAddr = "198.51.100.7".parse().expect("valid IPv4");
        assert_eq!(canonical_client_key(&v4), v4, "IPv4 is unchanged");

        // v4-mapped IPv6 collapses to the IPv4 form.
        let mapped: IpAddr = "::ffff:198.51.100.7".parse().expect("valid mapped v6");
        assert_eq!(canonical_client_key(&mapped), v4);

        // /64 truncation: host bits are zeroed, prefix kept.
        let a: IpAddr = "2001:db8:1:2:3:4:5:6".parse().expect("valid IPv6");
        let b: IpAddr = "2001:db8:1:2:ffff:ffff:ffff:ffff"
            .parse()
            .expect("valid IPv6");
        let canonical_a = canonical_client_key(&a);
        assert_eq!(
            canonical_a,
            "2001:db8:1:2::".parse::<IpAddr>().expect("valid IPv6")
        );
        assert_eq!(
            canonical_client_key(&b),
            canonical_a,
            "all addresses inside one /64 share the canonical key"
        );

        // Distinct /64s keep distinct keys.
        let c: IpAddr = "2001:db8:1:3::1".parse().expect("valid IPv6");
        assert_ne!(canonical_client_key(&c), canonical_a);
    }

    #[tokio::test]
    async fn test_ipv6_slash64_rotation_shares_budget_and_reputation() {
        // Rotating the interface ID inside a /64 previously minted a fresh
        // cost bucket, session and reputation entry per request.
        let config = ProtectorConfig {
            default_cost_budget: 30, // /v1/health costs 10 → exhausted after 3
            system_cost_capacity: 10_000_000,
            ..ProtectorConfig::default()
        };
        let protector = DdosProtector::new(config)
            .await
            .expect("test should succeed");

        let ctx = |ip: &str| RequestContext {
            ip: ip.parse().expect("valid IPv6"),
            path: "/v1/health".to_string(),
            method: "GET".to_string(),
            tls_fingerprint: None,
            h2_fingerprint: None,
            user_agent: None,
            body_size: 0,
            tenant_id: None,
            api_key_id: None,
            challenge_id: None,
            challenge_solution: None,
        };

        // Drain the /64's shared budget from ::1 and ::2.
        for _ in 0..3 {
            let _ = protector.evaluate(&ctx("2001:db8:aa:bb::1")).await;
        }
        assert!(
            matches!(
                protector.evaluate(&ctx("2001:db8:aa:bb::2")).await,
                ProtectionDecision::RateLimit { .. }
            ),
            "a rotated interface ID in the same /64 must NOT get a fresh budget"
        );

        // Reputation is also keyed per /64 (single shared entry).
        assert_eq!(protector.reputation_entry_count(), 1);
    }

    #[tokio::test]
    async fn test_missing_fingerprint_still_lowers_reputation() {
        // Audit F2b + F-DDOS-1: a missing fingerprint is the NORM for every
        // HTTP caller (rustls never exposes the JA4 inputs), so the default
        // MUST NOT penalize it — the unconditional penalty drained every
        // legitimate client. The penalty exists only for deployments that
        // opt in via `penalize_missing_fingerprint` (a proxy forwards
        // fingerprints AND redemption is wired).
        let config = ProtectorConfig {
            block_threshold: 0, // never block in this test
            challenge_threshold: 5,
            ..ProtectorConfig::default()
        };
        let protector = DdosProtector::new(config)
            .await
            .expect("test should succeed");

        let ip: IpAddr = "203.0.113.60".parse().expect("hardcoded test IP");
        let ctx = RequestContext {
            ip,
            path: "/".to_string(),
            method: "GET".to_string(),
            tls_fingerprint: None,
            h2_fingerprint: None,
            user_agent: None,
            body_size: 0,
            tenant_id: None,
            api_key_id: None,
            challenge_id: None,
            challenge_solution: None,
        };
        let _ = protector.evaluate(&ctx).await;
        let _ = protector.evaluate(&ctx).await;
        let _ = protector.evaluate(&ctx).await;
        let score = protector
            .reputation_db
            .get(&ip)
            .map(|e| e.score)
            .expect("reputation entry exists");
        assert_eq!(
            score, 50,
            "default config must not penalize a missing fingerprint (score {score})"
        );

        // Opt-in deployments keep the signal: the penalty lowers reputation
        // when `penalize_missing_fingerprint` is set.
        let config = ProtectorConfig {
            block_threshold: 0,
            challenge_threshold: 5,
            penalize_missing_fingerprint: true,
            ..ProtectorConfig::default()
        };
        let protector = DdosProtector::new(config)
            .await
            .expect("test should succeed");
        let _ = protector.evaluate(&ctx).await;
        let _ = protector.evaluate(&ctx).await;
        let _ = protector.evaluate(&ctx).await;
        let score = protector
            .reputation_db
            .get(&ip)
            .map(|e| e.score)
            .expect("reputation entry exists");
        assert!(
            score < 50,
            "opt-in missing-fingerprint penalty must lower reputation (score {score})"
        );

        // A suspicious (unparseable/short) fingerprint takes the full hit.
        let suspicious: IpAddr = "203.0.113.61".parse().expect("hardcoded test IP");
        let ctx = RequestContext {
            ip: suspicious,
            path: "/".to_string(),
            method: "GET".to_string(),
            tls_fingerprint: Some("short".to_string()),
            h2_fingerprint: None,
            user_agent: None,
            body_size: 0,
            tenant_id: None,
            api_key_id: None,
            challenge_id: None,
            challenge_solution: None,
        };
        let _ = protector.evaluate(&ctx).await;
        let suspicious_score = protector
            .reputation_db
            .get(&suspicious)
            .map(|e| e.score)
            .expect("reputation entry exists");
        assert_eq!(suspicious_score, 40, "suspicious fingerprint penalty is 10");
    }

    #[tokio::test]
    async fn test_enable_per_ip_adaptive_is_enforced() {
        // Audit F2c: the adaptive limiter is wired into the decide path.
        // With per_ip_min_rpm = 60 (1 rps floor) a burst of >60 requests
        // within the first minute from one IP must be rate limited.
        let config = ProtectorConfig {
            default_cost_budget: 10_000_000,
            system_cost_capacity: 100_000_000,
            block_threshold: 0, // isolate the adaptive layer
            enable_per_ip_adaptive: true,
            per_ip_min_rpm: 60,
            per_ip_max_rpm: 6_000,
            ..ProtectorConfig::default()
        };
        let protector = DdosProtector::new(config)
            .await
            .expect("test should succeed");

        let ctx = RequestContext {
            ip: "203.0.113.70".parse().expect("hardcoded test IP"),
            path: "/v1/health".to_string(),
            method: "GET".to_string(),
            tls_fingerprint: None,
            h2_fingerprint: None,
            user_agent: None,
            body_size: 0,
            tenant_id: None,
            api_key_id: None,
            challenge_id: None,
            challenge_solution: None,
        };

        let mut limited = false;
        for _ in 0..70 {
            if matches!(
                protector.evaluate(&ctx).await,
                ProtectionDecision::RateLimit { .. }
            ) {
                limited = true;
                break;
            }
        }
        assert!(
            limited,
            "a >60 RPM burst must hit the adaptive per-IP limit"
        );
    }

    #[tokio::test]
    async fn test_disabled_per_ip_adaptive_never_limits() {
        // Flag off → the adaptive layer must not interfere.
        let config = ProtectorConfig {
            default_cost_budget: 10_000_000,
            system_cost_capacity: 100_000_000,
            block_threshold: 0,
            enable_per_ip_adaptive: false,
            per_ip_min_rpm: 1,
            per_ip_max_rpm: 1,
            ..ProtectorConfig::default()
        };
        let protector = DdosProtector::new(config)
            .await
            .expect("test should succeed");
        assert!(protector.adaptive_limiter.is_none());

        let ctx = RequestContext {
            ip: "203.0.113.71".parse().expect("hardcoded test IP"),
            path: "/v1/health".to_string(),
            method: "GET".to_string(),
            tls_fingerprint: None,
            h2_fingerprint: None,
            user_agent: None,
            body_size: 0,
            tenant_id: None,
            api_key_id: None,
            challenge_id: None,
            challenge_solution: None,
        };
        for _ in 0..10 {
            assert!(matches!(
                protector.evaluate(&ctx).await,
                ProtectionDecision::Allow
            ));
        }
    }

    #[cfg(feature = "ml")]
    #[tokio::test]
    async fn test_anomaly_detector_is_constructed() {
        // Audit F2a: the detector was previously always None, making the
        // whole ML anomaly block dead code.
        let protector = DdosProtector::new(ProtectorConfig::default())
            .await
            .expect("test should succeed");
        assert!(
            protector.anomaly_detector.is_some(),
            "anomaly detector must be constructed in new()"
        );
    }
}
