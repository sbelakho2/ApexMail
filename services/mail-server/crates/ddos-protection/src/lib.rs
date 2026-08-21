//! # ApexMail DDoS Protection System
//!
//! Multi-layer DDoS protection providing://!
//! - **Layer 1**:Network edge protection (XDP/eBPF packet filtering)
//! - **Layer 2**:Protocol-level defense (TLS fingerprinting, protocol validation)
//! - **Layer 3**:Application-level protection (rate limiting, challenges)
//! - **Layer 4**:Behavioral analysis & ML (anomaly detection, adaptive thresholds)
//! - **Layer 5**:Distributed coordination (cross-region threat intel, CRDT rate limits)
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
//! - `coordinator`:Cross-region threat intelligence sharing
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

        let protector = Self {
            config,
            reputation_db: Arc::new(DashMap::new()),
            session_tracker,
            cost_limiter,
            blocklist: Arc::new(DashMap::new()),
            attack_state: Arc::new(RwLock::new(AttackState::default())),
            #[cfg(feature = "ml")]
            anomaly_detector: None,
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

        // Layer 0:Check blocklist
        if self.is_blocked(&ctx.ip) {
            if let Some(metric) = metrics::REQUESTS_TOTAL.as_ref() {
                metric.with_label_values(&["blocked", "blocklist"]).inc();
            }
            return ProtectionDecision::Block;
        }

        // Layer 1:Check fingerprint (if available)
        if let Some(ref fp) = ctx.tls_fingerprint {
            if self.is_suspicious_fingerprint(fp) {
                self.decrease_reputation(&ctx.ip, 10);
            }
        }

        // Re-read reputation after potential fingerprint penalty so the
        // current request's decisions use the updated score.
        let reputation = self.get_or_create_reputation(&ctx.ip);

        // Layer 2:Cost-based rate limiting
        let cost_decision =
            self.cost_limiter
                .check(&ctx.tenant_id.clone().unwrap_or_default(), &ctx.path, None);

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
                    // Fix I: issue through the ChallengeManager so the
                    // challenge data is random per issuance (the previous
                    // constant prefix `"challenge"` made solved nonces
                    // replayable forever) and so verification goes through
                    // the manager's replay cache.
                    if let challenges::ChallengeType::ProofOfWork(pow) = cm.issue_pow_challenge() {
                        // Adaptive PoW:scale difficulty based on anomaly severity.
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
                        let expected_time = 1000_u64
                            .saturating_mul(
                                1u64.checked_shl(extra_bits.min(10) as u32).unwrap_or(1024),
                            )
                            .min(u32::MAX as u64) as u32;
                        return ProtectionDecision::Challenge(crate::decision::Challenge::Pow(
                            crate::decision::PowChallenge {
                                id: pow.challenge_id,
                                data: pow.prefix,
                                difficulty: adaptive_difficulty,
                                expires_at: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_secs() + 300)
                                    .unwrap_or(0),
                                expected_time_ms: expected_time,
                            },
                        ));
                    }
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
                    // Fix I: issue through the ChallengeManager (random
                    // per-issuance data). The previous per-IP constant
                    // prefix `rep_challenge:<ip>` allowed one solved nonce
                    // to be replayed for every future request from that IP.
                    if let challenges::ChallengeType::ProofOfWork(pow) = cm.issue_pow_challenge() {
                        return ProtectionDecision::Challenge(crate::decision::Challenge::Pow(
                            crate::decision::PowChallenge {
                                id: pow.challenge_id,
                                data: pow.prefix,
                                difficulty: self.config.pow_difficulty,
                                expires_at: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_secs() + 300)
                                    .unwrap_or(0),
                                expected_time_ms: 1000,
                            },
                        ));
                    }
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

    /// Verify a proof-of-work challenge response with replay protection.
    ///
    /// Fix I: routes through the [`challenges::ChallengeManager`] so a
    /// solved nonce is rejected on replay (UsedResponseCache) and the
    /// verification is audited.
    #[cfg(feature = "challenges")]
    pub fn verify_pow(
        &self,
        challenge: &crate::decision::PowChallenge,
        nonce: u64,
        client_fingerprint: Option<&str>,
    ) -> challenges::ChallengeVerifyResult {
        match &self.challenge_manager {
            Some(cm) => cm.verify_decision_pow(challenge, nonce, client_fingerprint),
            None => challenges::ChallengeVerifyResult {
                valid: false,
                replayed: false,
                expired: true,
            },
        }
    }

    /// Background cleanup task
    pub async fn run_cleanup_loop(&self, interval: Duration) {        let mut ticker = tokio::time::interval(interval);

        loop {
            ticker.tick().await;

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

                !is_stale && !(is_neutral && is_inactive && is_old)
            });

            // Periodic enforcement of the hard capacity cap as well.
            self.enforce_reputation_capacity();

            info!(
                blocked_ips = self.blocklist.len(),
                active_sessions = self.session_tracker.active_count(),
                reputation_entries = self.reputation_db.len(),
                "DDoS protection cleanup complete"
            );
        }
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

/// DDoS protection errors
#[derive(Debug, thiserror::Error)]
pub enum DdosError {    /// Configuration error
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
            };
            let _ = protector.evaluate(&ctx).await;
        }

        assert!(
            protector.reputation_db.contains_key(&trusted_ip),
            "trusted entry must survive capacity eviction"
        );
        assert!(protector.reputation_entry_count() <= 10);
    }

    // ── Fix I:challenge issuance/verification hardening ────────────

    #[cfg(feature = "challenges")]
    #[tokio::test]
    async fn test_verify_pow_replay_rejected_through_protector() {
        let protector = DdosProtector::new(ProtectorConfig::default())
            .await
            .expect("test should succeed");

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            + 300;
        let challenge = crate::decision::PowChallenge {
            id: "test-pow".to_string(),
            data: "random-prefix".to_string(),
            difficulty: 0,
            expires_at: now,
            expected_time_ms: 1,
        };

        let first = protector.verify_pow(&challenge, 7, Some("203.0.113.4"));
        assert!(first.valid, "first submission must pass");
        let replay = protector.verify_pow(&challenge, 7, Some("203.0.113.4"));
        assert!(
            !replay.valid && replay.replayed,
            "replayed nonce must be rejected via the replay cache"
        );
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
    }
}
