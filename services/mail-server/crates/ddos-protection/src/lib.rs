//! # ApexMail DDoS Protection System
//!
//! Multi-layer DDoS protection providing:
//!
//! - **Layer 1**: Network edge protection (XDP/eBPF packet filtering)
//! - **Layer 2**: Protocol-level defense (TLS fingerprinting, protocol validation)
//! - **Layer 3**: Application-level protection (rate limiting, challenges)
//! - **Layer 4**: Behavioral analysis & ML (anomaly detection, adaptive thresholds)
//! - **Layer 5**: Distributed coordination (cross-region threat intel, CRDT rate limits)
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use ddos_protection::{DdosProtector, ProtectorConfig};
//!
//! let config = ProtectorConfig::default();
//! let protector = DdosProtector::new(config).await?;
//!
//! // In your middleware
//! match protector.evaluate(&request_context).await {
//!     ProtectionDecision::Allow => { /* proceed */ }
//!     ProtectionDecision::Challenge(c) => { /* issue challenge */ }
//!     ProtectionDecision::RateLimit { retry_after } => { /* 429 */ }
//!     ProtectionDecision::Block => { /* 403 */ }
//! }
//! ```
//!
//! ## Feature Flags
//!
//! - `core` (default): Basic rate limiting and fingerprinting
//! - `ml`: Machine learning anomaly detection (Isolation Forest)
//! - `challenges`: Proof-of-work and JS challenges
//! - `coordinator`: Cross-region threat intelligence sharing
//! - `full`: All features enabled

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

use dashmap::DashMap;
use parking_lot::RwLock;
use tracing::{debug, info, warn};

pub use config::ProtectorConfig;
pub use adaptive::AdaptiveRateLimiter;
pub use bot_detection::SessionBehavior;
pub use cost_based::{CostBasedLimiter, RequestCost};
pub use decision::ProtectionDecision;
pub use middleware::{evaluate_request, extract_client_ip, MiddlewareAction, RequestContextBuilder};
pub use reputation::ReputationScore;
pub use session::SessionTracker;
pub use smtp_protection::{SmtpConnectionProtection, SmtpConnectionTracker, SmtpProtectionConfig};

// Re-export from fingerprint crate
pub use fingerprint::{Ja4Fingerprint, Http2Fingerprint};

/// Main DDoS protection orchestrator
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
        
        Ok(Self {
            config,
            reputation_db: Arc::new(DashMap::new()),
            session_tracker,
            cost_limiter,
            blocklist: Arc::new(DashMap::new()),
            attack_state: Arc::new(RwLock::new(AttackState::default())),
            #[cfg(feature = "ml")]
            anomaly_detector: None,
            #[cfg(feature = "challenges")]
            challenge_manager: None,
            #[cfg(feature = "coordinator")]
            threat_intel: None,
        })
    }
    
    /// Evaluate a request and return protection decision
    pub async fn evaluate(&self, ctx: &RequestContext) -> ProtectionDecision {
        // Increment metrics
        metrics::REQUESTS_TOTAL.with_label_values(&["evaluated", "all"]).inc();
        
        // Layer 0: Check blocklist
        if self.is_blocked(&ctx.ip) {
            metrics::REQUESTS_TOTAL.with_label_values(&["blocked", "blocklist"]).inc();
            return ProtectionDecision::Block;
        }
        
        // Get/create reputation score
        let reputation = self.get_or_create_reputation(&ctx.ip);
        
        // Layer 1: Check fingerprint (if available)
        if let Some(ref fp) = ctx.tls_fingerprint {
            if self.is_suspicious_fingerprint(fp) {
                self.decrease_reputation(&ctx.ip, 10);
            }
        }
        
        // Re-read reputation after potential fingerprint penalty so the
        // current request's decisions use the updated score.
        let reputation = self.get_or_create_reputation(&ctx.ip);
        
        // Layer 2: Cost-based rate limiting
        let cost_decision = self.cost_limiter.check(
            &ctx.tenant_id.clone().unwrap_or_default(),
            &ctx.path,
            None,
        );
        
        match cost_decision {
            cost_based::CostDecision::SystemOverloaded { retry_after } => {
                metrics::REQUESTS_TOTAL.with_label_values(&["limited", "system"]).inc();
                return ProtectionDecision::RateLimit { retry_after };
            }
            cost_based::CostDecision::QuotaExceeded { retry_after, .. } => {
                metrics::REQUESTS_TOTAL.with_label_values(&["limited", "tenant"]).inc();
                return ProtectionDecision::RateLimit { retry_after };
            }
            cost_based::CostDecision::Allowed { .. } => {}
        }
        
        // Layer 3: Session tracking and behavioral analysis
        let session = self.session_tracker.track(ctx);
        
        // ML anomaly detection (uses anomaly_score, not a predict() method)
        #[cfg(feature = "ml")]
        if let Some(ref detector) = self.anomaly_detector {
            // Build feature vector from session info
            let features = ml::FeatureVector {
                request_rate: session.requests_per_minute / 60.0, // Convert to RPS
                bytes_rate: 0.0, // Not available from session
                connection_age: session.age_secs as f64,
                size_variance: 0.0, // Not available
                iat_mean: 0.0, // Could compute from session
                iat_variance: 0.0,
                endpoint_diversity: session.endpoint_diversity,
                error_rate: session.error_rate,
                geo_distance: 0.0,
                time_factor: 0.0,
            };
            
            let anomaly_score = detector.anomaly_score(&features);
            
            metrics::ANOMALY_SCORE
                .with_label_values(&[&ctx.path])
                .observe(anomaly_score);
            
            if anomaly_score > self.config.anomaly_threshold {
                self.decrease_reputation(&ctx.ip, 20);
                
                // Issue challenge for high anomaly scores
                #[cfg(feature = "challenges")]
                if let Some(ref cm) = self.challenge_manager {
                    let challenge = cm.select_challenge(anomaly_score);
                    return ProtectionDecision::Challenge(crate::decision::Challenge::Pow(
                        crate::decision::PowChallenge {
                            id: uuid::Uuid::new_v4().to_string(),
                            data: "challenge".to_string(),
                            difficulty: self.config.pow_difficulty,
                            expires_at: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs() + 300)
                                .unwrap_or(0),
                            expected_time_ms: 1000,
                        }
                    ));
                }
            }
        }
        
        // Layer 4: Reputation-based decisions
        if reputation.score < self.config.block_threshold {
            self.block_ip(ctx.ip, Duration::from_secs(3600), "low_reputation".to_string());
            metrics::REQUESTS_TOTAL.with_label_values(&["blocked", "reputation"]).inc();
            return ProtectionDecision::Block;
        }
        
        #[cfg(feature = "challenges")]
        if reputation.score < self.config.challenge_threshold {
            if let Some(ref _cm) = self.challenge_manager {
                // Convert reputation to risk score (lower reputation = higher risk)
                let risk_score = 1.0 - (reputation.score as f64 / 100.0);
                if risk_score > 0.3 {
                    metrics::REQUESTS_TOTAL.with_label_values(&["challenged", "reputation"]).inc();
                    return ProtectionDecision::Challenge(crate::decision::Challenge::Pow(
                        crate::decision::PowChallenge {
                            id: uuid::Uuid::new_v4().to_string(),
                            data: format!("rep_challenge:{}", ctx.ip),
                            difficulty: self.config.pow_difficulty,
                            expires_at: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs() + 300)
                                .unwrap_or(0),
                            expected_time_ms: 1000,
                        }
                    ));
                }
            }
        }
        
        // Allowed
        metrics::REQUESTS_TOTAL.with_label_values(&["allowed", "ok"]).inc();
        ProtectionDecision::Allow
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
        
        metrics::BLOCKED_IPS.with_label_values(&["local"]).inc();
        warn!(%ip, "IP blocked");
        
        #[cfg(feature = "coordinator")]
        if let Some(ref intel) = self.threat_intel {
            // Async publish to other regions
            let intel = intel.clone();
            let ip_str = ip.to_string();
            tokio::spawn(async move {
                let _ = intel.publish_ip_block(&ip_str, duration).await;
            });
        }
    }
    
    /// Get or create reputation for an IP
    fn get_or_create_reputation(&self, ip: &IpAddr) -> ReputationScore {
        self.reputation_db
            .entry(*ip)
            .or_insert_with(ReputationScore::default)
            .clone()
    }
    
    /// Decrease reputation score for an IP
    fn decrease_reputation(&self, ip: &IpAddr, amount: u8) {
        if let Some(mut entry) = self.reputation_db.get_mut(ip) {
            entry.score = entry.score.saturating_sub(amount);
            debug!(%ip, new_score = entry.score, "Reputation decreased");
        }
    }
    
    /// Check if a TLS fingerprint is suspicious.
    ///
    /// Parses the JA4 fingerprint and checks for anomalies:
    /// - Very few cipher suites (< 5)
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
    
    /// Background cleanup task
    pub async fn run_cleanup_loop(&self, interval: Duration) {
        let mut ticker = tokio::time::interval(interval);
        
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
                metrics::BLOCKED_IPS.with_label_values(&["local"]).dec();
            }
            
            // Cleanup old sessions
            self.session_tracker.cleanup(now);
            
            // Decay reputation scores toward neutral and evict stale entries
            // Bug E-104 fix: Evict entries that have been at neutral for >1 hour
            // to prevent unbounded memory growth from ephemeral IPs
            let eviction_threshold = Duration::from_secs(3600);
            self.reputation_db.retain(|_ip, entry| {
                // Decay toward neutral
                if entry.score < 50 {
                    entry.score = (entry.score + 1).min(50);
                } else if entry.score > 50 {
                    entry.score = (entry.score - 1).max(50);
                }
                
                // Evict if: neutral score AND no significant activity AND old enough
                let is_neutral = entry.score == 50;
                let is_inactive = entry.total_requests < 10 
                    && entry.challenges_passed == 0 
                    && entry.challenges_failed == 0
                    && entry.rate_limit_hits == 0
                    && entry.blocked_requests == 0
                    && !entry.is_trusted
                    && !entry.is_flagged;
                let is_old = entry.first_seen.elapsed() > eviction_threshold;
                
                // Keep entry if it's NOT evictable
                !(is_neutral && is_inactive && is_old)
            });
            
            info!(
                blocked_ips = self.blocklist.len(),
                active_sessions = self.session_tracker.active_count(),
                reputation_entries = self.reputation_db.len(),
                "DDoS protection cleanup complete"
            );
        }
    }
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
        let protector = DdosProtector::new(config).await.unwrap();
        
        let ctx = RequestContext {
            ip: "192.168.1.1".parse().unwrap(),
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
        let protector = DdosProtector::new(config).await.unwrap();
        
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
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
}
