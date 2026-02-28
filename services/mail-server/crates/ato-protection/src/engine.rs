//! ATO Engine — orchestrates all ATO protection components
//!
//! Evaluates login events against:
//! 1. Failed attempt lockout
//! 2. Impossible travel detection
//! 3. Device fingerprint novelty
//! 4. Behavioral profiling
//!
//! Produces a composite risk score and recommended action.

use crate::behavior;
use crate::config::AtoConfig;
use crate::geo::{self, GeoPoint};
use crate::lockout_backend::{InMemoryLockoutBackend, LockoutBackend, RedisLockoutBackend};
use crate::session::{LoginEvent, SessionStore};
use crate::tls_fingerprint::UserTlsHistory;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use tracing;

type LockoutRegistry = Arc<DashMap<String, Vec<DateTime<Utc>>>>;

fn global_lockout_registry() -> LockoutRegistry {
    static GLOBAL_LOCKOUT_REGISTRY: OnceLock<LockoutRegistry> = OnceLock::new();
    GLOBAL_LOCKOUT_REGISTRY
        .get_or_init(|| Arc::new(DashMap::new()))
        .clone()
}

/// Risk evaluation result
#[derive(Debug, Clone)]
pub struct AtoVerdict {
    /// Composite risk score (0.0 = safe, 10.0 = maximum risk)
    pub risk_score: f64,
    /// Recommended action
    pub action: AtoAction,
    /// Whether the device is new for this user
    pub new_device: bool,
    /// Whether impossible travel was detected
    pub impossible_travel: bool,
    /// Individual risk factors
    pub factors: Vec<RiskFactor>,
}

/// Recommended action based on risk assessment
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtoAction {
    /// Allow the login
    Allow,
    /// Require step-up MFA (e.g., TOTP, push notification)
    RequireMfa,
    /// Block the login attempt
    Block,
    /// Require CAPTCHA or admin unlock — escalated lockout after repeated lockout events
    /// This is more severe than Block and indicates repeated abuse patterns
    RequireCaptcha,
}

impl std::fmt::Display for AtoAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AtoAction::Allow => write!(f, "ALLOW"),
            AtoAction::RequireMfa => write!(f, "REQUIRE_MFA"),
            AtoAction::Block => write!(f, "BLOCK"),
            AtoAction::RequireCaptcha => write!(f, "REQUIRE_CAPTCHA"),
        }
    }
}

/// Individual risk factor
#[derive(Debug, Clone)]
pub struct RiskFactor {
    /// Factor identifier
    pub id: &'static str,
    /// Description
    pub description: String,
    /// Risk contribution
    pub risk: f64,
}

/// Continuous session activity event for post-login risk evaluation.
#[derive(Debug, Clone)]
pub struct SessionActivityEvent {
    /// User identifier for the active session.
    pub user_id: String,
    /// Session identifier associated with this activity.
    pub session_id: String,
    /// Whether the client IP changed within the same session.
    pub ip_changed: bool,
    /// Whether the User-Agent changed within the same session.
    pub user_agent_changed: bool,
    /// Whether the TLS fingerprint changed within the same session.
    pub tls_fingerprint_changed: bool,
    /// Whether the event represents a privileged action.
    pub privileged_action: bool,
    /// Optional in-session geovelocity estimate in km/h.
    pub geo_velocity_kmh: Option<f64>,
}

/// Session-level risk verdict.
#[derive(Debug, Clone)]
pub struct SessionRiskVerdict {
    /// Composite session risk score (0.0-10.0).
    pub risk_score: f64,
    /// Recommended response action for this session activity.
    pub action: AtoAction,
    /// Session risk factors that contributed to the score.
    pub factors: Vec<RiskFactor>,
}

/// The ATO protection engine
pub struct AtoEngine {
    config: AtoConfig,
    store: SessionStore,
    /// Per-user TLS fingerprint history — detects bot stack changes
    tls_histories: Arc<DashMap<String, UserTlsHistory>>,
    /// Per-user lockout event timestamps — for escalation tracking (legacy in-memory path)
    /// When a user hits the max_failed_attempts threshold, the timestamp is recorded.
    /// After lockout_escalation_threshold events within lockout_escalation_window,
    /// escalate to RequireCaptcha action.
    lockout_events: Arc<DashMap<String, Vec<DateTime<Utc>>>>,
    /// Pluggable lockout backend for shared state across nodes.
    /// When `config.redis_lockout_url` is set, this is a `RedisLockoutBackend`.
    /// Otherwise it falls back to [`InMemoryLockoutBackend`].
    lockout_backend: Arc<dyn LockoutBackend>,
    /// Per-IP call counter for self-protecting rate limit.
    /// Maps IP → (epoch_second, count) to enforce `config.rate_limit_rps`.
    ip_call_counts: Arc<DashMap<String, (u64, AtomicU64)>>,
}

impl AtoEngine {
    /// Create engine with default config
    pub fn new() -> Self {
        let config = AtoConfig::default();
        let store = SessionStore::new(config.max_history_per_user);
        let lockout_events = if config.use_process_global_lockout_registry {
            global_lockout_registry()
        } else {
            Arc::new(DashMap::new())
        };
        let lockout_backend: Arc<dyn LockoutBackend> = match &config.redis_lockout_url {
            Some(url) => Arc::new(RedisLockoutBackend::new(url.clone())),
            None => Arc::new(InMemoryLockoutBackend::new()),
        };
        Self {
            config,
            store,
            tls_histories: Arc::new(DashMap::new()),
            lockout_events,
            lockout_backend,
            ip_call_counts: Arc::new(DashMap::new()),
        }
    }

    /// Create engine with custom config
    pub fn with_config(config: AtoConfig) -> Self {
        let store = SessionStore::new(config.max_history_per_user);
        let lockout_events = if config.use_process_global_lockout_registry {
            global_lockout_registry()
        } else {
            Arc::new(DashMap::new())
        };
        let lockout_backend: Arc<dyn LockoutBackend> = match &config.redis_lockout_url {
            Some(url) => Arc::new(RedisLockoutBackend::new(url.clone())),
            None => Arc::new(InMemoryLockoutBackend::new()),
        };
        Self {
            config,
            store,
            tls_histories: Arc::new(DashMap::new()),
            lockout_events,
            lockout_backend,
            ip_call_counts: Arc::new(DashMap::new()),
        }
    }

    /// Evaluate a login event and return a risk verdict.
    ///
    /// When `config.rate_limit_rps > 0`, this method enforces a per-IP
    /// calls-per-second limit. If the caller exceeds the limit, an immediate
    /// `Block` verdict is returned to prevent resource exhaustion from
    /// brute-force floods targeting the auth endpoint.
    pub fn evaluate(&self, event: &LoginEvent) -> AtoVerdict {
        // 0. Self-protecting rate limit (per-IP, per-second)
        if self.config.rate_limit_rps > 0 {
            let now_epoch = Utc::now().timestamp() as u64;
            let mut entry = self.ip_call_counts
                .entry(event.ip_address.clone())
                .or_insert_with(|| (now_epoch, AtomicU64::new(0)));

            let (ref mut epoch_sec, ref counter) = *entry;

            if *epoch_sec != now_epoch {
                // New second — reset counter
                *epoch_sec = now_epoch;
                counter.store(1, Ordering::Release);
            } else {
                let prev = counter.fetch_add(1, Ordering::AcqRel);
                if prev >= self.config.rate_limit_rps as u64 {
                    return AtoVerdict {
                        risk_score: 10.0,
                        action: AtoAction::Block,
                        new_device: false,
                        impossible_travel: false,
                        factors: vec![RiskFactor {
                            id: "RATE_LIMITED",
                            description: format!(
                                "IP {} exceeded {} evaluate calls/sec",
                                event.ip_address, self.config.rate_limit_rps
                            ),
                            risk: 10.0,
                        }],
                    };
                }
            }
        }

        let mut factors = Vec::new();
        let mut risk_score: f64 = 0.0;
        let mut impossible_travel = false;
        let mut escalated_lockout = false;

        // 1. Check failed attempt lockout with escalation tracking
        let recent_failures = self.store.recent_failures(
            &event.user_id,
            self.config.failed_attempt_window_secs,
        );
        if recent_failures >= self.config.max_failed_attempts {
            // This is a lockout event - record it for escalation tracking
            let now = Utc::now();
            let escalation_cutoff = now - chrono::Duration::seconds(
                self.config.lockout_escalation_window_secs as i64
            );
            
            // Record via pluggable backend (Redis or in-memory)
            self.lockout_backend.record_lockout(
                &event.user_id,
                self.config.lockout_escalation_window_secs,
            );

            let mut entry = self.lockout_events
                .entry(event.user_id.clone())
                .or_insert_with(Vec::new);
            
            // Clean up old lockout events outside the escalation window
            entry.retain(|ts| *ts > escalation_cutoff);
            
            // Record this lockout event in the local DashMap too
            entry.push(now);
            
            // Use the higher of local count and backend count for consistency
            let local_count = entry.len() as u32;
            let backend_count = self.lockout_backend.recent_lockouts(
                &event.user_id,
                self.config.lockout_escalation_window_secs,
            );
            let lockout_count = local_count.max(backend_count);
            
            // Check if we should escalate to RequireCaptcha
            if lockout_count >= self.config.lockout_escalation_threshold {
                escalated_lockout = true;
                factors.push(RiskFactor {
                    id: "LOCKOUT_ESCALATED",
                    description: format!(
                        "{} lockout events in {} hours — requires CAPTCHA/admin unlock",
                        lockout_count,
                        self.config.lockout_escalation_window_secs / 3600
                    ),
                    risk: 10.0,
                });
            } else {
                factors.push(RiskFactor {
                    id: "LOCKOUT",
                    description: format!(
                        "{} failed attempts in {} seconds (max: {}), lockout {}/{}",
                        recent_failures,
                        self.config.failed_attempt_window_secs,
                        self.config.max_failed_attempts,
                        lockout_count,
                        self.config.lockout_escalation_threshold
                    ),
                    risk: 10.0,
                });
            }
            risk_score += 10.0 * self.config.weight_failures;
        } else if recent_failures > 0 {
            let failure_risk = (recent_failures as f64 / self.config.max_failed_attempts as f64) * 5.0;
            factors.push(RiskFactor {
                id: "FAILED_ATTEMPTS",
                description: format!("{} recent failed attempts", recent_failures),
                risk: failure_risk,
            });
            risk_score += failure_risk * self.config.weight_failures;
        }

        // 2. Impossible travel detection (BEFORE recording the new event)
        if let (Some(lat), Some(lon)) = (event.latitude, event.longitude) {
            if let Some(history) = self.store.get_history(&event.user_id) {
                if let Some(last) = history.last_successful() {
                    if let (Some(prev_lat), Some(prev_lon)) = (last.latitude, last.longitude) {
                        let elapsed = event.timestamp
                            .signed_duration_since(last.timestamp)
                            .num_seconds() as f64;
                        let from = GeoPoint { lat: prev_lat, lon: prev_lon };
                        let to = GeoPoint { lat, lon };

                        let (is_impossible, speed, distance) = geo::check_impossible_travel(
                            &from,
                            &to,
                            elapsed,
                            self.config.max_travel_speed_kmh,
                        );

                        if is_impossible {
                            impossible_travel = true;
                            factors.push(RiskFactor {
                                id: "IMPOSSIBLE_TRAVEL",
                                description: format!(
                                    "Travel {:.0} km in {:.0} min requires {:.0} km/h (max: {:.0})",
                                    distance,
                                    elapsed / 60.0,
                                    speed,
                                    self.config.max_travel_speed_kmh
                                ),
                                risk: 8.0,
                            });
                            risk_score += 8.0 * self.config.weight_geo;
                        }
                    }
                }
            }
        } else {
            // No geo coordinates available for this login — check if IP is different
            // from the last successful login. If so, apply a moderate penalty because
            // we cannot verify geographic feasibility.
            if let Some(history) = self.store.get_history(&event.user_id) {
                if let Some(last) = history.last_successful() {
                    if last.ip_address != event.ip_address {
                        let geo_unknown_risk = 2.0;
                        factors.push(RiskFactor {
                            id: "GEO_UNKNOWN",
                            description: format!(
                                "IP changed ({} → {}) but GeoIP data unavailable — travel speed unverifiable",
                                last.ip_address, event.ip_address
                            ),
                            risk: geo_unknown_risk,
                        });
                        risk_score += geo_unknown_risk * self.config.weight_geo;
                    }
                }
            }
        }

        // 3. Record the event and check device novelty
        let new_device = self.store.record_login(event);
        if new_device {
            factors.push(RiskFactor {
                id: "NEW_DEVICE",
                description: "Login from previously unseen device".into(),
                risk: 3.0,
            });
            risk_score += 3.0 * self.config.weight_device;
        }

        // 4. Behavioral analysis
        if let Some(history) = self.store.get_history(&event.user_id) {
            let login_hour = event.timestamp.format("%H").to_string()
                .parse::<u32>()
                .unwrap_or(0);
            let behavior_result = behavior::analyze_behavior(login_hour, &history);
            for finding in &behavior_result.findings {
                risk_score += finding.risk * self.config.weight_time;
            }
            factors.extend(behavior_result.findings.into_iter().map(|f| RiskFactor {
                id: f.id,
                description: f.description,
                risk: f.risk,
            }));
        }

        // 5. TLS fingerprint anomaly detection
        if let Some(ref tls_fp) = event.tls_fingerprint {
            let mut entry = self.tls_histories
                .entry(event.user_id.clone())
                .or_insert_with(|| UserTlsHistory::new(10));
            let fp_risk = entry.fingerprint_risk(tls_fp);
            entry.record(tls_fp);
            if fp_risk > 0.0 {
                factors.push(RiskFactor {
                    id: "TLS_FINGERPRINT",
                    description: format!(
                        "TLS fingerprint anomaly: hash={}, bot_like={}",
                        tls_fp.hash,
                        tls_fp.looks_like_bot()
                    ),
                    risk: fp_risk,
                });
                // Weight equally to device fingerprint
                risk_score += fp_risk * self.config.weight_device;
            }
        }

        // Cap risk score at 10.0
        risk_score = risk_score.min(10.0);

        // Determine action
        // Escalated lockout requires CAPTCHA/admin unlock (not a timed block)
        let action = if escalated_lockout {
            AtoAction::RequireCaptcha
        } else if risk_score >= self.config.block_threshold {
            AtoAction::Block
        } else if risk_score >= self.config.mfa_threshold {
            AtoAction::RequireMfa
        } else {
            AtoAction::Allow
        };

        AtoVerdict {
            risk_score,
            action,
            new_device,
            impossible_travel,
            factors,
        }
    }

    /// Get the session store (for testing/inspection)
    pub fn store(&self) -> &SessionStore {
        &self.store
    }

    /// Evict stale entries from the per-IP rate limit map.
    ///
    /// Call periodically (e.g., every 60 seconds) to prevent unbounded growth
    /// of `ip_call_counts`. Entries whose epoch second is older than `max_age_secs`
    /// seconds ago are removed.
    pub fn evict_stale_rate_limits(&self, max_age_secs: u64) -> usize {
        let cutoff = Utc::now().timestamp() as u64 - max_age_secs;
        let before = self.ip_call_counts.len();
        self.ip_call_counts.retain(|_, (epoch_sec, _)| *epoch_sec >= cutoff);
        let removed = before - self.ip_call_counts.len();
        if removed > 0 {
            tracing::debug!(
                removed = removed,
                remaining = self.ip_call_counts.len(),
                "Evicted stale ip_call_counts entries"
            );
        }
        removed
    }

    /// Evict TLS history entries for users whose last activity is older than
    /// `max_age_secs` seconds ago.
    ///
    /// `tls_histories` has no self-evicting mechanism; without this call the
    /// map grows indefinitely as new users authenticate.  Call periodically
    /// (e.g., every 300 seconds) to prevent memory exhaustion.
    pub fn evict_stale_tls_histories(&self, max_age_secs: i64) -> usize {
        let cutoff = Utc::now() - chrono::Duration::seconds(max_age_secs);
        let before = self.tls_histories.len();
        self.tls_histories.retain(|_, history| history.last_seen >= cutoff);
        let removed = before - self.tls_histories.len();
        if removed > 0 {
            tracing::debug!(
                removed = removed,
                remaining = self.tls_histories.len(),
                "Evicted stale tls_histories entries"
            );
        }
        removed
    }

    /// Evict per-user lockout event lists whose most recent event is older than
    /// `max_age_secs` seconds ago.
    ///
    /// The `lockout_events` map accretes entries for users who are locked out
    /// but never attempt to authenticate again (their per-login cleanup never
    /// runs).  Call periodically to bound memory usage.
    pub fn evict_stale_lockout_events(&self, max_age_secs: i64) -> usize {
        let cutoff = Utc::now() - chrono::Duration::seconds(max_age_secs);
        let before = self.lockout_events.len();
        self.lockout_events.retain(|_, events| {
            // Keep the entry only if at least one event is still within the window.
            events.iter().any(|ts| *ts >= cutoff)
        });
        let removed = before - self.lockout_events.len();
        if removed > 0 {
            tracing::debug!(
                removed = removed,
                remaining = self.lockout_events.len(),
                "Evicted stale lockout_events entries"
            );
        }
        removed
    }

    /// Spawn a background Tokio task that periodically evicts stale in-memory
    /// state from all three unbounded DashMaps.
    ///
    /// The returned [`tokio::task::JoinHandle`] can be awaited or aborted by
    /// the caller.  `interval_secs` controls how often the cleanup runs;
    /// 60 seconds is a reasonable default.  The method requires `Arc<Self>`
    /// because the background task must hold an independent reference to the
    /// engine after this method returns.
    ///
    /// # Eviction windows
    ///   * `ip_call_counts`   — entries older than 2× interval (2 × rate-limit windows)
    ///   * `lockout_events`   — entries whose newest event is older than 1 hour
    ///   * `tls_histories`    — entries not seen in 24 hours
    pub fn run_cleanup_loop(
        self: Arc<Self>,
        interval_secs: u64,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let interval = tokio::time::Duration::from_secs(interval_secs);
            let mut ticker = tokio::time::interval(interval);
            // Skip the first (immediate) tick so we don't evict on startup.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let rate_removed  = self.evict_stale_rate_limits(interval_secs * 2);
                let lock_removed  = self.evict_stale_lockout_events(3_600);
                let tls_removed   = self.evict_stale_tls_histories(86_400);
                if rate_removed + lock_removed + tls_removed > 0 {
                    tracing::info!(
                        rate_removed,
                        lock_removed,
                        tls_removed,
                        "ATO engine periodic cleanup complete"
                    );
                }
            }
        })
    }

    /// Evaluate in-session behavior to support continuous authentication decisions.
    pub fn evaluate_session_activity(&self, event: &SessionActivityEvent) -> SessionRiskVerdict {
        let mut factors = Vec::new();
        let mut risk_score: f64 = 0.0;

        if event.ip_changed {
            factors.push(RiskFactor {
                id: "SESSION_IP_CHANGE",
                description: format!("Session {} observed IP change", event.session_id),
                risk: 2.5,
            });
            risk_score += 2.5;
        }

        if event.user_agent_changed {
            factors.push(RiskFactor {
                id: "SESSION_UA_CHANGE",
                description: "User-Agent changed mid-session".into(),
                risk: 2.0,
            });
            risk_score += 2.0;
        }

        if event.tls_fingerprint_changed {
            factors.push(RiskFactor {
                id: "SESSION_TLS_CHANGE",
                description: "TLS fingerprint changed mid-session".into(),
                risk: 2.5,
            });
            risk_score += 2.5;
        }

        if event.privileged_action {
            factors.push(RiskFactor {
                id: "SESSION_PRIVILEGED_ACTION",
                description: "Privileged action requested".into(),
                risk: 1.5,
            });
            risk_score += 1.5;
        }

        if let Some(speed) = event.geo_velocity_kmh {
            if speed > self.config.max_travel_speed_kmh {
                factors.push(RiskFactor {
                    id: "SESSION_GEO_VELOCITY",
                    description: format!(
                        "In-session geovelocity {:.0} km/h exceeds threshold {:.0} km/h",
                        speed,
                        self.config.max_travel_speed_kmh
                    ),
                    risk: 8.0,
                });
                risk_score += 8.0;
            }
        } else if event.ip_changed {
            // Geo-velocity was not computed even though IP changed —
            // this means the GeoIP lookup failed or was unavailable.
            // Apply a moderate risk penalty because we CANNOT verify
            // travel speed. An attacker who hides their geo-location
            // should not get a free pass on impossible-travel checks.
            let geo_unknown_penalty = 2.0;
            factors.push(RiskFactor {
                id: "SESSION_GEO_UNKNOWN",
                description: "IP changed but GeoIP lookup unavailable — cannot verify travel speed".into(),
                risk: geo_unknown_penalty,
            });
            risk_score += geo_unknown_penalty;
            tracing::warn!(
                user_id = %event.user_id,
                session_id = %event.session_id,
                "geo_velocity_kmh is None but IP changed — GeoIP lookup may have failed; applied {:.1} risk penalty",
                geo_unknown_penalty
            );
        }

        risk_score = risk_score.min(10.0);
        let action = if risk_score >= self.config.block_threshold {
            AtoAction::Block
        } else if risk_score >= self.config.mfa_threshold {
            AtoAction::RequireMfa
        } else {
            AtoAction::Allow
        };

        SessionRiskVerdict {
            risk_score,
            action,
            factors,
        }
    }
}

#[cfg(feature = "events")]
impl AtoEngine {
    /// Evaluate a login event and also produce a normalized security event.
    ///
    /// Requires the `events` feature flag (which enables the `mail-common` dep).
    pub fn evaluate_with_event(
        &self,
        event: &LoginEvent,
        correlation: Option<mail_common::security::CorrelationContext>,
    ) -> (AtoVerdict, mail_common::security::SecurityEvent) {
        let verdict = self.evaluate(event);
        let correlation = correlation.unwrap_or_else(
            mail_common::security::CorrelationContext::generated,
        );

        let (action, severity) = match verdict.action {
            AtoAction::Allow => (
                mail_common::security::SecurityAction::Allow,
                mail_common::security::SecuritySeverity::Info,
            ),
            AtoAction::RequireMfa => (
                mail_common::security::SecurityAction::RequireMfa,
                mail_common::security::SecuritySeverity::Medium,
            ),
            AtoAction::Block => (
                mail_common::security::SecurityAction::Block,
                mail_common::security::SecuritySeverity::High,
            ),
            AtoAction::RequireCaptcha => (
                mail_common::security::SecurityAction::Block,
                mail_common::security::SecuritySeverity::Critical,
            ),
        };

        let mut sec_event = mail_common::security::SecurityEvent::new(
            mail_common::security::SecuritySystem::Ato,
            action,
            severity,
            verdict.risk_score,
            format!(
                "ATO action={} risk={:.1} travel={} new_device={}",
                verdict.action, verdict.risk_score, verdict.impossible_travel, verdict.new_device
            ),
            correlation,
        )
        .with_metadata("user_id", event.user_id.clone())
        .with_metadata("src_ip", event.ip_address.clone())
        .with_metadata("ip_address", event.ip_address.clone());

        if let Some(alert) = mail_common::security::ingest_security_event(sec_event.clone()) {
            sec_event.metadata.insert("composite_alert".to_string(), "true".to_string());
            sec_event.metadata.insert(
                "composite_score".to_string(),
                format!("{:.2}", alert.composite_score),
            );
            sec_event.metadata.insert(
                "composite_action".to_string(),
                format!("{:?}", alert.recommended_action),
            );
        }

        (verdict, sec_event)
    }
}

impl Default for AtoEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn login_event(user: &str, ip: &str, lat: f64, lon: f64) -> LoginEvent {
        LoginEvent {
            user_id: user.into(),
            ip_address: ip.into(),
            user_agent: "Mozilla/5.0 (Test)".into(),
            latitude: Some(lat),
            longitude: Some(lon),
            timestamp: Utc::now(),
            success: true,
            tls_fingerprint: None,
        }
    }

    #[test]
    fn test_first_login() {
        let engine = AtoEngine::new();
        let event = login_event("user1", "1.2.3.4", 40.7128, -74.006);
        let verdict = engine.evaluate(&event);
        assert!(verdict.new_device, "First login should be new device");
        // New device alone shouldn't block
        assert_ne!(verdict.action, AtoAction::Block);
    }

    #[test]
    fn test_known_device() {
        let engine = AtoEngine::new();
        let event = login_event("user1", "1.2.3.4", 40.7128, -74.006);
        engine.evaluate(&event); // First login
        let verdict = engine.evaluate(&event); // Same device again
        assert!(!verdict.new_device, "Known device should not be new");
    }

    #[test]
    fn test_failed_attempts_lockout() {
        let engine = AtoEngine::new();
        // Record multiple failures
        for _ in 0..6 {
            let mut fail = login_event("user1", "1.2.3.4", 40.7128, -74.006);
            fail.success = false;
            engine.evaluate(&fail);
        }
        // Now a successful attempt should be blocked
        let event = login_event("user1", "1.2.3.4", 40.7128, -74.006);
        let verdict = engine.evaluate(&event);
        assert_eq!(verdict.action, AtoAction::Block,
            "Should be blocked after {} failed attempts, risk={:.1}",
            6, verdict.risk_score);
    }

    #[test]
    fn test_impossible_travel() {
        let engine = AtoEngine::new();

        // Login from NYC
        let nyc = login_event("user1", "1.2.3.4", 40.7128, -74.006);
        engine.evaluate(&nyc);

        // Immediately login from Tokyo (impossible)
        let tokyo = login_event("user1", "5.6.7.8", 35.6762, 139.6503);
        let verdict = engine.evaluate(&tokyo);
        assert!(verdict.impossible_travel, "Should detect impossible travel");
        assert!(verdict.risk_score > 5.0, "High risk for impossible travel: {}", verdict.risk_score);
    }

    #[test]
    fn test_action_display() {
        assert_eq!(AtoAction::Allow.to_string(), "ALLOW");
        assert_eq!(AtoAction::RequireMfa.to_string(), "REQUIRE_MFA");
        assert_eq!(AtoAction::Block.to_string(), "BLOCK");
    }

    #[test]
    fn test_session_continuous_auth_risk() {
        let engine = AtoEngine::new();
        let verdict = engine.evaluate_session_activity(&SessionActivityEvent {
            user_id: "user1".into(),
            session_id: "sess-1".into(),
            ip_changed: true,
            user_agent_changed: true,
            tls_fingerprint_changed: true,
            privileged_action: true,
            geo_velocity_kmh: Some(1400.0),
        });
        assert!(matches!(verdict.action, AtoAction::RequireMfa | AtoAction::Block));
    }
}
