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
use crate::session::{LoginEvent, SessionStore};
use crate::tls_fingerprint::UserTlsHistory;

use dashmap::DashMap;
use std::sync::Arc;

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
}

impl std::fmt::Display for AtoAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AtoAction::Allow => write!(f, "ALLOW"),
            AtoAction::RequireMfa => write!(f, "REQUIRE_MFA"),
            AtoAction::Block => write!(f, "BLOCK"),
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

/// The ATO protection engine
pub struct AtoEngine {
    config: AtoConfig,
    store: SessionStore,
    /// Per-user TLS fingerprint history — detects bot stack changes
    tls_histories: Arc<DashMap<String, UserTlsHistory>>,
}

impl AtoEngine {
    /// Create engine with default config
    pub fn new() -> Self {
        let config = AtoConfig::default();
        let store = SessionStore::new(config.max_history_per_user);
        Self { config, store, tls_histories: Arc::new(DashMap::new()) }
    }

    /// Create engine with custom config
    pub fn with_config(config: AtoConfig) -> Self {
        let store = SessionStore::new(config.max_history_per_user);
        Self { config, store, tls_histories: Arc::new(DashMap::new()) }
    }

    /// Evaluate a login event and return a risk verdict
    pub fn evaluate(&self, event: &LoginEvent) -> AtoVerdict {
        let mut factors = Vec::new();
        let mut risk_score = 0.0;
        let mut impossible_travel = false;

        // 1. Check failed attempt lockout
        let recent_failures = self.store.recent_failures(
            &event.user_id,
            self.config.failed_attempt_window_secs,
        );
        if recent_failures >= self.config.max_failed_attempts {
            factors.push(RiskFactor {
                id: "LOCKOUT",
                description: format!(
                    "{} failed attempts in {} seconds (max: {})",
                    recent_failures,
                    self.config.failed_attempt_window_secs,
                    self.config.max_failed_attempts
                ),
                risk: 10.0,
            });
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
        let action = if risk_score >= self.config.block_threshold {
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
}
