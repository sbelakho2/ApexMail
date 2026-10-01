//! Process-shared ATO runtime — the deployment gate and engine handle that
//! real login flows call.
//!
//! The api-server login handlers (JSON `/login` and the SSR password step)
//! must be able to evaluate a login without owning an [`AtoEngine`] instance
//! (they hold `AppState`, which deliberately carries no ATO field). This
//! module provides the process-wide, lazily built runtime:
//!
//! - **Gate** — `ATO_PROTECTION_ENABLED` explicitly forces the protection on
//!   or off; when unset the default is OFF outside production/staging so
//!   local development flows are untouched, and ON where the product
//!   advertises account-takeover protection.
//! - **Config** — engine tuning via `ATO_REDIS_LOCKOUT_URL`,
//!   `ATO_MFA_THRESHOLD`, `ATO_BLOCK_THRESHOLD` (plus the pepper env read by
//!   [`crate::config::AtoConfig::default`]).
//! - **Fail-open contract** — an engine that cannot be built (invalid
//!   configuration) leaves the runtime DEGRADED: [`AtoRuntime::evaluate_login`]
//!   reports the error and callers allow the login with a loud log. A
//!   security layer must never take authentication down with it.

use crate::config::{AtoConfig, DeploymentMode};
use crate::engine::{AtoAction, AtoEngine, AtoVerdict};
use crate::session::LoginEvent;

use parking_lot::RwLock;
use std::sync::Arc;

/// Coarse, deterministic risk band derived from the engine verdict.
///
/// The login handlers map this band onto the shared response policy:
/// - `Low` → allow (score logged, no audit row),
/// - `Medium` → allow, but require MFA step-up when the user has MFA
///   enrolled (otherwise allow + flag) — always with an audit row,
/// - `High` → refuse the attempt with the handler's standard
///   wrong-password response (anti-enumeration) — always with an audit row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtoBand {
    /// Composite risk below the MFA threshold.
    Low,
    /// Composite risk at/above the MFA threshold, below the block threshold.
    Medium,
    /// Composite risk at/above the block threshold (or an escalated lockout).
    High,
}

impl AtoBand {
    /// Stable lowercase name used in audit rows and logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            AtoBand::Low => "low",
            AtoBand::Medium => "medium",
            AtoBand::High => "high",
        }
    }
}

/// Map an engine action onto the response band.
///
/// `RequireCaptcha` (escalated lockout) is at least as severe as `Block`,
/// so both land in the high band.
pub fn band_for(action: AtoAction) -> AtoBand {
    match action {
        AtoAction::Allow => AtoBand::Low,
        AtoAction::RequireMfa => AtoBand::Medium,
        AtoAction::Block | AtoAction::RequireCaptcha => AtoBand::High,
    }
}

/// Resolve the deployment gate.
///
/// `explicit` is the raw `ATO_PROTECTION_ENABLED` value (if set);
/// `environment` is the raw `ENVIRONMENT` value (if set). An explicit
/// truthy/falsy value always wins; otherwise the gate defaults ON for
/// production/staging and OFF elsewhere (development default OFF).
pub fn resolve_gate(explicit: Option<&str>, environment: Option<&str>) -> bool {
    if let Some(raw) = explicit {
        match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => return true,
            "0" | "false" | "no" | "off" => return false,
            _ => {}
        }
    }
    matches!(
        environment.map(|value| value.trim().to_ascii_lowercase()),
        Some(ref env) if env == "production" || env == "prod" || env == "staging"
    )
}

/// Engine configuration for the login flows, from the `ATO_*` environment
/// variables. The base is [`AtoConfig::development`] (honest about
/// single-node in-memory lockout state); setting `ATO_REDIS_LOCKOUT_URL`
/// upgrades the deployment to cross-node Redis lockout tracking.
pub fn runtime_config_from_env() -> AtoConfig {
    let mut config = AtoConfig::development();
    if let Ok(url) = std::env::var("ATO_REDIS_LOCKOUT_URL") {
        let url = url.trim().to_string();
        if !url.is_empty() {
            config.redis_lockout_url = Some(url);
            config.deployment_mode = DeploymentMode::Production;
            config.allow_single_node_mode = false;
        }
    }
    if let Ok(raw) = std::env::var("ATO_MFA_THRESHOLD") {
        if let Ok(value) = raw.trim().parse::<f64>() {
            if value.is_finite() {
                config.mfa_threshold = value;
            }
        }
    }
    if let Ok(raw) = std::env::var("ATO_BLOCK_THRESHOLD") {
        if let Ok(value) = raw.trim().parse::<f64>() {
            if value.is_finite() {
                config.block_threshold = value;
                // coverage: justified — llvm-cov closing-brace region
                // artifact: this arm executes (the ladder test applies
                // "0.77" — the assignment above carries a hit) and the block
                // cannot be exited except through the brace.
            }
        }
    }
    config
}

/// The gate + engine pair the login flows evaluate against.
///
/// A runtime whose configuration failed validation is DEGRADED: `enabled`
/// still reports the gate state, but every [`AtoRuntime::evaluate_login`]
/// returns `Err` so callers fail OPEN (allow + loud log) instead of taking
/// authentication down with the security layer.
pub struct AtoRuntime {
    enabled: bool,
    engine: Option<AtoEngine>,
    init_error: Option<String>,
}

impl AtoRuntime {
    /// Build a runtime. An invalid configuration is NOT a construction
    /// error — it produces a degraded runtime whose evaluations fail open
    /// (this is the fail-open contract, not a panic path).
    pub fn build(enabled: bool, config: AtoConfig) -> Self {
        if let Err(error) = config.validate() {
            tracing::error!(
                enabled,
                error = ?error,
                "ATO protection configuration is INVALID — runtime DEGRADED: \
                 every evaluation fails OPEN (allow + log). Fix ATO_* settings."
            );
            return Self {
                enabled,
                engine: None,
                init_error: Some(format!("invalid ATO configuration: {error:?}")),
            };
        }
        Self {
            enabled,
            engine: Some(AtoEngine::with_config(config)),
            init_error: None,
        }
    }

    /// Whether the deployment gate is on. When `false`, callers skip the
    /// detector entirely and behave byte-identically to the unprotected
    /// flow.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Evaluate a login event. `Err` means the detector could not run
    /// (disabled is reported as an error too, so a caller that skipped the
    /// gate check still fails open); the caller must then allow the login
    /// with a loud log.
    pub fn evaluate_login(&self, event: &LoginEvent) -> Result<AtoVerdict, String> {
        if !self.enabled {
            return Err("ato protection is disabled".to_string());
        }
        match &self.engine {
            Some(engine) => Ok(engine.evaluate(event)),
            None => Err(self
                .init_error
                .clone()
                .unwrap_or_else(|| "ato engine unavailable".to_string())),
        }
    }

    /// Env-driven runtime used by [`shared`] on first use in a process.
    fn from_env() -> Self {
        let explicit = std::env::var("ATO_PROTECTION_ENABLED").ok();
        let environment = std::env::var("ENVIRONMENT").ok();
        let enabled = resolve_gate(explicit.as_deref(), environment.as_deref());
        if enabled {
            tracing::info!(
                "ATO protection ENABLED for the login flows \
                 (ATO_PROTECTION_ENABLED / ENVIRONMENT gate)"
            );
        }
        Self::build(enabled, runtime_config_from_env())
    }
}

static SHARED_RUNTIME: RwLock<Option<Arc<AtoRuntime>>> = RwLock::new(None);

/// Process-shared runtime. Built once from the environment on first use;
/// every login flow in the process evaluates against the same engine (its
/// per-user history and lockout state are therefore also process-wide).
pub fn shared() -> Arc<AtoRuntime> {
    {
        let read = SHARED_RUNTIME.read();
        if let Some(runtime) = read.as_ref() {
            return runtime.clone();
        }
    }
    let mut write = SHARED_RUNTIME.write();
    if let Some(runtime) = write.as_ref() {
        // coverage: justified — double-checked-locking re-check: reachable
        // only when a concurrent first builder completes between this
        // thread's read-lock release and write-lock acquisition — a race
        // window that cannot be entered deterministically from a
        // single-threaded test (the fast path above and the build path below
        // are both covered).
        return runtime.clone();
    }
    let runtime = Arc::new(AtoRuntime::from_env());
    *write = Some(runtime.clone());
    runtime
}

/// Test hook: replace the process-shared runtime with an explicit gate +
/// configuration so verdicts are deterministic (fresh engine, no history).
/// nextest runs each test in its own process, so the swap cannot leak
/// between tests. Not for production use.
#[doc(hidden)]
pub fn install_for_tests(enabled: bool, config: AtoConfig) {
    *SHARED_RUNTIME.write() = Some(Arc::new(AtoRuntime::build(enabled, config)));
}

/// Test hook: drop the installed runtime so the next [`shared`] call
/// rebuilds from the environment (in tests: development defaults, gate off).
#[doc(hidden)]
pub fn uninstall_for_tests() {
    *SHARED_RUNTIME.write() = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::AtoAction;
    use chrono::{Duration, Utc};

    fn geo_event(
        user: &str,
        ip: &str,
        lat: f64,
        lon: f64,
        at: chrono::DateTime<Utc>,
    ) -> LoginEvent {
        LoginEvent {
            user_id: user.into(),
            ip_address: ip.into(),
            user_agent: "Mozilla/5.0 (Test)".into(),
            latitude: Some(lat),
            longitude: Some(lon),
            timestamp: at,
            success: true,
            tls_fingerprint: None,
            device_fingerprint: None,
        }
    }

    #[test]
    fn resolve_gate_explicit_values_win() {
        for on in ["1", "true", "yes", "on", "TRUE", " On "] {
            assert!(
                resolve_gate(Some(on), Some("development")),
                "explicit {on} must enable"
            );
        }
        for off in ["0", "false", "no", "off", "FALSE", " Off "] {
            assert!(
                !resolve_gate(Some(off), Some("production")),
                "explicit {off} must disable even in production"
            );
        }
        // Unparseable values fall through to the environment default.
        assert!(!resolve_gate(Some("maybe"), Some("development")));
        assert!(resolve_gate(Some("maybe"), Some("production")));
    }

    #[test]
    fn resolve_gate_environment_default() {
        assert!(resolve_gate(None, Some("production")));
        assert!(resolve_gate(None, Some("prod")));
        assert!(resolve_gate(None, Some("staging")));
        assert!(resolve_gate(None, Some(" Production ")));
        assert!(!resolve_gate(None, Some("development")));
        assert!(!resolve_gate(None, Some("")));
        assert!(!resolve_gate(None, None));
    }

    #[test]
    fn band_mapping_is_deterministic() {
        assert_eq!(band_for(AtoAction::Allow), AtoBand::Low);
        assert_eq!(band_for(AtoAction::RequireMfa), AtoBand::Medium);
        assert_eq!(band_for(AtoAction::Block), AtoBand::High);
        assert_eq!(band_for(AtoAction::RequireCaptcha), AtoBand::High);
        assert_eq!(AtoBand::Low.as_str(), "low");
        assert_eq!(AtoBand::Medium.as_str(), "medium");
        assert_eq!(AtoBand::High.as_str(), "high");
    }

    #[test]
    fn disabled_runtime_reports_error_so_callers_fail_open() {
        let runtime = AtoRuntime::build(false, AtoConfig::development());
        assert!(!runtime.enabled());
        let event = geo_event("u", "1.2.3.4", 40.0, -74.0, Utc::now());
        assert!(runtime.evaluate_login(&event).is_err());
    }

    #[test]
    fn invalid_configuration_degrades_to_fail_open() {
        // mfa_threshold >= block_threshold fails validation; the runtime
        // must exist but every evaluation reports the init error instead of
        // panicking or returning a verdict.
        let config = AtoConfig {
            mfa_threshold: 9.0,
            block_threshold: 5.0,
            ..AtoConfig::development()
        };
        let runtime = AtoRuntime::build(true, config);
        assert!(runtime.enabled(), "the gate stays on even when degraded");
        let event = geo_event("u", "1.2.3.4", 40.0, -74.0, Utc::now());
        let error = runtime
            .evaluate_login(&event)
            .expect_err("degraded runtime must report an error");
        assert!(error.contains("invalid ATO configuration"), "{error}");
    }

    #[test]
    fn evaluate_returns_deterministic_low_for_a_fresh_login() {
        let runtime = AtoRuntime::build(true, AtoConfig::development());
        let event = geo_event("fresh-user", "1.2.3.4", 40.0, -74.0, Utc::now());
        let verdict = runtime
            .evaluate_login(&event)
            .expect("healthy runtime evaluates");
        assert_eq!(verdict.action, AtoAction::Allow);
        assert!(verdict.new_device);
    }

    #[test]
    fn impossible_travel_shape_lands_in_the_high_band() {
        let runtime = AtoRuntime::build(true, AtoConfig::development());
        let user = "band-user";
        let nyc = geo_event(
            user,
            "1.2.3.4",
            40.7128,
            -74.0060,
            Utc::now() - Duration::hours(1),
        );
        runtime
            .evaluate_login(&nyc)
            .expect("healthy runtime evaluates");
        let tokyo = geo_event(user, "5.6.7.8", 35.6762, 139.6503, Utc::now());
        let verdict = runtime
            .evaluate_login(&tokyo)
            .expect("healthy runtime evaluates");
        assert!(verdict.impossible_travel, "shape must be impossible travel");
        assert_eq!(band_for(verdict.action), AtoBand::High);
    }

    #[test]
    fn ip_pivot_without_geo_lands_in_the_medium_band() {
        let runtime = AtoRuntime::build(true, AtoConfig::development());
        let user = "pivot-user";
        let first = LoginEvent {
            latitude: None,
            longitude: None,
            ..geo_event(user, "203.0.113.10", 0.0, 0.0, Utc::now())
        };
        runtime
            .evaluate_login(&first)
            .expect("healthy runtime evaluates");
        let second = LoginEvent {
            latitude: None,
            longitude: None,
            user_agent: "Mozilla/5.0 (Attacker)".into(),
            ..geo_event(user, "198.51.100.20", 0.0, 0.0, Utc::now())
        };
        let verdict = runtime
            .evaluate_login(&second)
            .expect("healthy runtime evaluates");
        assert_eq!(band_for(verdict.action), AtoBand::Medium);
        // coverage: justified — lazy assert-format argument: the factor-id
        // list is evaluated only when the assertion FAILS; a green suite by
        // definition never formats it.
        assert!(
            verdict
                .factors
                .iter()
                .any(|f| f.id == "GEO_UNKNOWN" || f.id == "NEW_DEVICE"),
            "IP pivot must be explainable: {:?}",
            verdict.factors.iter().map(|f| f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn install_and_uninstall_swap_the_shared_runtime() {
        install_for_tests(true, AtoConfig::development());
        assert!(shared().enabled());

        let config = AtoConfig {
            mfa_threshold: 9.0,
            block_threshold: 5.0,
            ..AtoConfig::development()
        };
        install_for_tests(true, config);
        let event = geo_event("u", "1.2.3.4", 40.0, -74.0, Utc::now());
        assert!(shared().evaluate_login(&event).is_err(), "degraded swap");

        install_for_tests(false, AtoConfig::development());
        assert!(!shared().enabled());

        uninstall_for_tests();
        // After uninstall the next `shared()` rebuilds from the environment;
        // under the test environment (no ENVIRONMENT override) the gate is
        // off, but the contract under test is only that a fresh runtime is
        // built without panicking.
        let _ = shared();
    }
    // ── Gap-closure:the env-driven configuration ladder and gate ──────

    /// `runtime_config_from_env`:an `ATO_REDIS_LOCKOUT_URL` upgrades the
    /// deployment to cross-node production lockout tracking; blank values
    /// are ignored; threshold overrides must parse as finite f64s —
    /// garbage, infinity and NaN are silently rejected (safe defaults).
    #[test]
    fn runtime_config_from_env_ladder() {
        struct EnvSnapshot(Vec<(&'static str, Option<String>)>);
        impl EnvSnapshot {
            fn take(vars: &[&'static str]) -> Self {
                Self(vars.iter().map(|v| (*v, std::env::var(v).ok())).collect())
            }
        }
        impl Drop for EnvSnapshot {
            fn drop(&mut self) {
                for (name, value) in self.0.drain(..) {
                    match value {
                        Some(v) => std::env::set_var(name, v),
                        None => std::env::remove_var(name),
                    }
                }
            }
        }
        // Pre-set one var so the snapshot captures a Some value and its Drop
        // restores through the set_var arm (the ladder tests leave the others
        // unset, covering the remove_var arm).
        std::env::set_var("ATO_MFA_THRESHOLD", "0.5");
        let _snapshot = EnvSnapshot::take(&[
            "ATO_REDIS_LOCKOUT_URL",
            "ATO_MFA_THRESHOLD",
            "ATO_BLOCK_THRESHOLD",
        ]);

        // Baseline: nothing set → honest single-node development config.
        for var in [
            "ATO_REDIS_LOCKOUT_URL",
            "ATO_MFA_THRESHOLD",
            "ATO_BLOCK_THRESHOLD",
        ] {
            std::env::remove_var(var);
        }
        let cfg = runtime_config_from_env();
        assert!(cfg.redis_lockout_url.is_none());
        assert_eq!(cfg.deployment_mode, DeploymentMode::Development);
        assert_eq!(cfg.mfa_threshold, 5.0);
        assert_eq!(cfg.block_threshold, 9.0);

        // A real URL upgrades the deployment.
        std::env::set_var("ATO_REDIS_LOCKOUT_URL", "  redis://lockout:6379  ");
        let cfg = runtime_config_from_env();
        assert_eq!(
            cfg.redis_lockout_url.as_deref(),
            Some("redis://lockout:6379")
        );
        assert_eq!(cfg.deployment_mode, DeploymentMode::Production);
        assert!(!cfg.allow_single_node_mode);

        // A blank URL is ignored (stays single-node development).
        std::env::set_var("ATO_REDIS_LOCKOUT_URL", "   ");
        let cfg = runtime_config_from_env();
        assert!(cfg.redis_lockout_url.is_none());
        assert_eq!(cfg.deployment_mode, DeploymentMode::Development);

        // Threshold overrides: finite values apply; garbage is rejected.
        std::env::remove_var("ATO_REDIS_LOCKOUT_URL");
        std::env::set_var("ATO_MFA_THRESHOLD", "0.42");
        std::env::set_var("ATO_BLOCK_THRESHOLD", "0.77");
        let cfg = runtime_config_from_env();
        assert_eq!(cfg.mfa_threshold, 0.42);
        assert_eq!(cfg.block_threshold, 0.77);

        std::env::set_var("ATO_MFA_THRESHOLD", "not-a-number");
        std::env::set_var("ATO_BLOCK_THRESHOLD", "inf");
        let cfg = runtime_config_from_env();
        assert_eq!(
            cfg.mfa_threshold, 5.0,
            "garbage threshold overrides are rejected (default retained)"
        );
        assert_eq!(
            cfg.block_threshold, 9.0,
            "infinite threshold overrides are rejected (default retained)"
        );
    }

    /// The process-shared runtime, rebuilt from a gate-ON environment,
    /// evaluates logins against a fresh engine (the `from_env` startup arm
    /// used by every login flow on first use).
    #[test]
    fn shared_runtime_rebuilds_from_a_gate_on_environment() {
        uninstall_for_tests();
        std::env::set_var("ATO_PROTECTION_ENABLED", "1");
        let runtime = shared();
        assert!(runtime.enabled(), "the explicit gate wins");
        let event = geo_event("gate-user", "1.2.3.4", 40.0, -74.0, Utc::now());
        let verdict = runtime
            .evaluate_login(&event)
            .expect("a healthy shared runtime evaluates");
        assert_eq!(verdict.action, AtoAction::Allow);

        // Clean up:drop the installed runtime and the env override so the
        // ambient (gate-off) defaults hold for anything that runs later in
        // this process.
        uninstall_for_tests();
        std::env::remove_var("ATO_PROTECTION_ENABLED");
    }
}
