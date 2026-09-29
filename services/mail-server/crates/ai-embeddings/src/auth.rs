//! Per-workload internal auth (P1 #6, 2026-09 privilege-boundary audit).
//!
//! The universal `INTERNAL_SERVICE_TOKEN` used to authenticate EVERY internal
//! service, so one compromised secret authorized calls against unrelated
//! workloads. This module implements the migration-safe per-workload
//! pattern:
//!
//! * `AI_EMBEDDINGS_AUTH_TOKEN` SET → requests must present EXACTLY it
//!   (timing-safe compare). The universal token is REFUSED — and detected
//!   (loudly logged) so operators can spot unmigrated callers.
//! * `AI_EMBEDDINGS_AUTH_TOKEN` UNSET → the universal token is still
//!   accepted (legacy behavior) so existing deployments keep working, BUT a
//!   production deployment REFUSES TO BOOT: the per-workload pattern is
//!   complete for this service, so there is no migration window left to
//!   warn through.

/// The dedicated per-workload credential env for this service.
pub const DEDICATED_TOKEN_ENV: &str = "AI_EMBEDDINGS_AUTH_TOKEN";

/// Production detection following the workspace convention (see
/// sales-autopilot / ai-service): `APP_ENV == "production"`
/// case-insensitively — and an UNSET `APP_ENV` counts as production
/// (fail closed).
fn is_production_mode() -> bool {
    std::env::var("APP_ENV")
        .map(|v| v.eq_ignore_ascii_case("production"))
        .unwrap_or(true)
}

/// Resolved internal-auth credentials for this service.
#[derive(Debug, Clone)]
pub struct ServiceAuth {
    /// The token that authorizes requests. Empty = deny all (nothing is
    /// configured — the same fail-closed behavior as before this change).
    accepted_token: String,
    /// The universal token, retained ONLY to detect and loudly log its use
    /// after the dedicated token is configured. It NEVER authorizes.
    refused_universal: Option<String>,
    /// Whether the dedicated token was configured (drives the boot logs).
    dedicated_configured: bool,
}

impl ServiceAuth {
    /// Resolve credentials from the dedicated + universal env values.
    ///
    /// `Err` names the dedicated env when production refuses to boot without
    /// it; every other combination resolves (possibly to a deny-all auth
    /// when nothing at all is configured).
    pub fn resolve(
        dedicated: Option<&str>,
        universal: Option<&str>,
        production: bool,
    ) -> Result<Self, String> {
        let dedicated = dedicated.map(str::trim).filter(|v| !v.is_empty());
        let universal = universal.map(str::trim).filter(|v| !v.is_empty());
        match (dedicated, universal) {
            (Some(token), _) => {
                if universal == Some(token) {
                    tracing::warn!(
                        "{DEDICATED_TOKEN_ENV} is set to the SAME value as the universal \
                         INTERNAL_SERVICE_TOKEN — that defeats the per-workload boundary; \
                         generate a distinct secret for this service"
                    );
                }
                Ok(Self {
                    accepted_token: token.to_string(),
                    refused_universal: universal.filter(|u| *u != token).map(String::from),
                    dedicated_configured: true,
                })
            }
            (None, Some(token)) => {
                if production {
                    return Err(format!(
                        "{DEDICATED_TOKEN_ENV} must be set when APP_ENV is production (or \
                         unset): the universal INTERNAL_SERVICE_TOKEN must not authorize \
                         this service — the per-workload credential pattern is complete"
                    ));
                }
                tracing::warn!(
                    "{DEDICATED_TOKEN_ENV} is not set — falling back to the universal \
                     INTERNAL_SERVICE_TOKEN. This is REQUIRED-SOON: production boots refuse \
                     without {DEDICATED_TOKEN_ENV}"
                );
                Ok(Self {
                    accepted_token: token.to_string(),
                    refused_universal: None,
                    dedicated_configured: false,
                })
            }
            (None, None) => {
                tracing::warn!(
                    "no service token configured ({DEDICATED_TOKEN_ENV} unset, \
                     INTERNAL_SERVICE_TOKEN unset) — every authenticated route rejects \
                     requests (401)"
                );
                Ok(Self {
                    accepted_token: String::new(),
                    refused_universal: None,
                    dedicated_configured: false,
                })
            }
        }
    }

    /// Resolve from the process environment (binaries call this at boot).
    pub fn from_env() -> Result<Self, String> {
        let dedicated = std::env::var(DEDICATED_TOKEN_ENV).ok();
        let universal = std::env::var("INTERNAL_SERVICE_TOKEN").ok();
        Self::resolve(dedicated.as_deref(), universal.as_deref(), is_production_mode())
    }

    /// Timing-safe authorization decision for a presented credential.
    pub fn authorize(&self, provided: &str) -> bool {
        !self.accepted_token.is_empty()
            && apexmail_lib::timing_safe_compare(provided, &self.accepted_token)
    }

    /// True when the caller presented the UNIVERSAL token while the
    /// dedicated one is configured — an unmigrated caller to log loudly
    /// about (it is refused either way).
    pub fn is_refused_universal_attempt(&self, provided: &str) -> bool {
        self.refused_universal
            .as_deref()
            .is_some_and(|legacy| apexmail_lib::timing_safe_compare(provided, legacy))
    }

    /// Whether the dedicated per-workload token is configured.
    pub fn dedicated_configured(&self) -> bool {
        self.dedicated_configured
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedicated_token_is_accepted_and_universal_refused() {
        let auth = ServiceAuth::resolve(Some("dedicated-secret"), Some("universal"), false)
            .expect("dedicated config resolves");
        assert!(auth.authorize("dedicated-secret"));
        assert!(!auth.authorize("universal"), "universal token must be refused");
        assert!(!auth.authorize("wrong"));
        assert!(auth.dedicated_configured());
        assert!(auth.is_refused_universal_attempt("universal"));
        assert!(!auth.is_refused_universal_attempt("wrong"));
    }

    #[test]
    fn unset_dedicated_keeps_legacy_universal_and_warns() {
        let auth = ServiceAuth::resolve(None, Some("universal"), false)
            .expect("non-production legacy resolves");
        assert!(auth.authorize("universal"), "legacy behavior preserved");
        assert!(!auth.authorize("dedicated-secret"));
        assert!(!auth.dedicated_configured());
        assert!(!auth.is_refused_universal_attempt("universal"));
    }

    #[test]
    fn unset_dedicated_refuses_to_boot_in_production() {
        let err = ServiceAuth::resolve(None, Some("universal"), true)
            .expect_err("production without the dedicated token must refuse");
        assert!(
            err.contains(DEDICATED_TOKEN_ENV),
            "refusal must name the dedicated env: {err}"
        );
    }

    #[test]
    fn nothing_configured_denies_everything() {
        let auth = ServiceAuth::resolve(None, None, false).expect("deny-all resolves");
        assert!(!auth.authorize(""));
        assert!(!auth.authorize("anything"));
    }

    #[test]
    fn dedicated_equal_to_universal_is_flagged_but_still_required() {
        let auth =
            ServiceAuth::resolve(Some("same"), Some("same"), false).expect("resolve succeeds");
        assert!(auth.authorize("same"));
        assert!(!auth.is_refused_universal_attempt("same"));
    }

    #[test]
    fn empty_env_values_are_treated_as_unset() {
        let auth = ServiceAuth::resolve(Some("  "), Some("universal"), false)
            .expect("blank dedicated counts as unset");
        assert!(auth.authorize("universal"));
        let auth = ServiceAuth::resolve(None, Some("   "), false).expect("blank universal");
        assert!(!auth.authorize("universal"));
    }

    // ── environment-resolution seam (from_env / is_production_mode) ──────

    /// Serializes the env-mutating tests below (they share one process under
    /// plain `cargo test`; under nextest each test is its own process).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Sets env vars for its lifetime and restores the previous values
    /// (including "unset") on drop — the same pattern as ai-service's
    /// `test_support::EnvGuard`.
    struct EnvGuard {
        saved: Vec<(String, Option<String>)>,
    }

    impl EnvGuard {
        fn with<'a>(vars: &[(&'a str, Option<&'a str>)]) -> Self {
            let mut saved = Vec::new();
            for (key, value) in vars {
                saved.push((key.to_string(), std::env::var(key).ok()));
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
            Self { saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in &self.saved {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    #[test]
    fn production_detection_follows_app_env_and_fails_closed() {
        let _lock = lock_env();

        // An UNSET APP_ENV counts as production (fail closed).
        {
            let _guard = EnvGuard::with(&[("APP_ENV", None)]);
            assert!(is_production_mode(), "unset APP_ENV must fail closed");
        }
        for value in ["production", "PRODUCTION", "Production"] {
            let _guard = EnvGuard::with(&[("APP_ENV", Some(value))]);
            assert!(is_production_mode(), "{value} must count as production");
        }
        {
            let _guard = EnvGuard::with(&[("APP_ENV", Some("development"))]);
            assert!(!is_production_mode(), "development is not production");
        }

        // A guard created while a var IS SET must restore that value on
        // drop: the inner guard removes it (fail-closed again), and its own
        // drop undoes the removal.
        {
            let outer = EnvGuard::with(&[("APP_ENV", Some("staging"))]);
            {
                let inner = EnvGuard::with(&[("APP_ENV", None)]);
                assert!(is_production_mode(), "a removed APP_ENV fails closed");
            }
            assert!(
                !is_production_mode(),
                "the inner guard's drop must restore the outer value"
            );
        }
    }

    #[test]
    fn from_env_resolves_credentials_and_refuses_production_gaps() {
        let _lock = lock_env();

        // Dedicated token configured: the only accepted credential, whatever
        // APP_ENV says.
        {
            let _guard = EnvGuard::with(&[
                (DEDICATED_TOKEN_ENV, Some("dedicated-secret")),
                ("INTERNAL_SERVICE_TOKEN", Some("universal")),
                ("APP_ENV", Some("production")),
            ]);
            let auth = ServiceAuth::from_env().expect("the dedicated token boots everywhere");
            assert!(auth.authorize("dedicated-secret"));
            assert!(!auth.authorize("universal"));
            assert!(auth.dedicated_configured());
        }

        // Legacy fallback outside production: the universal token still
        // authorizes.
        {
            let _guard = EnvGuard::with(&[
                (DEDICATED_TOKEN_ENV, None),
                ("INTERNAL_SERVICE_TOKEN", Some("universal")),
                ("APP_ENV", Some("development")),
            ]);
            let auth =
                ServiceAuth::from_env().expect("legacy fallback resolves outside production");
            assert!(auth.authorize("universal"));
            assert!(!auth.dedicated_configured());
        }

        // Production — explicit AND fail-closed-unset — without the
        // dedicated token refuses to boot, naming the env to set.
        for app_env in [Some("production"), None] {
            let _guard = EnvGuard::with(&[
                (DEDICATED_TOKEN_ENV, None),
                ("INTERNAL_SERVICE_TOKEN", Some("universal")),
                ("APP_ENV", app_env),
            ]);
            let error = ServiceAuth::from_env()
                .expect_err("production without the dedicated token must refuse");
            assert!(error.contains(DEDICATED_TOKEN_ENV), "{error}");
        }

        // Nothing configured at all: boots (outside production) but every
        // authenticated route denies.
        {
            let _guard = EnvGuard::with(&[
                (DEDICATED_TOKEN_ENV, None),
                ("INTERNAL_SERVICE_TOKEN", None),
                ("APP_ENV", Some("development")),
            ]);
            let auth = ServiceAuth::from_env().expect("deny-all resolves");
            assert!(!auth.authorize(""));
            assert!(!auth.authorize("anything"));
            assert!(!auth.dedicated_configured());
        }
    }
}
