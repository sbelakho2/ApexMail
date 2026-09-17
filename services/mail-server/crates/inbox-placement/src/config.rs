use std::env;

#[derive(Debug, Clone)]
pub struct PlacementConfig {
    pub enabled: bool,
    pub polling_interval_secs: u64,
    pub max_polling_attempts: u32,
    pub max_seeds_per_test: usize,
    pub max_tests_per_hour: u32,
    pub imap_connection_timeout_secs: u64,
    pub encrypt_stored_passwords: bool,
    /// KEK secret material used to derive the AES-256 key used to wrap
    /// IMAP-account passwords stored in `seed_accounts.imap_password_encrypted`.
    /// When `None`, stored passwords are treated as plaintext (development only).
    pub encryption_secret: Option<String>,
    /// Interval between seed-account IMAP health checks (seconds).
    pub health_check_interval_secs: u64,
    /// Number of consecutive IMAP failures after which a seed account is
    /// auto-disabled (`is_active = false`).
    pub seed_account_failure_threshold: u32,
    /// Platform SMTP relay used to send placement test messages
    /// (internal MTA hostname; compose service name is `mta`).
    pub smtp_host: String,
    /// Port on the platform SMTP relay (25 = internal delivery port).
    pub smtp_port: u16,
    /// Optional SMTP AUTH username for the relay. When unset the relay is
    /// used unauthenticated (internal network, e.g. `mta:25`).
    pub smtp_user: Option<String>,
    /// Optional SMTP AUTH password for the relay.
    pub smtp_pass: Option<String>,
    /// Age (seconds) after which a `running` placement test with no progress
    /// is reaped (marked `failed` with a timeout error).
    pub stuck_test_timeout_secs: u64,
}

impl Default for PlacementConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            polling_interval_secs: 300,
            max_polling_attempts: 12,
            max_seeds_per_test: 50,
            max_tests_per_hour: 5,
            imap_connection_timeout_secs: 30,
            encrypt_stored_passwords: true,
            encryption_secret: None,
            health_check_interval_secs: 1800,
            seed_account_failure_threshold: 3,
            smtp_host: "mta".to_string(),
            smtp_port: 25,
            smtp_user: None,
            smtp_pass: None,
            stuck_test_timeout_secs: 7200,
        }
    }
}

impl PlacementConfig {
    pub fn from_env() -> Self {
        Self {
            enabled: env::var("PLACEMENT_ENABLED")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
            polling_interval_secs: env::var("PLACEMENT_POLLING_INTERVAL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),
            max_polling_attempts: env::var("PLACEMENT_MAX_POLLING_ATTEMPTS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(12),
            max_seeds_per_test: env::var("PLACEMENT_MAX_SEEDS_PER_TEST")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(50),
            max_tests_per_hour: env::var("PLACEMENT_MAX_TESTS_PER_HOUR")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            imap_connection_timeout_secs: env::var("PLACEMENT_IMAP_TIMEOUT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            encrypt_stored_passwords: env::var("PLACEMENT_ENCRYPT_PASSWORDS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
            encryption_secret: env::var("PLACEMENT_ENCRYPTION_SECRET")
                .ok()
                .filter(|v| !v.is_empty()),
            health_check_interval_secs: env::var("PLACEMENT_HEALTH_CHECK_INTERVAL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1800),
            seed_account_failure_threshold: env::var("PLACEMENT_SEED_FAILURE_THRESHOLD")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3),
            // Platform SMTP relay (compose service `mta`, internal port 25).
            smtp_host: env::var("PLACEMENT_SMTP_HOST")
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "mta".to_string()),
            smtp_port: env::var("PLACEMENT_SMTP_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(25),
            smtp_user: env::var("PLACEMENT_SMTP_USER")
                .ok()
                .filter(|v| !v.is_empty()),
            smtp_pass: env::var("PLACEMENT_SMTP_PASS")
                .ok()
                .filter(|v| !v.is_empty()),
            // Default 2h comfortably exceeds the worst-case per-account polling
            // cycle (max_polling_attempts × polling_interval_secs = 1h).
            stuck_test_timeout_secs: env::var("PLACEMENT_STUCK_TEST_TIMEOUT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(7200),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes env-mutating tests.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Set env vars, run `f`, restore previous values afterwards.
    fn with_env<T>(vars: &[(&str, Option<&str>)], f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved: Vec<(String, Option<String>)> = vars
            .iter()
            .map(|(k, _)| ((*k).to_string(), std::env::var(k).ok()))
            .collect();
        for (k, v) in vars {
            match v {
                Some(value) => std::env::set_var(k, value),
                None => std::env::remove_var(k),
            }
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        for (k, v) in saved {
            match v {
                Some(value) => std::env::set_var(&k, value),
                None => std::env::remove_var(&k),
            }
        }
        match result {
            Ok(value) => value,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    #[test]
    fn from_env_reads_overrides_and_keeps_defaults() {
        let cfg = with_env(
            &[
                ("PLACEMENT_ENABLED", Some("false")),
                ("PLACEMENT_POLLING_INTERVAL", Some("60")),
                ("PLACEMENT_MAX_POLLING_ATTEMPTS", Some("3")),
                ("PLACEMENT_MAX_SEEDS_PER_TEST", Some("7")),
                ("PLACEMENT_MAX_TESTS_PER_HOUR", Some("11")),
                ("PLACEMENT_IMAP_TIMEOUT", Some("5")),
                ("PLACEMENT_ENCRYPT_PASSWORDS", Some("false")),
                ("PLACEMENT_ENCRYPTION_SECRET", Some("kek-secret")),
                ("PLACEMENT_HEALTH_CHECK_INTERVAL", Some("90")),
                ("PLACEMENT_SEED_FAILURE_THRESHOLD", Some("4")),
                ("PLACEMENT_SMTP_HOST", Some("relay.internal")),
                ("PLACEMENT_SMTP_PORT", Some("2525")),
                ("PLACEMENT_SMTP_USER", Some("u")),
                ("PLACEMENT_SMTP_PASS", Some("p")),
                ("PLACEMENT_STUCK_TEST_TIMEOUT", Some("3600")),
            ],
            PlacementConfig::from_env,
        );
        assert!(!cfg.enabled);
        assert_eq!(cfg.polling_interval_secs, 60);
        assert_eq!(cfg.max_polling_attempts, 3);
        assert_eq!(cfg.max_seeds_per_test, 7);
        assert_eq!(cfg.max_tests_per_hour, 11);
        assert_eq!(cfg.imap_connection_timeout_secs, 5);
        assert!(!cfg.encrypt_stored_passwords);
        assert_eq!(cfg.encryption_secret.as_deref(), Some("kek-secret"));
        assert_eq!(cfg.health_check_interval_secs, 90);
        assert_eq!(cfg.seed_account_failure_threshold, 4);
        assert_eq!(cfg.smtp_host, "relay.internal");
        assert_eq!(cfg.smtp_port, 2525);
        assert_eq!(cfg.smtp_user.as_deref(), Some("u"));
        assert_eq!(cfg.smtp_pass.as_deref(), Some("p"));
        assert_eq!(cfg.stuck_test_timeout_secs, 3600);

        // Unset → defaults; empty-string secret/credentials are treated as
        // unset (a blank secret must not look configured).
        let cfg = with_env(
            &[
                ("PLACEMENT_ENABLED", None),
                ("PLACEMENT_POLLING_INTERVAL", None),
                ("PLACEMENT_MAX_POLLING_ATTEMPTS", None),
                ("PLACEMENT_MAX_SEEDS_PER_TEST", None),
                ("PLACEMENT_MAX_TESTS_PER_HOUR", None),
                ("PLACEMENT_IMAP_TIMEOUT", None),
                ("PLACEMENT_ENCRYPT_PASSWORDS", None),
                ("PLACEMENT_ENCRYPTION_SECRET", Some("")),
                ("PLACEMENT_HEALTH_CHECK_INTERVAL", None),
                ("PLACEMENT_SEED_FAILURE_THRESHOLD", None),
                ("PLACEMENT_SMTP_HOST", Some("")),
                ("PLACEMENT_SMTP_PORT", None),
                ("PLACEMENT_SMTP_USER", Some("")),
                ("PLACEMENT_SMTP_PASS", Some("")),
                ("PLACEMENT_STUCK_TEST_TIMEOUT", None),
            ],
            PlacementConfig::from_env,
        );
        let default = PlacementConfig::default();
        assert_eq!(cfg.enabled, default.enabled);
        assert_eq!(cfg.polling_interval_secs, default.polling_interval_secs);
        assert_eq!(cfg.max_polling_attempts, default.max_polling_attempts);
        assert_eq!(cfg.max_seeds_per_test, default.max_seeds_per_test);
        assert_eq!(cfg.max_tests_per_hour, default.max_tests_per_hour);
        assert_eq!(
            cfg.imap_connection_timeout_secs,
            default.imap_connection_timeout_secs
        );
        assert_eq!(
            cfg.encrypt_stored_passwords,
            default.encrypt_stored_passwords
        );
        assert_eq!(cfg.encryption_secret, None);
        assert_eq!(
            cfg.health_check_interval_secs,
            default.health_check_interval_secs
        );
        assert_eq!(
            cfg.seed_account_failure_threshold,
            default.seed_account_failure_threshold
        );
        assert_eq!(cfg.smtp_host, "mta");
        assert_eq!(cfg.smtp_port, default.smtp_port);
        assert_eq!(cfg.smtp_user, None);
        assert_eq!(cfg.smtp_pass, None);
        assert_eq!(cfg.stuck_test_timeout_secs, default.stuck_test_timeout_secs);

        // Garbage numeric values fall back to the defaults instead of panicking.
        let cfg = with_env(
            &[
                ("PLACEMENT_POLLING_INTERVAL", Some("not-a-number")),
                ("PLACEMENT_SMTP_PORT", Some("99999")),
            ],
            PlacementConfig::from_env,
        );
        assert_eq!(cfg.polling_interval_secs, 300);
        assert_eq!(cfg.smtp_port, 25);
    }
}
