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
        }
    }
}
