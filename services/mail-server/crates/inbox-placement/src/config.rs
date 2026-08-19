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
