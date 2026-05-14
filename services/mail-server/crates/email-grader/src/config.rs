use std::collections::HashMap;

/// Per-tenant scoring weight overrides. Weights must sum to ~1.0; the engine
/// will normalize them defensively at evaluation time.
#[derive(Debug, Clone, PartialEq)]
pub struct ScoringWeights {
    pub dns_health: f64,
    pub authentication: f64,
    pub spam_likelihood: f64,
    pub content_quality: f64,
    pub reputation: f64,
}

impl Default for ScoringWeights {
    fn default() -> Self {
        Self {
            dns_health: 0.20,
            authentication: 0.35,
            spam_likelihood: 0.20,
            content_quality: 0.15,
            reputation: 0.10,
        }
    }
}

impl ScoringWeights {
    /// Validate that the weight sum is positive and finite, falling back to
    /// uniform defaults otherwise. Logs a warning on fallback so operators
    /// can detect misconfigurations during startup or at runtime.
    pub fn validate_or_fallback(&self, label: &str) -> Self {
        let sum = self.dns_health
            + self.authentication
            + self.spam_likelihood
            + self.content_quality
            + self.reputation;
        if sum > 0.0 && sum.is_finite() {
            return self.clone();
        }
        tracing::warn!(
            label = %label,
            dns_health = %self.dns_health,
            authentication = %self.authentication,
            spam_likelihood = %self.spam_likelihood,
            content_quality = %self.content_quality,
            reputation = %self.reputation,
            "ScoringWeights sum is non-positive or non-finite; falling back to uniform weights"
        );
        Self::default()
    }

    /// Return a normalized copy whose components sum to 1.0. If the sum is
    /// non-positive or non-finite, the default distribution is returned.
    pub fn normalized(&self) -> Self {
        let sum = self.dns_health
            + self.authentication
            + self.spam_likelihood
            + self.content_quality
            + self.reputation;
        if sum <= 0.0 || !sum.is_finite() {
            return Self::default();
        }
        Self {
            dns_health: self.dns_health / sum,
            authentication: self.authentication / sum,
            spam_likelihood: self.spam_likelihood / sum,
            content_quality: self.content_quality / sum,
            reputation: self.reputation / sum,
        }
    }
}

/// Configuration for the Email Grader.
#[derive(Debug, Clone)]
pub struct GraderConfig {
    pub enabled: bool,
    pub rate_limit_max: u32,
    pub rate_limit_window_seconds: u64,
    pub tenant_dns_budget_max: u32,
    pub tenant_dns_budget_window_seconds: u64,
    pub cache_ttl_seconds: u64,
    pub default_dkim_selectors: Vec<String>,
    pub max_body_size: u32,
    pub encrypt_stored_content: bool,
    pub encryption_master_key_base64: Option<String>,
    pub auth_hostname: String,
    pub network_timeout_seconds: u64,
    pub dkim_lookup_concurrency: usize,
    pub mta_sts_policy_max_bytes: usize,
    pub idempotency_window_seconds: i64,
    pub default_retention_days: i64,
    pub max_jsonb_bytes: usize,
    pub tenant_weights: HashMap<String, ScoringWeights>,
}

impl Default for GraderConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rate_limit_max: 10,
            rate_limit_window_seconds: 3600,
            tenant_dns_budget_max: 600,
            tenant_dns_budget_window_seconds: 60,
            cache_ttl_seconds: 300,
            default_dkim_selectors: vec![
                "default".into(),
                "google".into(),
                "dkim".into(),
                "selector1".into(),
            ],
            max_body_size: 256_000,
            encrypt_stored_content: false,
            encryption_master_key_base64: None,
            auth_hostname: "grader.apexmail.ee".into(),
            network_timeout_seconds: 5,
            dkim_lookup_concurrency: 4,
            mta_sts_policy_max_bytes: 65_536,
            idempotency_window_seconds: 86_400,
            default_retention_days: 90,
            max_jsonb_bytes: 256_000,
            tenant_weights: HashMap::new(),
        }
    }
}

impl GraderConfig {
    /// Parse from environment variables, falling back to defaults.
    pub fn from_env() -> Self {
        Self {
            enabled: env_parse("GRADER_ENABLED", true),
            rate_limit_max: env_parse("GRADER_RATE_LIMIT", 10),
            rate_limit_window_seconds: env_parse("GRADER_RATE_WINDOW", 3600),
            tenant_dns_budget_max: env_parse("GRADER_TENANT_DNS_BUDGET", 600),
            tenant_dns_budget_window_seconds: env_parse("GRADER_TENANT_DNS_WINDOW", 60),
            cache_ttl_seconds: env_parse("GRADER_CACHE_TTL", 300),
            default_dkim_selectors: std::env::var("GRADER_DKIM_SELECTORS")
                .ok()
                .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_else(|| {
                    vec![
                        "default".into(),
                        "google".into(),
                        "dkim".into(),
                        "selector1".into(),
                    ]
                }),
            max_body_size: env_parse("GRADER_MAX_BODY_SIZE", 256_000),
            encrypt_stored_content: env_parse("GRADER_ENCRYPT_STORED", false),
            encryption_master_key_base64: std::env::var("GRADER_ENCRYPTION_KEY_BASE64").ok(),
            auth_hostname: std::env::var("GRADER_AUTH_HOSTNAME")
                .unwrap_or_else(|_| "grader.apexmail.ee".into()),
            network_timeout_seconds: env_parse("GRADER_NETWORK_TIMEOUT", 5),
            dkim_lookup_concurrency: env_parse("GRADER_DKIM_CONCURRENCY", 4),
            mta_sts_policy_max_bytes: env_parse("GRADER_MTA_STS_MAX_BYTES", 65_536),
            idempotency_window_seconds: env_parse("GRADER_IDEMPOTENCY_WINDOW", 86_400),
            default_retention_days: env_parse("GRADER_RETENTION_DAYS", 90),
            max_jsonb_bytes: env_parse("GRADER_MAX_JSONB_BYTES", 256_000),
            tenant_weights: HashMap::new(),
        }
    }

    /// Resolve scoring weights for a tenant, normalized.
    pub fn weights_for(&self, tenant_id: &str) -> ScoringWeights {
        self.tenant_weights
            .get(tenant_id)
            .cloned()
            .unwrap_or_default()
            .normalized()
    }
}

fn env_parse<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
