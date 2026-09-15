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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_or_fallback_keeps_sane_weights_and_replaces_broken_ones() {
        let sane = ScoringWeights {
            dns_health: 1.0,
            authentication: 0.0,
            spam_likelihood: 0.0,
            content_quality: 0.0,
            reputation: 0.0,
        };
        assert_eq!(sane.validate_or_fallback("t"), sane);

        for broken in [
            ScoringWeights {
                dns_health: 0.0,
                authentication: 0.0,
                spam_likelihood: 0.0,
                content_quality: 0.0,
                reputation: 0.0,
            },
            ScoringWeights {
                dns_health: -1.0,
                authentication: 0.0,
                spam_likelihood: 0.0,
                content_quality: 0.0,
                reputation: 0.0,
            },
            ScoringWeights {
                dns_health: f64::INFINITY,
                authentication: 0.0,
                spam_likelihood: 0.0,
                content_quality: 0.0,
                reputation: 0.0,
            },
            ScoringWeights {
                dns_health: f64::NAN,
                authentication: 0.0,
                spam_likelihood: 0.0,
                content_quality: 0.0,
                reputation: 0.0,
            },
        ] {
            assert_eq!(
                broken.validate_or_fallback("tenant-x"),
                ScoringWeights::default(),
                "broken weights must fall back"
            );
        }
    }

    #[test]
    fn normalized_weights_sum_to_one() {
        let w = ScoringWeights {
            dns_health: 1.0,
            authentication: 1.0,
            spam_likelihood: 1.0,
            content_quality: 1.0,
            reputation: 1.0,
        }
        .normalized();
        let sum =
            w.dns_health + w.authentication + w.spam_likelihood + w.content_quality + w.reputation;
        assert!((sum - 1.0).abs() < 1e-9, "{sum}");

        // Broken input → defaults (which already sum to 1.0).
        let broken = ScoringWeights {
            dns_health: 0.0,
            authentication: 0.0,
            spam_likelihood: 0.0,
            content_quality: 0.0,
            reputation: 0.0,
        }
        .normalized();
        assert_eq!(broken, ScoringWeights::default());
    }

    /// Serializes env-mutating tests.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn from_env_reads_overrides_and_falls_back_on_garbage() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let keys = [
            "GRADER_ENABLED",
            "GRADER_RATE_LIMIT",
            "GRADER_CACHE_TTL",
            "GRADER_DKIM_SELECTORS",
            "GRADER_MAX_BODY_SIZE",
            "GRADER_ENCRYPT_STORED",
            "GRADER_ENCRYPTION_KEY_BASE64",
            "GRADER_AUTH_HOSTNAME",
            "GRADER_NETWORK_TIMEOUT",
            "GRADER_DKIM_CONCURRENCY",
            "GRADER_MTA_STS_MAX_BYTES",
            "GRADER_IDEMPOTENCY_WINDOW",
            "GRADER_RETENTION_DAYS",
            "GRADER_MAX_JSONB_BYTES",
        ];
        let saved: Vec<(&str, Option<String>)> =
            keys.iter().map(|k| (*k, std::env::var(k).ok())).collect();
        for k in keys {
            std::env::remove_var(k);
        }

        let defaults = GraderConfig::from_env();
        assert!(defaults.enabled);
        assert_eq!(defaults.rate_limit_max, 10);
        assert_eq!(defaults.cache_ttl_seconds, 300);
        assert_eq!(
            defaults.default_dkim_selectors,
            vec!["default", "google", "dkim", "selector1"]
        );
        assert_eq!(defaults.auth_hostname, "grader.apexmail.ee");

        std::env::set_var("GRADER_ENABLED", "false");
        std::env::set_var("GRADER_RATE_LIMIT", "7");
        std::env::set_var("GRADER_CACHE_TTL", "not-a-number");
        std::env::set_var("GRADER_DKIM_SELECTORS", " s1 , s2 ,");
        std::env::set_var("GRADER_MAX_BODY_SIZE", "1234");
        std::env::set_var("GRADER_ENCRYPT_STORED", "true");
        std::env::set_var("GRADER_ENCRYPTION_KEY_BASE64", "a2V5");
        std::env::set_var("GRADER_AUTH_HOSTNAME", "grader.test");
        std::env::set_var("GRADER_NETWORK_TIMEOUT", "2");
        std::env::set_var("GRADER_DKIM_CONCURRENCY", "9");
        std::env::set_var("GRADER_MTA_STS_MAX_BYTES", "4096");
        std::env::set_var("GRADER_IDEMPOTENCY_WINDOW", "60");
        std::env::set_var("GRADER_RETENTION_DAYS", "0");
        std::env::set_var("GRADER_MAX_JSONB_BYTES", "1024");

        let parsed = GraderConfig::from_env();
        assert!(!parsed.enabled);
        assert_eq!(parsed.rate_limit_max, 7);
        assert_eq!(parsed.cache_ttl_seconds, 300, "garbage keeps the default");
        assert_eq!(parsed.default_dkim_selectors, vec!["s1", "s2", ""]);
        assert_eq!(parsed.encryption_master_key_base64.as_deref(), Some("a2V5"));
        assert!(parsed.encrypt_stored_content);
        assert_eq!(parsed.auth_hostname, "grader.test");
        assert_eq!(parsed.network_timeout_seconds, 2);
        assert_eq!(parsed.dkim_lookup_concurrency, 9);
        assert_eq!(parsed.mta_sts_policy_max_bytes, 4096);
        assert_eq!(parsed.idempotency_window_seconds, 60);
        assert_eq!(parsed.default_retention_days, 0);
        assert_eq!(parsed.max_jsonb_bytes, 1024);

        for (k, v) in saved {
            match v {
                Some(value) => std::env::set_var(k, value),
                None => std::env::remove_var(k),
            }
        }
    }

    #[test]
    fn weights_for_tenant_override_normalizes_and_defaults() {
        let mut config = GraderConfig::default();
        config.tenant_weights.insert(
            "tenant-a".into(),
            ScoringWeights {
                dns_health: 3.0,
                authentication: 1.0,
                spam_likelihood: 0.0,
                content_quality: 0.0,
                reputation: 0.0,
            },
        );
        let w = config.weights_for("tenant-a");
        assert!((w.dns_health - 0.75).abs() < 1e-9);
        assert!((w.authentication - 0.25).abs() < 1e-9);
        assert_eq!(w.spam_likelihood, 0.0);

        // Unknown tenant → defaults, normalized.
        assert_eq!(config.weights_for("tenant-b"), ScoringWeights::default());

        // A broken tenant override falls back to the uniform default (0.2 each).
        config.tenant_weights.insert(
            "tenant-b".into(),
            ScoringWeights {
                dns_health: 0.0,
                authentication: 0.0,
                spam_likelihood: 0.0,
                content_quality: 0.0,
                reputation: 0.0,
            },
        );
        assert_eq!(config.weights_for("tenant-b"), ScoringWeights::default());
    }
}
