//! Configuration for the tracking service.
//!
//! Reads the shared environment variables used by the tracking service.

use anyhow::{Context, Result};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Top-level configuration assembled from env vars.
#[derive(Debug, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub clickhouse: ClickHouseConfig,
    pub tracking: TrackingConfig,
    pub rate_limit: RateLimitConfig,
    pub metrics: MetricsConfig,
    pub secret_key: zeroize::Zeroizing<String>,
    /// RSA public key (PEM) for verifying RS256 JWTs (stream tokens).
    /// SECURITY (SEC-119): All JWTs use RS256 — no HS256.
    pub jwt_public_key_pem: String,
}

/// ClickHouse OLAP connection for event ingestion.
///
/// Reads the shared `CLICKHOUSE_*` variables used across ApexMail services.
/// The password is bridged from the `CLICKHOUSE_PASSWORD_FILE` Docker secret
/// by the entrypoint wrapper.
#[derive(Debug, Clone)]
pub struct ClickHouseConfig {
    pub url: String,
    pub database: String,
    pub user: String,
    pub password: String,
    /// Timeout for a single ClickHouse insert batch (seconds).
    pub insert_timeout_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub addr: SocketAddr,
}

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone)]
pub struct RedisConfig {
    pub url: String,
    /// Redis key prefix used by processor deployments.
    pub key_prefix: String,
    pub pool_size: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TrackingConfig {
    pub base_url: String,
    pub pixel_path: String,
    pub click_path: String,
    pub unsubscribe_path: String,
    pub preferences_path: String,
    pub fallback_url: String,
    pub confirmation_url: String,
    pub redirect_status: u16,
    pub trusted_proxies: Vec<IpNetwork>,
    /// Max allowed length for a redirect URL (O-6.2). URLs exceeding this
    /// length are rejected and the fallback is used instead.
    #[serde(default = "default_max_redirect_url_len")]
    pub max_redirect_url_len: usize,
}

fn default_max_redirect_url_len() -> usize {
    2048
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub max_per_minute: u32,
}

#[derive(Debug, Clone)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub port: u16,
}

fn var_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn var_or_u16(name: &str, default: u16) -> u16 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn var_or_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn var_or_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn var_or_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn var_or_bool(name: &str, default: bool) -> bool {
    match std::env::var(name).as_deref() {
        Ok("true") | Ok("1") | Ok("yes") => true,
        Ok("false") | Ok("0") | Ok("no") => false,
        _ => default,
    }
}

fn parse_trusted_proxies(s: &str) -> Vec<IpNetwork> {
    s.split(',')
        .filter_map(|part| {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                return None;
            }
            trimmed.parse::<IpNetwork>().ok().or_else(|| {
                // Try bare IP without prefix — default to /32 or /128
                trimmed
                    .parse::<std::net::IpAddr>()
                    .ok()
                    .map(IpNetwork::from)
            })
        })
        .collect()
}

const DEFAULT_TRUSTED_PROXIES: &str = "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16";

fn build_redis_url(host: &str, port: u16, db: u32, password: Option<&str>) -> String {
    match password.filter(|pw| !pw.is_empty()) {
        Some(password) => format!(
            "redis://:{}@{}:{}/{}",
            urlencoding::encode(password),
            host,
            port,
            db
        ),
        None => format!("redis://{}:{}/{}", host, port, db),
    }
}

/// The effective Postgres URL: `DATABASE_URL` when set, otherwise composed
/// from the discrete `DB_*` parts (the docker-compose variable shape).
/// Extracted from `load` so the fallback is unit-testable — `load` runs
/// `dotenvy`, and a repo-checkout `.env` normally provides `DATABASE_URL`,
/// which would make the branch unreachable from a whole-`load` test.
fn compose_database_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        let h = var_or("DB_HOST", "localhost");
        let p = var_or_u16("DB_PORT", 5432);
        let d = var_or("DB_NAME", "apexmail");
        let u = var_or("DB_USER", "apexmail");
        let pw = var_or("DB_PASSWORD", "");
        format!("postgresql://{}:{}@{}:{}/{}", u, pw, h, p, d)
    })
}

/// Load and validate configuration from environment.
pub fn load() -> Result<Config> {
    dotenvy::dotenv().ok();

    let secret_key = std::env::var("TRACKING_SECRET_KEY")
        .context("TRACKING_SECRET_KEY environment variable is required")?;

    if secret_key.len() < 32 {
        anyhow::bail!("TRACKING_SECRET_KEY must be at least 32 characters");
    }

    let host = var_or("TRACKING_HOST", "0.0.0.0");
    let port = var_or_u16("TRACKING_PORT", 3001);
    let addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .context("Invalid TRACKING_HOST/TRACKING_PORT")?;

    let db_url = compose_database_url();

    let redis_url = {
        let host = var_or("REDIS_HOST", "localhost");
        let port = var_or_u16("REDIS_PORT", 6379);
        let db = var_or_u32("REDIS_DB", 0);
        let password = std::env::var("REDIS_PASSWORD").ok();
        build_redis_url(&host, port, db, password.as_deref())
    };

    let clickhouse = ClickHouseConfig {
        url: var_or("CLICKHOUSE_URL", "http://clickhouse:8123"),
        database: var_or("CLICKHOUSE_DATABASE", "apexmail"),
        user: var_or("CLICKHOUSE_USER", "default"),
        password: var_or("CLICKHOUSE_PASSWORD", ""),
        insert_timeout_seconds: var_or_u64("CLICKHOUSE_INSERT_TIMEOUT_SECONDS", 30),
    };

    let trusted_proxies =
        parse_trusted_proxies(&var_or("TRUSTED_PROXIES", DEFAULT_TRUSTED_PROXIES));

    let redirect_status = var_or_u16("TRACKING_REDIRECT_STATUS", 302);
    let max_connections = var_or_u32("DB_MAX_CONNECTIONS", 50);
    let pool_size = var_or_usize("REDIS_POOL_SIZE", 16);
    let max_per_minute = var_or_u32("RATE_LIMIT_MAX_PER_MINUTE", 1000);
    let metrics_port = var_or_u16("METRICS_PORT", 9092);
    let max_redirect_url_len = var_or_usize("TRACKING_MAX_REDIRECT_URL_LEN", 2048);

    // #199:Runtime validation of config values
    if max_connections == 0 || max_connections > 10_000 {
        anyhow::bail!("DB_MAX_CONNECTIONS must be between 1 and 10,000 (got {max_connections})");
    }
    if pool_size == 0 || pool_size > 1_000 {
        anyhow::bail!("REDIS_POOL_SIZE must be between 1 and 1,000 (got {pool_size})");
    }
    if max_per_minute == 0 {
        anyhow::bail!("RATE_LIMIT_MAX_PER_MINUTE must be > 0");
    }
    if redirect_status != 301
        && redirect_status != 302
        && redirect_status != 307
        && redirect_status != 308
    {
        anyhow::bail!(
            "TRACKING_REDIRECT_STATUS must be 301, 302, 307, or 308 (got {redirect_status})"
        );
    }
    if port == metrics_port {
        anyhow::bail!("TRACKING_PORT and METRICS_PORT must differ (both {port})");
    }

    Ok(Config {
        server: ServerConfig { addr },
        database: DatabaseConfig {
            url: db_url,
            max_connections,
        },
        redis: RedisConfig {
            url: redis_url,
            key_prefix: "tracking:".into(),
            pool_size,
        },
        clickhouse,
        tracking: TrackingConfig {
            // C: TRACKING_PUBLIC_HOST is the unified public tracking host
            // shared with the worker's link rewriter; TRACKING_BASE_URL is
            // kept as a legacy alias. Default matches the worker.
            base_url: var_or(
                "TRACKING_PUBLIC_HOST",
                &var_or("TRACKING_BASE_URL", "https://t.apexmail.ee"),
            ),
            pixel_path: var_or("TRACKING_PIXEL_PATH", "/o"),
            click_path: var_or("TRACKING_CLICK_PATH", "/c"),
            unsubscribe_path: var_or("TRACKING_UNSUBSCRIBE_PATH", "/u"),
            preferences_path: var_or("TRACKING_PREFERENCES_PATH", "/p"),
            fallback_url: var_or("TRACKING_FALLBACK_URL", "https://apexmail.ee"),
            confirmation_url: var_or(
                "TRACKING_UNSUBSCRIBE_CONFIRMATION_URL",
                "https://apexmail.ee/unsubscribed",
            ),
            redirect_status,
            trusted_proxies,
            max_redirect_url_len,
        },
        rate_limit: RateLimitConfig {
            enabled: var_or_bool("RATE_LIMIT_ENABLED", true),
            max_per_minute,
        },
        metrics: MetricsConfig {
            enabled: var_or_bool("METRICS_ENABLED", true),
            port: metrics_port,
        },
        secret_key: zeroize::Zeroizing::new(secret_key),
        jwt_public_key_pem: std::env::var("JWT_PUBLIC_KEY_PEM")
            .context("JWT_PUBLIC_KEY_PEM environment variable is required for RS256 stream token verification")?,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        build_redis_url, compose_database_url, default_max_redirect_url_len, load,
        parse_trusted_proxies, var_or_bool, TrackingConfig,
    };

    /// Serializes env-mutating tests.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Set env vars, run `f`, restore the previous values afterwards.
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
    fn trusted_proxy_parsing_accepts_cidr_bare_and_drops_garbage() {
        let parsed = parse_trusted_proxies("10.0.0.0/8, 203.0.113.7 , ,not-an-ip,2001:db8::/32");
        assert_eq!(parsed.len(), 3, "{parsed:?}");
        assert!(parsed[0].contains("10.0.0.1".parse::<std::net::IpAddr>().unwrap()));
        // A bare IPv4 becomes a /32.
        assert!(parsed[1].contains("203.0.113.7".parse::<std::net::IpAddr>().unwrap()));
        assert!(parse_trusted_proxies("").is_empty());
    }

    #[test]
    fn bool_env_parsing_matches_documented_values() {
        with_env(&[("TRACKING_TEST_BOOL", Some("true"))], || {
            assert!(var_or_bool("TRACKING_TEST_BOOL", false))
        });
        for value in ["1", "yes"] {
            with_env(&[("TRACKING_TEST_BOOL", Some(value))], || {
                assert!(var_or_bool("TRACKING_TEST_BOOL", false), "{value}")
            });
        }
        for value in ["false", "0", "no"] {
            with_env(&[("TRACKING_TEST_BOOL", Some(value))], || {
                assert!(!var_or_bool("TRACKING_TEST_BOOL", true), "{value}")
            });
        }
        with_env(&[("TRACKING_TEST_BOOL", Some("banana"))], || {
            assert!(
                var_or_bool("TRACKING_TEST_BOOL", true),
                "garbage keeps default"
            );
            assert!(!var_or_bool("TRACKING_TEST_BOOL", false));
        });
        with_env(&[("TRACKING_TEST_BOOL", None)], || {
            assert!(var_or_bool("TRACKING_TEST_BOOL", true));
        });
    }

    /// NOTE: `load()` runs `dotenvy::dotenv()`, and the workspace root
    /// `.env` provides both TRACKING_SECRET_KEY and JWT_PUBLIC_KEY_PEM. The
    /// "variable entirely absent" branches are therefore not reachable from
    /// a repo checkout; the empty/too-short values exercise the same
    /// validation ladder deterministically.
    #[test]
    fn load_rejects_empty_or_short_secret_key() {
        let err = with_env(
            &[
                ("TRACKING_SECRET_KEY", Some("")),
                ("JWT_PUBLIC_KEY_PEM", Some("pem")),
            ],
            load,
        )
        .expect_err("empty secret");
        assert!(err.to_string().contains("at least 32 characters"), "{err}");

        let err = with_env(
            &[
                ("TRACKING_SECRET_KEY", Some("short")),
                ("JWT_PUBLIC_KEY_PEM", Some("pem")),
            ],
            load,
        )
        .expect_err("short secret");
        assert!(err.to_string().contains("at least 32 characters"), "{err}");

        // A 32+-char secret with the JWT key present loads.
        let config = with_env(
            &[
                (
                    "TRACKING_SECRET_KEY",
                    Some("01234567890123456789012345678901"),
                ),
                ("JWT_PUBLIC_KEY_PEM", Some("-----BEGIN PUBLIC KEY-----")),
            ],
            load,
        )
        .expect("valid minimal config");
        assert_eq!(
            config.secret_key.as_str(),
            "01234567890123456789012345678901"
        );
    }

    #[test]
    fn load_parses_overrides_and_rejects_unsafe_values() {
        let secret = "01234567890123456789012345678901";
        let base: Vec<(&str, Option<&str>)> = vec![
            ("TRACKING_SECRET_KEY", Some(secret)),
            ("JWT_PUBLIC_KEY_PEM", Some("-----BEGIN PUBLIC KEY-----")),
            ("TRACKING_HOST", Some("127.0.0.1")),
            ("TRACKING_PORT", Some("4100")),
            ("METRICS_PORT", Some("9100")),
            ("DATABASE_URL", Some("postgresql://u:p@db:5432/apex")),
            ("REDIS_HOST", Some("cache")),
            ("REDIS_PORT", Some("6380")),
            ("REDIS_DB", Some("3")),
            ("REDIS_PASSWORD", Some("p@ss word")),
            ("REDIS_POOL_SIZE", Some("7")),
            ("DB_MAX_CONNECTIONS", Some("9")),
            ("CLICKHOUSE_URL", Some("http://ch:8123")),
            ("CLICKHOUSE_DATABASE", Some("apex")),
            ("CLICKHOUSE_USER", Some("u")),
            ("CLICKHOUSE_PASSWORD", Some("p")),
            ("CLICKHOUSE_INSERT_TIMEOUT_SECONDS", Some("5")),
            ("TRUSTED_PROXIES", Some("10.0.0.0/8, 192.0.2.9")),
            ("TRACKING_PUBLIC_HOST", Some("https://t.example")),
            ("TRACKING_PIXEL_PATH", Some("/px")),
            ("TRACKING_CLICK_PATH", Some("/cl")),
            ("TRACKING_UNSUBSCRIBE_PATH", Some("/un")),
            ("TRACKING_PREFERENCES_PATH", Some("/pr")),
            ("TRACKING_FALLBACK_URL", Some("https://fallback.example")),
            (
                "TRACKING_UNSUBSCRIBE_CONFIRMATION_URL",
                Some("https://done.example"),
            ),
            ("TRACKING_REDIRECT_STATUS", Some("307")),
            ("TRACKING_MAX_REDIRECT_URL_LEN", Some("1234")),
            ("RATE_LIMIT_ENABLED", Some("no")),
            ("RATE_LIMIT_MAX_PER_MINUTE", Some("55")),
            ("METRICS_ENABLED", Some("0")),
        ];
        let config = with_env(&base, load).expect("valid config");
        assert_eq!(config.server.addr.to_string(), "127.0.0.1:4100");
        assert_eq!(config.database.url, "postgresql://u:p@db:5432/apex");
        assert_eq!(config.database.max_connections, 9);
        assert_eq!(config.redis.url, "redis://:p%40ss%20word@cache:6380/3");
        assert_eq!(config.redis.pool_size, 7);
        assert_eq!(config.clickhouse.database, "apex");
        assert_eq!(config.tracking.base_url, "https://t.example");
        assert_eq!(config.tracking.pixel_path, "/px");
        assert_eq!(config.tracking.redirect_status, 307);
        assert_eq!(config.tracking.max_redirect_url_len, 1234);
        assert_eq!(config.tracking.trusted_proxies.len(), 2);
        assert!(!config.rate_limit.enabled);
        assert_eq!(config.rate_limit.max_per_minute, 55);
        assert!(!config.metrics.enabled);
        assert_eq!(config.metrics.port, 9100);

        // Every validation rule refuses instead of accepting a broken value.
        let broken: Vec<(&str, Option<&str>, &str)> = vec![
            ("DB_MAX_CONNECTIONS", Some("0"), "DB_MAX_CONNECTIONS"),
            ("DB_MAX_CONNECTIONS", Some("10001"), "DB_MAX_CONNECTIONS"),
            ("REDIS_POOL_SIZE", Some("0"), "REDIS_POOL_SIZE"),
            ("REDIS_POOL_SIZE", Some("1001"), "REDIS_POOL_SIZE"),
            (
                "RATE_LIMIT_MAX_PER_MINUTE",
                Some("0"),
                "RATE_LIMIT_MAX_PER_MINUTE",
            ),
            (
                "TRACKING_REDIRECT_STATUS",
                Some("200"),
                "TRACKING_REDIRECT_STATUS",
            ),
            ("TRACKING_PORT", Some("9100"), "must differ"),
        ];
        for (key, value, needle) in broken {
            let mut vars = base.clone();
            vars.push((key, value));
            if key == "TRACKING_PORT" {
                vars.push(("METRICS_PORT", Some("9100")));
            }
            let err = with_env(&vars, load).expect_err(key);
            assert!(err.to_string().contains(needle), "{key}={value:?}: {err}");
        }
    }

    #[test]
    fn redis_password_is_percent_encoded() {
        let redis_url = build_redis_url("redis", 6379, 4, Some("abc+/=:@"));

        assert_eq!(redis_url, "redis://:abc%2B%2F%3D%3A%40@redis:6379/4");
    }

    #[test]
    fn empty_redis_password_uses_plain_url() {
        let redis_url = build_redis_url("redis", 6379, 2, Some(""));

        assert_eq!(redis_url, "redis://redis:6379/2");
    }

    /// `with_env` must restore a variable that WAS set before the call (the
    /// Some arm of the restore loop).
    #[test]
    fn with_env_restores_previously_set_values() {
        let key = "TRACKING_WITH_ENV_RESTORE_TEST";
        std::env::set_var(key, "original");
        with_env(&[(key, Some("temporary"))], || {
            assert_eq!(std::env::var(key).as_deref(), Ok("temporary"));
        });
        assert_eq!(std::env::var(key).as_deref(), Ok("original"));
        std::env::remove_var(key);
    }

    /// A panic inside `with_env`'s closure still restores the environment and
    /// is re-raised in the test (the resume_unwind arm).
    #[test]
    #[should_panic(expected = "boom-inside-with-env")]
    fn with_env_resumes_the_closure_panic_after_restoring() {
        let key = "TRACKING_WITH_ENV_PANIC_TEST";
        with_env(&[(key, Some("x"))], || panic!("boom-inside-with-env"));
    }

    /// With DATABASE_URL unset, the URL is composed from the DB_* parts.
    /// (`compose_database_url` is tested directly: `load` runs `dotenvy`,
    /// and a repo-checkout `.env` normally provides DATABASE_URL, which
    /// would make the fallback unreachable through `load` itself.)
    #[test]
    fn database_url_falls_back_to_db_parts() {
        let url = with_env(
            &[
                ("DATABASE_URL", None),
                ("DB_HOST", Some("db.example.test")),
                ("DB_PORT", Some("6543")),
                ("DB_NAME", Some("apexdb")),
                ("DB_USER", Some("apexuser")),
                ("DB_PASSWORD", Some("s3cret")),
            ],
            compose_database_url,
        );
        assert_eq!(
            url,
            "postgresql://apexuser:s3cret@db.example.test:6543/apexdb"
        );

        // An explicit DATABASE_URL always wins.
        let explicit = with_env(
            &[("DATABASE_URL", Some("postgresql://explicit@db/choice"))],
            compose_database_url,
        );
        assert_eq!(explicit, "postgresql://explicit@db/choice");
    }

    /// The serde default for `max_redirect_url_len` (2048) applies when the
    /// struct is deserialized without the field (all other fields are
    /// required).
    #[test]
    fn tracking_config_defaults_max_redirect_url_len() {
        let json = r#"{
            "base_url": "https://t.example",
            "pixel_path": "/px",
            "click_path": "/c",
            "unsubscribe_path": "/u",
            "preferences_path": "/prefs",
            "fallback_url": "https://fallback.example",
            "confirmation_url": "https://t.example/confirm",
            "redirect_status": 302,
            "trusted_proxies": []
        }"#;
        let cfg: TrackingConfig = serde_json::from_str(json).expect("without the optional field");
        assert_eq!(cfg.max_redirect_url_len, default_max_redirect_url_len());
        assert_eq!(cfg.max_redirect_url_len, 2048);
    }
}
