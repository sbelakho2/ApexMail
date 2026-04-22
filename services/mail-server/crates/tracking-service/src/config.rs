//! Configuration for the tracking service.
//!
//! Reads from environment variables matching the TypeScript service exactly
//! so this binary is a drop-in replacement (same env vars, same routes).

use std::net::SocketAddr;
use anyhow::{Context, Result};
use ipnetwork::IpNetwork;

/// Top-level configuration assembled from env vars.
#[derive(Debug, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub tracking: TrackingConfig,
    pub rate_limit: RateLimitConfig,
    pub metrics: MetricsConfig,
    pub secret_key: zeroize::Zeroizing<String>,
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
    #[allow(unused)] // key_prefix used in processor; flagged only because binary target sees no external consumer
    pub key_prefix: String,
    pub pool_size: usize,
}

#[derive(Debug, Clone)]
pub struct TrackingConfig {
    #[allow(unused)] // base_url used for outbound link generation, not yet wired
    pub base_url: String,
    pub pixel_path: String,
    pub click_path: String,
    pub unsubscribe_path: String,
    pub preferences_path: String,
    pub fallback_url: String,
    #[allow(unused)] // confirmation_url used by unsubscribe confirmation page, not yet wired
    pub confirmation_url: String,
    pub redirect_status: u16,
    pub trusted_proxies: Vec<IpNetwork>,
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
                    .map(|ip| IpNetwork::from(ip))
            })
        })
        .collect()
}

const DEFAULT_TRUSTED_PROXIES: &str =
    "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16";

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

    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        let h = var_or("DB_HOST", "localhost");
        let p = var_or_u16("DB_PORT", 5432);
        let d = var_or("DB_NAME", "apexmail");
        let u = var_or("DB_USER", "apexmail");
        let pw = var_or("DB_PASSWORD", "");
        format!("postgresql://{}:{}@{}:{}/{}", u, pw, h, p, d)
    });

    let redis_url = {
        let host = var_or("REDIS_HOST", "localhost");
        let port = var_or_u16("REDIS_PORT", 6379);
        let db = var_or_u32("REDIS_DB", 0);
        match std::env::var("REDIS_PASSWORD").ok().filter(|p| !p.is_empty()) {
            Some(pw) => format!("redis://:{}@{}:{}/{}", pw, host, port, db),
            None => format!("redis://{}:{}/{}", host, port, db),
        }
    };

    let trusted_proxies = parse_trusted_proxies(
        &var_or("TRUSTED_PROXIES", DEFAULT_TRUSTED_PROXIES),
    );

    let redirect_status = var_or_u16("TRACKING_REDIRECT_STATUS", 302);
    let max_connections = var_or_u32("DB_MAX_CONNECTIONS", 50);
    let pool_size = var_or_usize("REDIS_POOL_SIZE", 16);
    let max_per_minute = var_or_u32("RATE_LIMIT_MAX_PER_MINUTE", 1000);
    let metrics_port = var_or_u16("METRICS_PORT", 9092);

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
    if redirect_status != 301 && redirect_status != 302 && redirect_status != 307 && redirect_status != 308 {
        anyhow::bail!("TRACKING_REDIRECT_STATUS must be 301, 302, 307, or 308 (got {redirect_status})");
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
        tracking: TrackingConfig {
            base_url: var_or("TRACKING_BASE_URL", "https://t.apexmail.ee"),
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
    })
}
