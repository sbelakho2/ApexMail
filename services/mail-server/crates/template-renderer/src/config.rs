use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RendererConfig {
    pub db: DatabaseConfig,
    pub server: ServerConfig,
    pub sandbox: SandboxConfig,
    pub cache: CacheConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    pub url: String,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// HTTP-level request timeout (seconds) enforced by `TimeoutLayer`.
    /// Bounds the whole /render request even when the blocking sandbox work
    /// cannot be preempted mid-phase (see `routes::render_handler`).
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxConfig {
    /// Max execution time in milliseconds
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Max memory in bytes for sandbox
    #[serde(default = "default_max_memory")]
    pub max_memory_bytes: usize,
    /// Max template source length
    #[serde(default = "default_max_source_len")]
    pub max_source_length: usize,
    /// Max rendered HTML length
    #[serde(default = "default_max_output_len")]
    pub max_output_length: usize,
    /// F8:prop paths whose `*_html` values are trusted to substitute RAW
    /// (pre-rendered HTML fragments). Empty by default — every value,
    /// including `*_html` ones, is HTML-escaped unless its exact path is
    /// listed here. The `*_html` leaf-name convention is still required for
    /// a listed path to take effect.
    #[serde(default)]
    pub trusted_html_props: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    /// Max cached compiled templates
    #[serde(default = "default_cache_max")]
    pub max_entries: u64,
    /// TTL in seconds
    #[serde(default = "default_cache_ttl")]
    pub ttl_secs: u64,
}

fn default_max_connections() -> u32 {
    5
}
fn default_host() -> String {
    "0.0.0.0".to_string()
}
fn default_port() -> u16 {
    9080
}
fn default_request_timeout_secs() -> u64 {
    30
}
fn default_timeout_ms() -> u64 {
    5000
}
fn default_max_memory() -> usize {
    64 * 1024 * 1024
}
fn default_max_source_len() -> usize {
    512 * 1024
}
fn default_max_output_len() -> usize {
    2 * 1024 * 1024
}
fn default_cache_max() -> u64 {
    1000
}
fn default_cache_ttl() -> u64 {
    3600
}
fn max_cache_ttl() -> u64 {
    86_400
}

impl RendererConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.db.url.trim().is_empty() {
            return Err("DATABASE_URL must not be empty".into());
        }
        if self.db.max_connections == 0 {
            return Err("DB_MAX_CONNECTIONS must be > 0".into());
        }
        if self.server.host.trim().is_empty() {
            return Err("HOST must not be empty".into());
        }
        if self.server.port == 0 {
            return Err("PORT must be > 0".into());
        }
        if self.server.request_timeout_secs == 0 {
            return Err("REQUEST_TIMEOUT_SECS must be > 0".into());
        }
        if self.sandbox.timeout_ms == 0 {
            return Err("SANDBOX_TIMEOUT_MS must be > 0".into());
        }
        if self.sandbox.max_memory_bytes == 0
            || self.sandbox.max_source_length == 0
            || self.sandbox.max_output_length == 0
        {
            return Err("Sandbox limits must be > 0".into());
        }
        if self.cache.max_entries == 0 || self.cache.ttl_secs == 0 {
            return Err("Cache limits must be > 0".into());
        }
        if self.cache.ttl_secs > max_cache_ttl() {
            return Err("Cache TTL must be <= 86400 seconds".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> RendererConfig {
        RendererConfig {
            db: DatabaseConfig {
                url: "postgres://localhost/test".to_string(),
                max_connections: 5,
            },
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 9080,
                request_timeout_secs: 30,
            },
            sandbox: SandboxConfig {
                timeout_ms: 5000,
                max_memory_bytes: 64 * 1024 * 1024,
                max_source_length: 512 * 1024,
                max_output_length: 2 * 1024 * 1024,
                trusted_html_props: Vec::new(),
            },
            cache: CacheConfig {
                max_entries: 1000,
                ttl_secs: 3600,
            },
        }
    }

    #[test]
    fn test_config_defaults() {
        let cfg = test_config();
        assert_eq!(cfg.sandbox.timeout_ms, 5000);
        assert_eq!(cfg.sandbox.max_memory_bytes, 64 * 1024 * 1024);
        assert_eq!(cfg.server.port, 9080);
        assert_eq!(cfg.cache.max_entries, 1000);
    }

    #[test]
    fn test_config_deserialize() {
        let json = r#"{
            "db": { "url": "postgres://localhost/test" },
            "server": { "host": "0.0.0.0", "port": 8080 },
            "sandbox": { "timeout_ms": 3000 },
            "cache": {}
        }"#;
        let cfg: RendererConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.server.port, 8080);
        assert_eq!(cfg.sandbox.timeout_ms, 3000);
        assert_eq!(cfg.sandbox.max_memory_bytes, default_max_memory());
        assert_eq!(cfg.cache.max_entries, default_cache_max());
        // F8:the trusted `*_html` allowlist defaults to EMPTY (all escaped).
        assert!(cfg.sandbox.trusted_html_props.is_empty());
    }

    /// F8:explicitly listed `*_html` paths are honoured; unknown fields in
    /// the sandbox section are still rejected.
    #[test]
    fn test_config_deserialize_trusted_html_props() {
        let json = r#"{
            "db": { "url": "postgres://localhost/test" },
            "server": { "host": "0.0.0.0", "port": 8080 },
            "sandbox": { "trusted_html_props": ["article.body_html"] },
            "cache": {}
        }"#;
        let cfg: RendererConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            cfg.sandbox.trusted_html_props,
            vec!["article.body_html".to_string()]
        );
    }

    #[test]
    fn test_config_rejects_unknown_cache_fields() {
        let json = r#"{
            "db": { "url": "postgres://localhost/test" },
            "server": { "host": "0.0.0.0", "port": 8080 },
            "sandbox": { "timeout_ms": 3000 },
            "cache": { "ttl_seconds": 60 }
        }"#;
        assert!(serde_json::from_str::<RendererConfig>(json).is_err());
    }

    #[test]
    fn test_config_rejects_excessive_cache_ttl() {
        let mut cfg = test_config();
        cfg.cache.ttl_secs = max_cache_ttl() + 1;
        assert!(cfg.validate().is_err());
    }
}
