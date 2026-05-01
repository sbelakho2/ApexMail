use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct RendererConfig {
    pub db: DatabaseConfig,
    pub server: ServerConfig,
    pub sandbox: SandboxConfig,
    pub cache: CacheConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
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
}

#[derive(Debug, Clone, Deserialize)]
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
            },
            sandbox: SandboxConfig {
                timeout_ms: 5000,
                max_memory_bytes: 64 * 1024 * 1024,
                max_source_length: 512 * 1024,
                max_output_length: 2 * 1024 * 1024,
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
    }
}
