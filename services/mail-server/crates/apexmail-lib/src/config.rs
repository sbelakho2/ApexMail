//! Configuration loading from environment variables.

use std::env;

/// Get an environment variable or a default.
pub fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Get a required environment variable.
pub fn env_required(key: &str) -> Result<String, String> {
    env::var(key).map_err(|_| format!("Missing required environment variable: {}", key))
}

/// Parse an env var as u16.
pub fn env_u16(key: &str, default: u16) -> u16 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Parse an env var as u64.
pub fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Parse an env var as bool.
pub fn env_bool(key: &str, default: bool) -> bool {
    env::var(key)
        .ok()
        .map(|v| matches!(v.as_str(), "true" | "1" | "yes"))
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_or_default() {
        let val = env_or("NONEXISTENT_TEST_VAR_12345", "default_val");
        assert_eq!(val, "default_val");
    }

    #[test]
    fn test_env_required_missing() {
        let result = env_required("NONEXISTENT_TEST_VAR_99999");
        assert!(result.is_err());
    }

    #[test]
    fn test_env_u16_default() {
        let val = env_u16("NONEXISTENT_PORT_VAR", 3000);
        assert_eq!(val, 3000);
    }

    #[test]
    fn test_env_bool_default() {
        assert!(!env_bool("NONEXISTENT_BOOL_VAR", false));
        assert!(env_bool("NONEXISTENT_BOOL_VAR", true));
    }
}
