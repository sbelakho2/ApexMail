//! Configuration loading from environment variables.
//!
//! Every parse helper below falls back to a caller-supplied default when a
//! variable is unset OR fails to parse — but a parse failure is never
//! silent: it emits a `tracing::warn!` naming the key, the offending
//! value, and the default in effect, so a typo like
//! `PORT=3O00` surfaces in logs instead of quietly binding a different
//! port.

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
    match env::var(key) {
        Ok(value) => match value.parse::<u16>() {
            Ok(parsed) => parsed,
            Err(error) => {
                tracing::warn!(
                    key = key,
                    value = %value,
                    default = default,
                    error = %error,
                    "invalid u16 environment variable, using default"
                );
                default
            }
        },
        Err(_) => default,
    }
}

/// Parse an env var as u64.
pub fn env_u64(key: &str, default: u64) -> u64 {
    match env::var(key) {
        Ok(value) => match value.parse::<u64>() {
            Ok(parsed) => parsed,
            Err(error) => {
                tracing::warn!(
                    key = key,
                    value = %value,
                    default = default,
                    error = %error,
                    "invalid u64 environment variable, using default"
                );
                default
            }
        },
        Err(_) => default,
    }
}

/// Parse an env var as bool.
///
/// Accepts explicit truthy values case-insensitively — `true`, `1`,
/// `yes`, `on` — and explicit falsy values — `false`, `0`, `no`, `off`.
/// Anything else (including an unset variable) falls back to `default`
/// with a warning: previously `TRUE` and `on` were silently treated as
/// false, flipping features off without any trace in the logs.
pub fn env_bool(key: &str, default: bool) -> bool {
    let Some(value) = env::var(key).ok() else {
        return default;
    };

    match parse_bool(&value) {
        Some(parsed) => parsed,
        None => {
            tracing::warn!(
                key = key,
                value = %value,
                default = default,
                "invalid boolean environment variable (expected true/1/yes/on or false/0/no/off), using default"
            );
            default
        }
    }
}

/// Case-insensitive boolean parsing of the accepted truthy/falsy spellings.
fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
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

    #[test]
    fn test_env_bool_accepts_case_insensitive_true_on_yes() {
        // Use a unique key per test run to avoid racing parallel tests.
        let key = "APEXMAIL_LIB_TEST_ENV_BOOL_TRUE";
        for value in ["true", "TRUE", "True", "1", "yes", "YES", "on", "ON"] {
            env::set_var(key, value);
            assert!(env_bool(key, false), "{value} must parse as true");
        }
        env::remove_var(key);
    }

    #[test]
    fn test_env_bool_accepts_explicit_false_no_off() {
        let key = "APEXMAIL_LIB_TEST_ENV_BOOL_FALSE";
        for value in ["false", "FALSE", "0", "no", "NO", "off", "OFF"] {
            env::set_var(key, value);
            assert!(!env_bool(key, true), "{value} must parse as false");
        }
        env::remove_var(key);
    }

    #[test]
    fn test_env_bool_invalid_value_falls_back_to_default() {
        let key = "APEXMAIL_LIB_TEST_ENV_BOOL_INVALID";
        env::set_var(key, "definitely-not-a-bool");
        assert!(
            env_bool(key, true),
            "invalid value must fall back to the default"
        );
        assert!(!env_bool(key, false));
        env::remove_var(key);
    }

    #[test]
    fn test_parse_bool_spellings() {
        assert_eq!(parse_bool(" true "), Some(true));
        assert_eq!(parse_bool("OFF"), Some(false));
        assert_eq!(parse_bool("maybe"), None);
        assert_eq!(parse_bool(""), None);
    }
}
