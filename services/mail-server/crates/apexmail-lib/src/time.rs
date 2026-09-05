//! Time parsing utilities (e.g. "24h", "30m", "7d").

use std::time::Duration;

/// Parse a human-readable duration string into a Duration.
/// Supported suffixes:s (seconds), m (minutes), h (hours), d (days).
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("Empty duration string".to_string());
    }
    // #217:Handle input with no suffix (e.g., "5") with a clear error message
    if s.len() < 2 {
        return Err(format!("Duration '{}' must have a suffix (s/m/h/d)", s));
    }
    // strip_suffix operates on char boundaries — split_at(len-1) panicked
    // when the final character was multibyte (e.g. "5ä").
    let (num, suffix) = s
        .strip_suffix(['s', 'm', 'h', 'd'])
        .zip(s.chars().last().map(|c| c.to_string()))
        .ok_or_else(|| format!("Unknown duration suffix in '{}'", s))?;
    let value: u64 = num
        .parse()
        .map_err(|_| format!("Invalid number in duration: '{}'", num))?;
    // Checked multiplication: "5e18d"-style inputs used to overflow u64
    // (panic in debug, silent wraparound in release).
    let secs = match suffix.as_str() {
        "s" => Some(value),
        "m" => value.checked_mul(60),
        "h" => value.checked_mul(3600),
        "d" => value.checked_mul(86400),
        _ => return Err(format!("Unknown duration suffix: {}", suffix)),
    }
    .ok_or_else(|| format!("Duration '{}' overflows the supported range", s))?;
    Ok(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_seconds() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn test_parse_minutes() {
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn test_parse_hours() {
        assert_eq!(parse_duration("24h").unwrap(), Duration::from_secs(86400));
    }

    #[test]
    fn test_parse_days() {
        assert_eq!(parse_duration("7d").unwrap(), Duration::from_secs(604800));
    }

    #[test]
    fn test_parse_invalid() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("10x").is_err());
    }

    #[test]
    fn test_parse_overflow_returns_error_not_panic() {
        // Regression: huge values used to overflow u64 on multiply (panic
        // in debug builds, silent wraparound in release).
        assert!(parse_duration("213504000000000000d").is_err()); // × 86400 > u64::MAX
        assert!(parse_duration("18446744073709551615s").is_ok()); // u64::MAX secs still fits
        assert!(parse_duration("99999999999999999999d").is_err()); // number itself over u64
    }
}
