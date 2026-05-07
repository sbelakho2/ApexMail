//! Bot detection – 5-signal scoring, UA matching, velocity tracking (O-11.1).
//!
//! # Bounded cache
//! The IP-velocity cache uses [`moka::sync::Cache`] with a fixed maximum
//! capacity and TTL-based eviction, preventing unbounded memory growth.

use moka::sync::Cache;
use regex::Regex;
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tracing::warn;

use crate::types::*;

/// Score thresholds.
const BOT_THRESHOLD: f64 = 50.0;

/// Signal weights.
const UA_MATCH_WEIGHT: f64 = 40.0;
const INSTANT_CLICK_WEIGHT: f64 = 35.0;
const KNOWN_BOT_IP_WEIGHT: f64 = 30.0;
const VELOCITY_WEIGHT: f64 = 25.0;
const SUSPICIOUS_HEADERS_WEIGHT: f64 = 20.0;

/// Velocity thresholds.
const VELOCITY_WINDOW_SECS: u64 = 5;
const VELOCITY_THRESHOLD: usize = 3;

/// Max velocity cache entries.
const VELOCITY_CACHE_MAX: usize = 500_000;

/// Combined bot UA regex.
static BOT_UA_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile_regex(
        r"(?i)(bot|crawler|spider|slurp|mediapartners|preview|fetch|scan|check|monitor|wget|curl|python-requests|go-http|java/|ahrefsbot|bingbot|yandexbot|baiduspider|duckduckbot|facebot|ia_archiver|semrushbot|mj12bot|dotbot|petalbot|rogerbot|seznambot|exabot)",
        "bot_ua",
    )
});

fn compile_regex(pattern: &str, label: &str) -> Option<Regex> {
    match Regex::new(pattern) {
        Ok(regex) => Some(regex),
        Err(e) => {
            warn!(pattern = %pattern, label, error = %e, "Invalid regex pattern; disabling matcher");
            None
        }
    }
}

/// Known bot IP prefixes (simplified – GCP/AWS crawlers).
static KNOWN_BOT_PREFIXES: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    vec![
        "66.249.",  // Googlebot
        "64.233.",  // Google
        "207.46.",  // Bing
        "40.77.",   // Bing
        "114.119.", // Baidu
        "180.76.",  // Baidu
        "77.88.",   // Yandex
        "141.8.",   // Yandex
        "17.0.",    // Apple
    ]
});

/// Suspicious header patterns.
static SUSPICIOUS_HEADERS: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| vec!["x-forwarded-for", "x-scanner", "x-check", "x-probe"]);

/// Bounded TTL cache for IP velocity tracking (O-11.1).
///
/// Uses moka with:
/// - `max_capacity`: [`VELOCITY_CACHE_MAX`] entries
/// - `time_to_live`: 10 minute idle expiry
/// - Automatic eviction of least-recently-used entries when full
pub struct BotDetectionService {
    velocity_cache: Cache<String, Vec<Instant>>,
}

impl Default for BotDetectionService {
    fn default() -> Self {
        Self::new()
    }
}

impl BotDetectionService {
    pub fn new() -> Self {
        Self {
            velocity_cache: Cache::builder()
                .max_capacity(VELOCITY_CACHE_MAX as u64)
                .time_to_live(Duration::from_secs(600)) // 10 min TTL
                .build(),
        }
    }

    /// Detect if a click event is from a bot.
    pub fn detect(&self, event: &ClickEvent) -> BotDetectionResult {
        let mut score = 0.0;
        let mut signals = Vec::with_capacity(5);

        // Signal 1:User-Agent match
        if let Some(ref ua) = event.user_agent {
            if is_bot_ua(ua) {
                score += UA_MATCH_WEIGHT;
                signals.push("ua_match".into());
            }
        } else {
            // No UA is suspicious
            score += UA_MATCH_WEIGHT * 0.5;
            signals.push("missing_ua".into());
        }

        // Signal 2:Instant click (< 1 second after delivery)
        if let Some(delay_ms) = event.click_delay_ms {
            if delay_ms < 1000 {
                score += INSTANT_CLICK_WEIGHT;
                signals.push("instant_click".into());
            }
        }

        // Signal 3:Known bot IP
        if is_known_bot_ip(&event.ip_address) {
            score += KNOWN_BOT_IP_WEIGHT;
            signals.push("known_bot_ip".into());
        }

        // Signal 4:Click velocity
        let velocity = self.record_velocity(&event.ip_address);
        if velocity >= VELOCITY_THRESHOLD {
            score += VELOCITY_WEIGHT;
            signals.push("high_velocity".into());
        }

        // Signal 5:Suspicious headers
        if let Some(ref headers) = event.headers {
            let header_score = check_suspicious_headers(headers);
            if header_score > 0.0 {
                score += header_score;
                signals.push("suspicious_headers".into());
            }
        }

        let is_bot = score >= BOT_THRESHOLD;
        let bot_type = if is_bot {
            classify_bot_type(&signals, event)
        } else {
            None
        };

        BotDetectionResult {
            is_bot,
            score,
            bot_type,
            signals,
        }
    }

    /// Record click and return recent velocity count.
    fn record_velocity(&self, ip: &str) -> usize {
        let now = Instant::now();
        let window = Duration::from_secs(VELOCITY_WINDOW_SECS);

        // moka handles bounded capacity + TTL eviction automatically (O-11.1)
        let mut timestamps = self.velocity_cache.get(ip).unwrap_or_default();

        timestamps.retain(|t| now.duration_since(*t) < window);
        timestamps.push(now);
        let count = timestamps.len();

        self.velocity_cache.insert(ip.to_string(), timestamps);
        count
    }

    /// Generate honeypot link for invisible injection.
    pub fn generate_honeypot_link(campaign_id: &str) -> String {
        let token = uuid::Uuid::new_v4().to_string();
        format!(
            "<a href=\"https://t.example.com/hp/{campaign_id}/{token}\" \
            style=\"display:none;visibility:hidden;width:0;height:0;overflow:hidden\">.</a>"
        )
    }

    /// Adjust metrics by removing bot clicks.
    pub fn adjust_metrics(total_clicks: i64, bot_clicks: i64) -> (i64, f64) {
        let human_clicks = (total_clicks - bot_clicks).max(0);
        let bot_rate = if total_clicks > 0 {
            bot_clicks as f64 / total_clicks as f64
        } else {
            0.0
        };
        (human_clicks, bot_rate)
    }
}

/// Check if user-agent matches known bot patterns.
pub fn is_bot_ua(ua: &str) -> bool {
    BOT_UA_RE.as_ref().is_some_and(|regex| regex.is_match(ua))
}

/// Check if IP matches known bot prefixes.
pub fn is_known_bot_ip(ip: &str) -> bool {
    KNOWN_BOT_PREFIXES
        .iter()
        .any(|prefix| ip.starts_with(prefix))
}

/// Score suspicious headers.
fn check_suspicious_headers(headers: &std::collections::HashMap<String, String>) -> f64 {
    let mut score = 0.0;
    for pattern in SUSPICIOUS_HEADERS.iter() {
        if headers.keys().any(|k| k.to_lowercase().contains(pattern)) {
            score += SUSPICIOUS_HEADERS_WEIGHT / SUSPICIOUS_HEADERS.len() as f64;
        }
    }
    score
}

/// Classify bot type based on signals.
fn classify_bot_type(signals: &[String], event: &ClickEvent) -> Option<BotType> {
    if signals.contains(&"known_bot_ip".into()) {
        return Some(BotType::SearchEngine);
    }
    if signals.contains(&"ua_match".into()) {
        if let Some(ref ua) = event.user_agent {
            if ua.to_lowercase().contains("preview") || ua.to_lowercase().contains("fetch") {
                return Some(BotType::LinkPreview);
            }
            if ua.to_lowercase().contains("security") || ua.to_lowercase().contains("scan") {
                return Some(BotType::SecurityScanner);
            }
        }
        return Some(BotType::Crawler);
    }
    if signals.contains(&"instant_click".into()) && signals.contains(&"high_velocity".into()) {
        return Some(BotType::ClickFarm);
    }
    Some(BotType::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_is_bot_ua_googlebot() {
        assert!(is_bot_ua("Mozilla/5.0 (compatible; Googlebot/2.1)"));
    }

    #[test]
    fn test_is_bot_ua_curl() {
        assert!(is_bot_ua("curl/7.68.0"));
    }

    #[test]
    fn test_is_not_bot_ua() {
        assert!(!is_bot_ua(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
        ));
    }

    #[test]
    fn test_known_bot_ip_google() {
        assert!(is_known_bot_ip("66.249.66.1"));
    }

    #[test]
    fn test_not_known_bot_ip() {
        assert!(!is_known_bot_ip("192.168.1.1"));
    }

    #[test]
    fn test_detect_bot_by_ua() {
        let svc = BotDetectionService::new();
        let event = ClickEvent {
            message_id: "msg1".into(),
            link_id: "link1".into(),
            ip_address: "1.2.3.4".into(),
            user_agent: Some("Mozilla/5.0 (compatible; Googlebot/2.1)".into()),
            click_delay_ms: Some(500),
            headers: None,
            timestamp: chrono::Utc::now(),
        };
        let result = svc.detect(&event);
        // UA match (40) + instant click (35) = 75 >= 50
        assert!(result.is_bot);
        assert!(result.score >= BOT_THRESHOLD);
    }

    #[test]
    fn test_detect_human_click() {
        let svc = BotDetectionService::new();
        let event = ClickEvent {
            message_id: "msg1".into(),
            link_id: "link1".into(),
            ip_address: "192.168.1.1".into(),
            user_agent: Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)".into()),
            click_delay_ms: Some(5000),
            headers: None,
            timestamp: chrono::Utc::now(),
        };
        let result = svc.detect(&event);
        assert!(!result.is_bot);
        assert!(result.score < BOT_THRESHOLD);
    }

    #[test]
    fn test_detect_instant_click_and_known_ip() {
        let svc = BotDetectionService::new();
        let event = ClickEvent {
            message_id: "msg2".into(),
            link_id: "link1".into(),
            ip_address: "66.249.66.1".into(),
            user_agent: Some("Mozilla/5.0".into()),
            click_delay_ms: Some(100),
            headers: None,
            timestamp: chrono::Utc::now(),
        };
        let result = svc.detect(&event);
        // Known IP (30) + instant click (35) = 65 >= 50
        assert!(result.is_bot);
    }

    #[test]
    fn test_honeypot_link_format() {
        let link = BotDetectionService::generate_honeypot_link("campaign123");
        assert!(link.contains("campaign123"));
        assert!(link.contains("display:none"));
        assert!(link.contains("hp/"));
    }

    #[test]
    fn test_adjust_metrics() {
        let (human, bot_rate) = BotDetectionService::adjust_metrics(1000, 250);
        assert_eq!(human, 750);
        assert!((bot_rate - 0.25).abs() < 0.001);
    }

    #[test]
    fn test_adjust_metrics_no_clicks() {
        let (human, bot_rate) = BotDetectionService::adjust_metrics(0, 0);
        assert_eq!(human, 0);
        assert!((bot_rate - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_velocity_tracking() {
        let svc = BotDetectionService::new();
        for _ in 0..5 {
            let event = ClickEvent {
                message_id: "msg".into(),
                link_id: "link".into(),
                ip_address: "1.2.3.4".into(),
                user_agent: Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)".into()),
                click_delay_ms: Some(5000),
                headers: None,
                timestamp: chrono::Utc::now(),
            };
            svc.detect(&event);
        }
        // After 5 rapid clicks from same IP, velocity should trigger
        let final_event = ClickEvent {
            message_id: "msg".into(),
            link_id: "link".into(),
            ip_address: "1.2.3.4".into(),
            user_agent: Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)".into()),
            click_delay_ms: Some(5000),
            headers: None,
            timestamp: chrono::Utc::now(),
        };
        let result = svc.detect(&final_event);
        assert!(result.signals.contains(&"high_velocity".into()));
    }

    #[test]
    fn test_suspicious_headers() {
        let mut headers = HashMap::new();
        headers.insert("X-Scanner".to_string(), "test".to_string());
        headers.insert("X-Probe".to_string(), "1".to_string());
        let score = check_suspicious_headers(&headers);
        assert!(score > 0.0);
    }

    #[test]
    fn test_classify_bot_type_search_engine() {
        let event = ClickEvent {
            message_id: "m".into(),
            link_id: "l".into(),
            ip_address: "66.249.66.1".into(),
            user_agent: None,
            click_delay_ms: None,
            headers: None,
            timestamp: chrono::Utc::now(),
        };
        let result = classify_bot_type(&["known_bot_ip".into()], &event);
        assert!(matches!(result, Some(BotType::SearchEngine)));
    }
}
