//! Reply tracking – auto-reply detection, sentiment, thread depth.

use chrono::Utc;
use moka::sync::Cache;
use regex::Regex;
use sqlx::PgPool;
use std::sync::LazyLock;
use std::time::Duration;
use tracing::warn;

use crate::types::*;

/// Max cache entries.
const REPLY_CACHE_MAX: u64 = 50_000;
static REPLY_CACHE_TTL_SECS: LazyLock<u64> = LazyLock::new(|| {
    std::env::var("ANALYTICS_REPLY_CACHE_TTL_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(3600)
});

/// Auto-reply detection patterns.
static AUTO_REPLY_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    compile_regexes(&[
        r"(?i)^auto[- ]?reply",
        r"(?i)^automatic reply",
        r"(?i)^out of (the )?office",
        r"(?i)^ooo\b",
        r"(?i)^away from",
        r"(?i)^on vacation",
        r"(?i)^i('m| am) (currently )?(out|away|on)",
        r"(?i)^this is an automated",
        r"(?i)^do not reply",
        r"(?i)^noreply",
        r"(?i)vacation.*auto.*response",
        r"(?i)delivery.*status.*notification",
        r"(?i)mail delivery.*failed",
        r"(?i)undeliverable",
        r"(?i)returned mail",
        r"(?i)message not delivered",
        r"(?i)^thank you for (your |contacting)",
        r"(?i)^we (have )?received your",
    ])
});

/// Auto-reply header indicators.
static AUTO_REPLY_HEADERS: LazyLock<Vec<(&'static str, &'static str)>> = LazyLock::new(|| {
    vec![
        ("auto-submitted", "auto-replied"),
        ("auto-submitted", "auto-generated"),
        ("auto-submitted", "auto-notified"),
        ("x-auto-response-suppress", ""),
        ("precedence", "bulk"),
    ]
});

/// Sentiment patterns.
static POSITIVE_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    compile_regexes(&[
        r"(?i)\b(thank|thanks|great|awesome|excellent|love|perfect|wonderful|appreciate)\b",
    ])
});
static NEGATIVE_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    compile_regexes(&[
        r"(?i)\b(unsubscribe|stop|remove|spam|hate|terrible|worst|annoying|complaint)\b",
    ])
});
static INQUIRY_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    compile_regexes(&[
        r"(?i)\b(question|how|when|where|what|why|can you|could you|please help)\b",
    ])
});
static UNSUB_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    compile_regexes(&[
        r"(?i)\b(unsubscribe|opt.out|stop (sending|emailing)|remove me)\b",
    ])
});
static OOO_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    compile_regexes(&[
        r"(?i)\b(out of office|ooo|on vacation|away|on leave|returning)\b",
    ])
});

fn compile_regexes(patterns: &[&str]) -> Vec<Regex> {
    patterns
        .iter()
        .filter_map(|pattern| match Regex::new(pattern) {
            Ok(regex) => Some(regex),
            Err(e) => {
                warn!(pattern = %pattern, error = %e, "Invalid regex pattern");
                None
            }
        })
        .collect()
}

pub struct ReplyTrackingService {
    pool: PgPool,
    cache: Cache<String, ReplyMetrics>,
}

impl ReplyTrackingService {
    pub fn new(pool: PgPool) -> Self {
        let cache = Cache::builder()
            .max_capacity(REPLY_CACHE_MAX)
            .time_to_live(Duration::from_secs(*REPLY_CACHE_TTL_SECS))
            .build();
        Self { pool, cache }
    }

    /// Process a reply event.
    pub async fn process_reply(&self, event: &ReplyEvent) -> anyhow::Result<ProcessedReply> {
        let is_auto = detect_auto_reply(&event.subject, &event.headers);
        let sentiment = analyze_sentiment(&event.body);
        let thread_depth = self.get_thread_depth(&event.in_reply_to).await?;

        // Store in DB
        sqlx::query(
            "INSERT INTO reply_events (message_id, in_reply_to, tenant_id, recipient, \
             subject, is_auto_reply, sentiment, thread_depth, timestamp) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(&event.message_id)
        .bind(&event.in_reply_to)
        .bind(&event.tenant_id)
        .bind(&event.recipient)
        .bind(&event.subject)
        .bind(is_auto)
        .bind(serde_json::to_string(&sentiment)?)
        .bind(thread_depth)
        .bind(event.timestamp)
        .execute(&self.pool)
        .await?;

        // Invalidate cache for this tenant
        self.cache.invalidate(&event.tenant_id);

        Ok(ProcessedReply {
            message_id: event.message_id.clone(),
            is_auto_reply: is_auto,
            sentiment,
            thread_depth,
        })
    }

    /// Get reply metrics for a tenant.
    pub async fn get_metrics(
        &self,
        tenant_id: &str,
        days: i64,
    ) -> anyhow::Result<ReplyMetrics> {
        if let Some(cached) = self.cache.get(tenant_id) {
            return Ok(cached);
        }

        let since = Utc::now() - chrono::Duration::days(days);

        let (total_replies,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM reply_events WHERE tenant_id = $1 AND timestamp >= $2",
        )
        .bind(tenant_id)
        .bind(since)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| anyhow::anyhow!("reply metrics total_replies query failed: {e}"))?;

        let (auto_replies,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM reply_events WHERE tenant_id = $1 AND timestamp >= $2 AND is_auto_reply = true",
        )
        .bind(tenant_id)
        .bind(since)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| anyhow::anyhow!("reply metrics auto_replies query failed: {e}"))?;

        let (total_sent,): (i64,) = sqlx::query_as(
            "SELECT COUNT(DISTINCT message_id) FROM events WHERE tenant_id = $1 AND event_type = 'sent' AND timestamp >= $2",
        )
        .bind(tenant_id)
        .bind(since)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| anyhow::anyhow!("reply metrics total_sent query failed: {e}"))?;

        let human_replies = total_replies - auto_replies;
        let reply_rate = if total_sent > 0 {
            human_replies as f64 / total_sent as f64
        } else {
            0.0
        };

        let (avg_depth,): (Option<f64>,) = sqlx::query_as(
            "SELECT AVG(thread_depth) FROM reply_events WHERE tenant_id = $1 AND timestamp >= $2",
        )
        .bind(tenant_id)
        .bind(since)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| anyhow::anyhow!("reply metrics avg_depth query failed: {e}"))?;

        let metrics = ReplyMetrics {
            total_replies,
            auto_replies,
            human_replies,
            reply_rate,
            avg_thread_depth: avg_depth.unwrap_or(0.0),
        };

        self.cache.insert(tenant_id.to_string(), metrics.clone());
        Ok(metrics)
    }

    async fn get_thread_depth(&self, in_reply_to: &str) -> anyhow::Result<i32> {
        let (depth,): (Option<i32>,) = sqlx::query_as(
            "SELECT MAX(thread_depth) FROM reply_events WHERE message_id = $1",
        )
        .bind(in_reply_to)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| anyhow::anyhow!("reply metrics thread_depth query failed: {e}"))?;

        Ok(depth.unwrap_or(0) + 1)
    }
}

/// Processed reply result.
#[derive(Debug, Clone)]
pub struct ProcessedReply {
    pub message_id: String,
    pub is_auto_reply: bool,
    pub sentiment: ReplySentiment,
    pub thread_depth: i32,
}

/// Detect if a reply is an auto-reply.
pub fn detect_auto_reply(
    subject: &str,
    headers: &std::collections::HashMap<String, String>,
) -> bool {
    // Check subject patterns
    for pattern in AUTO_REPLY_PATTERNS.iter() {
        if pattern.is_match(subject) {
            return true;
        }
    }

    // Check headers
    for (header_name, header_value) in AUTO_REPLY_HEADERS.iter() {
        if let Some(val) = headers.get(*header_name) {
            if header_value.is_empty() || val.to_lowercase().contains(header_value) {
                return true;
            }
        }
    }

    false
}

/// Analyze sentiment of reply body.
pub fn analyze_sentiment(body: &str) -> ReplySentiment {
    // Check specific categories first (most specific)
    for p in UNSUB_PATTERNS.iter() {
        if p.is_match(body) {
            return ReplySentiment::Unsubscribe;
        }
    }

    for p in OOO_PATTERNS.iter() {
        if p.is_match(body) {
            return ReplySentiment::OutOfOffice;
        }
    }

    // Count positive/negative/inquiry signal strength
    let positive_count: usize = POSITIVE_PATTERNS.iter().map(|p| p.find_iter(body).count()).sum();
    let negative_count: usize = NEGATIVE_PATTERNS.iter().map(|p| p.find_iter(body).count()).sum();
    let inquiry_count: usize = INQUIRY_PATTERNS.iter().map(|p| p.find_iter(body).count()).sum();

    if inquiry_count > positive_count && inquiry_count > negative_count {
        return ReplySentiment::Inquiry;
    }

    if positive_count > negative_count {
        return ReplySentiment::Positive;
    }

    if negative_count > 0 {
        return ReplySentiment::Negative;
    }

    ReplySentiment::Neutral
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_detect_auto_reply_subject() {
        let headers = HashMap::new();
        assert!(detect_auto_reply("Auto-Reply: I'm out of office", &headers));
        assert!(detect_auto_reply("Automatic Reply: On vacation", &headers));
        assert!(detect_auto_reply("Out of office until Monday", &headers));
        assert!(detect_auto_reply("OOO until Friday", &headers));
    }

    #[test]
    fn test_detect_auto_reply_headers() {
        let mut headers = HashMap::new();
        headers.insert("auto-submitted".into(), "auto-replied".into());
        assert!(detect_auto_reply("Re: Meeting notes", &headers));
    }

    #[test]
    fn test_detect_not_auto_reply() {
        let headers = HashMap::new();
        assert!(!detect_auto_reply("Re: Your proposal looks great!", &headers));
        assert!(!detect_auto_reply("Re: Meeting tomorrow", &headers));
    }

    #[test]
    fn test_sentiment_positive() {
        assert!(matches!(
            analyze_sentiment("Thank you so much! This is great!"),
            ReplySentiment::Positive
        ));
    }

    #[test]
    fn test_sentiment_negative() {
        assert!(matches!(
            analyze_sentiment("This is terrible, worst experience ever"),
            ReplySentiment::Negative
        ));
    }

    #[test]
    fn test_sentiment_inquiry() {
        assert!(matches!(
            analyze_sentiment("Question: How can I change my plan? When does it renew?"),
            ReplySentiment::Inquiry
        ));
    }

    #[test]
    fn test_sentiment_unsubscribe() {
        assert!(matches!(
            analyze_sentiment("Please unsubscribe me from this list"),
            ReplySentiment::Unsubscribe
        ));
    }

    #[test]
    fn test_sentiment_ooo() {
        assert!(matches!(
            analyze_sentiment("I am currently out of office and will return on Monday"),
            ReplySentiment::OutOfOffice
        ));
    }

    #[test]
    fn test_sentiment_neutral() {
        assert!(matches!(
            analyze_sentiment("Got it, noted."),
            ReplySentiment::Neutral
        ));
    }

    #[test]
    fn test_delivery_notification_auto_reply() {
        let headers = HashMap::new();
        assert!(detect_auto_reply("Delivery Status Notification (Failure)", &headers));
    }

    #[test]
    fn test_precedence_header_auto_reply() {
        let mut headers = HashMap::new();
        headers.insert("precedence".into(), "bulk".into());
        assert!(detect_auto_reply("Re: Newsletter", &headers));
    }

    #[test]
    fn test_reply_metrics_struct() {
        let metrics = ReplyMetrics {
            total_replies: 100,
            auto_replies: 20,
            human_replies: 80,
            reply_rate: 0.08,
            avg_thread_depth: 1.5,
        };
        assert_eq!(metrics.human_replies, 80);
        assert!((metrics.reply_rate - 0.08).abs() < 0.001);
    }
}
