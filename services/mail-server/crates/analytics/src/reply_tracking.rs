//! Reply tracking – auto-reply detection, sentiment, thread depth.

use chrono::Utc;
use dashmap::DashMap;
use moka::sync::Cache;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::LazyLock;
use std::time::Duration;
use tracing::warn;

use crate::types::*;

/// Max cache entries.
const REPLY_CACHE_MAX: u64 = 50_000;

/// F68:bounds for the metrics time window. `days` is caller-supplied and
/// must be clamped BEFORE any `chrono::Duration::days` construction — a
/// huge value panics the duration builder and a non-positive one inverts
/// the window (since in the future → empty metrics).
const MIN_METRICS_WINDOW_DAYS: i64 = 1;
const MAX_METRICS_WINDOW_DAYS: i64 = 365;

/// F68:clamp the requested window to a sane, non-panicking range. The
/// clamped value is the canonical window identity used in the cache key.
fn clamp_window_days(days: i64) -> i64 {
    days.clamp(MIN_METRICS_WINDOW_DAYS, MAX_METRICS_WINDOW_DAYS)
}

/// F67:idempotent event identity — SHA-256 over the tenant-qualified
/// message identity (tenant + external RFC 5322 Message-ID). The crate
/// computes it before INSERT; `reply_events.event_id` carries a UNIQUE
/// constraint so a re-delivered event collapses to the stored row.
fn reply_event_id(tenant_id: &str, message_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(tenant_id.as_bytes());
    // Unit separator: keeps (tenant, message) pairs unambiguous even if a
    // value ever contains the printable separators used elsewhere.
    hasher.update([0x1f]);
    hasher.update(message_id.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// F67:canonical sentiment storage — the bare enum variant label, not a
/// JSON-encoded string (matches `reply_events.sentiment` VARCHAR(32)).
fn sentiment_label(sentiment: &ReplySentiment) -> &'static str {
    match sentiment {
        ReplySentiment::Positive => "Positive",
        ReplySentiment::Negative => "Negative",
        ReplySentiment::Neutral => "Neutral",
        ReplySentiment::Inquiry => "Inquiry",
        ReplySentiment::Unsubscribe => "Unsubscribe",
        ReplySentiment::OutOfOffice => "OutOfOffice",
    }
}

/// F69:saturating thread-depth successor — a poisoned/degenerate chain
/// cannot overflow i32 and wrap negative (the CHECK constraint on
/// `thread_depth` would then reject the insert, losing the event).
fn next_thread_depth(parent_depth: Option<i32>) -> i32 {
    parent_depth.unwrap_or(0).saturating_add(1)
}
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
    compile_regexes(&[r"(?i)\b(question|how|when|where|what|why|can you|could you|please help)\b"])
});
static UNSUB_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    compile_regexes(&[r"(?i)\b(unsubscribe|opt.out|stop (sending|emailing)|remove me)\b"])
});
static OOO_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    compile_regexes(&[r"(?i)\b(out of office|ooo|on vacation|away|on leave|returning)\b"])
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
    /// F68:per-tenant data-generation counter. Cached metrics keys embed
    /// the current generation, so a single bump invalidates every cached
    /// window for the tenant at once (moka has no prefix invalidation);
    /// orphaned entries age out via TTL/LRU.
    generations: DashMap<String, u64>,
}

impl ReplyTrackingService {
    pub fn new(pool: PgPool) -> Self {
        let cache = Cache::builder()
            .max_capacity(REPLY_CACHE_MAX)
            .time_to_live(Duration::from_secs(*REPLY_CACHE_TTL_SECS))
            .build();
        Self {
            pool,
            cache,
            generations: DashMap::new(),
        }
    }

    /// F68:current data generation for the tenant (0 until first ingest).
    fn generation_of(&self, tenant_id: &str) -> u64 {
        self.generations.get(tenant_id).map(|g| *g).unwrap_or(0)
    }

    /// F68:advance the tenant's data generation — all cached metric
    /// windows for the tenant become unreachable in one step.
    fn bump_generation(&self, tenant_id: &str) {
        *self.generations.entry(tenant_id.to_string()).or_insert(0) += 1;
    }

    /// F68:cache key carrying the full request identity: tenant, data
    /// generation, and the validated window. A 1-day request can never be
    /// served a cached 30-day result (and vice versa), and post-ingest
    /// requests never see a pre-ingest generation.
    fn metrics_cache_key(&self, tenant_id: &str, days: i64) -> String {
        metrics_cache_key_parts(tenant_id, self.generation_of(tenant_id), days)
    }

    /// Process a reply event.
    ///
    /// F67:durable, idempotent ingress. The event identity
    /// (tenant-qualified message identity, hashed into `event_id`) makes
    /// re-delivery a no-op: one row, one count, no duplicate-driven
    /// metric inflation. Derived fields (auto-reply, sentiment, depth) are
    /// computed before the insert and first write wins.
    pub async fn process_reply(&self, event: &ReplyEvent) -> anyhow::Result<ProcessedReply> {
        let is_auto = detect_auto_reply(&event.subject, &event.headers);
        let sentiment = analyze_sentiment(&event.body);
        let thread_depth = self
            .get_thread_depth(&event.tenant_id, &event.in_reply_to)
            .await?;

        // F67:canonical persistence (migration 159) with idempotent event
        // identity — ON CONFLICT DO NOTHING collapses re-delivered events.
        let event_id = reply_event_id(&event.tenant_id, &event.message_id);
        let stored = sqlx::query(
            "INSERT INTO reply_events (event_id, message_id, in_reply_to, tenant_id, recipient, \
             subject, is_auto_reply, sentiment, thread_depth, timestamp) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (event_id) DO NOTHING",
        )
        .bind(&event_id)
        .bind(&event.message_id)
        .bind(&event.in_reply_to)
        .bind(&event.tenant_id)
        .bind(&event.recipient)
        .bind(&event.subject)
        .bind(is_auto)
        .bind(sentiment_label(&sentiment))
        .bind(thread_depth)
        .bind(event.timestamp)
        .execute(&self.pool)
        .await?
        .rows_affected()
            > 0;

        // F68:only a row that actually landed changes the data, and the
        // generation bump invalidates every cached window for the tenant.
        if stored {
            self.bump_generation(&event.tenant_id);
        }

        Ok(ProcessedReply {
            message_id: event.message_id.clone(),
            is_auto_reply: is_auto,
            sentiment,
            thread_depth,
        })
    }

    /// Get reply metrics for a tenant over a `days`-day window.
    ///
    /// F68:the cache key carries the validated window (and the tenant's
    /// data generation), so concurrently cached 1/7/30-day results never
    /// bleed into each other.
    pub async fn get_metrics(&self, tenant_id: &str, days: i64) -> anyhow::Result<ReplyMetrics> {
        // F68:bound the window BEFORE constructing the duration.
        let days = clamp_window_days(days);
        let cache_key = self.metrics_cache_key(tenant_id, days);
        if let Some(cached) = self.cache.get(&cache_key) {
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
            // F67:thread_depth is INTEGER, so AVG() yields NUMERIC — cast
            // in SQL to keep the existing f64 result binding.
            "SELECT AVG(thread_depth)::double precision FROM reply_events \
             WHERE tenant_id = $1 AND timestamp >= $2",
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

        self.cache.insert(cache_key, metrics.clone());
        Ok(metrics)
    }

    /// F69:tenant-qualified thread-depth lookup. Depth is resolved against
    /// the owning (tenant_id, message_id) identity — never the external
    /// Message-ID alone, which is attacker-aliasable across tenants — and
    /// the successor arithmetic saturates instead of overflowing.
    async fn get_thread_depth(&self, tenant_id: &str, in_reply_to: &str) -> anyhow::Result<i32> {
        let (depth,): (Option<i32>,) = sqlx::query_as(
            "SELECT MAX(thread_depth) FROM reply_events WHERE tenant_id = $1 AND message_id = $2",
        )
        .bind(tenant_id)
        .bind(in_reply_to)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| anyhow::anyhow!("reply metrics thread_depth query failed: {e}"))?;

        Ok(next_thread_depth(depth))
    }

    /// F67: adapter from authenticated inbound reply ingestion to the durable
    /// reply-analytics operation. Maps the inbound processor's row onto the
    /// canonical ReplyEvent contract and commits it through
    /// [`Self::process_reply`]: tenant-scoped, canonical message identity,
    /// replier as recipient, the inbound headers (auto-reply detection), and
    /// a STABLE provider/inbound event id — the RFC 5322 Message-ID header
    /// when present, else the inbound row id (both survive restarts and
    /// re-delivery collapses through the same event_id hash).
    pub async fn process_inbound_reply(
        &self,
        handoff: &InboundReplyHandoff<'_>,
    ) -> anyhow::Result<ProcessedReply> {
        let canonical_message_id = handoff
            .message_id_header
            .map(str::to_string)
            .unwrap_or_else(|| format!("inbound:{}", handoff.inbound_id));
        let event = ReplyEvent {
            message_id: canonical_message_id,
            in_reply_to: handoff.in_reply_to.unwrap_or_default().to_string(),
            tenant_id: handoff.tenant_id.to_string(),
            recipient: handoff.from_email.to_string(),
            subject: handoff.subject.to_string(),
            body: handoff.body.to_string(),
            headers: handoff.headers.clone(),
            timestamp: handoff.received_at,
        };
        self.process_reply(&event).await
    }

    /// F67: ingestion readiness and lag. `schema_ready` is false when the
    /// canonical reply_events relation (migration 159) is missing — the
    /// component must not pretend to ingest. `pending_inbound` is the count
    /// of accepted-but-unprocessed inbound messages (the analytics handoff's
    /// backlog); `latest_reply_at` makes the explicit no-events state
    /// distinguishable from "events exist but are old".
    pub async fn status(&self) -> ReplyAnalyticsStatus {
        let schema_ready = sqlx::query_scalar::<_, Option<String>>(
            "SELECT to_regclass('public.reply_events')::text",
        )
        .fetch_one(&self.pool)
        .await
        .ok()
        .flatten()
        .is_some();

        let pending_inbound = if sqlx::query_scalar::<_, Option<String>>(
            "SELECT to_regclass('public.inbound_messages')::text",
        )
        .fetch_one(&self.pool)
        .await
        .ok()
        .flatten()
        .is_some()
        {
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM inbound_messages WHERE processed_at IS NULL",
            )
            .fetch_one(&self.pool)
            .await
            .unwrap_or(0)
        } else {
            0
        };

        let latest_reply_at = if schema_ready {
            sqlx::query_scalar::<_, Option<chrono::DateTime<Utc>>>(
                "SELECT MAX(timestamp) FROM reply_events",
            )
            .fetch_one(&self.pool)
            .await
            .unwrap_or(None)
        } else {
            None
        };

        ReplyAnalyticsStatus {
            schema_ready,
            pending_inbound,
            latest_reply_at,
            has_events: latest_reply_at.is_some(),
        }
    }
}

/// F67: inbound → analytics handoff contract. Built by the authenticated
/// inbound reply processor (worker reply_handler) from its claimed
/// `inbound_messages` row.
#[derive(Debug, Clone)]
pub struct InboundReplyHandoff<'a> {
    /// The inbound row's primary key (stable across redelivery).
    pub inbound_id: &'a str,
    /// Tenant that accepted the message (None rows are not handed off).
    pub tenant_id: &'a str,
    /// RFC 5322 Message-ID header of the reply, when captured.
    pub message_id_header: Option<&'a str>,
    /// In-Reply-To header, when captured.
    pub in_reply_to: Option<&'a str>,
    /// The replier's address (the `from` of the inbound message).
    pub from_email: &'a str,
    pub subject: &'a str,
    pub body: &'a str,
    /// Selected inbound headers (lower-cased names → values) feeding
    /// auto-reply detection.
    pub headers: std::collections::HashMap<String, String>,
    pub received_at: chrono::DateTime<Utc>,
}

/// F67: explicit readiness/lag/no-events state for the reply-analytics
/// component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplyAnalyticsStatus {
    /// The canonical reply_events relation exists.
    pub schema_ready: bool,
    /// Accepted inbound messages not yet processed (handoff backlog).
    pub pending_inbound: i64,
    /// Newest persisted reply event, if any.
    pub latest_reply_at: Option<chrono::DateTime<Utc>>,
    /// Explicit no-events state (false = no reply has ever been ingested).
    pub has_events: bool,
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
    let positive_count: usize = POSITIVE_PATTERNS
        .iter()
        .map(|p| p.find_iter(body).count())
        .sum();
    let negative_count: usize = NEGATIVE_PATTERNS
        .iter()
        .map(|p| p.find_iter(body).count())
        .sum();
    let inquiry_count: usize = INQUIRY_PATTERNS
        .iter()
        .map(|p| p.find_iter(body).count())
        .sum();

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
        assert!(!detect_auto_reply(
            "Re: Your proposal looks great!",
            &headers
        ));
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
        assert!(detect_auto_reply(
            "Delivery Status Notification (Failure)",
            &headers
        ));
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

    // ── F68:window validation ────────────────────────────────────────────────

    #[test]
    fn test_clamp_window_days_bounds_before_duration_construction() {
        assert_eq!(clamp_window_days(7), 7, "in-range windows pass through");
        assert_eq!(clamp_window_days(1), 1, "minimum window is 1 day");
        assert_eq!(clamp_window_days(0), MIN_METRICS_WINDOW_DAYS);
        assert_eq!(clamp_window_days(-30), MIN_METRICS_WINDOW_DAYS);
        assert_eq!(
            clamp_window_days(i64::MAX),
            MAX_METRICS_WINDOW_DAYS,
            "a huge value must not reach chrono::Duration::days and panic"
        );
    }

    #[test]
    fn test_metrics_cache_key_carries_window_and_generation() {
        // Same identity -> same key (stable across calls).
        assert_eq!(
            metrics_cache_key_parts("tenant_a", 3, 30),
            metrics_cache_key_parts("tenant_a", 3, 30)
        );
        // Different windows -> different keys (the F68 bug served one
        // window's cached value for another).
        assert_ne!(
            metrics_cache_key_parts("tenant_a", 3, 1),
            metrics_cache_key_parts("tenant_a", 3, 30)
        );
        // Different generations (pre/post ingest) -> different keys.
        assert_ne!(
            metrics_cache_key_parts("tenant_a", 2, 7),
            metrics_cache_key_parts("tenant_a", 3, 7)
        );
        // Different tenants -> different keys.
        assert_ne!(
            metrics_cache_key_parts("tenant_a", 3, 7),
            metrics_cache_key_parts("tenant_b", 3, 7)
        );
    }

    #[tokio::test]
    async fn test_generation_bump_invalidates_all_windows() {
        let pool = PgPool::connect_lazy("postgres://fake:fake@localhost:1/fake")
            .expect("lazy pool needs no server");
        let svc = ReplyTrackingService::new(pool);
        assert_eq!(svc.generation_of("tenant_a"), 0);
        let before: Vec<_> = [1, 7, 30]
            .iter()
            .map(|d| svc.metrics_cache_key("tenant_a", *d))
            .collect();
        svc.bump_generation("tenant_a");
        assert_eq!(svc.generation_of("tenant_a"), 1);
        for (days, old_key) in [1, 7, 30].iter().zip(&before) {
            let new_key = svc.metrics_cache_key("tenant_a", *days);
            assert_ne!(&new_key, old_key, "window {days} must be invalidated");
        }
    }

    // ── F67:idempotent event identity ────────────────────────────────────────

    #[test]
    fn test_reply_event_id_is_stable_and_tenant_scoped() {
        assert_eq!(
            reply_event_id("tenant_a", "<msg-1@example.com>"),
            reply_event_id("tenant_a", "<msg-1@example.com>")
        );
        assert_ne!(
            reply_event_id("tenant_a", "<msg-1@example.com>"),
            reply_event_id("tenant_b", "<msg-1@example.com>"),
            "the same external Message-ID must not collide across tenants"
        );
        assert_ne!(
            reply_event_id("tenant_a", "<msg-1@example.com>"),
            reply_event_id("tenant_a", "<msg-2@example.com>")
        );
    }

    #[test]
    fn test_sentiment_labels_are_canonical() {
        assert_eq!(sentiment_label(&ReplySentiment::Positive), "Positive");
        assert_eq!(sentiment_label(&ReplySentiment::Negative), "Negative");
        assert_eq!(sentiment_label(&ReplySentiment::Neutral), "Neutral");
        assert_eq!(sentiment_label(&ReplySentiment::Inquiry), "Inquiry");
        assert_eq!(sentiment_label(&ReplySentiment::Unsubscribe), "Unsubscribe");
        assert_eq!(sentiment_label(&ReplySentiment::OutOfOffice), "OutOfOffice");
    }

    // ── F69:saturating depth arithmetic ──────────────────────────────────────

    #[test]
    fn test_next_thread_depth_saturates() {
        assert_eq!(next_thread_depth(None), 1);
        assert_eq!(next_thread_depth(Some(0)), 1);
        assert_eq!(next_thread_depth(Some(41)), 42);
        assert_eq!(
            next_thread_depth(Some(i32::MAX)),
            i32::MAX,
            "a poisoned chain must not overflow into a negative depth"
        );
    }
}

/// F68:cache-key construction split out so identity properties are testable
/// without a pool.
fn metrics_cache_key_parts(tenant_id: &str, generation: u64, days: i64) -> String {
    format!("reply:{tenant_id}:g{generation}:d{days}")
}

#[cfg(test)]
mod db_tests {
    //! DB-backed tests for the reply-tracking ingress and metrics paths.
    //!
    //! Gated on `TEST_DATABASE_URL` (workspace convention — see the
    //! compliance crate's gdpr_compliance_db_tests). A dedicated database
    //! (`<db>_analytics_replies`) is derived from the URL, dropped and
    //! recreated once per test, and the canonical reply_events shape
    //! (migration 159, byte-equivalent DDL) plus the minimal events table
    //! get_metrics touches are applied. When the variable is unset every
    //! test skips.

    use super::*;
    use chrono::DateTime;
    use std::collections::HashMap;

    /// Canonical reply_events shape — migration 159.
    const REPLY_EVENTS_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS reply_events (
    id            BIGSERIAL PRIMARY KEY,
    event_id      VARCHAR(64)  NOT NULL,
    tenant_id     VARCHAR(26)  NOT NULL,
    message_id    TEXT         NOT NULL,
    in_reply_to   TEXT         NOT NULL DEFAULT '',
    recipient     VARCHAR(255) NOT NULL DEFAULT '',
    subject       TEXT         NOT NULL DEFAULT '',
    is_auto_reply BOOLEAN      NOT NULL DEFAULT FALSE,
    sentiment     VARCHAR(32)  NOT NULL DEFAULT 'Neutral',
    thread_depth  INTEGER      NOT NULL DEFAULT 0,
    timestamp     TIMESTAMPTZ  NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_reply_events_event_id UNIQUE (event_id),
    CONSTRAINT ck_reply_events_thread_depth_non_negative CHECK (thread_depth >= 0)
);
CREATE INDEX IF NOT EXISTS idx_reply_events_tenant_time
    ON reply_events (tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_reply_events_tenant_message
    ON reply_events (tenant_id, message_id);
"#;

    /// Minimal slice of the events table get_metrics reads (total_sent).
    const EVENTS_MINIMAL_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS events (
    id         VARCHAR(64) PRIMARY KEY,
    tenant_id  VARCHAR(26) NOT NULL,
    message_id VARCHAR(64),
    event_type VARCHAR(50) NOT NULL,
    recipient  VARCHAR(255),
    timestamp  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

    async fn isolated_pool(db_suffix: &str) -> Option<PgPool> {
        let database_url = match std::env::var("TEST_DATABASE_URL") {
            Ok(v) if !v.trim().is_empty() => v,
            _ => {
                eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed reply tests");
                return None;
            }
        };
        let (server_part, db_part) = database_url.rsplit_once('/')?;
        let db_only = db_part.split('?').next().unwrap_or(db_part);
        let isolated = format!("{db_only}_{db_suffix}");
        let isolated_url = format!("{server_part}/{isolated}");
        let admin_url = format!("{server_part}/postgres");

        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&admin_url)
            .await
            .ok()?;

        let _ = sqlx::query(&format!(
            r#"DROP DATABASE IF EXISTS "{isolated}" WITH (FORCE)"#
        ))
        .execute(&admin)
        .await;
        if sqlx::query(&format!(r#"CREATE DATABASE "{isolated}""#))
            .execute(&admin)
            .await
            .is_err()
        {
            eprintln!("skipping: could not create isolated test database {isolated}");
            return None;
        }

        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&isolated_url)
            .await
            .ok()?;

        sqlx::raw_sql(REPLY_EVENTS_DDL)
            .execute(&pool)
            .await
            .expect("failed to create reply_events schema");
        sqlx::raw_sql(EVENTS_MINIMAL_DDL)
            .execute(&pool)
            .await
            .expect("failed to create events schema");

        Some(pool)
    }

    fn reply_event(
        tenant: &str,
        message_id: &str,
        in_reply_to: &str,
        subject: &str,
        body: &str,
        timestamp: DateTime<Utc>,
    ) -> ReplyEvent {
        ReplyEvent {
            message_id: message_id.to_string(),
            in_reply_to: in_reply_to.to_string(),
            tenant_id: tenant.to_string(),
            recipient: format!("user@{tenant}.example"),
            subject: subject.to_string(),
            body: body.to_string(),
            headers: HashMap::new(),
            timestamp,
        }
    }

    async fn scalar_i64(pool: &PgPool, sql: &str, tenant: &str) -> i64 {
        let (n,): (i64,) = sqlx::query_as(sql)
            .bind(tenant)
            .fetch_one(pool)
            .await
            .expect("scalar query");
        n
    }

    /// F67:re-delivering the same event identity must leave exactly one row
    /// and the metrics must count it once.
    #[tokio::test]
    async fn db_idempotent_ingest_one_row_one_count() {
        let Some(pool) = isolated_pool("reply_idempotent").await else {
            return;
        };
        let svc = ReplyTrackingService::new(pool.clone());
        let now = Utc::now();
        let event = reply_event(
            "tenant_idem",
            "<idem-1@example.com>",
            "<root@example.com>",
            "Re: proposal",
            "Thanks, looks great",
            now,
        );

        let first = svc.process_reply(&event).await.expect("first ingest");
        let second = svc
            .process_reply(&event)
            .await
            .expect("re-delivered ingest");

        // Same derived payload on re-delivery.
        assert_eq!(first.message_id, second.message_id);
        assert_eq!(first.thread_depth, second.thread_depth);
        assert_eq!(first.is_auto_reply, second.is_auto_reply);

        // One durable row, one counted reply.
        let rows = scalar_i64(
            &pool,
            "SELECT COUNT(*) FROM reply_events WHERE tenant_id = $1",
            "tenant_idem",
        )
        .await;
        assert_eq!(rows, 1, "duplicate event identity must not add a row");

        let metrics = svc.get_metrics("tenant_idem", 1).await.expect("metrics");
        assert_eq!(metrics.total_replies, 1, "duplicate must not double-count");
        assert_eq!(metrics.human_replies, 1);
        assert_eq!(metrics.auto_replies, 0);
        assert!((metrics.avg_thread_depth - 1.0).abs() < f64::EPSILON);
    }

    /// F68:1/7/30-day queries against a warm cache each return their own
    /// window, and an ingest immediately refreshes every window.
    #[tokio::test]
    async fn db_metrics_cache_is_window_keyed() {
        let Some(pool) = isolated_pool("reply_windows").await else {
            return;
        };
        let svc = ReplyTrackingService::new(pool.clone());
        let now = Utc::now();
        let tenant = "tenant_windows";

        // Seed replies at 2h, 5d, 20d, 50d old — one per window bucket.
        let ages_hours: [i64; 4] = [2, 24 * 5, 24 * 20, 24 * 50];
        for (i, hours) in ages_hours.iter().enumerate() {
            let event = reply_event(
                tenant,
                &format!("<win-{i}@example.com>"),
                &format!("<root-{i}@example.com>"),
                "Re: campaign",
                "Noted, thanks",
                now - chrono::Duration::hours(*hours),
            );
            svc.process_reply(&event).await.expect("seed ingest");
        }

        // Warm the cache with the WIDEST window first — the pre-fix code
        // cached by tenant alone, so the subsequent 1-day request would be
        // served the 30-day result.
        let m30 = svc.get_metrics(tenant, 30).await.expect("30d metrics");
        assert_eq!(m30.total_replies, 3);

        let m1 = svc.get_metrics(tenant, 1).await.expect("1d metrics");
        assert_eq!(m1.total_replies, 1, "1-day window must not see 30-day data");

        let m7 = svc.get_metrics(tenant, 7).await.expect("7d metrics");
        assert_eq!(m7.total_replies, 2);

        let m365 = svc.get_metrics(tenant, 365).await.expect("365d metrics");
        assert_eq!(m365.total_replies, 4);

        // Warm-cache reads are stable per window.
        assert_eq!(svc.get_metrics(tenant, 1).await.unwrap().total_replies, 1);
        assert_eq!(svc.get_metrics(tenant, 30).await.unwrap().total_replies, 3);

        // Ingest bumps the data generation: every window refreshes even
        // though all of the above entries are still within TTL.
        svc.process_reply(&reply_event(
            tenant,
            "<win-new@example.com>",
            "<root-0@example.com>",
            "Re: campaign",
            "Thanks!",
            now,
        ))
        .await
        .expect("post-cache ingest");
        assert_eq!(
            svc.get_metrics(tenant, 1).await.unwrap().total_replies,
            2,
            "post-ingest 1-day window must include the new reply"
        );
        assert_eq!(svc.get_metrics(tenant, 30).await.unwrap().total_replies, 4);
    }

    /// F69:thread depth is resolved per tenant — the same external
    /// Message-ID must not carry another tenant's chain depth.
    #[tokio::test]
    async fn db_thread_depth_is_tenant_isolated() {
        let Some(pool) = isolated_pool("reply_tenants").await else {
            return;
        };
        let svc = ReplyTrackingService::new(pool.clone());
        let now = Utc::now();

        // Tenant A builds a chain: root -> a1 (depth 1) -> a2 (depth 2).
        let a1 = svc
            .process_reply(&reply_event(
                "tenant_a",
                "<a-1@example.com>",
                "<ext-root@example.com>",
                "Re: thread",
                "First reply",
                now,
            ))
            .await
            .expect("tenant A first reply");
        assert_eq!(a1.thread_depth, 1);

        let a2 = svc
            .process_reply(&reply_event(
                "tenant_a",
                "<a-2@example.com>",
                "<a-1@example.com>",
                "Re: thread",
                "Second reply",
                now,
            ))
            .await
            .expect("tenant A second reply");
        assert_eq!(a2.thread_depth, 2);

        // Tenant B replies INTO the same external Message-ID that tenant A
        // owns a depth-2 row for. Pre-fix lookup (message_id alone) would
        // return 3; the tenant-qualified identity must return 1.
        let b1 = svc
            .process_reply(&reply_event(
                "tenant_b",
                "<b-1@example.com>",
                "<a-1@example.com>",
                "Re: other thread",
                "Unrelated reply",
                now,
            ))
            .await
            .expect("tenant B reply");
        assert_eq!(
            b1.thread_depth, 1,
            "tenant B must not inherit tenant A's chain depth"
        );

        // Durable state agrees: per-tenant maxima stay isolated.
        let max_a = scalar_i64(
            &pool,
            "SELECT COALESCE(MAX(thread_depth), 0)::bigint FROM reply_events WHERE tenant_id = $1",
            "tenant_a",
        )
        .await;
        let max_b = scalar_i64(
            &pool,
            "SELECT COALESCE(MAX(thread_depth), 0)::bigint FROM reply_events WHERE tenant_id = $1",
            "tenant_b",
        )
        .await;
        assert_eq!(max_a, 2);
        assert_eq!(max_b, 1);

        // And B's metrics never count A's rows.
        let metrics_b = svc.get_metrics("tenant_b", 1).await.expect("metrics B");
        assert_eq!(metrics_b.total_replies, 1);
    }
}
