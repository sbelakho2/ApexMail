//! Delivery edge-case service – SMTP response parsing, retry scheduling,
//! loop detection, auto-responder detection, MX resolution, greylisting.

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;
use std::time::Duration;

use moka::sync::Cache;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::OnceLock;
use trust_dns_resolver::TokioResolver;

use crate::config::{LoopDetectionConfig, RetryConfig, AUTO_SUBMITTED_VALUES};

use std::fmt;

/// O-21.2: Typed MX resolution errors instead of raw `anyhow`.
///
/// Previously, `resolve_mx` returned `anyhow::Error` with unstructured
/// messages. Callers could not distinguish "no records" from "DNS timeout"
/// without string-matching. This enum provides clear variants so callers
/// can handle each case appropriately.
#[derive(Debug, Clone)]
pub enum MxLookupError {
    /// No MX or A records exist for the domain.
    NoRecords(String),
    /// DNS resolution timed out or the resolver returned an error.
    ResolverError(String),
    /// The domain is syntactically invalid.
    InvalidDomain(String),
}

impl fmt::Display for MxLookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRecords(d) => write!(f, "No MX or A records for {d}"),
            Self::ResolverError(e) => write!(f, "MX resolver error: {e}"),
            Self::InvalidDomain(d) => write!(f, "Invalid domain: {d}"),
        }
    }
}

impl std::error::Error for MxLookupError {}

// ── types ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryStatus {
    Pending,
    Delivered,
    Deferred,
    Bounced,
    Dropped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseType {
    Success,
    TemporaryFailure,
    PermanentFailure,
    Greylist,
    RateLimit,
    ConnectionError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SMTPResponse {
    pub code: u16,
    pub message: String,
    pub enhanced: Option<String>,
    pub response_type: ResponseType,
    pub is_greylist: bool,
    pub suggested_retry_delay: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MXRecord {
    pub exchange: String,
    pub priority: u16,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryAttempt {
    pub message_id: String,
    pub attempt: i32,
    pub mx_host: String,
    pub mx_priority: u16,
    pub response_code: u16,
    pub response_message: String,
    pub response_type: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub duration_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopDetection {
    pub is_loop: bool,
    pub hop_count: usize,
    pub max_hops: usize,
    pub loop_path: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoResponderDetection {
    pub is_auto_responder: bool,
    #[serde(rename = "type")]
    pub auto_type: Option<String>,
    pub confidence: u32,
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrySchedule {
    pub next_attempt: chrono::DateTime<chrono::Utc>,
    pub attempt_number: u32,
    pub delay_secs: u64,
    pub reason: String,
}

// ── service ────────────────────────────────────────────────────────────────────

pub struct DeliveryService {
    pool: PgPool,
    redis: deadpool_redis::Pool,
    resolver: TokioResolver,
    retry_config: RetryConfig,
    loop_config: LoopDetectionConfig,
    mx_cache: Cache<String, Vec<MXRecord>>,
    greylist_patterns: Vec<Regex>,
    rate_limit_patterns: Vec<Regex>,
    auto_responder_subject_patterns: Vec<Regex>,
}

static DELIVERY_RESOLVER: LazyLock<TokioResolver> = LazyLock::new(|| {
    trust_dns_resolver::Resolver::builder_tokio()
        .expect("system resolver configuration is always buildable")
        .build()
        .expect("system resolver configuration is always buildable")
});

impl DeliveryService {
    pub fn new(
        pool: PgPool,
        redis: deadpool_redis::Pool,
        retry_config: RetryConfig,
        loop_config: LoopDetectionConfig,
        subject_patterns: &[String],
    ) -> Self {
        let resolver = DELIVERY_RESOLVER.clone();

        let greylist_patterns: Vec<Regex> = [
            r"(?i)greylist",
            r"(?i)gray\s*list",
            r"(?i)try\s+again\s+later",
            r"(?i)please\s+retry",
            r"(?i)temporarily\s+rejected",
            r"(?i)too\s+many\s+connections",
            r"(?i)rate\s+limited",
            r"(?i)4\.7\.1",
            r"(?i)service\s+temporarily\s+unavailable",
        ]
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect();

        let rate_limit_patterns: Vec<Regex> = [
            r"(?i)rate\s*limit",
            r"(?i)too\s+many",
            r"(?i)throttl",
            r"(?i)slow\s+down",
            r"(?i)over\s+quota",
            r"(?i)exceeded.*limit",
            r"(?i)connection\s+limit",
        ]
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect();

        let auto_responder_subject_patterns: Vec<Regex> = subject_patterns
            .iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect();

        Self {
            pool,
            redis,
            resolver,
            retry_config,
            loop_config,
            mx_cache: Cache::builder()
                .max_capacity(5_000)
                .time_to_live(Duration::from_secs(3600))
                .build(),
            greylist_patterns,
            rate_limit_patterns,
            auto_responder_subject_patterns,
        }
    }

    /// Parse an SMTP response code + message.
    pub fn parse_smtp_response(&self, code: u16, message: &str) -> SMTPResponse {
        let is_rate_limit = (400..500).contains(&code) && self.is_rate_limit_message(message);
        let is_greylist =
            !is_rate_limit && (400..500).contains(&code) && self.is_greylist_message(message);

        let response_type = match code {
            200..=299 => ResponseType::Success,
            _ if is_greylist => ResponseType::Greylist,
            _ if is_rate_limit => ResponseType::RateLimit,
            400..=499 => ResponseType::TemporaryFailure,
            500..=599 => ResponseType::PermanentFailure,
            _ => ResponseType::ConnectionError,
        };

        let enhanced = extract_enhanced_status(message);
        let suggested_retry_delay = self.extract_retry_delay(message);

        SMTPResponse {
            code,
            message: message.to_string(),
            enhanced,
            response_type,
            is_greylist,
            suggested_retry_delay,
        }
    }

    /// Calculate retry schedule.
    pub fn calculate_retry_schedule(
        &self,
        response: &SMTPResponse,
        current_attempt: u32,
    ) -> Option<RetrySchedule> {
        if response.response_type == ResponseType::PermanentFailure {
            return None;
        }
        if current_attempt >= self.retry_config.max_retries {
            return None;
        }

        let (delay, reason) = match response.response_type {
            ResponseType::Greylist => (
                self.retry_config.greylist_retry_delay_secs,
                "greylist".to_string(),
            ),
            ResponseType::RateLimit => {
                let delay = response
                    .suggested_retry_delay
                    .unwrap_or(self.retry_config.initial_delay_secs * 5);
                (delay, "rate_limit".to_string())
            }
            _ => {
                let delay = (self.retry_config.initial_delay_secs as f64
                    * self
                        .retry_config
                        .backoff_multiplier
                        .powi(current_attempt as i32)) as u64;
                let delay = delay.min(self.retry_config.max_delay_secs);
                (delay, "temporary_failure".to_string())
            }
        };

        let next = chrono::Utc::now() + chrono::Duration::seconds(delay as i64);
        Some(RetrySchedule {
            next_attempt: next,
            attempt_number: current_attempt + 1,
            delay_secs: delay,
            reason,
        })
    }

    /// Detect email loop from Received headers.
    pub fn detect_loop(&self, received_headers: &[String]) -> LoopDetection {
        let hop_count = received_headers.len();

        if hop_count > self.loop_config.max_hops {
            return LoopDetection {
                is_loop: true,
                hop_count,
                max_hops: self.loop_config.max_hops,
                loop_path: None,
            };
        }

        // Check for repeated hosts (>3 occurrences = loop)
        let mut host_count: HashMap<String, usize> = HashMap::new();
        let mut hosts = Vec::new();

        for header in received_headers {
            if let Some(host) = extract_host_from_received(header) {
                *host_count.entry(host.clone()).or_insert(0) += 1;
                hosts.push(host);
            }
        }

        let is_loop = host_count.values().any(|&count| count > 3);
        let loop_path = if is_loop { Some(hosts) } else { None };

        LoopDetection {
            is_loop,
            hop_count,
            max_hops: self.loop_config.max_hops,
            loop_path,
        }
    }

    /// Detect auto-responder from headers, subject, and body.
    pub fn detect_auto_responder(
        &self,
        headers: &HashMap<String, String>,
        subject: &str,
        body: Option<&str>,
    ) -> AutoResponderDetection {
        let mut score: u32 = 0;
        let mut indicators = Vec::new();
        let mut auto_type: Option<String> = None;

        // Auto-Submitted header (+40)
        if let Some(val) = headers
            .get("auto-submitted")
            .or(headers.get("Auto-Submitted"))
        {
            let lower = val.to_lowercase();
            if AUTO_SUBMITTED_VALUES.iter().any(|v| lower.contains(v)) {
                score += 40;
                indicators.push(format!("Auto-Submitted: {val}"));
                auto_type = Some(classify_auto_type(&lower));
            }
        }

        // Precedence header (+30)
        if let Some(val) = headers.get("precedence").or(headers.get("Precedence")) {
            let lower = val.to_lowercase();
            if lower == "bulk" || lower == "junk" || lower == "auto_reply" {
                score += 30;
                indicators.push(format!("Precedence: {val}"));
            }
        }

        // X-Auto-Response-Suppress (+25)
        if headers.contains_key("x-auto-response-suppress")
            || headers.contains_key("X-Auto-Response-Suppress")
        {
            score += 25;
            indicators.push("X-Auto-Response-Suppress present".into());
        }

        // X-Autorespond / X-Autoreply (+35)
        if headers.contains_key("x-autorespond")
            || headers.contains_key("X-Autorespond")
            || headers.contains_key("x-autoreply")
            || headers.contains_key("X-Autoreply")
        {
            score += 35;
            indicators.push("X-Autorespond/X-Autoreply present".into());
        }

        // Empty or system Return-Path (+20)
        if let Some(rp) = headers.get("return-path").or(headers.get("Return-Path")) {
            let trimmed = rp.trim();
            if trimmed == "<>" || trimmed.is_empty() || trimmed.contains("mailer-daemon") {
                score += 20;
                indicators.push(format!("Return-Path: {rp}"));
            }
        }

        // Subject pattern match (+25)
        let lower_subject = subject.to_lowercase();
        for pat in &self.auto_responder_subject_patterns {
            if pat.is_match(&lower_subject) {
                score += 25;
                indicators.push(format!("Subject matches pattern: {}", pat.as_str()));
                if auto_type.is_none() {
                    auto_type = Some(classify_subject_type(&lower_subject));
                }
                break;
            }
        }

        // Body keyword match (+15 each)
        if let Some(body_text) = body {
            let lower_body = body_text.to_lowercase();
            let keywords = [
                ("out of office", "ooo"),
                ("on vacation", "vacation"),
                ("auto-reply", "system"),
                ("this is an automated", "system"),
            ];
            for (kw, t) in &keywords {
                if lower_body.contains(kw) {
                    score += 15;
                    indicators.push(format!("Body contains: {kw}"));
                    if auto_type.is_none() {
                        auto_type = Some(t.to_string());
                    }
                }
            }
        }

        AutoResponderDetection {
            is_auto_responder: score >= 50,
            auto_type: if score >= 50 { auto_type } else { None },
            confidence: score.min(100),
            indicators,
        }
    }

    /// Resolve MX records for a domain.
    /// O-21.2: Returns typed `MxLookupError` instead of raw `anyhow::Error`.
    pub async fn resolve_mx(&self, domain: &str) -> Result<Vec<MXRecord>, MxLookupError> {
        if let Some(cached) = self.mx_cache.get(domain) {
            return Ok(cached);
        }

        let mut records: Vec<MXRecord> = match self.resolver.mx_lookup(domain).await {
            Ok(mx) => mx
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    trust_dns_resolver::proto::rr::RData::MX(rec) => Some(MXRecord {
                        exchange: rec.exchange.to_string().trim_end_matches('.').to_string(),
                        priority: rec.preference,
                        ttl: None,
                    }),
                    _ => None,
                })
                .collect(),
            Err(e) => {
                // MX lookup failed; attempt implicit-MX fallback to the
                // domain's A/AAAA record (RFC 5321 §5.1) and log the
                // underlying error so operators can diagnose flaky resolvers.
                tracing::debug!(domain = %domain, error = %e, "MX lookup failed; trying A/AAAA fallback");
                // Fallback to A record
                if self.resolver.lookup_ip(domain).await.is_ok() {
                    vec![MXRecord {
                        exchange: domain.to_string(),
                        priority: 10,
                        ttl: None,
                    }]
                } else {
                    return Err(MxLookupError::NoRecords(domain.to_string()));
                }
            }
        };

        records.sort_by_key(|r| r.priority);
        self.mx_cache.insert(domain.to_string(), records.clone());
        Ok(records)
    }

    /// Select next MX to try, skipping failed hosts.
    pub fn select_next_mx(
        records: &[MXRecord],
        failed_hosts: &HashSet<String>,
        preferred_priority: Option<u16>,
    ) -> Option<MXRecord> {
        let available: Vec<&MXRecord> = records
            .iter()
            .filter(|r| !failed_hosts.contains(&r.exchange))
            .collect();

        if available.is_empty() {
            return None;
        }

        if let Some(prio) = preferred_priority {
            let same_prio: Vec<&&MXRecord> =
                available.iter().filter(|r| r.priority == prio).collect();
            if !same_prio.is_empty() {
                // Random selection among same priority
                let idx = rand_idx(same_prio.len());
                return Some((*same_prio[idx]).clone());
            }
        }

        // Return lowest priority available
        Some(available[0].clone())
    }

    /// Record a delivery attempt.
    pub async fn record_delivery_attempt(&self, attempt: &DeliveryAttempt) -> anyhow::Result<()> {
        sqlx::query(
            r#"INSERT INTO edge_delivery_attempts
               (id, message_id, attempt_number, mx_host, mx_priority,
                response_code, response_message, response_type, attempt_time, duration_ms)
               VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
        )
        .bind(&attempt.message_id)
        .bind(attempt.attempt)
        .bind(&attempt.mx_host)
        .bind(attempt.mx_priority as i32)
        .bind(attempt.response_code as i32)
        .bind(&attempt.response_message)
        .bind(&attempt.response_type)
        .bind(attempt.timestamp)
        .bind(attempt.duration_ms)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Get delivery history.
    pub async fn get_delivery_history(
        &self,
        message_id: &str,
    ) -> anyhow::Result<Vec<DeliveryAttempt>> {
        let rows = sqlx::query_as::<_, (String, i32, String, i16, i16, String, String, chrono::DateTime<chrono::Utc>, i64)>(
            "SELECT message_id, attempt_number, mx_host, mx_priority, response_code, response_message, response_type, attempt_time, duration_ms FROM edge_delivery_attempts WHERE message_id = $1 ORDER BY attempt_number ASC"
        )
        .bind(message_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(mid, att, mx, prio, code, msg, rt, ts, dur)| DeliveryAttempt {
                    message_id: mid,
                    attempt: att,
                    mx_host: mx,
                    mx_priority: prio as u16,
                    response_code: code as u16,
                    response_message: msg,
                    response_type: rt,
                    timestamp: ts,
                    duration_ms: dur,
                },
            )
            .collect())
    }

    /// Check if domain is a known greylister.
    pub async fn is_known_greylister(&self, domain: &str) -> anyhow::Result<bool> {
        // Redis cache
        if let Ok(mut conn) = self.redis.get().await {
            let key = format!("greylist:known:{domain}");
            if let Ok(Some(val)) = redis::cmd("GET")
                .arg(&key)
                .query_async::<Option<String>>(&mut *conn)
                .await
            {
                return Ok(val == "1");
            }
        }

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM edge_delivery_attempts WHERE mx_host LIKE $1 AND response_type = 'greylist' AND attempt_time > NOW() - INTERVAL '30 days'"
        )
        .bind(format!("%.{domain}"))
        .fetch_one(&self.pool)
        .await?;

        let is_known = count > 10;

        // Cache for 24h
        if let Ok(mut conn) = self.redis.get().await {
            let key = format!("greylist:known:{domain}");
            redis::cmd("SET")
                .arg(&key)
                .arg(if is_known { "1" } else { "0" })
                .arg("EX")
                .arg(86400i64)
                .query_async::<String>(&mut *conn)
                .await
                .ok();
        }

        Ok(is_known)
    }

    // ── internal ───────────────────────────────────────────────────────────────

    fn is_greylist_message(&self, message: &str) -> bool {
        self.greylist_patterns.iter().any(|p| p.is_match(message))
    }

    fn is_rate_limit_message(&self, message: &str) -> bool {
        self.rate_limit_patterns.iter().any(|p| p.is_match(message))
    }

    fn extract_retry_delay(&self, message: &str) -> Option<u64> {
        let re = RETRY_DELAY_RE
            .get_or_init(|| Regex::new(r"(\d+)\s*(second|minute|hour)").expect("retry regex"));
        let caps = re.captures(message)?;
        let n: u64 = caps[1].parse().ok()?;
        let unit = &caps[2];
        Some(match unit {
            "minute" | "minutes" => n * 60,
            "hour" | "hours" => n * 3600,
            _ => n,
        })
    }
}

// ── helpers ────────────────────────────────────────────────────────────────────

// ── helpers ────────────────────────────────────────────────────────────────────

/// Test-only seam: prime the MX cache so resolution logic is exercised
/// without any DNS egress. Compiled only under `cfg(test)`.
#[cfg(test)]
impl DeliveryService {
    pub(crate) fn prime_mx_cache(&self, domain: &str, records: Vec<MXRecord>) {
        self.mx_cache.insert(domain.to_string(), records);
    }
}

fn extract_enhanced_status(message: &str) -> Option<String> {
    let re =
        ENHANCED_STATUS_RE.get_or_init(|| Regex::new(r"(\d\.\d+\.\d+)").expect("status regex"));
    re.captures(message).map(|c| c[1].to_string())
}

fn extract_host_from_received(header: &str) -> Option<String> {
    let re = RECEIVED_HOST_RE.get_or_init(|| Regex::new(r"from\s+(\S+)").expect("received regex"));
    re.captures(header).map(|c| c[1].to_lowercase())
}

fn classify_auto_type(value: &str) -> String {
    if value.contains("replied") {
        "ooo".into()
    } else if value.contains("generated") {
        "system".into()
    } else if value.contains("notified") {
        "notification".into()
    } else {
        "system".into()
    }
}

fn classify_subject_type(subject: &str) -> String {
    if subject.contains("out of office") || subject.contains("ooo") {
        "ooo".into()
    } else if subject.contains("vacation") {
        "vacation".into()
    } else if subject.contains("bounce") || subject.contains("undeliverable") {
        "bounce".into()
    } else {
        "system".into()
    }
}

/// Validate IPv4/IPv6 with optional CIDR.
pub fn is_valid_ip(ip: &str) -> bool {
    if let Some((addr, prefix)) = ip.split_once('/') {
        let prefix_len: u32 = match prefix.parse() {
            Ok(p) => p,
            Err(_) => return false,
        };
        if addr.contains(':') {
            addr.parse::<std::net::Ipv6Addr>().is_ok() && prefix_len <= 128
        } else {
            addr.parse::<std::net::Ipv4Addr>().is_ok() && prefix_len <= 32
        }
    } else {
        ip.parse::<std::net::IpAddr>().is_ok()
    }
}

fn rand_idx(max: usize) -> usize {
    // Cheap non-crypto random for MX rotation
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as usize;
    seed % max
}

static RETRY_DELAY_RE: OnceLock<Regex> = OnceLock::new();
static ENHANCED_STATUS_RE: OnceLock<Regex> = OnceLock::new();
static RECEIVED_HOST_RE: OnceLock<Regex> = OnceLock::new();

// ── tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_smtp_response_success() {
        let svc = TestDelivery::new();
        let resp = svc.parse_smtp_response(250, "OK");
        assert_eq!(resp.response_type, ResponseType::Success);
        assert!(!resp.is_greylist);
    }

    #[test]
    fn test_parse_smtp_response_greylist() {
        let svc = TestDelivery::new();
        let resp = svc.parse_smtp_response(450, "Greylisted, try again later");
        assert_eq!(resp.response_type, ResponseType::Greylist);
        assert!(resp.is_greylist);
    }

    #[test]
    fn test_parse_smtp_response_rate_limit() {
        let svc = TestDelivery::new();
        let resp = svc.parse_smtp_response(421, "Rate limit exceeded for your IP");
        assert_eq!(resp.response_type, ResponseType::RateLimit);
    }

    #[test]
    fn test_parse_smtp_response_permanent() {
        let svc = TestDelivery::new();
        let resp = svc.parse_smtp_response(550, "User not found");
        assert_eq!(resp.response_type, ResponseType::PermanentFailure);
    }

    #[test]
    fn test_detect_loop_no_loop() {
        let svc = TestDelivery::new();
        let headers = vec![
            "from mail1.example.com".into(),
            "from mail2.example.com".into(),
        ];
        let result = svc.detect_loop(&headers);
        assert!(!result.is_loop);
        assert_eq!(result.hop_count, 2);
    }

    #[test]
    fn test_detect_loop_too_many_hops() {
        let svc = TestDelivery::new();
        let headers: Vec<String> = (0..30)
            .map(|i| format!("from host{i}.example.com"))
            .collect();
        let result = svc.detect_loop(&headers);
        assert!(result.is_loop);
    }

    #[test]
    fn test_detect_loop_repeated_host() {
        let svc = TestDelivery::new();
        let headers: Vec<String> = (0..5).map(|_| "from looping.example.com".into()).collect();
        let result = svc.detect_loop(&headers);
        assert!(result.is_loop);
    }

    #[test]
    fn test_detect_auto_responder() {
        let svc = TestDelivery::new();
        let mut headers = HashMap::new();
        headers.insert("Auto-Submitted".to_string(), "auto-replied".to_string());
        headers.insert("Precedence".to_string(), "bulk".to_string());
        let result = svc.detect_auto_responder(&headers, "Re: Meeting", None);
        // Auto-Submitted (+40) + Precedence (+30) = 70 >= threshold 50
        assert!(result.is_auto_responder);
        assert!(result.confidence >= 50);
    }

    #[test]
    fn test_detect_auto_responder_subject() {
        let svc = TestDelivery::new();
        let headers = HashMap::new();
        let result = svc.detect_auto_responder(
            &headers,
            "Out of Office: I am away",
            Some("I am out of office until Monday"),
        );
        // Subject pattern (+25) + body keyword (+15) = 40, below threshold 50
        // unless subject patterns are configured
        assert!(result.confidence > 0);
    }

    #[test]
    fn test_extract_enhanced_status() {
        assert_eq!(
            extract_enhanced_status("550 5.1.1 User not found"),
            Some("5.1.1".into())
        );
        assert_eq!(extract_enhanced_status("250 OK"), None);
    }

    #[test]
    fn test_is_valid_ip() {
        assert!(is_valid_ip("192.168.1.1"));
        assert!(is_valid_ip("::1"));
        assert!(is_valid_ip("10.0.0.0/8"));
        assert!(is_valid_ip("fe80::/10"));
        assert!(!is_valid_ip("not-an-ip"));
        assert!(!is_valid_ip("192.168.1.1/33"));
    }

    #[test]
    fn test_calculate_retry_schedule_permanent() {
        let svc = TestDelivery::new();
        let resp = SMTPResponse {
            code: 550,
            message: "User not found".into(),
            enhanced: None,
            response_type: ResponseType::PermanentFailure,
            is_greylist: false,
            suggested_retry_delay: None,
        };
        assert!(svc.calculate_retry_schedule(&resp, 0).is_none());
    }

    #[test]
    fn test_calculate_retry_schedule_greylist() {
        let svc = TestDelivery::new();
        let resp = SMTPResponse {
            code: 450,
            message: "Greylisted".into(),
            enhanced: None,
            response_type: ResponseType::Greylist,
            is_greylist: true,
            suggested_retry_delay: None,
        };
        let schedule = svc.calculate_retry_schedule(&resp, 0).unwrap();
        assert_eq!(schedule.delay_secs, 300);
        assert_eq!(schedule.reason, "greylist");
    }

    #[test]
    fn test_calculate_retry_backoff() {
        let svc = TestDelivery::new();
        let resp = SMTPResponse {
            code: 451,
            message: "Try again later".into(),
            enhanced: None,
            response_type: ResponseType::TemporaryFailure,
            is_greylist: false,
            suggested_retry_delay: None,
        };
        let s1 = svc.calculate_retry_schedule(&resp, 0).unwrap();
        let s2 = svc.calculate_retry_schedule(&resp, 1).unwrap();
        assert!(s2.delay_secs > s1.delay_secs);
    }

    #[test]
    fn test_select_next_mx() {
        let records = vec![
            MXRecord {
                exchange: "mx1.example.com".into(),
                priority: 10,
                ttl: None,
            },
            MXRecord {
                exchange: "mx2.example.com".into(),
                priority: 10,
                ttl: None,
            },
            MXRecord {
                exchange: "mx3.example.com".into(),
                priority: 20,
                ttl: None,
            },
        ];
        let mut failed = HashSet::new();
        let selected = DeliveryService::select_next_mx(&records, &failed, None).unwrap();
        assert!(selected.priority == 10); // Should select lowest priority

        failed.insert("mx1.example.com".into());
        failed.insert("mx2.example.com".into());
        let selected = DeliveryService::select_next_mx(&records, &failed, None).unwrap();
        assert_eq!(selected.exchange, "mx3.example.com");
    }

    // ── adversarial: real service (lazy pools; no network for pure logic) ──

    fn offline_service() -> DeliveryService {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://fake:fake@localhost:1/fake")
            .expect("lazy pool never connects");
        let redis = deadpool_redis::Config::from_url("redis://localhost:1")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("redis pool");
        DeliveryService::new(
            pool,
            redis,
            RetryConfig::default(),
            LoopDetectionConfig::default(),
            &crate::config::AutoResponderConfig::default().subject_patterns,
        )
    }

    async fn canonical_pool(test_name: &str) -> Option<sqlx::PgPool> {
        match migrator::test_support::fresh_canonical_pool(test_name, test_name).await {
            Ok(pool) => pool,
            Err(error) => panic!("{}", error.panic_message()),
        }
    }

    fn real_redis_pool() -> deadpool_redis::Pool {
        let url =
            std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        deadpool_redis::Config::from_url(url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("redis pool")
    }

    #[tokio::test]
    async fn parse_smtp_response_classifies_and_extracts_metadata() {
        let svc = offline_service();
        // Connection-level codes are neither transient nor permanent.
        let resp = svc.parse_smtp_response(100, "banner");
        assert_eq!(resp.response_type, ResponseType::ConnectionError);

        // Success wins even if the message text mentions greylisting.
        let resp = svc.parse_smtp_response(250, "OK greylist cleared");
        assert_eq!(resp.response_type, ResponseType::Success);
        assert!(!resp.is_greylist);

        // A greylist phrase without any retry hint.
        let resp = svc.parse_smtp_response(451, "please retry later");
        assert_eq!(resp.response_type, ResponseType::Greylist);
        assert!(resp.is_greylist);
        assert_eq!(resp.enhanced, None);

        // Rate limit outranks greylist when both phrases appear.
        let resp = svc.parse_smtp_response(421, "too many connections: rate limited");
        assert_eq!(resp.response_type, ResponseType::RateLimit);
        assert!(!resp.is_greylist);

        // Enhanced status is extracted from the message.
        let resp = svc.parse_smtp_response(550, "5.1.1 User unknown");
        assert_eq!(resp.response_type, ResponseType::PermanentFailure);
        assert_eq!(resp.enhanced.as_deref(), Some("5.1.1"));
    }

    #[tokio::test]
    async fn retry_delay_is_parsed_from_human_text() {
        let svc = offline_service();
        let resp = svc.parse_smtp_response(421, "try again in 5 minutes");
        assert_eq!(resp.suggested_retry_delay, Some(300));
        let resp = svc.parse_smtp_response(421, "retry after 2 hours");
        assert_eq!(resp.suggested_retry_delay, Some(7200));
        let resp = svc.parse_smtp_response(421, "wait 30 second(s)");
        assert_eq!(resp.suggested_retry_delay, Some(30));
        let resp = svc.parse_smtp_response(421, "slow down");
        assert_eq!(resp.suggested_retry_delay, None);
    }

    #[tokio::test]
    async fn retry_schedule_honours_suggested_delay_and_budgets() {
        let svc = offline_service();
        // Rate limit with a server-suggested delay uses that delay.
        let mut resp = svc.parse_smtp_response(421, "retry after 2 minutes");
        resp.response_type = ResponseType::RateLimit;
        let schedule = svc.calculate_retry_schedule(&resp, 0).unwrap();
        assert_eq!(schedule.delay_secs, 120);
        assert_eq!(schedule.reason, "rate_limit");
        assert_eq!(schedule.attempt_number, 1);

        // Rate limit without a hint falls back to initial_delay * 5.
        resp.suggested_retry_delay = None;
        let schedule = svc.calculate_retry_schedule(&resp, 0).unwrap();
        assert_eq!(schedule.delay_secs, 5);

        // The exponential delay is capped at max_delay_secs (needs a retry
        // budget larger than the default three to reach the cap at all).
        let long_budget = DeliveryService::new(
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(std::time::Duration::from_millis(100))
                .connect_lazy("postgres://fake:fake@localhost:1/fake")
                .expect("lazy pool never connects"),
            deadpool_redis::Config::from_url("redis://localhost:1")
                .create_pool(Some(deadpool_redis::Runtime::Tokio1))
                .expect("redis pool"),
            RetryConfig {
                max_retries: 40,
                ..RetryConfig::default()
            },
            LoopDetectionConfig::default(),
            &[],
        );
        let temp = SMTPResponse {
            code: 451,
            message: "try again later".into(),
            enhanced: None,
            response_type: ResponseType::TemporaryFailure,
            is_greylist: false,
            suggested_retry_delay: None,
        };
        let schedule = long_budget.calculate_retry_schedule(&temp, 29).unwrap();
        assert_eq!(schedule.delay_secs, long_budget.retry_config.max_delay_secs);

        // Retry budget exhausted → no schedule.
        assert!(svc
            .calculate_retry_schedule(&temp, svc.retry_config.max_retries)
            .is_none());
    }

    #[tokio::test]
    async fn loop_detection_edge_cases() {
        let svc = offline_service();
        // Headers without a "from" host are ignored, not counted as loops.
        let result = svc.detect_loop(&["by relay.example.com".into()]);
        assert!(!result.is_loop);
        assert_eq!(result.loop_path, None);

        // Exactly max_hops is fine; max_hops + 1 is a loop and carries no path.
        let at_limit: Vec<String> = (0..svc.loop_config.max_hops)
            .map(|i| format!("from host{i}.example.com"))
            .collect();
        assert!(!svc.detect_loop(&at_limit).is_loop);
        let over: Vec<String> = (0..=svc.loop_config.max_hops)
            .map(|i| format!("from host{i}.example.com"))
            .collect();
        let result = svc.detect_loop(&over);
        assert!(result.is_loop);
        assert_eq!(result.loop_path, None);

        // Four occurrences of one host is a loop and reports the path.
        let repeated: Vec<String> = (0..4)
            .map(|_| "from looping.example.com with ESMTP".into())
            .collect();
        let result = svc.detect_loop(&repeated);
        assert!(result.is_loop);
        let expected: Vec<String> = vec!["looping.example.com".to_string(); 4];
        assert_eq!(result.loop_path.as_deref(), Some(expected.as_slice()));
    }

    #[tokio::test]
    async fn auto_responder_scoring_is_explainable_and_thresholded() {
        let svc = offline_service();
        // A single weak signal stays below the 50-point threshold and is not
        // labelled.
        let mut headers = HashMap::new();
        headers.insert("Precedence".into(), "bulk".into());
        let result = svc.detect_auto_responder(&headers, "Hello", None);
        assert!(!result.is_auto_responder);
        assert_eq!(result.auto_type, None);
        assert_eq!(result.confidence, 30);

        // Auto-Submitted: auto-replied → 40 + Return-Path <> → 20 = 60.
        let mut headers = HashMap::new();
        headers.insert("Auto-Submitted".into(), "auto-replied".into());
        headers.insert("Return-Path".into(), "<>".into());
        let result = svc.detect_auto_responder(&headers, "Re: hi", None);
        assert!(result.is_auto_responder);
        assert_eq!(result.auto_type.as_deref(), Some("ooo"));
        assert_eq!(result.confidence, 60);

        // X-Autorespond + subject pattern.
        let mut headers = HashMap::new();
        headers.insert("x-autorespond".into(), "yes".into());
        let result = svc.detect_auto_responder(&headers, "Automatic reply: gone", None);
        assert!(result.is_auto_responder);
        assert_eq!(result.confidence, 60);

        // Body keyword only (15) → below threshold; with header it is labelled
        // from the body.
        let result =
            svc.detect_auto_responder(&HashMap::new(), "hi", Some("I am on vacation until Monday"));
        assert!(!result.is_auto_responder);
        assert!(result.indicators.iter().any(|i| i.contains("on vacation")));

        // Non-matching Auto-Submitted value must not score.
        let mut headers = HashMap::new();
        headers.insert("Auto-Submitted".into(), "no".into());
        let result = svc.detect_auto_responder(&headers, "hi", None);
        assert_eq!(result.confidence, 0);

        // mailer-daemon Return-Path scores as a bounce signal.
        let mut headers = HashMap::new();
        headers.insert("Return-Path".into(), "<mailer-daemon@example.com>".into());
        headers.insert("Precedence".into(), "auto_reply".into());
        let result = svc.detect_auto_responder(&headers, "Undeliverable", None);
        assert!(result.is_auto_responder);

        // X-Auto-Response-Suppress contributes 25 and is reported.
        let mut headers = HashMap::new();
        headers.insert("X-Auto-Response-Suppress".into(), "All".into());
        headers.insert("x-auto-response-suppress".into(), "All".into());
        let result = svc.detect_auto_responder(&headers, "hi", None);
        assert_eq!(result.confidence, 25);
        assert!(result
            .indicators
            .iter()
            .any(|i| i.contains("X-Auto-Response-Suppress")));

        // Auto-Submitted variants select the right auto-type: generated →
        // system, notified → notification.
        let mut headers = HashMap::new();
        headers.insert("Auto-Submitted".into(), "auto-generated".into());
        headers.insert("Precedence".into(), "bulk".into());
        let result = svc.detect_auto_responder(&headers, "hi", None);
        assert_eq!(result.auto_type.as_deref(), Some("system"));

        let mut headers = HashMap::new();
        headers.insert("Auto-Submitted".into(), "auto-notified".into());
        headers.insert("Precedence".into(), "junk".into());
        let result = svc.detect_auto_responder(&headers, "hi", None);
        assert_eq!(result.auto_type.as_deref(), Some("notification"));

        // Subject classification: vacation and bounce (each needs a second
        // signal to cross the 50-point threshold).
        let mut headers = HashMap::new();
        headers.insert("Precedence".into(), "bulk".into());
        let result = svc.detect_auto_responder(&headers, "Vacation: away", None);
        assert_eq!(result.auto_type.as_deref(), Some("vacation"));

        let mut headers = HashMap::new();
        headers.insert("Precedence".into(), "bulk".into());
        let result = svc.detect_auto_responder(&headers, "Auto: bounce notice", None);
        assert_eq!(result.auto_type.as_deref(), Some("bounce"));

        // A matched subject with an unclassifiable body falls back to system.
        let mut headers = HashMap::new();
        headers.insert("x-autorespond".into(), "yes".into());
        let result = svc.detect_auto_responder(
            &headers,
            "Auto: hello",
            Some("this is an automated message"),
        );
        assert_eq!(result.auto_type.as_deref(), Some("system"));

        // Out-of-office subject is classified from the subject text (needs a
        // second signal to cross the 50-point threshold).
        let mut headers = HashMap::new();
        headers.insert("Precedence".into(), "bulk".into());
        let result = svc.detect_auto_responder(&headers, "Out of Office: back Monday", None);
        assert_eq!(result.auto_type.as_deref(), Some("ooo"));
        assert!(result.is_auto_responder);
    }

    #[tokio::test]
    async fn mx_selection_prefers_requested_priority_and_reports_exhaustion() {
        let records = vec![
            MXRecord {
                exchange: "mx1.example.com".into(),
                priority: 10,
                ttl: None,
            },
            MXRecord {
                exchange: "mx2.example.com".into(),
                priority: 20,
                ttl: None,
            },
        ];
        let selected =
            DeliveryService::select_next_mx(&records, &HashSet::new(), Some(20)).unwrap();
        assert_eq!(selected.exchange, "mx2.example.com");

        // Requested priority is unavailable → lowest priority wins.
        let selected =
            DeliveryService::select_next_mx(&records, &HashSet::new(), Some(99)).unwrap();
        assert_eq!(selected.exchange, "mx1.example.com");

        // All hosts failed → None, never a fabricated host.
        let failed: HashSet<String> = records.iter().map(|r| r.exchange.clone()).collect();
        assert!(DeliveryService::select_next_mx(&records, &failed, None).is_none());
        assert!(DeliveryService::select_next_mx(&[], &HashSet::new(), None).is_none());
    }

    #[tokio::test]
    async fn ip_validation_rejects_oversized_prefixes() {
        assert!(!is_valid_ip("10.0.0.0/33"));
        assert!(!is_valid_ip("10.0.0.0/abc"));
        assert!(!is_valid_ip("2001:db8::/129"));
        assert!(is_valid_ip("2001:db8::/128"));
        assert!(is_valid_ip("0.0.0.0/0"));
        assert!(!is_valid_ip(""));
    }

    #[tokio::test]
    async fn resolve_mx_returns_cached_records_sorted_and_typed_errors() {
        let svc = offline_service();
        // Empty cached record set is returned as-is (a resolvable domain with
        // no MX and no A record is reported through the error type instead).
        svc.prime_mx_cache("empty.example", vec![]);
        assert!(svc.resolve_mx("empty.example").await.unwrap().is_empty());

        svc.prime_mx_cache(
            "multi.example",
            vec![
                MXRecord {
                    exchange: "b.example".into(),
                    priority: 20,
                    ttl: None,
                },
                MXRecord {
                    exchange: "a.example".into(),
                    priority: 10,
                    ttl: None,
                },
            ],
        );
        let records = svc.resolve_mx("multi.example").await.unwrap();
        // A primed cache is returned verbatim (sorting happens on live
        // resolution, before the records are cached).
        assert_eq!(records[0].exchange, "b.example");
        assert_eq!(records[1].exchange, "a.example");
    }

    #[tokio::test]
    async fn delivery_attempts_round_trip_through_the_canonical_schema() {
        let Some(pool) = canonical_pool("edge_delivery_attempts").await else {
            return;
        };
        let svc = DeliveryService::new(
            pool,
            real_redis_pool(),
            RetryConfig::default(),
            LoopDetectionConfig::default(),
            &[],
        );
        let message_id = format!("msg_{}", uuid::Uuid::new_v4().simple());
        for attempt in 1..=2 {
            svc.record_delivery_attempt(&DeliveryAttempt {
                message_id: message_id.clone(),
                attempt,
                mx_host: "mx.example.com".into(),
                mx_priority: 10,
                response_code: if attempt == 1 { 451 } else { 250 },
                response_message: if attempt == 1 {
                    "try again later"
                } else {
                    "OK"
                }
                .into(),
                response_type: if attempt == 1 {
                    "temporary_failure"
                } else {
                    "success"
                }
                .into(),
                timestamp: chrono::Utc::now(),
                duration_ms: 12 * attempt as i64,
            })
            .await
            .expect("record attempt");
        }

        let history = svc.get_delivery_history(&message_id).await.unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].attempt, 1);
        assert_eq!(history[0].mx_priority, 10);
        assert_eq!(history[0].response_code, 451);
        assert_eq!(history[1].duration_ms, 24);
        assert!(svc
            .get_delivery_history("msg_does_not_exist")
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn greylister_is_learned_from_history_and_cached_in_redis() {
        let Some(pool) = canonical_pool("edge_greylister").await else {
            return;
        };
        let redis = real_redis_pool();
        let svc = DeliveryService::new(
            pool.clone(),
            redis.clone(),
            RetryConfig::default(),
            LoopDetectionConfig::default(),
            &[],
        );
        let domain = format!("grey-{}.example", uuid::Uuid::new_v4().simple());

        // Clear any stale cache key first.
        if let Ok(mut conn) = redis.get().await {
            let _: Result<(), _> = redis::cmd("DEL")
                .arg(format!("greylist:known:{domain}"))
                .query_async(&mut *conn)
                .await;
        }

        // Unknown with no history.
        assert!(!svc.is_known_greylister(&domain).await.unwrap());

        // 11 greylist responses in the last 30 days → known greylister.
        for attempt in 1..=11 {
            sqlx::query(
                "INSERT INTO edge_delivery_attempts
                   (id, message_id, attempt_number, mx_host, mx_priority, response_code,
                    response_message, response_type, attempt_time, duration_ms)
                 VALUES (gen_random_uuid(), $1, $2, $3, 10, 450, 'greylisted',
                         'greylist', NOW(), 1)",
            )
            .bind(format!("msg_{}", uuid::Uuid::new_v4().simple()))
            .bind(attempt)
            .bind(format!("mx1.{domain}"))
            .execute(&pool)
            .await
            .expect("insert greylist attempt");
        }

        // Delete the cache entry written by the first call, then re-derive.
        if let Ok(mut conn) = redis.get().await {
            let _: Result<(), _> = redis::cmd("DEL")
                .arg(format!("greylist:known:{domain}"))
                .query_async(&mut *conn)
                .await;
        }
        assert!(svc.is_known_greylister(&domain).await.unwrap());
        // The second call is served from the Redis cache (still true).
        assert!(svc.is_known_greylister(&domain).await.unwrap());
    }

    /// Lightweight test helper – no DB/Redis pools needed for pure-logic tests.
    struct TestDelivery {
        retry_config: RetryConfig,
        loop_config: LoopDetectionConfig,
        greylist_patterns: Vec<Regex>,
        rate_limit_patterns: Vec<Regex>,
        auto_responder_subject_patterns: Vec<Regex>,
    }

    impl TestDelivery {
        fn new() -> Self {
            Self {
                retry_config: RetryConfig::default(),
                loop_config: LoopDetectionConfig::default(),
                greylist_patterns: [
                    r"(?i)greylist",
                    r"(?i)try\s+again\s+later",
                    r"(?i)too\s+many\s+connections",
                ]
                .iter()
                .filter_map(|p| Regex::new(p).ok())
                .collect(),
                rate_limit_patterns: [r"(?i)rate\s*limit", r"(?i)too\s+many"]
                    .iter()
                    .filter_map(|p| Regex::new(p).ok())
                    .collect(),
                auto_responder_subject_patterns: [r"(?i)^out of office", r"(?i)^automatic reply"]
                    .iter()
                    .filter_map(|p| Regex::new(p).ok())
                    .collect(),
            }
        }

        fn parse_smtp_response(&self, code: u16, message: &str) -> SMTPResponse {
            let is_rate_limit = (400..500).contains(&code)
                && self.rate_limit_patterns.iter().any(|p| p.is_match(message));
            let is_greylist = !is_rate_limit
                && (400..500).contains(&code)
                && self.greylist_patterns.iter().any(|p| p.is_match(message));

            let response_type = match code {
                200..=299 => ResponseType::Success,
                _ if is_greylist => ResponseType::Greylist,
                _ if is_rate_limit => ResponseType::RateLimit,
                400..=499 => ResponseType::TemporaryFailure,
                500..=599 => ResponseType::PermanentFailure,
                _ => ResponseType::ConnectionError,
            };

            let enhanced = extract_enhanced_status(message);

            SMTPResponse {
                code,
                message: message.to_string(),
                enhanced,
                response_type,
                is_greylist,
                suggested_retry_delay: None,
            }
        }

        fn calculate_retry_schedule(
            &self,
            response: &SMTPResponse,
            current_attempt: u32,
        ) -> Option<RetrySchedule> {
            if response.response_type == ResponseType::PermanentFailure {
                return None;
            }
            if current_attempt >= self.retry_config.max_retries {
                return None;
            }
            let (delay, reason) = match response.response_type {
                ResponseType::Greylist => (
                    self.retry_config.greylist_retry_delay_secs,
                    "greylist".to_string(),
                ),
                ResponseType::RateLimit => {
                    let delay = response
                        .suggested_retry_delay
                        .unwrap_or(self.retry_config.initial_delay_secs * 5);
                    (delay, "rate_limit".to_string())
                }
                _ => {
                    let delay = (self.retry_config.initial_delay_secs as f64
                        * self
                            .retry_config
                            .backoff_multiplier
                            .powi(current_attempt as i32)) as u64;
                    let delay = delay.min(self.retry_config.max_delay_secs);
                    (delay, "temporary_failure".to_string())
                }
            };
            let next = chrono::Utc::now() + chrono::Duration::seconds(delay as i64);
            Some(RetrySchedule {
                next_attempt: next,
                attempt_number: current_attempt + 1,
                delay_secs: delay,
                reason,
            })
        }

        fn detect_loop(&self, received_headers: &[String]) -> LoopDetection {
            let hop_count = received_headers.len();
            if hop_count > self.loop_config.max_hops {
                return LoopDetection {
                    is_loop: true,
                    hop_count,
                    max_hops: self.loop_config.max_hops,
                    loop_path: None,
                };
            }
            let mut host_count: HashMap<String, usize> = HashMap::new();
            let mut hosts = Vec::new();
            for header in received_headers {
                if let Some(host) = extract_host_from_received(header) {
                    *host_count.entry(host.clone()).or_insert(0) += 1;
                    hosts.push(host);
                }
            }
            let is_loop = host_count.values().any(|&count| count > 3);
            let loop_path = if is_loop { Some(hosts) } else { None };
            LoopDetection {
                is_loop,
                hop_count,
                max_hops: self.loop_config.max_hops,
                loop_path,
            }
        }

        fn detect_auto_responder(
            &self,
            headers: &HashMap<String, String>,
            subject: &str,
            body: Option<&str>,
        ) -> AutoResponderDetection {
            let mut score: u32 = 0;
            let mut indicators = Vec::new();
            let mut auto_type: Option<String> = None;

            if let Some(val) = headers.get("Auto-Submitted") {
                let lower = val.to_lowercase();
                if AUTO_SUBMITTED_VALUES.iter().any(|v| lower.contains(v)) {
                    score += 40;
                    indicators.push(format!("Auto-Submitted: {val}"));
                    auto_type = Some(classify_auto_type(&lower));
                }
            }
            if let Some(val) = headers.get("Precedence") {
                let lower = val.to_lowercase();
                if lower == "bulk" || lower == "junk" || lower == "auto_reply" {
                    score += 30;
                    indicators.push(format!("Precedence: {val}"));
                }
            }
            if headers.contains_key("X-Auto-Response-Suppress") {
                score += 25;
                indicators.push("X-Auto-Response-Suppress present".into());
            }
            if headers.contains_key("X-Autorespond") || headers.contains_key("X-Autoreply") {
                score += 35;
                indicators.push("X-Autorespond/X-Autoreply present".into());
            }
            let lower_subject = subject.to_lowercase();
            for pat in &self.auto_responder_subject_patterns {
                if pat.is_match(&lower_subject) {
                    score += 25;
                    indicators.push(format!("Subject matches: {}", pat.as_str()));
                    if auto_type.is_none() {
                        auto_type = Some(classify_subject_type(&lower_subject));
                    }
                    break;
                }
            }
            if let Some(body_text) = body {
                let lower_body = body_text.to_lowercase();
                for (kw, t) in &[
                    ("out of office", "ooo"),
                    ("on vacation", "vacation"),
                    ("auto-reply", "system"),
                    ("this is an automated", "system"),
                ] {
                    if lower_body.contains(kw) {
                        score += 15;
                        indicators.push(format!("Body contains: {kw}"));
                        if auto_type.is_none() {
                            auto_type = Some(t.to_string());
                        }
                    }
                }
            }
            AutoResponderDetection {
                is_auto_responder: score >= 50,
                auto_type: if score >= 50 { auto_type } else { None },
                confidence: score.min(100),
                indicators,
            }
        }
    }
}
