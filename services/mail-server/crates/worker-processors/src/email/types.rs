//! Email processor types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::FromRow;
use zeroize::Zeroizing;

/// An email job from the queue.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct EmailJob {
    pub id: String,
    #[sqlx(rename = "messageId")]
    pub message_id: String,
    #[sqlx(rename = "tenantId")]
    pub tenant_id: String,
    #[sqlx(rename = "domainId")]
    pub domain_id: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub html: Option<String>,
    pub text: Option<String>,
    pub headers: Option<JsonValue>,
    pub attachments: Option<JsonValue>,
    #[sqlx(rename = "campaignId")]
    pub campaign_id: Option<String>,
    pub tags: Option<Vec<String>>,
    pub metadata: Option<JsonValue>,
    #[sqlx(rename = "scheduledAt")]
    pub scheduled_at: Option<DateTime<Utc>>,
    pub attempt: i32,
    #[sqlx(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}

/// Domain configuration for sending.
#[derive(Debug, Clone, FromRow)]
pub struct Domain {
    pub id: String,
    pub tenant_id: String,
    pub domain: String,
    pub dkim_selector: Option<String>,
    /// Canonical DNS `p=` value used to validate the decrypted private key.
    pub dkim_public_key: Option<String>,
    /// Encrypted-at-rest private-key envelope; it is decrypted only while an
    /// SMTP message is being prepared.
    pub dkim_private_key: Option<String>,
    pub warmup_enabled: bool,
    pub warmup_day: i32,
    pub return_path: Option<String>,
}

/// Suppression entry.
#[derive(Debug, Clone)]
pub struct Suppression {
    pub email: String,
    pub reason: String,
    pub created_at: DateTime<Utc>,
}

/// Prepared email ready for sending.
#[derive(Debug, Clone)]
pub struct PreparedEmail {
    pub from: String,
    pub to: String,
    pub subject: String,
    pub html: Option<String>,
    pub text: Option<String>,
    pub headers: Vec<(String, String)>,
    pub attachments: Vec<Attachment>,
    pub dkim: Option<DkimConfig>,
}

/// Email attachment.
#[derive(Debug, Clone)]
pub struct Attachment {
    pub filename: String,
    pub content: Vec<u8>,
    pub content_type: String,
}

/// DKIM signing configuration.
#[derive(Debug, Clone)]
pub struct DkimConfig {
    pub selector: String,
    pub domain: String,
    pub private_key: Zeroizing<String>,
}

/// Email send result.
#[derive(Debug, Clone)]
pub struct SendResult {
    pub smtp_message_id: Option<String>,
    pub accepted: bool,
    pub response: String,
}

/// Send outcome for error rate tracking.
#[derive(Debug, Clone, Copy)]
pub enum SendOutcome {
    Success,
    SoftBounce,
    HardBounce,
    RateLimit,
    Suppressed,
    /// A locally rejected job, such as a missing or mismatched authorized
    /// domain. These are not transport failures and must not open the SMTP
    /// circuit breaker.
    Rejected,
    TransportError,
}

/// Warmup schedule entry.
#[derive(Debug, Clone)]
pub struct WarmupLimits {
    /// Daily send limit for this warmup day.
    pub daily_limit: i64,
    /// Hourly send limit (daily_limit / 24, roughly).
    pub hourly_limit: i64,
}

impl WarmupLimits {
    /// Get warmup limits for a given warmup day.
    /// Standard warmup schedule:exponential growth over ~30 days.
    pub fn for_day(day: i32) -> Self {
        let daily_limit = match day {
            0 => 50,
            1 => 100,
            2 => 200,
            3 => 400,
            4 => 800,
            5 => 1500,
            6 => 2500,
            7 => 4000,
            8 => 6000,
            9 => 8000,
            10 => 10000,
            11 => 15000,
            12 => 20000,
            13 => 30000,
            14 => 40000,
            15 => 50000,
            16 => 65000,
            17 => 80000,
            18 => 100000,
            19 => 125000,
            20 => 150000,
            21 => 200000,
            22 => 250000,
            23 => 300000,
            24 => 400000,
            25 => 500000,
            26 => 650000,
            27 => 800000,
            28 => 1000000,
            _ => i64::MAX, // Fully warmed up
        };

        let hourly_limit = (daily_limit / 18).max(10); // 18 sending hours per day

        Self {
            daily_limit,
            hourly_limit,
        }
    }
}

/// Cached suppression check result.
#[derive(Debug, Clone)]
pub struct CachedSuppression {
    pub suppressed: bool,
    pub reason: Option<String>,
    pub expires_at: std::time::Instant,
}

/// IP rate limit check result.
#[derive(Debug, Clone)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub reason: Option<String>,
    pub current_count: i64,
    pub limit: i64,
    pub retry_after_ms: Option<u64>,
    pub isp: Option<String>,
}
