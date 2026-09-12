//! AI-powered insights routes.

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use billing_entitlements::FeatureKey;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/send-time", get(send_time_optimization))
        .route("/subject-analysis", get(subject_analysis))
        .route("/churn-prediction", get(churn_prediction))
        .route("/bot-detection", get(bot_detection))
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendTimeQuery {
    #[serde(default)]
    pub recipient: Option<String>,
    #[serde(default)]
    pub timezone: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SendTimeResponse {
    pub recommended_hour_utc: u8,
    pub confidence: f64,
    pub timezone: String,
    pub local_time: String,
    pub reasoning: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectAnalysisQuery {
    pub subject: String,
}

#[derive(Debug, Serialize)]
pub struct SubjectAnalysisResponse {
    pub score: f64,
    pub predicted_open_rate: f64,
    pub suggestions: Vec<String>,
    pub spam_likelihood: f64,
    pub word_count: usize,
    pub has_personalization: bool,
    pub has_emoji: bool,
}

#[derive(Debug, Serialize)]
pub struct ChurnPredictionResponse {
    pub at_risk_contacts: i64,
    pub churn_probability: f64,
    pub top_risk_factors: Vec<String>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BotDetectionQuery {
    /// Event id — `events.id` is VARCHAR(64) (migration 075), so this is a
    /// free-form string, never parsed as a UUID.
    #[serde(default)]
    pub event_id: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BotDetectionResponse {
    pub is_bot: bool,
    pub confidence: f64,
    pub signals: Vec<String>,
}

// ─── Handlers ──────────────────────────────────────────────────

async fn send_time_optimization(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<SendTimeQuery>,
) -> Result<Json<SendTimeResponse>, ApiError> {
    require_scopes(&auth, &["ai:read"])?;

    // Entitlement gate: `send_time_optimization` (403 Forbidden without it).
    crate::entitlements::require_feature(&state, &auth.tenant_id, FeatureKey::SendTimeOptimization)
        .await?;

    let tz = params.timezone.clone().unwrap_or_else(|| "UTC".into());
    let recipient = params.recipient.as_deref();

    // Query historical engagement data - when did recipients open emails most
    let hour_data: Vec<(i32, i64)> = if let Some(email) = recipient {
        // For specific recipient, analyze their personal open patterns
        sqlx::query_as(
            "SELECT EXTRACT(HOUR FROM timestamp)::int as hour, COUNT(*) as opens
             FROM events
             WHERE tenant_id = $1 AND event_type IN ('opened', 'open') AND recipient = $2
             GROUP BY hour
             ORDER BY opens DESC",
        )
        .bind(&auth.tenant_id)
        .bind(email)
        .fetch_all(&state.db)
        .await?
    } else {
        // For tenant-wide, analyze all open patterns
        sqlx::query_as(
            "SELECT EXTRACT(HOUR FROM timestamp)::int as hour, COUNT(*) as opens
             FROM events
             WHERE tenant_id = $1 AND event_type IN ('opened', 'open') AND timestamp > NOW() - INTERVAL '90 days'
             GROUP BY hour
             ORDER BY opens DESC",
        )
        .bind(&auth.tenant_id)
        .fetch_all(&state.db)
        .await?
    };

    let cache_key = format!(
        "send_time:{}:{}:{}",
        auth.tenant_id,
        recipient.unwrap_or("all"),
        tz
    );

    match sqlx::query("DELETE FROM ai_send_time_cache WHERE expires_at <= NOW()")
        .execute(&state.db)
        .await
    {
        Ok(result) => {
            let deleted = result.rows_affected();
            if deleted > 0 {
                metrics::counter!("ai_send_time_cache_expired_deleted_total").increment(deleted);
            }
        }
        Err(error) => {
            tracing::warn!(error = %error, "Failed to purge expired send-time cache rows");
        }
    }

    let cached: Option<(i32, f64)> = sqlx::query_as(
        "SELECT recommended_hour, confidence FROM ai_send_time_cache
         WHERE cache_key = $1 AND expires_at > NOW()",
    )
    .bind(&cache_key)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    let (recommended_hour, confidence, reasoning) = if let Some((hour, conf)) = cached {
        (
            hour.clamp(0, 23) as u8,
            conf,
            "Based on cached engagement analysis.".into(),
        )
    } else if !hour_data.is_empty() {
        let best_hour = hour_data[0].0.clamp(0, 23) as u8;
        let total_opens: i64 = hour_data.iter().map(|(_, c)| c).sum();
        let best_opens = hour_data[0].1;
        let confidence = if total_opens > 100 {
            0.85 + (best_opens as f64 / total_opens as f64 * 0.1)
        } else if total_opens > 10 {
            0.65 + (best_opens as f64 / total_opens as f64 * 0.15)
        } else {
            0.5
        };
        let confidence = confidence.min(0.95);

        // Cache the result
        if let Err(e) = sqlx::query(
            "INSERT INTO ai_send_time_cache (cache_key, tenant_id, recipient_email, recommended_hour, confidence, expires_at)
             VALUES ($1, $2, $3, $4, $5, NOW() + INTERVAL '24 hours')
             ON CONFLICT (cache_key) DO UPDATE SET recommended_hour = $4, confidence = $5, expires_at = NOW() + INTERVAL '24 hours'"
        )
            .bind(&cache_key)
            .bind(&auth.tenant_id)
            .bind(recipient)
            .bind(best_hour as i32)
            .bind(confidence)
            .execute(&state.db)
            .await
        {
            tracing::warn!(error = %e, cache_key = %cache_key, "Failed to cache send-time prediction");
        }

        let reasoning = format!(
            "Based on {} opens analyzed. Peak engagement at {}:00 UTC with {} opens.",
            total_opens, best_hour, best_opens
        );
        (best_hour, confidence, reasoning)
    } else {
        // Fallback to industry defaults when no data
        (
            14,
            0.5,
            "No historical data available. Using industry best practice (mid-afternoon).".into(),
        )
    };

    Ok(Json(SendTimeResponse {
        recommended_hour_utc: recommended_hour,
        confidence,
        timezone: tz,
        local_time: format!("{}:00", recommended_hour),
        reasoning,
    }))
}

async fn subject_analysis(
    State(_state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<SubjectAnalysisQuery>,
) -> Result<Json<SubjectAnalysisResponse>, ApiError> {
    require_scopes(&auth, &["ai:read"])?;

    let subject = &params.subject;
    let word_count = subject.split_whitespace().count();
    let has_personalization = subject.contains("{{") || subject.contains("{%");
    let has_emoji = subject.chars().any(|c| {
        let cp = c as u32;
        // Common emoji ranges:emoticons, dingbats, symbols, flags, etc.
        matches!(cp,
            0x1F600..=0x1F64F | // Emoticons
            0x1F300..=0x1F5FF | // Misc Symbols and Pictographs
            0x1F680..=0x1F6FF | // Transport and Map
            0x1F700..=0x1F77F | // Alchemical Symbols
            0x1F780..=0x1F7FF | // Geometric Shapes Extended
            0x1F800..=0x1F8FF | // Supplemental Arrows-C
            0x1F900..=0x1F9FF | // Supplemental Symbols and Pictographs
            0x1FA00..=0x1FA6F | // Chess Symbols
            0x1FA70..=0x1FAFF | // Symbols and Pictographs Extended-A
            0x2600..=0x26FF   | // Misc symbols (weather, zodiac, etc.)
            0x2700..=0x27BF   | // Dingbats
            0x231A..=0x231B   | // Watch, Hourglass
            0x23E9..=0x23F3   | // Media control symbols
            0x23F8..=0x23FA   | // More media controls
            0x25AA..=0x25AB   | // Squares
            0x25B6 | 0x25C0   | // Play buttons
            0x25FB..=0x25FE // Squares
        )
    });
    let has_spam_words = ["free", "urgent", "act now", "limited time"]
        .iter()
        .any(|w| subject.to_lowercase().contains(w));

    let mut score: f64 = 0.7;
    if (3..=10).contains(&word_count) {
        score += 0.1;
    }
    if has_personalization {
        score += 0.05;
    }
    if has_spam_words {
        score -= 0.2;
    }
    score = score.clamp(0.0, 1.0);

    let mut suggestions = Vec::new();
    if word_count > 10 {
        suggestions.push("Consider shortening the subject line to under 10 words.".into());
    }
    if !has_personalization {
        suggestions
            .push("Adding personalization (e.g. recipient name) can improve open rates.".into());
    }

    Ok(Json(SubjectAnalysisResponse {
        score,
        predicted_open_rate: score * 0.35,
        suggestions,
        spam_likelihood: if has_spam_words { 0.6 } else { 0.1 },
        word_count,
        has_personalization,
        has_emoji,
    }))
}

async fn churn_prediction(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<ChurnPredictionResponse>, ApiError> {
    require_scopes(&auth, &["ai:read"])?;

    // Simple heuristic:contacts with no events in the last 90 days
    let at_risk = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(DISTINCT c.id) FROM contacts c
         LEFT JOIN events e ON e.recipient = c.email AND e.tenant_id = c.tenant_id
            AND e.timestamp > NOW() - INTERVAL '90 days'
         WHERE c.tenant_id = $1 AND c.status = 'active' AND e.id IS NULL",
    )
    .bind(&auth.tenant_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| ApiError::Internal(format!("churn prediction query failed: {e}")))?;

    let total = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM contacts WHERE tenant_id = $1 AND status = 'active'",
    )
    .bind(&auth.tenant_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| ApiError::Internal(format!("churn prediction total query failed: {e}")))?
    .max(1);

    Ok(Json(ChurnPredictionResponse {
        at_risk_contacts: at_risk,
        churn_probability: at_risk as f64 / total as f64,
        top_risk_factors: vec!["No opens in 90 days".into(), "Engagement declining".into()],
        recommendations: vec![
            "Send a re-engagement campaign".into(),
            "Offer an incentive to inactive subscribers".into(),
        ],
    }))
}

/// Validate an event id query parameter against the VARCHAR(64) column
/// (same rule as events.rs): non-empty, at most 64 bytes, no control
/// characters. An unvalidated value reaching the database surfaces as a
/// 500 instead of a 400.
fn is_valid_event_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && !id.bytes().any(|b| b.is_ascii_control())
}

/// Send-time evidence for bot detection (audit F12): `messages.id` is UUID
/// while `events.message_id` is VARCHAR(64) (migrations 056/075), so the
/// join crosses the type boundary explicitly with `m.id::text` — comparing
/// them directly is a `operator does not exist: uuid = character varying`
/// error that used to be swallowed by `.ok().flatten()`, silently disabling
/// this signal. Tenant predicates apply on BOTH sides, and `m.sent_at` is
/// nullable (outer Option = row found, inner = sent_at value).
const BOT_SEND_TIME_SQL: &str = r#"
    SELECT m.sent_at
    FROM messages m
    WHERE m.tenant_id = $2
      AND m.id::text = (
          SELECT e.message_id FROM events e
          WHERE e.id = $1 AND e.tenant_id = $2
      )"#;

async fn bot_detection(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<BotDetectionQuery>,
) -> Result<Json<BotDetectionResponse>, ApiError> {
    require_scopes(&auth, &["ai:read"])?;

    let mut signals = Vec::new();
    let mut confidence = 0.0_f64;
    let mut is_bot = false;

    // Check by IP address patterns
    if let Some(ip) = &params.ip_address {
        // Check if IP is from known data center ranges
        if ip.starts_with("10.") || ip.starts_with("192.168.") || ip.starts_with("172.16.") {
            signals.push("private IP range".into());
            confidence += 0.2;
        }

        // Query event patterns for this IP to detect bot-like behavior
        let ip_stats: Option<(i64, i64, Option<f64>)> = sqlx::query_as(
            "SELECT
                COUNT(*) as event_count,
                COUNT(DISTINCT recipient) as unique_recipients,
                EXTRACT(EPOCH FROM (MAX(timestamp) - MIN(timestamp))) as time_span_seconds
             FROM events
             WHERE tenant_id = $1 AND ip_address = $2 AND timestamp > NOW() - INTERVAL '1 hour'",
        )
        .bind(&auth.tenant_id)
        .bind(ip)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

        if let Some((event_count, unique_recipients, time_span)) = ip_stats {
            // High velocity from single IP
            if event_count > 100 && time_span.unwrap_or(3600.0) < 60.0 {
                signals.push(format!("{} events in <60 seconds", event_count));
                confidence += 0.4;
            }
            // Same IP hitting many recipients
            if unique_recipients > 50 && event_count > 100 {
                signals.push(format!(
                    "{} unique recipients from single IP",
                    unique_recipients
                ));
                confidence += 0.3;
            }
        }
    }

    // Check by event ID to get user-agent and timing patterns
    if let Some(event_id) = params.event_id.as_deref() {
        // events.id is VARCHAR(64) (migration 075): validate the shape the
        // same way events.rs does rather than parsing it as a UUID (which
        // made the comparison against the varchar column invalid).
        if !is_valid_event_id(event_id) {
            return Err(ApiError::BadRequest(
                "event id must be 1-64 characters without control characters".into(),
            ));
        }

        let event_data: Option<(
            Option<String>,
            Option<String>,
            chrono::DateTime<chrono::Utc>,
        )> = sqlx::query_as(
            "SELECT user_agent, ip_address, timestamp FROM events WHERE id = $1 AND tenant_id = $2",
        )
        .bind(event_id)
        .bind(&auth.tenant_id)
        .fetch_optional(&state.db)
        .await?;

        if let Some((user_agent, _ip, timestamp)) = event_data {
            // Check user agent against known bot patterns
            if let Some(ua) = user_agent {
                let ua_lower = ua.to_lowercase();
                let bot_patterns = [
                    ("googlebot", "search_engine"),
                    ("bingbot", "search_engine"),
                    ("facebookexternalhit", "social_crawler"),
                    ("twitterbot", "social_crawler"),
                    ("linkedinbot", "social_crawler"),
                    ("barracuda", "email_gateway"),
                    ("mimecast", "email_gateway"),
                    ("proofpoint", "email_gateway"),
                    ("curl/", "automation"),
                    ("wget/", "automation"),
                    ("python-requests", "automation"),
                    ("bot/", "generic"),
                    ("spider/", "generic"),
                    ("crawler", "generic"),
                ];

                for (pattern, category) in bot_patterns {
                    if ua_lower.contains(pattern) {
                        signals.push(format!("UA matches {} pattern ({})", pattern, category));
                        confidence += 0.5;
                        is_bot = true;
                        break;
                    }
                }

                // Check for suspicious UA characteristics
                if ua.is_empty() || ua.len() < 10 {
                    signals.push("missing or minimal user agent".into());
                    confidence += 0.3;
                }
            }

            // Check for impossibly fast opens after send (< 1 second usually indicates prefetching).
            let send_time: Option<Option<chrono::DateTime<chrono::Utc>>> =
                sqlx::query_scalar(BOT_SEND_TIME_SQL)
                    .bind(event_id)
                    .bind(&auth.tenant_id)
                    .fetch_optional(&state.db)
                    .await
                    .map_err(|error| {
                        // A failed query is an error, not "no evidence": flatten-
                        // to-None here would silently repeat the original bug.
                        tracing::error!(
                            error = %error,
                            tenant_id = %auth.tenant_id,
                            event_id = %event_id,
                            "bot-detection send-time lookup failed"
                        );
                        ApiError::Internal("bot-detection send-time lookup failed".into())
                    })?;

            // sent_at is nullable (message not sent yet): the inner None is
            // "no send-time evidence", distinct from a query failure above.
            if let Some(Some(sent)) = send_time {
                let delay = (timestamp - sent).num_milliseconds();
                if delay < 1000 {
                    signals.push(format!("opened {}ms after send (prefetch likely)", delay));
                    confidence += 0.4;
                    is_bot = true;
                }
            }
        }
    }

    confidence = confidence.min(0.99);
    is_bot = is_bot || confidence > 0.5;

    Ok(Json(BotDetectionResponse {
        is_bot,
        confidence,
        signals,
    }))
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subject_analysis_short() {
        let word_count = "Hello World".split_whitespace().count();
        assert_eq!(word_count, 2);
    }

    #[test]
    fn test_subject_spam_detection() {
        let subject = "FREE money act now";
        let has_spam = ["free", "urgent", "act now"]
            .iter()
            .any(|w| subject.to_lowercase().contains(w));
        assert!(has_spam);
    }

    #[test]
    fn test_send_time_response_serialisation() {
        let resp = SendTimeResponse {
            recommended_hour_utc: 14,
            confidence: 0.78,
            timezone: "UTC".into(),
            local_time: "14:00".into(),
            reasoning: "best time".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["recommended_hour_utc"], 14);
    }

    #[test]
    fn test_bot_detection_response() {
        let resp = BotDetectionResponse {
            is_bot: false,
            confidence: 0.1,
            signals: vec![],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["is_bot"], false);
    }

    #[test]
    fn test_event_id_validation() {
        assert!(is_valid_event_id("evt_0001"));
        assert!(!is_valid_event_id(""));
        assert!(!is_valid_event_id(&"e".repeat(65)));
        assert!(!is_valid_event_id("evt\u{0000}1"));
        assert!(is_valid_event_id(&"e".repeat(64)));
    }
}

// ─── F12 database tests ────────────────────────────────────────
//
// Exercise the send-time lookup's UUID/varchar boundary, tenant
// predicates, nullable sent_at, and failure propagation against a real
// PostgreSQL (audit_log.rs isolated-per-test database convention).
// Skipped unless TEST_DATABASE_URL is set.

#[cfg(test)]
mod bot_detection_db_tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;
    use std::time::Duration;

    async fn isolated_pool(db_suffix: &str) -> Option<sqlx::PgPool> {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())?;
        let (server_part, db_part) = database_url.rsplit_once('/')?;
        let db_only = db_part.split('?').next().unwrap_or(db_part);
        let isolated_db = format!("{db_only}_api_ai_insights_f12_{db_suffix}");
        let isolated_url = format!("{server_part}/{isolated_db}");
        let admin_url = format!("{server_part}/postgres");

        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(3))
            .connect(&admin_url)
            .await
            .ok()?;
        let _ = sqlx::query(&format!(
            r#"DROP DATABASE IF EXISTS "{isolated_db}" WITH (FORCE)"#
        ))
        .execute(&admin)
        .await;
        let created = sqlx::query(&format!(r#"CREATE DATABASE "{isolated_db}""#))
            .execute(&admin)
            .await;
        admin.close().await;
        created.ok()?;

        let pool = PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&isolated_url)
            .await
            .ok()?;
        Some(pool)
    }

    async fn lookup(
        pool: &sqlx::PgPool,
        event_id: &str,
        tenant_id: &str,
    ) -> Result<Option<Option<chrono::DateTime<chrono::Utc>>>, sqlx::Error> {
        sqlx::query_scalar::<_, Option<chrono::DateTime<chrono::Utc>>>(BOT_SEND_TIME_SQL)
            .bind(event_id)
            .bind(tenant_id)
            .fetch_optional(pool)
            .await
    }

    #[tokio::test]
    async fn send_time_lookup_crosses_the_uuid_varchar_boundary() {
        let Some(pool) = isolated_pool("boundary").await else {
            eprintln!("skipping send_time_lookup_crosses_the_uuid_varchar_boundary: TEST_DATABASE_URL not set");
            return;
        };
        // Minimal canonical shapes for this lookup (migrations 056/073/075):
        // messages.id is UUID with nullable sent_at; events.id and
        // events.message_id are VARCHAR(64). The full apexmail-db SCHEMA
        // cannot be applied to a fresh database (its campaigns/templates
        // FK is uuid-to-varchar), so the subset is spelled out here.
        sqlx::raw_sql(
            "CREATE TABLE messages (
                id         UUID PRIMARY KEY,
                tenant_id  VARCHAR(26) NOT NULL,
                from_email TEXT NOT NULL,
                to_emails  JSONB NOT NULL,
                subject    TEXT NOT NULL,
                sent_at    TIMESTAMPTZ
            );
            CREATE TABLE events (
                id         VARCHAR(64) PRIMARY KEY,
                tenant_id  VARCHAR(26) NOT NULL,
                message_id VARCHAR(64),
                event_type VARCHAR(50) NOT NULL,
                timestamp  TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );",
        )
        .execute(&pool)
        .await
        .expect("canonical messages/events shapes");

        let tenant = "test-f12-ten";
        let other_tenant = "test-f12-oten";

        // Postgres TIMESTAMPTZ keeps microsecond precision — truncate the
        // seed so the read-back comparison is exact.
        let seeded_at = chrono::Utc::now() - chrono::Duration::seconds(60);
        let submicro_nanos = i64::from(chrono::Timelike::nanosecond(&seeded_at) % 1_000);
        let sent_at = seeded_at - chrono::Duration::nanoseconds(submicro_nanos);
        let message_id = uuid::Uuid::new_v4();
        let unsent_message_id = uuid::Uuid::new_v4();
        let foreign_message_id = uuid::Uuid::new_v4();
        for (id, sent) in [
            (message_id, Some(sent_at)),
            (unsent_message_id, None), // sent_at NULL
        ] {
            sqlx::query(
                "INSERT INTO messages (id, tenant_id, from_email, to_emails, subject, sent_at) \
                 VALUES ($1, $2, 'from@x.ee', '[]'::jsonb, 's', $3)",
            )
            .bind(id)
            .bind(tenant)
            .bind(sent)
            .execute(&pool)
            .await
            .expect("message seed");
        }
        // A message that belongs to ANOTHER tenant but is referenced by an
        // event in ours.
        sqlx::query(
            "INSERT INTO messages (id, tenant_id, from_email, to_emails, subject, sent_at) \
             VALUES ($1, $2, 'from@x.ee', '[]'::jsonb, 's', $3)",
        )
        .bind(foreign_message_id)
        .bind(other_tenant)
        .bind(sent_at)
        .execute(&pool)
        .await
        .expect("foreign message seed");

        let seed_event = |id: &str, message_id: Option<String>, tenant: &str| {
            let pool = pool.clone();
            let id = id.to_string();
            let tenant = tenant.to_string();
            async move {
                sqlx::query(
                    "INSERT INTO events (id, tenant_id, message_id, event_type) \
                     VALUES ($1, $2, $3, 'opened')",
                )
                .bind(&id)
                .bind(&tenant)
                .bind(message_id)
                .execute(&pool)
                .await
                .expect("event seed");
            }
        };
        seed_event("evt_f12_open", Some(message_id.to_string()), tenant).await;
        seed_event(
            "evt_f12_unsent",
            Some(unsent_message_id.to_string()),
            tenant,
        )
        .await;
        seed_event(
            "evt_f12_foreign",
            Some(foreign_message_id.to_string()),
            tenant,
        )
        .await;
        seed_event("evt_f12_nomsg", None, tenant).await;
        seed_event("evt_f12_other", Some(message_id.to_string()), other_tenant).await;

        // Matching event -> the send time (the old uuid = varchar form
        // errored on every one of these lookups).
        let found = lookup(&pool, "evt_f12_open", tenant)
            .await
            .expect("matching lookup is a query result, not an error");
        assert_eq!(found.flatten(), Some(sent_at));

        // Nullable sent_at: evidence of the message, but no send time.
        let unsent = lookup(&pool, "evt_f12_unsent", tenant)
            .await
            .expect("unsent lookup is a query result, not an error");
        assert_eq!(unsent, Some(None));

        // Tenant predicates on both sides: a message owned by another
        // tenant is not our send-time evidence.
        let foreign = lookup(&pool, "evt_f12_foreign", tenant)
            .await
            .expect("foreign-message lookup is a query result, not an error");
        assert_eq!(foreign, None, "foreign-tenant message must not match");

        // Event with no message_id / event of another tenant: no evidence.
        assert_eq!(
            lookup(&pool, "evt_f12_nomsg", tenant)
                .await
                .expect("no-message lookup"),
            None
        );
        assert_eq!(
            lookup(&pool, "evt_f12_open", other_tenant)
                .await
                .expect("cross-tenant lookup"),
            None,
            "the event must only be visible to its own tenant"
        );

        pool.close().await;
    }

    /// A failed query must surface as Err — the old `.ok().flatten()`
    /// conflated database failure with "no evidence" and silently dropped
    /// the signal.
    #[tokio::test]
    async fn send_time_lookup_propagates_query_failure() {
        let Some(pool) = isolated_pool("failure").await else {
            eprintln!(
                "skipping send_time_lookup_propagates_query_failure: TEST_DATABASE_URL not set"
            );
            return;
        };
        // events exists, messages does not -> every lookup errors.
        sqlx::query(
            "CREATE TABLE events (
                id         VARCHAR(64) PRIMARY KEY,
                tenant_id  VARCHAR(26) NOT NULL,
                message_id VARCHAR(64),
                event_type VARCHAR(50) NOT NULL,
                timestamp  TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )",
        )
        .execute(&pool)
        .await
        .expect("events seed table");
        sqlx::query("INSERT INTO events (id, tenant_id, message_id, event_type) VALUES ('evt_x', 't', NULL, 'opened')")
            .execute(&pool)
            .await
            .expect("event seed");

        let result = lookup(&pool, "evt_x", "t").await;
        assert!(
            result.is_err(),
            "a failed query must propagate as an error, not flatten to None"
        );

        pool.close().await;
    }
}
