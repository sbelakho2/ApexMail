//! AI-powered insights routes.

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
pub struct BotDetectionQuery {
    #[serde(default)]
    pub event_id: Option<Uuid>,
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

    let tz = params.timezone.clone().unwrap_or_else(|| "UTC".into());
    let recipient = params.recipient.as_deref();

    // Query historical engagement data - when did recipients open emails most
    let hour_data: Vec<(i32, i64)> = if let Some(email) = recipient {
        // For specific recipient, analyze their personal open patterns
        sqlx::query_as(
            "SELECT EXTRACT(HOUR FROM timestamp)::int as hour, COUNT(*) as opens
             FROM events
             WHERE tenant_id = $1 AND event_type = 'open' AND recipient = $2
             GROUP BY hour
             ORDER BY opens DESC"
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
             WHERE tenant_id = $1 AND event_type = 'open' AND timestamp > NOW() - INTERVAL '90 days'
             GROUP BY hour
             ORDER BY opens DESC"
        )
            .bind(&auth.tenant_id)
            .fetch_all(&state.db)
            .await?
    };

    // Fix #54: Include timezone in cache key to avoid returning wrong cached results.
    let cache_key = format!("send_time:{}:{}:{}", auth.tenant_id, recipient.unwrap_or("all"), &tz);
    let cached: Option<(i32, f64)> = sqlx::query_as(
        "SELECT recommended_hour, confidence FROM ai_send_time_cache
         WHERE cache_key = $1 AND expires_at > NOW()"
    )
        .bind(&cache_key)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

    let (recommended_hour, confidence, reasoning) = if let Some((hour, conf)) = cached {
        (hour.clamp(0, 23) as u8, conf, "Based on cached engagement analysis.".into())
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
        (14, 0.5, "No historical data available. Using industry best practice (mid-afternoon).".into())
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
    // Fix #55: Proper emoji detection using Unicode emoji ranges.
    let has_emoji = subject.chars().any(|c| {
        let cp = c as u32;
        // Common emoji ranges: emoticons, dingbats, symbols, flags, etc.
        matches!(cp,
            0x1F600..=0x1F64F |  // Emoticons
            0x1F300..=0x1F5FF |  // Misc Symbols and Pictographs
            0x1F680..=0x1F6FF |  // Transport and Map
            0x1F700..=0x1F77F |  // Alchemical Symbols
            0x1F780..=0x1F7FF |  // Geometric Shapes Extended
            0x1F800..=0x1F8FF |  // Supplemental Arrows-C
            0x1F900..=0x1F9FF |  // Supplemental Symbols and Pictographs
            0x1FA00..=0x1FA6F |  // Chess Symbols
            0x1FA70..=0x1FAFF |  // Symbols and Pictographs Extended-A
            0x2600..=0x26FF   |  // Misc symbols (weather, zodiac, etc.)
            0x2700..=0x27BF   |  // Dingbats
            0x231A..=0x231B   |  // Watch, Hourglass
            0x23E9..=0x23F3   |  // Media control symbols
            0x23F8..=0x23FA   |  // More media controls
            0x25AA..=0x25AB   |  // Squares
            0x25B6 | 0x25C0   |  // Play buttons
            0x25FB..=0x25FE      // Squares
        )
    });
    let has_spam_words = ["free", "urgent", "act now", "limited time"]
        .iter()
        .any(|w| subject.to_lowercase().contains(w));

    let mut score: f64 = 0.7;
    if word_count >= 3 && word_count <= 10 {
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
        suggestions.push("Adding personalization (e.g. recipient name) can improve open rates.".into());
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

    // Simple heuristic: contacts with no events in the last 90 days
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
        top_risk_factors: vec![
            "No opens in 90 days".into(),
            "Engagement declining".into(),
        ],
        recommendations: vec![
            "Send a re-engagement campaign".into(),
            "Offer an incentive to inactive subscribers".into(),
        ],
    }))
}

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
             WHERE tenant_id = $1 AND ip_address = $2 AND timestamp > NOW() - INTERVAL '1 hour'"
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
                signals.push(format!("{} unique recipients from single IP", unique_recipients));
                confidence += 0.3;
            }
        }
    }

    // Check by event ID to get user-agent and timing patterns
    if let Some(event_id) = params.event_id {
        let event_data: Option<(Option<String>, Option<String>, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
            "SELECT user_agent, ip_address, timestamp FROM events WHERE id = $1 AND tenant_id = $2"
        )
            .bind(event_id)
            .bind(&auth.tenant_id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();

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

            // Check for impossibly fast opens after send (< 1 second usually indicates prefetching)
            let send_time: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
                "SELECT sent_at FROM messages WHERE id = (SELECT message_id FROM events WHERE id = $1)"
            )
                .bind(event_id)
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten();

            if let Some(sent) = send_time {
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
}
