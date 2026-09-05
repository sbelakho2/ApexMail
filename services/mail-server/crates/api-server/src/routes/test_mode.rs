//! Test Mode — deterministic outcomes for isolated email testing.
//!
//! Test mode intercepts messages addressed to `@test.apexmail.ee` addresses,
//! produces realistic message records, webhook events, and SMTP-style codes
//! without delivering to external mailboxes or affecting reputation.
//!
//! Messages sent with `am_test_` API keys are automatically routed through
//! test mode regardless of the recipient domain.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_test_addresses))
        .route("/send", post(test_send))
        .route("/addresses", get(list_test_addresses))
}

// ─── Test Address Definitions ─────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestAddress {
    pub address: String,
    pub outcome: String,
    pub smtp_code: String,
    pub smtp_enhanced_code: String,
    pub description: String,
    pub event_sequence: Vec<String>,
    pub webhook_events: Vec<String>,
    pub suppressed: bool,
}

fn test_addresses() -> Vec<TestAddress> {
    vec![
        TestAddress {
            address: "delivered@test.apexmail.ee".into(),
            outcome: "delivered".into(),
            smtp_code: "250".into(),
            smtp_enhanced_code: "2.0.0".into(),
            description: "Simulates successful delivery to the recipient mailbox.".into(),
            event_sequence: vec!["queued".into(), "delivered".into()],
            webhook_events: vec!["delivered".into()],
            suppressed: false,
        },
        TestAddress {
            address: "soft-bounce@test.apexmail.ee".into(),
            outcome: "soft_bounce".into(),
            smtp_code: "452".into(),
            smtp_enhanced_code: "4.2.2".into(),
            description: "Simulates a temporary delivery failure (mailbox full). Automatically retried.".into(),
            event_sequence: vec!["queued".into(), "deferred".into(), "deferred".into(), "soft_bounce".into()],
            webhook_events: vec!["deferred".into(), "bounced".into()],
            suppressed: false,
        },
        TestAddress {
            address: "hard-bounce@test.apexmail.ee".into(),
            outcome: "hard_bounce".into(),
            smtp_code: "550".into(),
            smtp_enhanced_code: "5.1.1".into(),
            description: "Simulates a permanent delivery failure (invalid mailbox). Adds recipient to suppression list.".into(),
            event_sequence: vec!["queued".into(), "bounced".into()],
            webhook_events: vec!["bounced".into()],
            suppressed: true,
        },
        TestAddress {
            address: "complaint@test.apexmail.ee".into(),
            outcome: "complaint".into(),
            smtp_code: "250".into(),
            smtp_enhanced_code: "2.0.0".into(),
            description: "Simulates delivery followed by a spam complaint from the recipient. Adds to suppression list.".into(),
            event_sequence: vec!["queued".into(), "delivered".into(), "complained".into()],
            webhook_events: vec!["delivered".into(), "complained".into()],
            suppressed: true,
        },
        TestAddress {
            address: "suppressed@test.apexmail.ee".into(),
            outcome: "suppressed".into(),
            smtp_code: "250".into(),
            smtp_enhanced_code: "2.0.0".into(),
            description: "Simulates a recipient already on the suppression list — message is accepted but not delivered.".into(),
            event_sequence: vec!["queued".into(), "suppressed".into()],
            webhook_events: vec!["suppressed".into()],
            suppressed: true,
        },
        TestAddress {
            address: "deferred@test.apexmail.ee".into(),
            outcome: "deferred".into(),
            smtp_code: "451".into(),
            smtp_enhanced_code: "4.7.1".into(),
            description: "Simulates greylisting / temporary deferral. Message is queued for retry.".into(),
            event_sequence: vec!["queued".into(), "deferred".into()],
            webhook_events: vec!["deferred".into()],
            suppressed: false,
        },
    ]
}

fn lookup_test_address(recipient: &str) -> Option<TestAddress> {
    let addr = recipient.trim().to_lowercase();
    test_addresses()
        .into_iter()
        .find(|ta| ta.address.to_lowercase() == addr)
}

pub fn is_test_address(recipient: &str) -> bool {
    let addr = recipient.trim().to_lowercase();
    addr.ends_with("@test.apexmail.ee")
}

pub fn lookup_outcome(recipient: &str) -> Option<(String, String, String, Vec<String>, Vec<String>)> {
    lookup_test_address(recipient).map(|ta| {
        (
            ta.outcome,
            ta.smtp_code,
            ta.smtp_enhanced_code,
            ta.event_sequence,
            ta.webhook_events,
        )
    })
}

// ─── Handlers ─────────────────────────────────────────────────

async fn list_test_addresses(
    State(_state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<TestAddress>>, ApiError> {
    // The router is unmounted today, but guard it anyway so a future
    // mounting cannot expose an unauthenticated enumeration endpoint.
    require_scopes(&auth, &["messages:read"])?;
    Ok(Json(test_addresses()))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestSendRequest {
    pub to: String,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TestSendResponse {
    pub accepted: bool,
    pub message_id: String,
    pub recipient: String,
    pub outcome: String,
    pub smtp_code: String,
    pub smtp_enhanced_code: String,
    pub events: Vec<serde_json::Value>,
    pub webhook_events: Vec<String>,
    pub suppressed: bool,
    pub test_mode: bool,
}

async fn test_send(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<TestSendRequest>,
) -> Result<(StatusCode, Json<TestSendResponse>), ApiError> {
    // The router is unmounted today, but guard it anyway: without a scope
    // check this would be an unauthenticated write primitive (messages +
    // events rows in any tenant) the moment someone mounts it.
    require_scopes(&auth, &["messages:send"])?;

    let ta = lookup_test_address(&body.to)
        .ok_or_else(|| ApiError::Validation(vec![
            format!("'{}' is not a valid test address. Use GET /v1/test/addresses to list available test addresses.", body.to)
        ]))?;

    let message_id = uuid::Uuid::new_v4().to_string();
    let now: DateTime<Utc> = Utc::now();

    let events: Vec<serde_json::Value> = ta.event_sequence.iter().enumerate().map(|(i, evt)| {
        let evt_time = now + chrono::Duration::seconds(i as i64 * 2);
        serde_json::json!({
            "event": evt,
            "timestamp": evt_time.to_rfc3339(),
            "message_id": message_id,
            "recipient": ta.address,
            "smtp_code": ta.smtp_code,
            "smtp_enhanced_code": ta.smtp_enhanced_code,
            "test_mode": true,
        })
    }).collect();

    // Persist message record
    let _ = sqlx::query(
        "INSERT INTO messages (id, tenant_id, from_email, to_emails, subject, status, created_at)
         VALUES ($1::uuid, $2, $3, $4::jsonb, $5, 'test', $6)"
    )
    .bind(&message_id)
    .bind(&auth.tenant_id)
    .bind(body.from.as_deref().unwrap_or("sender@test.apexmail.ee"))
    .bind(serde_json::json!([ta.address]))
    .bind(body.subject.as_deref().unwrap_or("ApexMail test message"))
    .bind(now)
    .execute(&state.db)
    .await;

    // Persist events
    for (i, evt) in ta.event_sequence.iter().enumerate() {
        let evt_time = now + chrono::Duration::seconds(i as i64 * 2);
        let _ = sqlx::query(
            "INSERT INTO events (id, tenant_id, message_id, event_type, recipient, metadata, timestamp)
             VALUES ($1, $2, $3, $4, $5, $6, $7)"
        )
        .bind(apexmail_lib::id::generate_id("evt", 22))
        .bind(&auth.tenant_id)
        .bind(&message_id)
        .bind(evt)
        .bind(&ta.address)
        .bind(serde_json::json!({
            "smtp_code": ta.smtp_code,
            "smtp_enhanced_code": ta.smtp_enhanced_code,
            "test_mode": true,
        }))
        .bind(evt_time)
        .execute(&state.db)
        .await;
    }

    Ok((
        StatusCode::OK,
        Json(TestSendResponse {
            accepted: true,
            message_id,
            recipient: ta.address.clone(),
            outcome: ta.outcome.clone(),
            smtp_code: ta.smtp_code.clone(),
            smtp_enhanced_code: ta.smtp_enhanced_code.clone(),
            events,
            webhook_events: ta.webhook_events.clone(),
            suppressed: ta.suppressed,
            test_mode: true,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addresses_has_all_required() {
        let addrs = test_addresses();
        assert_eq!(addrs.len(), 6);
        let required: Vec<&str> = vec![
            "delivered", "soft-bounce", "hard-bounce",
            "complaint", "suppressed", "deferred",
        ];
        for r in &required {
            assert!(
                addrs.iter().any(|a| a.address.starts_with(&format!("{}@", r))),
                "missing test address: {}@test.apexmail.ee", r
            );
        }
    }

    #[test]
    fn is_test_address_detects() {
        assert!(is_test_address("delivered@test.apexmail.ee"));
        assert!(is_test_address("anything@test.apexmail.ee"));
        assert!(!is_test_address("user@gmail.com"));
        assert!(!is_test_address("test@apexmail.ee"));
    }

    #[test]
    fn lookup_finds_known_address() {
        let ta = lookup_test_address("delivered@test.apexmail.ee");
        assert!(ta.is_some());
        assert_eq!(ta.unwrap().outcome, "delivered");

        assert!(lookup_test_address("nonexistent@test.apexmail.ee").is_none());
    }

    #[test]
    fn each_test_address_has_event_sequence() {
        for ta in test_addresses() {
            assert!(!ta.event_sequence.is_empty(), "{} has no events", ta.address);
            assert!(!ta.smtp_code.is_empty(), "{} has no SMTP code", ta.address);
        }
    }
}
