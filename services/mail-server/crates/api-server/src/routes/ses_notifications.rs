//! AWS SES bounce/complaint notification handler.
//!
//! SES sends event notifications via **Amazon SNS** as HTTP POST requests.
//! This module://! 1. Handles SNS subscription confirmation (auto-confirms).
//! 2. Processes SES bounce notifications → auto-suppresses hard bounces.
//! 3. Processes SES complaint notifications → auto-suppresses complainants.
//! 4. Processes SES delivery notifications → updates message status.
//!
//! ## Endpoint
//!
//! `POST /v1/ses/notifications` — public (no auth), validated via SNS message signature.
//!
//! ## Setup
//!
//! In AWS SES → Configuration Set → Event destinations → add SNS topic.
//! In SNS → Subscription → HTTPS → `https://api.apexmail.io/v1/ses/notifications`.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::Router;
use serde::Deserialize;
use tracing::{debug, error, info, warn};

use crate::error::ApiError;
use crate::state::AppState;

/// Router for SES notification handling (public — no auth middleware).
pub fn router() -> Router<AppState> {
    Router::new().route("/notifications", post(handle_sns_notification))
}

// ─── SNS envelope types ────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[allow(dead_code)]
struct SnsMessage {
/// "Notification", "SubscriptionConfirmation", "UnsubscribeConfirmation"
    #[serde(rename = "Type")]
    message_type: String,
/// For SubscriptionConfirmation — URL to GET to confirm.
    #[serde(alias = "SubscribeURL")]
    subscribe_url: Option<String>,
/// JSON-encoded SES event payload (for Notification type).
    message: Option<String>,
/// SNS message ID.
    message_id: Option<String>,
/// Topic ARN for validation.
    topic_arn: Option<String>,
}

// ─── SES event types ───────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SesEvent {
/// "Bounce", "Complaint", "Delivery", "Send", "Reject", "Open", "Click"
    event_type: String,
    mail: Option<SesMail>,
    bounce: Option<SesBounce>,
    complaint: Option<SesComplaint>,
    delivery: Option<SesDelivery>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct SesMail {
    message_id: Option<String>,
    source: Option<String>,
    destination: Option<Vec<String>>,
/// Custom headers we attached (e.g. X-ApexMail-MessageId, X-ApexMail-TenantId)
    headers: Option<Vec<SesHeader>>,
    common_headers: Option<SesCommonHeaders>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SesHeader {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct SesCommonHeaders {
    from: Option<Vec<String>>,
    to: Option<Vec<String>>,
    subject: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SesBounce {
    bounce_type: String,
    bounce_sub_type: Option<String>,
    bounced_recipients: Option<Vec<BouncedRecipient>>,
    timestamp: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct BouncedRecipient {
    email_address: Option<String>,
    status: Option<String>,
    action: Option<String>,
    diagnostic_code: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct SesComplaint {
    complaint_sub_type: Option<String>,
    complained_recipients: Option<Vec<ComplainedRecipient>>,
    complaint_feedback_type: Option<String>,
    timestamp: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ComplainedRecipient {
    email_address: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SesDelivery {
    timestamp: Option<String>,
    processing_time_millis: Option<u64>,
    recipients: Option<Vec<String>>,
    smtp_response: Option<String>,
}

// ─── Handler ───────────────────────────────────────────────────

async fn handle_sns_notification(
    State(state): State<AppState>,
    _headers: HeaderMap,
    body: String,
) -> Result<StatusCode, ApiError> {
// SNS sends Content-Type:text/plain with a JSON body.
    let sns_msg: SnsMessage = serde_json::from_str(&body).map_err(|e| {
        warn!(error = %e, "Failed to parse SNS message");
        ApiError::Validation(vec![format!("Invalid SNS message: {e}")])
    })?;

// ── Topic ARN validation ────────────────────────────────
// Only process messages from configured SNS topic ARNs.
    let allowed_arns_raw = std::env::var("SNS_ALLOWED_TOPIC_ARNS").unwrap_or_default();
    let allowed_arns: Vec<&str> = allowed_arns_raw
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    if !allowed_arns.is_empty() {
        let msg_arn = sns_msg.topic_arn.as_deref().unwrap_or("");
        if !allowed_arns.contains(&msg_arn) {
            warn!(topic_arn = %msg_arn, "Rejected SNS message from unknown topic ARN");
            return Err(ApiError::Validation(vec!["Unknown SNS topic ARN".into()]));
        }
    }

    match sns_msg.message_type.as_str() {
        "SubscriptionConfirmation" => {
            handle_subscription_confirmation(&state, &sns_msg).await
        }
        "Notification" => {
            handle_notification(&state, &sns_msg).await
        }
        "UnsubscribeConfirmation" => {
            info!(topic = ?sns_msg.topic_arn, "SNS unsubscribe confirmation received");
            Ok(StatusCode::OK)
        }
        other => {
            warn!(message_type = %other, "Unknown SNS message type");
            Ok(StatusCode::OK)
        }
    }
}

/// Auto-confirm SNS subscription by fetching the subscribe URL.
/// Validates the URL is from a legitimate AWS SNS domain to prevent SSRF.
async fn handle_subscription_confirmation(
    state: &AppState,
    msg: &SnsMessage,
) -> Result<StatusCode, ApiError> {
    let url = msg.subscribe_url.as_deref().ok_or_else(|| {
        ApiError::Validation(vec!["Missing SubscribeURL in confirmation".into()])
    })?;

// SSRF defence:only allow URLs from official AWS SNS endpoints.
// Legitimate SubscribeURLs look like:// https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&...
    let parsed = url::Url::parse(url).map_err(|_| {
        ApiError::Validation(vec!["Invalid SubscribeURL".into()])
    })?;
    let host = parsed.host_str().unwrap_or("");
    let is_aws_sns = parsed.scheme() == "https"
        && (host.ends_with(".amazonaws.com") || host.ends_with(".amazonaws.com.cn"));
    if !is_aws_sns {
        warn!(url = %url, host = %host, "Rejected non-AWS SubscribeURL — possible SSRF attempt");
        return Err(ApiError::Validation(vec![
            "SubscribeURL must be an AWS SNS endpoint".into(),
        ]));
    }

    info!(topic = ?msg.topic_arn, "Auto-confirming SNS subscription");

    state
        .http_client
        .get(url)
        .send()
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to confirm SNS subscription");
            ApiError::ServiceUnavailable(format!("SNS confirmation failed: {e}"))
        })?;

    info!(topic = ?msg.topic_arn, "SNS subscription confirmed");
    Ok(StatusCode::OK)
}

/// Process an SES event notification.
async fn handle_notification(
    state: &AppState,
    msg: &SnsMessage,
) -> Result<StatusCode, ApiError> {
    let event_json = msg.message.as_deref().ok_or_else(|| {
        ApiError::Validation(vec!["Missing Message in SNS notification".into()])
    })?;

    let event: SesEvent = serde_json::from_str(event_json).map_err(|e| {
        warn!(error = %e, "Failed to parse SES event");
        ApiError::Validation(vec![format!("Invalid SES event: {e}")])
    })?;

    match event.event_type.as_str() {
        "Bounce" => process_bounce(state, &event).await?,
        "Complaint" => process_complaint(state, &event).await?,
        "Delivery" => process_delivery(state, &event).await?,
        "Send" => {
            debug!(ses_message_id = ?event.mail.as_ref().and_then(|m| m.message_id.as_ref()), "SES Send event");
        }
        "Reject" => {
            warn!(ses_message_id = ?event.mail.as_ref().and_then(|m| m.message_id.as_ref()), "SES Reject event");
        }
        other => {
            debug!(event_type = %other, "SES event (unhandled)");
        }
    }

    Ok(StatusCode::OK)
}

/// Extract our internal message_id from SES mail headers.
fn extract_apexmail_header(mail: &SesMail, header_name: &str) -> Option<String> {
    mail.headers.as_ref()?.iter().find(|h| h.name == header_name).map(|h| h.value.clone())
}

// ─── Bounce processing ────────────────────────────────────────

async fn process_bounce(state: &AppState, event: &SesEvent) -> Result<(), ApiError> {
    let bounce = event.bounce.as_ref().ok_or_else(|| {
        ApiError::Validation(vec!["Bounce event missing bounce details".into()])
    })?;

    let mail = event.mail.as_ref();
    let ses_message_id = mail.and_then(|m| m.message_id.clone());
    let apexmail_message_id = mail.and_then(|m| extract_apexmail_header(m, "X-ApexMail-MessageId"));
    let tenant_id = mail.and_then(|m| extract_apexmail_header(m, "X-ApexMail-TenantId"));

    let is_permanent = bounce.bounce_type == "Permanent";
    let bounce_sub_type = bounce.bounce_sub_type.as_deref().unwrap_or("General");

    info!(
        bounce_type = %bounce.bounce_type,
        bounce_sub_type = %bounce_sub_type,
        ses_message_id = ?ses_message_id,
        apexmail_message_id = ?apexmail_message_id,
        tenant_id = ?tenant_id,
        "Processing SES bounce"
    );

    if let Some(recipients) = &bounce.bounced_recipients {
        for recipient in recipients {
            if let Some(email) = &recipient.email_address {
                let reason = if is_permanent {
                    format!("ses_hard_bounce:{bounce_sub_type}")
                } else {
                    format!("ses_soft_bounce:{bounce_sub_type}")
                };

// Auto-suppress hard bounces
                if is_permanent {
                    let _ = sqlx::query(
                        "INSERT INTO suppression_list (id, email, reason, source, created_at)
                         VALUES (gen_random_uuid(), $1, $2, 'ses_bounce', NOW())
                         ON CONFLICT (email) DO NOTHING",
                    )
                    .bind(email)
                    .bind(&reason)
                    .execute(&state.db)
                    .await
                    .map_err(|e| warn!(email = %apexmail_lib::pii::redact_email(email), error = %e, "Failed to suppress bounced address"));

                    info!(email = %apexmail_lib::pii::redact_email(email), reason = %reason, "Auto-suppressed hard-bounced address");
                }

// Update message status if we have the internal ID
                if let Some(ref msg_id) = apexmail_message_id {
                    let status = if is_permanent { "bounced" } else { "deferred" };
                    if let Err(e) = sqlx::query(
                        "UPDATE messages SET status = $1, bounce_type = $2, updated_at = NOW()
                         WHERE id = $3::uuid",
                    )
                    .bind(status)
                    .bind(&reason)
                    .bind(msg_id)
                    .execute(&state.db)
                    .await
                    {
                        warn!(message_id = %msg_id, error = %e, "Failed to update bounce status");
                    }
                }

// Queue webhook event for the tenant
                if let Some(ref tid) = tenant_id {
                    let payload = serde_json::json!({
                        "event": "email.bounced",
                        "type": bounce.bounce_type,
                        "subType": bounce_sub_type,
                        "recipient": email,
                        "messageId": apexmail_message_id,
                        "sesMessageId": ses_message_id,
                        "diagnosticCode": recipient.diagnostic_code,
                        "timestamp": bounce.timestamp,
                    });
                    queue_webhook_event(state, tid, "email.bounced", &payload).await;
                }
            }
        }
    }

    Ok(())
}

// ─── Complaint processing ──────────────────────────────────────

async fn process_complaint(state: &AppState, event: &SesEvent) -> Result<(), ApiError> {
    let complaint = event.complaint.as_ref().ok_or_else(|| {
        ApiError::Validation(vec!["Complaint event missing details".into()])
    })?;

    let mail = event.mail.as_ref();
    let ses_message_id = mail.and_then(|m| m.message_id.clone());
    let apexmail_message_id = mail.and_then(|m| extract_apexmail_header(m, "X-ApexMail-MessageId"));
    let tenant_id = mail.and_then(|m| extract_apexmail_header(m, "X-ApexMail-TenantId"));

    let feedback_type = complaint.complaint_feedback_type.as_deref().unwrap_or("abuse");

    info!(
        feedback_type = %feedback_type,
        ses_message_id = ?ses_message_id,
        tenant_id = ?tenant_id,
        "Processing SES complaint"
    );

    if let Some(recipients) = &complaint.complained_recipients {
        for recipient in recipients {
            if let Some(email) = &recipient.email_address {
                let reason = format!("ses_complaint:{feedback_type}");

// Always suppress — complaints are serious
                let _ = sqlx::query(
                    "INSERT INTO suppression_list (id, email, reason, source, created_at)
                     VALUES (gen_random_uuid(), $1, $2, 'ses_complaint', NOW())
                     ON CONFLICT (email) DO NOTHING",
                )
                .bind(email)
                .bind(&reason)
                .execute(&state.db)
                .await
                .map_err(|e| warn!(email = %apexmail_lib::pii::redact_email(email), error = %e, "Failed to suppress complained address"));

                info!(email = %apexmail_lib::pii::redact_email(email), reason = %reason, "Auto-suppressed complained address");

// Update message status
                if let Some(ref msg_id) = apexmail_message_id {
                    if let Err(e) = sqlx::query(
                        "UPDATE messages SET status = 'complained', updated_at = NOW()
                         WHERE id = $1::uuid",
                    )
                    .bind(msg_id)
                    .execute(&state.db)
                    .await
                    {
                        warn!(message_id = %msg_id, error = %e, "Failed to update complaint status");
                    }
                }

// Queue webhook
                if let Some(ref tid) = tenant_id {
                    let payload = serde_json::json!({
                        "event": "email.complained",
                        "feedbackType": feedback_type,
                        "recipient": email,
                        "messageId": apexmail_message_id,
                        "sesMessageId": ses_message_id,
                        "timestamp": complaint.timestamp,
                    });
                    queue_webhook_event(state, tid, "email.complained", &payload).await;
                }
            }
        }
    }

    Ok(())
}

// ─── Delivery processing ──────────────────────────────────────

async fn process_delivery(state: &AppState, event: &SesEvent) -> Result<(), ApiError> {
    let delivery = event.delivery.as_ref().ok_or_else(|| {
        ApiError::Validation(vec!["Delivery event missing details".into()])
    })?;

    let mail = event.mail.as_ref();
    let apexmail_message_id = mail.and_then(|m| extract_apexmail_header(m, "X-ApexMail-MessageId"));
    let tenant_id = mail.and_then(|m| extract_apexmail_header(m, "X-ApexMail-TenantId"));

    debug!(
        recipients = ?delivery.recipients,
        processing_time_ms = ?delivery.processing_time_millis,
        "SES delivery confirmed"
    );

// Update message status to 'delivered'
    if let Some(ref msg_id) = apexmail_message_id {
        if let Err(e) = sqlx::query(
            "UPDATE messages SET status = 'delivered', delivered_at = NOW(), updated_at = NOW()
             WHERE id = $1::uuid AND status != 'delivered'",
        )
        .bind(msg_id)
        .execute(&state.db)
        .await
        {
            warn!(message_id = %msg_id, error = %e, "Failed to update delivery status");
        }
    }

// Queue webhook
    if let Some(ref tid) = tenant_id {
        let payload = serde_json::json!({
            "event": "email.delivered",
            "recipients": delivery.recipients,
            "messageId": apexmail_message_id,
            "processingTimeMs": delivery.processing_time_millis,
            "smtpResponse": delivery.smtp_response,
            "timestamp": delivery.timestamp,
        });
        queue_webhook_event(state, tid, "email.delivered", &payload).await;
    }

    Ok(())
}

// ─── Webhook event queuing ─────────────────────────────────────

/// Queue a webhook event for delivery to the tenant's registered endpoints.
/// Uses Redis list as a lightweight queue (same pattern as MTA webhook_queue).
async fn queue_webhook_event(
    state: &AppState,
    tenant_id: &str,
    event_type: &str,
    payload: &serde_json::Value,
) {
    let event = serde_json::json!({
        "tenantId": tenant_id,
        "eventType": event_type,
        "payload": payload,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    match state.redis.get().await {
        Ok(mut conn) => {
            let event_str = event.to_string();
            let result: Result<(), _> = redis::cmd("LPUSH")
                .arg("ses:webhook_queue")
                .arg(&event_str)
                .query_async(&mut *conn)
                .await;
            if let Err(e) = result {
                warn!(error = %e, "Failed to queue SES webhook event");
            }
        }
        Err(e) => {
            warn!(error = %e, "Failed to get Redis connection for webhook queuing");
        }
    }
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sns_subscription_confirmation() {
        let json = r#"{
            "Type": "SubscriptionConfirmation",
            "MessageId": "test-id",
            "TopicArn": "arn:aws:sns:us-east-1:123:test",
            "SubscribeURL": "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&Token=abc"
        }"#;
        let msg: SnsMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.message_type, "SubscriptionConfirmation");
        assert!(msg.subscribe_url.is_some());
    }

    #[test]
    fn test_parse_ses_bounce_event() {
        let json = r#"{
            "eventType": "Bounce",
            "mail": {
                "messageId": "ses-msg-id-123",
                "source": "sender@example.com",
                "destination": ["recipient@example.com"],
                "headers": [
                    {"name": "X-ApexMail-MessageId", "value": "apex-msg-123"},
                    {"name": "X-ApexMail-TenantId", "value": "tenant-456"}
                ]
            },
            "bounce": {
                "bounceType": "Permanent",
                "bounceSubType": "General",
                "bouncedRecipients": [
                    {"emailAddress": "bad@example.com", "status": "5.1.1", "action": "failed", "diagnosticCode": "550 User unknown"}
                ],
                "timestamp": "2026-02-27T10:00:00Z"
            }
        }"#;
        let event: SesEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.event_type, "Bounce");
        let bounce = event.bounce.unwrap();
        assert_eq!(bounce.bounce_type, "Permanent");
        assert_eq!(bounce.bounced_recipients.unwrap().len(), 1);

        let mail = event.mail.unwrap();
        let msg_id = extract_apexmail_header(&mail, "X-ApexMail-MessageId");
        assert_eq!(msg_id, Some("apex-msg-123".to_string()));
    }

    #[test]
    fn test_parse_ses_complaint_event() {
        let json = r#"{
            "eventType": "Complaint",
            "mail": {
                "messageId": "ses-msg-id-456",
                "source": "sender@example.com",
                "destination": ["user@example.com"]
            },
            "complaint": {
                "complaintSubType": null,
                "complainedRecipients": [
                    {"emailAddress": "user@example.com"}
                ],
                "complaintFeedbackType": "abuse",
                "timestamp": "2026-02-27T11:00:00Z"
            }
        }"#;
        let event: SesEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.event_type, "Complaint");
        let complaint = event.complaint.unwrap();
        assert_eq!(complaint.complaint_feedback_type, Some("abuse".into()));
    }

    #[test]
    fn test_parse_ses_delivery_event() {
        let json = r#"{
            "eventType": "Delivery",
            "mail": {
                "messageId": "ses-msg-789",
                "source": "sender@example.com",
                "destination": ["user@example.com"],
                "headers": [
                    {"name": "X-ApexMail-MessageId", "value": "apex-789"}
                ]
            },
            "delivery": {
                "timestamp": "2026-02-27T12:00:00Z",
                "processingTimeMillis": 1200,
                "recipients": ["user@example.com"],
                "smtpResponse": "250 2.0.0 OK"
            }
        }"#;
        let event: SesEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.event_type, "Delivery");
        let delivery = event.delivery.unwrap();
        assert_eq!(delivery.processing_time_millis, Some(1200));
    }

    #[test]
    fn test_parse_sns_notification_with_ses_event() {
        let ses_event = r#"{"eventType":"Send","mail":{"messageId":"test"}}"#;
        let sns_json = format!(
            r#"{{"Type":"Notification","MessageId":"sns-123","Message":{}}}"#,
            serde_json::to_string(ses_event).unwrap()
        );
        let msg: SnsMessage = serde_json::from_str(&sns_json).unwrap();
        assert_eq!(msg.message_type, "Notification");
        assert!(msg.message.is_some());
// Parse the inner SES event
        let event: SesEvent = serde_json::from_str(msg.message.as_ref().unwrap()).unwrap();
        assert_eq!(event.event_type, "Send");
    }

    #[test]
    fn test_extract_apexmail_header_missing() {
        let mail = SesMail {
            message_id: Some("test".into()),
            source: None,
            destination: None,
            headers: Some(vec![]),
            common_headers: None,
        };
        assert_eq!(extract_apexmail_header(&mail, "X-ApexMail-MessageId"), None);
    }

    #[test]
    fn test_extract_apexmail_header_no_headers() {
        let mail = SesMail {
            message_id: None,
            source: None,
            destination: None,
            headers: None,
            common_headers: None,
        };
        assert_eq!(extract_apexmail_header(&mail, "X-ApexMail-MessageId"), None);
    }
}
