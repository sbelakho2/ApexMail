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
//! In SNS → Subscription → HTTPS → `https://api.apexmail.ee/v1/ses/notifications`.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::Router;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use serde::Deserialize;
use sha1::Sha1;
use sha2::Sha256;
use tracing::{debug, error, info, warn};
use x509_parser::certificate::X509Certificate;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::FromDer;

use crate::error::ApiError;
use crate::state::AppState;

/// Router for SES notification handling (public — no auth middleware).
pub fn router() -> Router<AppState> {
    Router::new().route("/notifications", post(handle_sns_notification))
}

// ─── SNS envelope types ────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
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
    subject: Option<String>,
    timestamp: Option<String>,
    token: Option<String>,
    signature: Option<String>,
    signature_version: Option<String>,
    #[serde(alias = "SigningCertURL")]
    signing_cert_url: Option<String>,
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
#[expect(
    dead_code,
    reason = "SES mail envelope preserves AWS fields for signature/audit compatibility"
)]
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
#[expect(
    dead_code,
    reason = "SES common headers are retained for AWS event compatibility"
)]
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
#[expect(
    dead_code,
    reason = "recipient status/action fields are retained for AWS bounce compatibility"
)]
struct BouncedRecipient {
    email_address: Option<String>,
    status: Option<String>,
    action: Option<String>,
    diagnostic_code: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[expect(
    dead_code,
    reason = "complaint subtype is retained for AWS complaint compatibility"
)]
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

    let allowed_arns_raw = std::env::var("SNS_ALLOWED_TOPIC_ARNS").unwrap_or_default();
    validate_sns_message(&state.http_client, &sns_msg, &allowed_arns_raw).await?;

    // PP-006: Deduplicate SNS notifications using Redis SET NX with TTL.
    // `SET key value NX EX ttl` returns OK if the key was newly created
    // (first time seeing this message_id), and nil if the key already exists
    // (duplicate).  We map the response to `is_new` — only process if true.
    //
    // L-07: The dedup key is composite (message_id + notification_type) to
    // prevent dedup collisions between different notification types for the
    // same message (e.g., a delivery notification and a bounce notification
    // for the same SES message). Previously the key used only message_id,
    // which could cause a bounce to be incorrectly deduplicated if a delivery
    // notification with the same SNS message_id arrived first.
    let notification_type = sns_msg.message_type.as_str();
    if let Some(msg_id) = &sns_msg.message_id {
        let dedup_key = format!("apexmail:dedup:sns:{}:{}", msg_id, notification_type);
        let ttl_secs = 300; // 5 minutes — SNS retries within a few minutes at most.
        let is_new: bool = redis::cmd("SET")
            .arg(&dedup_key)
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(ttl_secs)
            .query_async(&mut state.redis.get().await.map_err(|e| {
                warn!(error = %e, "Failed to acquire redis for SNS dedup");
                ApiError::ServiceUnavailable("Redis unavailable".into())
            })?)
            .await
            .unwrap_or(false);
        if !is_new {
            info!(message_id = %msg_id, "Deduplicated duplicate SNS notification");
            return Ok(StatusCode::OK);
        }
    } else {
        warn!("SNS notification missing message_id — cannot deduplicate");
    }

    match sns_msg.message_type.as_str() {
        "SubscriptionConfirmation" => handle_subscription_confirmation(&state, &sns_msg).await,
        "Notification" => handle_notification(&state, &sns_msg).await,
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
    let url = msg
        .subscribe_url
        .as_deref()
        .ok_or_else(|| ApiError::Validation(vec!["Missing SubscribeURL in confirmation".into()]))?;

    // SSRF defence:only allow URLs from official AWS SNS endpoints.
    // Legitimate SubscribeURLs look like:// https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&...
    let parsed = url::Url::parse(url)
        .map_err(|_| ApiError::Validation(vec!["Invalid SubscribeURL".into()]))?;
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

    state.http_client.get(url).send().await.map_err(|e| {
        error!(error = %e, "Failed to confirm SNS subscription");
        ApiError::ServiceUnavailable(format!("SNS confirmation failed: {e}"))
    })?;

    info!(topic = ?msg.topic_arn, "SNS subscription confirmed");
    Ok(StatusCode::OK)
}

async fn validate_sns_message(
    http_client: &reqwest::Client,
    msg: &SnsMessage,
    allowed_arns_raw: &str,
) -> Result<(), ApiError> {
    validate_sns_topic_arn(msg, allowed_arns_raw)?;
    validate_sns_signature(http_client, msg).await
}

fn validate_sns_topic_arn(msg: &SnsMessage, allowed_arns_raw: &str) -> Result<(), ApiError> {
    let allowed_arns: Vec<&str> = allowed_arns_raw
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    if allowed_arns.is_empty() {
        warn!("SNS_ALLOWED_TOPIC_ARNS is not configured; rejecting SNS request");
        return Err(ApiError::ServiceUnavailable(
            "SNS notifications are not configured".into(),
        ));
    }

    let msg_arn = msg.topic_arn.as_deref().unwrap_or("");
    if !allowed_arns.contains(&msg_arn) {
        warn!(topic_arn = %msg_arn, "Rejected SNS message from unknown topic ARN");
        return Err(ApiError::Forbidden("Unknown SNS topic ARN".into()));
    }

    Ok(())
}

async fn validate_sns_signature(
    http_client: &reqwest::Client,
    msg: &SnsMessage,
) -> Result<(), ApiError> {
    let cert_url = msg.signing_cert_url.as_deref().ok_or_else(|| {
        ApiError::Validation(vec!["Missing SigningCertURL in SNS message".into()])
    })?;
    validate_signing_cert_url(cert_url)?;

    let public_key = fetch_sns_signing_key(http_client, cert_url).await?;
    verify_sns_signature_with_key(msg, &public_key)
}

fn validate_signing_cert_url(cert_url: &str) -> Result<(), ApiError> {
    let parsed = url::Url::parse(cert_url)
        .map_err(|_| ApiError::Validation(vec!["Invalid SigningCertURL in SNS message".into()]))?;

    let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
    let path = parsed.path();
    let is_allowed_host = (host == "sns.amazonaws.com" || host.starts_with("sns."))
        && (host.ends_with(".amazonaws.com") || host.ends_with(".amazonaws.com.cn"));
    let is_allowed_path = path.starts_with("/SimpleNotificationService-") && path.ends_with(".pem");
    let port_ok = parsed.port_or_known_default().unwrap_or(443) == 443;

    if parsed.scheme() != "https" || !is_allowed_host || !is_allowed_path || !port_ok {
        warn!(cert_url = %cert_url, "Rejected invalid SNS SigningCertURL");
        return Err(ApiError::Validation(vec![
            "SigningCertURL must reference an AWS SNS certificate".into(),
        ]));
    }

    Ok(())
}

async fn fetch_sns_signing_key(
    http_client: &reqwest::Client,
    cert_url: &str,
) -> Result<RsaPublicKey, ApiError> {
    let response = http_client
        .get(cert_url)
        .send()
        .await
        .map_err(|e| {
            error!(error = %e, cert_url = %cert_url, "Failed to fetch SNS signing certificate");
            ApiError::ServiceUnavailable("Failed to fetch SNS signing certificate".into())
        })?
        .error_for_status()
        .map_err(|e| {
            error!(error = %e, cert_url = %cert_url, "SNS signing certificate request failed");
            ApiError::ServiceUnavailable("Failed to fetch SNS signing certificate".into())
        })?;

    let cert_bytes = response.bytes().await.map_err(|e| {
        error!(error = %e, cert_url = %cert_url, "Failed to read SNS signing certificate");
        ApiError::ServiceUnavailable("Failed to fetch SNS signing certificate".into())
    })?;

    let (_, pem) = parse_x509_pem(&cert_bytes).map_err(|e| {
        warn!(error = ?e, cert_url = %cert_url, "Invalid SNS signing certificate PEM");
        ApiError::Validation(vec!["Invalid SNS signing certificate".into()])
    })?;
    let (_, certificate) = X509Certificate::from_der(&pem.contents).map_err(|e| {
        warn!(error = ?e, cert_url = %cert_url, "Invalid SNS signing certificate DER");
        ApiError::Validation(vec!["Invalid SNS signing certificate".into()])
    })?;

    RsaPublicKey::from_pkcs1_der(&certificate.public_key().subject_public_key.data).map_err(|e| {
        warn!(error = %e, cert_url = %cert_url, "Invalid SNS signing certificate public key");
        ApiError::Validation(vec!["Invalid SNS signing certificate".into()])
    })
}

fn verify_sns_signature_with_key(
    msg: &SnsMessage,
    public_key: &RsaPublicKey,
) -> Result<(), ApiError> {
    let encoded_signature = msg
        .signature
        .as_deref()
        .ok_or_else(|| ApiError::Validation(vec!["Missing Signature in SNS message".into()]))?;
    let signature = BASE64
        .decode(encoded_signature)
        .map_err(|_| ApiError::Validation(vec!["Invalid SNS signature encoding".into()]))?;
    let signature = RsaSignature::try_from(signature.as_slice())
        .map_err(|_| ApiError::Validation(vec!["Invalid SNS signature".into()]))?;
    let string_to_sign = build_sns_string_to_sign(msg)?;

    match msg.signature_version.as_deref() {
        Some("1") => VerifyingKey::<Sha1>::new(public_key.clone())
            .verify(string_to_sign.as_bytes(), &signature),
        Some("2") => VerifyingKey::<Sha256>::new(public_key.clone())
            .verify(string_to_sign.as_bytes(), &signature),
        Some(other) => {
            warn!(signature_version = %other, "Rejected unsupported SNS signature version");
            return Err(ApiError::Validation(vec![
                "Unsupported SNS signature version".into(),
            ]));
        }
        None => {
            return Err(ApiError::Validation(vec![
                "Missing SignatureVersion in SNS message".into(),
            ]));
        }
    }
    .map_err(|_| ApiError::Forbidden("Invalid SNS signature".into()))
}

fn build_sns_string_to_sign(msg: &SnsMessage) -> Result<String, ApiError> {
    let mut string_to_sign = String::new();

    match msg.message_type.as_str() {
        "Notification" => {
            append_required_field(&mut string_to_sign, "Message", msg.message.as_deref())?;
            append_required_field(&mut string_to_sign, "MessageId", msg.message_id.as_deref())?;
            if let Some(subject) = msg.subject.as_deref() {
                append_field(&mut string_to_sign, "Subject", subject);
            }
            append_required_field(&mut string_to_sign, "Timestamp", msg.timestamp.as_deref())?;
            append_required_field(&mut string_to_sign, "TopicArn", msg.topic_arn.as_deref())?;
            append_field(&mut string_to_sign, "Type", &msg.message_type);
        }
        "SubscriptionConfirmation" | "UnsubscribeConfirmation" => {
            append_required_field(&mut string_to_sign, "Message", msg.message.as_deref())?;
            append_required_field(&mut string_to_sign, "MessageId", msg.message_id.as_deref())?;
            append_required_field(
                &mut string_to_sign,
                "SubscribeURL",
                msg.subscribe_url.as_deref(),
            )?;
            append_required_field(&mut string_to_sign, "Timestamp", msg.timestamp.as_deref())?;
            append_required_field(&mut string_to_sign, "Token", msg.token.as_deref())?;
            append_required_field(&mut string_to_sign, "TopicArn", msg.topic_arn.as_deref())?;
            append_field(&mut string_to_sign, "Type", &msg.message_type);
        }
        other => {
            return Err(ApiError::Validation(vec![format!(
                "Unsupported SNS message type: {other}"
            )]));
        }
    }

    Ok(string_to_sign)
}

fn append_required_field(
    string_to_sign: &mut String,
    name: &str,
    value: Option<&str>,
) -> Result<(), ApiError> {
    let value = value
        .ok_or_else(|| ApiError::Validation(vec![format!("Missing {name} in SNS message")]))?;
    append_field(string_to_sign, name, value);
    Ok(())
}

fn append_field(string_to_sign: &mut String, name: &str, value: &str) {
    string_to_sign.push_str(name);
    string_to_sign.push('\n');
    string_to_sign.push_str(value);
    string_to_sign.push('\n');
}

/// Process an SES event notification.
async fn handle_notification(state: &AppState, msg: &SnsMessage) -> Result<StatusCode, ApiError> {
    let event_json = msg
        .message
        .as_deref()
        .ok_or_else(|| ApiError::Validation(vec!["Missing Message in SNS notification".into()]))?;

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
    mail.headers
        .as_ref()?
        .iter()
        .find(|h| h.name == header_name)
        .map(|h| h.value.clone())
}

// ─── Bounce processing ────────────────────────────────────────

async fn process_bounce(state: &AppState, event: &SesEvent) -> Result<(), ApiError> {
    let bounce = event
        .bounce
        .as_ref()
        .ok_or_else(|| ApiError::Validation(vec!["Bounce event missing bounce details".into()]))?;

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
                    if let Err(e) = sqlx::query(
                        "INSERT INTO suppression_list (id, email, reason, source, created_at)
                         VALUES (gen_random_uuid(), $1, $2, 'ses_bounce', NOW())
                         ON CONFLICT (email) DO NOTHING",
                    )
                    .bind(email)
                    .bind(&reason)
                    .execute(&state.db)
                    .await
                    {
                        warn!(email = %apexmail_lib::pii::redact_email(email), error = %e, "Failed to suppress bounced address");
                    } else {
                        info!(email = %apexmail_lib::pii::redact_email(email), reason = %reason, "Auto-suppressed hard-bounced address");
                    }
                }

                // Update message status if we have the internal ID
                if let Some(ref msg_id) = apexmail_message_id {
                    let status = if is_permanent { "bounced" } else { "deferred" };
                    // Strip any "msg_" prefix from the message ID before matching
                    let db_id = msg_id.strip_prefix("msg_").unwrap_or(msg_id);
                    if let Err(e) = sqlx::query(
                        "UPDATE messages SET status = $1, bounce_type = $2, updated_at = NOW()
                         WHERE id = $3",
                    )
                    .bind(status)
                    .bind(&reason)
                    .bind(db_id)
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
    let complaint = event
        .complaint
        .as_ref()
        .ok_or_else(|| ApiError::Validation(vec!["Complaint event missing details".into()]))?;

    let mail = event.mail.as_ref();
    let ses_message_id = mail.and_then(|m| m.message_id.clone());
    let apexmail_message_id = mail.and_then(|m| extract_apexmail_header(m, "X-ApexMail-MessageId"));
    let tenant_id = mail.and_then(|m| extract_apexmail_header(m, "X-ApexMail-TenantId"));

    let feedback_type = complaint
        .complaint_feedback_type
        .as_deref()
        .unwrap_or("abuse");

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
                if let Err(e) = sqlx::query(
                    "INSERT INTO suppression_list (id, email, reason, source, created_at)
                     VALUES (gen_random_uuid(), $1, $2, 'ses_complaint', NOW())
                     ON CONFLICT (email) DO NOTHING",
                )
                .bind(email)
                .bind(&reason)
                .execute(&state.db)
                .await
                {
                    warn!(email = %apexmail_lib::pii::redact_email(email), error = %e, "Failed to suppress complained address");
                } else {
                    info!(email = %apexmail_lib::pii::redact_email(email), reason = %reason, "Auto-suppressed complained address");
                }

                // Update message status
                if let Some(ref msg_id) = apexmail_message_id {
                    // Strip any "msg_" prefix from the message ID before matching
                    let db_id = msg_id.strip_prefix("msg_").unwrap_or(msg_id);
                    if let Err(e) = sqlx::query(
                        "UPDATE messages SET status = 'complained', updated_at = NOW()
                         WHERE id = $1",
                    )
                    .bind(db_id)
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
    let delivery = event
        .delivery
        .as_ref()
        .ok_or_else(|| ApiError::Validation(vec!["Delivery event missing details".into()]))?;

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
        // Strip any "msg_" prefix from the message ID before matching
        let db_id = msg_id.strip_prefix("msg_").unwrap_or(msg_id);
        if let Err(e) = sqlx::query(
            "UPDATE messages SET status = 'delivered', delivered_at = NOW(), updated_at = NOW()
             WHERE id = $1 AND status != 'delivered'",
        )
        .bind(db_id)
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
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::RsaPrivateKey;

    #[test]
    fn test_parse_sns_subscription_confirmation() {
        let json = r#"{
            "Type": "SubscriptionConfirmation",
            "MessageId": "test-id",
            "TopicArn": "arn:aws:sns:us-east-1:123:test",
            "SubscribeURL": "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&Token=abc",
            "Timestamp": "2026-02-27T09:00:00Z",
            "Token": "abc",
            "SignatureVersion": "2",
            "Signature": "ZmFrZQ==",
            "SigningCertURL": "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-test.pem"
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
            r#"{{"Type":"Notification","MessageId":"sns-123","Message":{},"Timestamp":"2026-02-27T10:00:00Z","TopicArn":"arn:aws:sns:us-east-1:123:test","SignatureVersion":"2","Signature":"ZmFrZQ==","SigningCertURL":"https://sns.us-east-1.amazonaws.com/SimpleNotificationService-test.pem"}}"#,
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

    #[test]
    fn test_validate_signing_cert_url_rejects_non_aws_host() {
        let err = validate_signing_cert_url(
            "https://evil.example.com/SimpleNotificationService-test.pem",
        )
        .unwrap_err();
        assert!(matches!(err, ApiError::Validation(_)));
    }

    #[test]
    fn test_validate_sns_topic_arn_requires_configuration() {
        let msg = sample_notification_message();
        let err = validate_sns_topic_arn(&msg, "").unwrap_err();
        assert!(matches!(err, ApiError::ServiceUnavailable(_)));
    }

    #[test]
    fn test_build_sns_string_to_sign_notification_includes_subject() {
        let mut msg = sample_notification_message();
        msg.subject = Some("ApexMail event".into());

        let string_to_sign = build_sns_string_to_sign(&msg).unwrap();
        assert!(string_to_sign.contains("Subject\nApexMail event\n"));
        assert!(string_to_sign.ends_with("Type\nNotification\n"));
    }

    #[test]
    fn test_verify_sns_signature_with_generated_key() {
        let mut rng = rsa::rand_core::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        let mut msg = sample_notification_message();
        let string_to_sign = build_sns_string_to_sign(&msg).unwrap();
        let signature = SigningKey::<Sha256>::new(private_key).sign(string_to_sign.as_bytes());

        msg.signature = Some(BASE64.encode(signature.to_bytes()));

        assert!(verify_sns_signature_with_key(&msg, &public_key).is_ok());
    }

    fn sample_notification_message() -> SnsMessage {
        SnsMessage {
            message_type: "Notification".into(),
            subscribe_url: None,
            message: Some("{\"eventType\":\"Send\"}".into()),
            message_id: Some("sns-123".into()),
            subject: None,
            timestamp: Some("2026-02-27T10:00:00Z".into()),
            token: None,
            signature: Some("ZmFrZQ==".into()),
            signature_version: Some("2".into()),
            signing_cert_url: Some(
                "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-test.pem".into(),
            ),
            topic_arn: Some("arn:aws:sns:us-east-1:123:test".into()),
        }
    }
}
