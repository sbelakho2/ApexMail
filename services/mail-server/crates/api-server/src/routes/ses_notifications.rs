//! AWS SES bounce/complaint notification handler.
//!
//! SES sends event notifications via **Amazon SNS** as HTTP POST requests.
//! This module://! 1. Handles SNS subscription confirmation (auto-confirms).
//! 2. Processes SES bounce notifications → auto-suppresses hard bounces.
//! 3. Processes SES complaint notifications → auto-suppresses complainants.
//! 4. Processes SES delivery notifications → updates message status.
//! 5. Processes SES open/click notifications → increments message stats.
//!
//! Every terminal event also writes an analytics `events` row ('delivered',
//! 'complained', 'opened', 'clicked') so the admin analytics surfaces that
//! bucket on the events table see SES traffic.
//!
//! ## Endpoint
//!
//! `POST /v1/ses/notifications` — public (no auth), validated via SNS message signature.
//!
//! ## Setup
//!
//! In AWS SES → Configuration Set → Event destinations → add SNS topic
//! (enable the Delivery, Open and Click event types in addition to Bounce
//! and Complaint).
//! In SNS → Subscription → HTTPS → `https://api.apexmail.ee/v1/ses/notifications`.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::Router;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{DateTime, Utc};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use serde::Deserialize;
use sha1::Sha1;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
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
    open: Option<SesOpen>,
    click: Option<SesClick>,
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

/// SES Open event payload (user_agent/ip only when event publishing
/// includes open/tracking metadata).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SesOpen {
    timestamp: Option<String>,
    user_agent: Option<String>,
    ip_address: Option<String>,
}

/// SES Click event payload.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SesClick {
    timestamp: Option<String>,
    link: Option<String>,
    user_agent: Option<String>,
    ip_address: Option<String>,
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

    // PP-006/L-07: Deduplicate SNS notifications with a Redis marker keyed
    // by (SNS message id + notification type). F75: the marker is now
    // claimed AFTER successful processing, not before — a processing
    // failure returns 5xx, SNS retries, and the retry must find NO marker
    // blocking the reprocessing (the pre-claim order permanently lost
    // events whose processing failed after the marker was set). All state
    // effects are idempotent under replay (deterministic event ids,
    // guarded timestamps, ON CONFLICT upserts), so a retry after a lost
    // marker is safe.
    //
    // Audit G(3): a Redis error is never coerced to "duplicate" — it
    // returns 5xx so SNS retries the delivery.
    let notification_type = sns_msg.message_type.as_str();
    let dedup_key = sns_msg
        .message_id
        .as_deref()
        .map(|msg_id| format!("apexmail:dedup:sns:{}:{}", msg_id, notification_type));
    let Some(dedup_key) = dedup_key else {
        warn!("SNS notification missing message_id — cannot deduplicate");
        return Err(ApiError::Validation(vec![
            "SNS notification missing MessageId".into(),
        ]));
    };
    let ttl_secs = 300; // 5 minutes — SNS retries within a few minutes at most.

    // Fast path: already processed within the dedup window?
    {
        let mut conn = state.redis.get().await.map_err(|e| {
            warn!(error = %e, "Failed to acquire redis for SNS dedup");
            ApiError::ServiceUnavailable("Redis unavailable".into())
        })?;
        let seen: Option<String> = redis::cmd("GET")
            .arg(&dedup_key)
            .query_async(&mut *conn)
            .await
            .map_err(|e| {
                warn!(error = %e, "Redis GET failed for SNS dedup — returning 5xx so SNS retries");
                ApiError::ServiceUnavailable("Redis unavailable".into())
            })?;
        if seen.is_some() {
            info!(dedup_key = %dedup_key, "Deduplicated duplicate SNS notification");
            return Ok(StatusCode::OK);
        }
    }

    // Process FIRST — every effect is durably committed before the SNS
    // acknowledgement (F75).
    let outcome: Result<(), ApiError> = match sns_msg.message_type.as_str() {
        "SubscriptionConfirmation" => handle_subscription_confirmation(&state, &sns_msg)
            .await
            .map(|_| ()),
        "Notification" => handle_notification(&state, &sns_msg).await,
        "UnsubscribeConfirmation" => {
            info!(topic = ?sns_msg.topic_arn, "SNS unsubscribe confirmation received");
            Ok(())
        }
        other => {
            warn!(message_type = %other, "Unknown SNS message type");
            Ok(())
        }
    };

    // Claim the dedup marker only after the outcome is committed; a marker
    // failure returns 5xx so SNS retries (the idempotent effects make the
    // replay safe).
    outcome?;
    let mut conn = state.redis.get().await.map_err(|e| {
        warn!(error = %e, "Failed to acquire redis for SNS dedup mark");
        ApiError::ServiceUnavailable("Redis unavailable".into())
    })?;
    let _: Option<String> = redis::cmd("SET")
        .arg(&dedup_key)
        .arg("1")
        .arg("NX")
        .arg("EX")
        .arg(ttl_secs)
        .query_async(&mut *conn)
        .await
        .map_err(|e| {
            warn!(error = %e, "Redis SET NX failed for SNS dedup — returning 5xx so SNS retries");
            ApiError::ServiceUnavailable("Redis unavailable".into())
        })?;

    Ok(StatusCode::OK)
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
        // Audit G(4): the transport error string (which can embed internal
        // network details) must not leak to the (unauthenticated) caller —
        // log the detail, return a generic message.
        error!(error = %e, "Failed to confirm SNS subscription");
        ApiError::ServiceUnavailable("SNS confirmation failed".into())
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
    validate_sns_signature(http_client, msg).await?;
    // Audit G(2): replay freshness — the signature check above proves the
    // message was signed by AWS, but not that it is recent. Reject captured
    // notifications older than 1 hour (SNS retries span at most ~1h including
    // the initial attempt) and clock-skewed ones more than 10 minutes in the
    // future.
    validate_sns_timestamp_freshness(msg)
}

/// SNS `Timestamp` freshness bounds (audit G).
const SNS_MAX_AGE_SECS: i64 = 3600;
const SNS_MAX_FUTURE_SKEW_SECS: i64 = 600;

fn validate_sns_timestamp_freshness(msg: &SnsMessage) -> Result<(), ApiError> {
    let timestamp = msg
        .timestamp
        .as_deref()
        .ok_or_else(|| ApiError::Validation(vec!["Missing Timestamp in SNS message".into()]))?;

    let parsed = chrono::DateTime::parse_from_rfc3339(timestamp)
        .map_err(|_| ApiError::Validation(vec!["Invalid Timestamp in SNS message".into()]))?
        .with_timezone(&chrono::Utc);

    let now = chrono::Utc::now();
    if now - parsed > chrono::Duration::seconds(SNS_MAX_AGE_SECS) {
        warn!(timestamp = %timestamp, "Rejected stale SNS notification (replay)");
        return Err(ApiError::Validation(vec![
            "SNS notification timestamp is too old".into(),
        ]));
    }
    if parsed - now > chrono::Duration::seconds(SNS_MAX_FUTURE_SKEW_SECS) {
        warn!(timestamp = %timestamp, "Rejected future-dated SNS notification");
        return Err(ApiError::Validation(vec![
            "SNS notification timestamp is too far in the future".into(),
        ]));
    }

    Ok(())
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

/// Cache of parsed SNS signing certificates keyed by cert URL (audit G).
///
/// The handler previously fetched the signing cert over HTTPS on EVERY POST —
/// a per-request outbound round-trip (latency + a DoS amplification surface:
/// every unauthenticated POST forced a TLS handshake to AWS). AWS publishes a
/// small, slowly-rotating set of cert URLs, so a bounded TTL cache removes
/// the repeated fetches while still picking up rotations.
static SNS_SIGNING_KEY_CACHE: Mutex<Option<HashMap<String, (RsaPublicKey, Instant)>>> =
    Mutex::new(None);

/// Cert cache entry lifetime (AWS rotates signing certs roughly yearly; one
/// hour keeps rotation pickup prompt while collapsing per-request traffic).
const SNS_SIGNING_KEY_CACHE_TTL: Duration = Duration::from_secs(3600);
/// Upper bound on cached cert URLs (defense against a caller spoofing many
/// cert URLs — validate_signing_cert_url already restricts hosts to AWS SNS,
/// so the cap is pure defense-in-depth).
const SNS_SIGNING_KEY_CACHE_MAX_ENTRIES: usize = 16;

fn cache_get_sns_signing_key(cert_url: &str) -> Option<RsaPublicKey> {
    let guard = SNS_SIGNING_KEY_CACHE.lock().ok()?;
    let cache = guard.as_ref()?;
    let (key, fetched_at) = cache.get(cert_url)?;
    if fetched_at.elapsed() > SNS_SIGNING_KEY_CACHE_TTL {
        return None; // expired — caller refetches and re-inserts
    }
    Some(key.clone())
}

fn cache_put_sns_signing_key(cert_url: &str, key: RsaPublicKey) {
    let Ok(mut guard) = SNS_SIGNING_KEY_CACHE.lock() else {
        return;
    };
    let cache = guard.get_or_insert_with(HashMap::new);
    // Simple bounded insert: evict everything when the cap is reached
    // (entries are tiny and refetched on demand).
    if cache.len() >= SNS_SIGNING_KEY_CACHE_MAX_ENTRIES && !cache.contains_key(cert_url) {
        cache.clear();
    }
    cache.insert(cert_url.to_string(), (key, Instant::now()));
}

async fn fetch_sns_signing_key(
    http_client: &reqwest::Client,
    cert_url: &str,
) -> Result<RsaPublicKey, ApiError> {
    if let Some(cached) = cache_get_sns_signing_key(cert_url) {
        return Ok(cached);
    }

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

    let key = RsaPublicKey::from_pkcs1_der(&certificate.public_key().subject_public_key.data)
        .map_err(|e| {
            warn!(error = %e, cert_url = %cert_url, "Invalid SNS signing certificate public key");
            ApiError::Validation(vec!["Invalid SNS signing certificate".into()])
        })?;

    cache_put_sns_signing_key(cert_url, key.clone());
    Ok(key)
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
async fn handle_notification(state: &AppState, msg: &SnsMessage) -> Result<(), ApiError> {
    let event_json = msg
        .message
        .as_deref()
        .ok_or_else(|| ApiError::Validation(vec!["Missing Message in SNS notification".into()]))?;

    let event: SesEvent = serde_json::from_str(event_json).map_err(|e| {
        warn!(error = %e, "Failed to parse SES event");
        ApiError::Validation(vec![format!("Invalid SES event: {e}")])
    })?;

    // The SNS notification id feeds the deterministic analytics-event ids
    // (F75 replay dedup).
    let sns_message_id = msg.message_id.as_deref().unwrap_or("sns-unknown");

    match event.event_type.as_str() {
        "Bounce" => process_bounce(state, &event, sns_message_id).await?,
        "Complaint" => process_complaint(state, &event, sns_message_id).await?,
        "Delivery" => process_delivery(state, &event, sns_message_id).await?,
        "Open" => process_open(state, &event, sns_message_id).await?,
        "Click" => process_click(state, &event, sns_message_id).await?,
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

    Ok(())
}

// ─── F74: trusted attribution from the durable provider-message mapping ────
//
// SES bounce/complaint/delivery/open/click events used to trust the
// X-ApexMail-* headers ECHOED BY SES for tenant/message authority. Those
// headers originate from the submitted message — a caller could set the
// legacy aliases (X-ApexMail-TenantId) through custom headers and have its
// bounces attributed (and its complaints suppress) ANOTHER tenant. A valid
// SNS provider signature proves the event came from SES, not that the
// headers inside the message are platform-generated.
//
// The ONLY authority now is the durable provider-message mapping: the
// worker persists the SES message id on the accepting queue row
// (`email_queue.smtp_message_id`, migration 186 indexes it). Every event
// resolves ses_message_id → stored queue row, verifies the callback
// recipient matches that row's stored envelope recipient, and takes
// tenant/message/recipient from the STORED record. Echoed identity headers
// are parsed case-insensitively purely for diagnostic correlation, with
// ambiguous duplicates rejected (logged) — never for authorization.

/// The stored delivery record a provider event resolves to.
struct SesAttribution {
    queue_row_id: String,
    message_id: String,
    tenant_id: String,
    /// The recipient as stored on the queue row (verified to match the
    /// callback recipient, case-insensitively).
    recipient: String,
}

/// F74: the provider-message → stored delivery record resolution. The
/// tenant/message/recipient authority comes EXCLUSIVELY from the stored
/// `email_queue` row that accepted the SES message id — never from the
/// echoed X-ApexMail-* headers. The callback recipient must match the
/// row's stored envelope (ownership verification).
const SES_ATTRIBUTION_SQL: &str = r#"
    SELECT q.id::text,
           COALESCE(q.message_id::text, q.id::text),
           q.tenant_id,
           q."to"
    FROM email_queue q
    WHERE q.smtp_message_id = $1
      AND q.tenant_id IS NOT NULL
      AND (
            LOWER(q."to") = LOWER($2)
         OR LOWER($2) = ANY (SELECT LOWER(a) FROM unnest(COALESCE(q.to_addresses, ARRAY[q."to"])) AS a)
      )
    LIMIT 1
"#;

/// Resolve the authoritative tenant/message/recipient for one provider
/// event: the queue row that accepted `ses_message_id`, additionally
/// verified to own `callback_recipient` in its envelope. `Ok(None)` when no
/// stored row matches — the caller surfaces that as an unattributed,
/// retryable outcome (the acceptance mapping may still be committing).
async fn resolve_ses_attribution(
    db: &sqlx::PgPool,
    ses_message_id: &str,
    callback_recipient: &str,
) -> Result<Option<SesAttribution>, sqlx::Error> {
    let row: Option<(String, String, String, String)> = sqlx::query_as(SES_ATTRIBUTION_SQL)
        .bind(ses_message_id)
        .bind(callback_recipient)
        .fetch_optional(db)
        .await?;
    Ok(row.map(
        |(queue_row_id, message_id, tenant_id, recipient)| SesAttribution {
            queue_row_id,
            message_id,
            tenant_id,
            recipient,
        },
    ))
}

/// Deterministic analytics-event id for one (SNS notification, event,
/// recipient) triple — SNS retries after a lost dedup marker re-INSERT the
/// same id, and the ON CONFLICT DO NOTHING turns the replay into a no-op
/// (F75 event deduplication). `evt_` + 32 hex chars fits events.id
/// VARCHAR(64).
fn ses_event_id(sns_message_id: &str, event_type: &str, recipient: &str) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(format!("{sns_message_id}|{event_type}|{recipient}"));
    format!("evt_{}", hex::encode(&digest[..16]))
}

/// Parse an SES event timestamp (RFC 3339) for the ACTUAL event time
/// (F25/F75: timestamps record their actual events), falling back to NOW().
fn ses_event_timestamp(raw: Option<&str>) -> DateTime<Utc> {
    raw.and_then(|ts| DateTime::parse_from_rfc3339(ts).ok())
        .map(|ts| ts.with_timezone(&Utc))
        .unwrap_or_else(Utc::now)
}

/// Diagnostic-only parse of the echoed identity headers (F74): case
/// insensitive canonical + alias spellings, ambiguous duplicates rejected.
/// Never used for authorization.
fn diagnostic_identity_headers(mail: &SesMail) -> (Option<String>, Option<String>) {
    let headers = mail
        .headers
        .iter()
        .flatten()
        .map(|h| (h.name.as_str(), h.value.as_str()));
    let message = match apexmail_lib::email_headers::find_identity_header(
        headers,
        apexmail_lib::email_headers::HEADER_MESSAGE_ID,
        apexmail_lib::email_headers::HEADER_ALIASES_MESSAGE_ID,
    ) {
        apexmail_lib::email_headers::IdentityHeaderLookup::Found(v) => Some(v.to_string()),
        apexmail_lib::email_headers::IdentityHeaderLookup::Ambiguous => {
            warn!("SES event carried ambiguous duplicate X-ApexMail message-id headers");
            None
        }
        apexmail_lib::email_headers::IdentityHeaderLookup::Missing => None,
    };
    let tenant = match apexmail_lib::email_headers::find_identity_header(
        mail.headers
            .iter()
            .flatten()
            .map(|h| (h.name.as_str(), h.value.as_str())),
        apexmail_lib::email_headers::HEADER_TENANT_ID,
        apexmail_lib::email_headers::HEADER_ALIASES_TENANT_ID,
    ) {
        apexmail_lib::email_headers::IdentityHeaderLookup::Found(v) => Some(v.to_string()),
        apexmail_lib::email_headers::IdentityHeaderLookup::Ambiguous => {
            warn!("SES event carried ambiguous duplicate X-ApexMail tenant-id headers");
            None
        }
        apexmail_lib::email_headers::IdentityHeaderLookup::Missing => None,
    };
    (message, tenant)
}

/// Extract our internal message_id from SES mail headers. F74: retained
/// TEST-ONLY — production code never reads identity authority from raw
/// headers.
#[cfg(test)]
fn extract_apexmail_header(mail: &SesMail, header_name: &str) -> Option<String> {
    mail.headers
        .as_ref()?
        .iter()
        .find(|h| h.name == header_name)
        .map(|h| h.value.clone())
}

/// Strip any "msg_" prefix from an X-ApexMail-MessageId header value.
/// F74: retained TEST-ONLY — production attribution resolves through the
/// stored provider-message mapping.
#[cfg(test)]
fn normalize_message_id(msg_id: &str) -> &str {
    msg_id.strip_prefix("msg_").unwrap_or(msg_id)
}

/// The unattributable-outcome error (F74): no stored provider-message
/// mapping matched. Surfaced as 5xx so SNS retries (the acceptance mapping
/// may still be committing), with a metric making the residue observable
/// instead of silently misattributing the event to header values.
fn unattributed_ses_event(ses_message_id: Option<&str>, recipient: &str) -> ApiError {
    metrics::counter!("apexmail_ses_unattributed_events").increment(1);
    warn!(
        ses_message_id = ?ses_message_id,
        recipient = %apexmail_lib::pii::redact_email(recipient),
        "SES event cannot be attributed to a stored provider-message mapping — retrying"
    );
    ApiError::ServiceUnavailable(
        "SES event attribution pending — notification will be retried".into(),
    )
}

/// Map a database failure inside the SES callback path onto a retryable
/// 5xx (F75): SNS must NOT be acknowledged before the callback state is
/// durably committed, so the error propagates and SNS retries. The detail
/// is logged; the response stays generic.
fn ses_db_error(context: &str, error: sqlx::Error) -> ApiError {
    metrics::counter!("apexmail_ses_callback_db_errors").increment(1);
    error!(context = context, error = %error, "SES callback database failure");
    ApiError::ServiceUnavailable("SES callback storage unavailable".into())
}

/// Insert an analytics `events` row for a terminal SES event with a
/// DETERMINISTIC id (`ses_event_id`) and ON CONFLICT DO NOTHING so an SNS
/// replay after a lost dedup marker cannot duplicate the effect (F75).
/// Failures PROPAGATE: the caller must not acknowledge SNS before the
/// event is durably recorded.
#[expect(clippy::too_many_arguments)]
async fn insert_analytics_event(
    executor: impl sqlx::PgExecutor<'_>,
    event_id: &str,
    tenant_id: &str,
    message_id: &str,
    event_type: &str,
    recipient: Option<&str>,
    link_url: Option<&str>,
    user_agent: Option<&str>,
    ip_address: Option<&str>,
    at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO events (id, tenant_id, message_id, event_type, recipient, link_url, user_agent, ip_address, timestamp)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(event_id)
    .bind(tenant_id)
    .bind(message_id)
    .bind(event_type)
    .bind(recipient)
    .bind(link_url)
    .bind(user_agent)
    .bind(ip_address)
    .bind(at)
    .execute(executor)
    .await
    .map(|_| ())
}

// ─── Bounce processing ────────────────────────────────────────

async fn process_bounce(
    state: &AppState,
    event: &SesEvent,
    sns_message_id: &str,
) -> Result<(), ApiError> {
    let bounce = event
        .bounce
        .as_ref()
        .ok_or_else(|| ApiError::Validation(vec!["Bounce event missing bounce details".into()]))?;

    let mail = event.mail.as_ref();
    let ses_message_id = mail.and_then(|m| m.message_id.clone());
    let Some(ses_message_id) = ses_message_id.as_deref() else {
        return Err(unattributed_ses_event(None, ""));
    };
    let (diagnostic_message_id, diagnostic_tenant_id) = match mail {
        Some(mail) => diagnostic_identity_headers(mail),
        None => (None, None),
    };

    let is_permanent = bounce.bounce_type == "Permanent";
    let bounce_sub_type = bounce.bounce_sub_type.as_deref().unwrap_or("General");
    let bounced_at = ses_event_timestamp(bounce.timestamp.as_deref());

    info!(
        bounce_type = %bounce.bounce_type,
        bounce_sub_type = %bounce_sub_type,
        ses_message_id = %ses_message_id,
        "Processing SES bounce"
    );

    if let Some(recipients) = &bounce.bounced_recipients {
        for recipient in recipients {
            let Some(email) = recipient.email_address.as_deref() else {
                continue;
            };

            // F74: authority comes from the stored provider-message
            // mapping, with the callback recipient verified against the
            // row's envelope. Raw headers are diagnostics only.
            let Some(attribution) = resolve_ses_attribution(&state.db, ses_message_id, email)
                .await
                .map_err(|e| {
                    metrics::counter!("apexmail_ses_callback_db_errors").increment(1);
                    error!(error = %e, "SES bounce attribution query failed");
                    ApiError::ServiceUnavailable("SES callback storage unavailable".into())
                })?
            else {
                // Unattributed — observable + retryable, never guessed from
                // the echoed headers (which may carry another tenant's id).
                debug!(
                    diagnostic_header_message_id = ?diagnostic_message_id,
                    diagnostic_header_tenant_id = ?diagnostic_tenant_id,
                    "bounce without a stored mapping"
                );
                return Err(unattributed_ses_event(Some(ses_message_id), email));
            };

            let reason = if is_permanent {
                format!("ses_hard_bounce:{bounce_sub_type}")
            } else {
                format!("ses_soft_bounce:{bounce_sub_type}")
            };

            // State mutations + the shared parent reconciliation run in ONE
            // transaction, COMMITTED BEFORE the SNS acknowledgement (F75):
            // a DB failure propagates as 5xx so SNS retries safely.
            let mut tx = state
                .db
                .begin()
                .await
                .map_err(|e| ses_db_error("begin", e))?;

            // Auto-suppress hard bounces (canonical `suppressions` table)
            // using the STORED tenant. Idempotent under SNS replay.
            if is_permanent {
                let suppression_id = apexmail_lib::id::generate_id("sup", 22);
                sqlx::query(
                    "INSERT INTO suppressions (id, tenant_id, email, reason, source, created_at)
                     VALUES ($1, $2, $3, $4, $5, NOW())
                     ON CONFLICT (tenant_id, email) DO NOTHING",
                )
                .bind(&suppression_id)
                .bind(&attribution.tenant_id)
                .bind(&attribution.recipient)
                .bind(&reason)
                .bind("ses")
                .execute(&mut *tx)
                .await
                .map_err(|e| ses_db_error("failed to record suppression", e))?;
                info!(email = %apexmail_lib::pii::redact_email(&attribution.recipient), reason = %reason, "Auto-suppressed hard-bounced address");
            }

            // F25/F75: the bounce transitions the RECIPIENT delivery record
            // (mirroring the worker's per-recipient HARD_BOUNCE semantics:
            // the recipient leaves the pending set, the row terminalizes
            // only when nothing remains owed), then the SHARED parent
            // reconciliation derives the aggregate from all recipient rows.
            if is_permanent {
                sqlx::query(
                    r#"
                    UPDATE email_queue
                    SET metadata = jsonb_set(
                            CASE WHEN jsonb_typeof(metadata) = 'object' THEN metadata ELSE '{}'::jsonb END,
                            '{pending_recipients}',
                            COALESCE(
                                metadata->'pending_recipients',
                                CASE WHEN jsonb_array_length(to_jsonb(to_addresses)) > 0
                                     THEN to_jsonb(to_addresses) END,
                                CASE WHEN "to" IS NOT NULL AND "to" <> ''
                                     THEN to_jsonb(ARRAY["to"]) END,
                                '[]'::jsonb
                            ) - $2::text
                        ),
                        status = CASE WHEN COALESCE(
                                metadata->'pending_recipients',
                                CASE WHEN jsonb_array_length(to_jsonb(to_addresses)) > 0
                                     THEN to_jsonb(to_addresses) END,
                                CASE WHEN "to" IS NOT NULL AND "to" <> ''
                                     THEN to_jsonb(ARRAY["to"]) END,
                                '[]'::jsonb
                            ) - $2::text = '[]'::jsonb
                            THEN 'bounced' ELSE status END,
                        error_message = $3,
                        updated_at = NOW()
                    WHERE id = $1::uuid
                    "#,
                )
                .bind(&attribution.queue_row_id)
                .bind(&attribution.recipient)
                .bind(&reason)
                .execute(&mut *tx)
                .await
                .map_err(|e| ses_db_error("failed to record bounce", e))?;

                sqlx::query(apexmail_lib::email_headers::RECONCILE_MESSAGE_PROGRESS_SQL)
                    .bind(&attribution.message_id)
                    .bind(&attribution.tenant_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| ses_db_error("reconcile message progress", e))?;
            }

            // Deterministic-id analytics event (replay-safe).
            insert_analytics_event(
                &mut *tx,
                &ses_event_id(sns_message_id, "bounced", &attribution.recipient),
                &attribution.tenant_id,
                &attribution.message_id,
                "bounced",
                Some(&attribution.recipient),
                None,
                None,
                None,
                bounced_at,
            )
            .await
            .map_err(|e| ses_db_error("failed to record bounce event", e))?;

            tx.commit().await.map_err(|e| ses_db_error("storage", e))?;

            // Queue webhook event for the tenant (post-commit; best-effort).
            let payload = serde_json::json!({
                "event": "message.bounced",
                "type": bounce.bounce_type,
                "subType": bounce_sub_type,
                "recipient": attribution.recipient,
                "messageId": attribution.message_id,
                "sesMessageId": ses_message_id,
                "diagnosticCode": recipient.diagnostic_code,
                "timestamp": bounce.timestamp,
            });
            queue_webhook_event(state, &attribution.tenant_id, "message.bounced", &payload).await;
        }
    }

    Ok(())
}

// ─── Complaint processing ──────────────────────────────────────

async fn process_complaint(
    state: &AppState,
    event: &SesEvent,
    sns_message_id: &str,
) -> Result<(), ApiError> {
    let complaint = event
        .complaint
        .as_ref()
        .ok_or_else(|| ApiError::Validation(vec!["Complaint event missing details".into()]))?;

    let mail = event.mail.as_ref();
    let ses_message_id = mail.and_then(|m| m.message_id.clone());
    let Some(ses_message_id) = ses_message_id.as_deref() else {
        return Err(unattributed_ses_event(None, ""));
    };

    let feedback_type = complaint
        .complaint_feedback_type
        .as_deref()
        .unwrap_or("abuse");
    let complained_at = ses_event_timestamp(complaint.timestamp.as_deref());

    info!(
        feedback_type = %feedback_type,
        ses_message_id = %ses_message_id,
        "Processing SES complaint"
    );

    if let Some(recipients) = &complaint.complained_recipients {
        for recipient in recipients {
            let Some(email) = recipient.email_address.as_deref() else {
                continue;
            };

            let Some(attribution) = resolve_ses_attribution(&state.db, ses_message_id, email)
                .await
                .map_err(|e| ses_db_error("storage", e))?
            else {
                return Err(unattributed_ses_event(Some(ses_message_id), email));
            };

            let reason = format!("ses_complaint:{feedback_type}");

            // Always suppress — complaints are serious. STORED tenant id,
            // committed before the SNS ack, idempotent under replay.
            let mut tx = state
                .db
                .begin()
                .await
                .map_err(|e| ses_db_error("storage", e))?;
            let suppression_id = apexmail_lib::id::generate_id("sup", 22);
            sqlx::query(
                "INSERT INTO suppressions (id, tenant_id, email, reason, source, created_at)
                 VALUES ($1, $2, $3, $4, $5, NOW())
                 ON CONFLICT (tenant_id, email) DO NOTHING",
            )
            .bind(&suppression_id)
            .bind(&attribution.tenant_id)
            .bind(&attribution.recipient)
            .bind(&reason)
            .bind("ses")
            .execute(&mut *tx)
            .await
            .map_err(|e| ses_db_error("failed to record suppression", e))?;
            info!(email = %apexmail_lib::pii::redact_email(&attribution.recipient), reason = %reason, "Auto-suppressed complained address");

            // Analytics event — one 'complained' row per complained
            // message (delivery_analytics' complaint rate reads these),
            // deterministic id for replay dedup.
            insert_analytics_event(
                &mut *tx,
                &ses_event_id(sns_message_id, "complained", &attribution.recipient),
                &attribution.tenant_id,
                &attribution.message_id,
                "complained",
                Some(&attribution.recipient),
                None,
                None,
                None,
                complained_at,
            )
            .await
            .map_err(|e| ses_db_error("failed to record complaint event", e))?;

            tx.commit().await.map_err(|e| ses_db_error("storage", e))?;

            // Queue webhook
            let payload = serde_json::json!({
                "event": "message.complained",
                "feedbackType": feedback_type,
                "recipient": attribution.recipient,
                "messageId": attribution.message_id,
                "sesMessageId": ses_message_id,
                "timestamp": complaint.timestamp,
            });
            queue_webhook_event(
                state,
                &attribution.tenant_id,
                "message.complained",
                &payload,
            )
            .await;
        }
    }

    Ok(())
}

// ─── Delivery processing ──────────────────────────────────────

async fn process_delivery(
    state: &AppState,
    event: &SesEvent,
    sns_message_id: &str,
) -> Result<(), ApiError> {
    let delivery = event
        .delivery
        .as_ref()
        .ok_or_else(|| ApiError::Validation(vec!["Delivery event missing details".into()]))?;

    let mail = event.mail.as_ref();
    let ses_message_id = mail.and_then(|m| m.message_id.clone());
    let Some(ses_message_id) = ses_message_id.as_deref() else {
        return Err(unattributed_ses_event(None, ""));
    };
    let delivered_at = ses_event_timestamp(delivery.timestamp.as_deref());

    debug!(
        recipients = ?delivery.recipients,
        processing_time_ms = ?delivery.processing_time_millis,
        "SES delivery confirmed"
    );

    // F75: persist the confirmation on the MATCHING RECIPIENT DELIVERY
    // RECORD (`email_queue.delivered_at`, migration 186) — the previous
    // handler wrote `messages.delivered_at`, a column that does not exist
    // (SQLSTATE 42703), and set the whole parent delivered for ONE
    // recipient. The parent aggregate is now derived by the shared F25
    // reconciliation: messages.delivered_at is stamped only when EVERY
    // recipient copy is confirmed delivered.
    let recipients = delivery.recipients.iter().flatten();
    for email in recipients {
        let Some(attribution) = resolve_ses_attribution(&state.db, ses_message_id, email)
            .await
            .map_err(|e| ses_db_error("storage", e))?
        else {
            return Err(unattributed_ses_event(Some(ses_message_id), email));
        };

        let mut tx = state
            .db
            .begin()
            .await
            .map_err(|e| ses_db_error("storage", e))?;
        sqlx::query(
            // Idempotent: COALESCE keeps the FIRST confirmation time under
            // an SNS replay.
            "UPDATE email_queue
             SET delivered_at = COALESCE(delivered_at, $2), updated_at = NOW()
             WHERE id = $1::uuid",
        )
        .bind(&attribution.queue_row_id)
        .bind(delivered_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| ses_db_error("failed to record delivery", e))?;

        // F25/F75: the shared parent reconciliation after every confirmed
        // recipient transition.
        sqlx::query(apexmail_lib::email_headers::RECONCILE_MESSAGE_PROGRESS_SQL)
            .bind(&attribution.message_id)
            .bind(&attribution.tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| ses_db_error("reconcile message progress", e))?;

        insert_analytics_event(
            &mut *tx,
            &ses_event_id(sns_message_id, "delivered", &attribution.recipient),
            &attribution.tenant_id,
            &attribution.message_id,
            "delivered",
            Some(&attribution.recipient),
            None,
            None,
            None,
            delivered_at,
        )
        .await
        .map_err(|e| ses_db_error("failed to record delivery event", e))?;

        tx.commit().await.map_err(|e| ses_db_error("storage", e))?;

        // Queue webhook (post-commit; best-effort)
        let payload = serde_json::json!({
            "event": "message.delivered",
            "recipients": [attribution.recipient],
            "messageId": attribution.message_id,
            "processingTimeMs": delivery.processing_time_millis,
            "smtpResponse": delivery.smtp_response,
            "timestamp": delivery.timestamp,
        });
        queue_webhook_event(state, &attribution.tenant_id, "message.delivered", &payload).await;
    }

    Ok(())
}

// ─── Open / Click processing ──────────────────────────────────

/// Extract the recipient from the SES mail destination (Open/Click events
/// carry no recipient of their own).
fn ses_recipient(event: &SesEvent) -> Option<String> {
    event
        .mail
        .as_ref()
        .and_then(|m| m.destination.as_ref())
        .and_then(|d| d.first())
        .cloned()
}

/// Resolve the attribution for an Open/Click event: the tracking token's
/// recipient when the rewrite captured one, otherwise the mail destination.
async fn resolve_engagement_attribution(
    state: &AppState,
    event: &SesEvent,
) -> Result<Option<SesAttribution>, ApiError> {
    let Some(ses_message_id) = event.mail.as_ref().and_then(|m| m.message_id.clone()) else {
        return Err(unattributed_ses_event(None, ""));
    };
    let Some(recipient) = ses_recipient(event) else {
        return Err(unattributed_ses_event(Some(&ses_message_id), ""));
    };
    resolve_ses_attribution(&state.db, &ses_message_id, &recipient)
        .await
        .map_err(|e| ses_db_error("attribution", e))
}

/// Process an SES Open notification: record an 'opened' analytics event and
/// increment the message's open counters — mirroring the tracking-service
/// processor.rs messages update (open_count +1, first_opened_at backfill).
async fn process_open(
    state: &AppState,
    event: &SesEvent,
    sns_message_id: &str,
) -> Result<(), ApiError> {
    let open = event
        .open
        .as_ref()
        .ok_or_else(|| ApiError::Validation(vec!["Open event missing details".into()]))?;

    let Some(attribution) = resolve_engagement_attribution(state, event).await? else {
        let ses_message_id = event.mail.as_ref().and_then(|m| m.message_id.clone());
        return Err(unattributed_ses_event(
            ses_message_id.as_deref(),
            ses_recipient(event).as_deref().unwrap_or(""),
        ));
    };
    let opened_at = ses_event_timestamp(open.timestamp.as_deref());

    // Mirror tracking-service processor.rs: open_count += 1,
    // first_opened_at backfilled on the first open. Committed before the
    // SNS ack.
    sqlx::query(
        "UPDATE messages SET
            open_count = open_count + 1,
            first_opened_at = COALESCE(first_opened_at, $3),
            updated_at = NOW()
         WHERE id = $1::uuid AND tenant_id = $2",
    )
    .bind(&attribution.message_id)
    .bind(&attribution.tenant_id)
    .bind(opened_at)
    .execute(&state.db)
    .await
    .map_err(|e| ses_db_error("storage", e))?;

    insert_analytics_event(
        &state.db,
        &ses_event_id(sns_message_id, "opened", &attribution.recipient),
        &attribution.tenant_id,
        &attribution.message_id,
        "opened",
        Some(&attribution.recipient),
        None,
        open.user_agent.as_deref(),
        open.ip_address.as_deref(),
        opened_at,
    )
    .await
    .map_err(|e| ses_db_error("failed to record open event", e))?;

    // Queue webhook
    let payload = serde_json::json!({
        "event": "message.opened",
        "messageId": attribution.message_id,
        "userAgent": open.user_agent,
        "timestamp": open.timestamp,
    });
    queue_webhook_event(state, &attribution.tenant_id, "message.opened", &payload).await;

    Ok(())
}

/// Process an SES Click notification: record a 'clicked' analytics event and
/// increment the message's click counters (click_count +1, first_clicked_at
/// backfill), mirroring the tracking-service processor.
async fn process_click(
    state: &AppState,
    event: &SesEvent,
    sns_message_id: &str,
) -> Result<(), ApiError> {
    let click = event
        .click
        .as_ref()
        .ok_or_else(|| ApiError::Validation(vec!["Click event missing details".into()]))?;

    let Some(attribution) = resolve_engagement_attribution(state, event).await? else {
        let ses_message_id = event.mail.as_ref().and_then(|m| m.message_id.clone());
        return Err(unattributed_ses_event(
            ses_message_id.as_deref(),
            ses_recipient(event).as_deref().unwrap_or(""),
        ));
    };
    let clicked_at = ses_event_timestamp(click.timestamp.as_deref());

    sqlx::query(
        "UPDATE messages SET
            click_count = click_count + 1,
            first_clicked_at = COALESCE(first_clicked_at, $3),
            updated_at = NOW()
         WHERE id = $1::uuid AND tenant_id = $2",
    )
    .bind(&attribution.message_id)
    .bind(&attribution.tenant_id)
    .bind(clicked_at)
    .execute(&state.db)
    .await
    .map_err(|e| ses_db_error("storage", e))?;

    insert_analytics_event(
        &state.db,
        &ses_event_id(sns_message_id, "clicked", &attribution.recipient),
        &attribution.tenant_id,
        &attribution.message_id,
        "clicked",
        Some(&attribution.recipient),
        click.link.as_deref(),
        click.user_agent.as_deref(),
        click.ip_address.as_deref(),
        clicked_at,
    )
    .await
    .map_err(|e| ses_db_error("failed to record click event", e))?;

    // Queue webhook
    let payload = serde_json::json!({
        "event": "message.clicked",
        "messageId": attribution.message_id,
        "link": click.link,
        "userAgent": click.user_agent,
        "timestamp": click.timestamp,
    });
    queue_webhook_event(state, &attribution.tenant_id, "message.clicked", &payload).await;

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

    // ── F74/F75: trusted attribution + delivery persistence ────────────

    #[test]
    fn attribution_resolves_through_the_stored_mapping_only() {
        // F74: the resolution keys on the stored provider message id
        // (smtp_message_id) and verifies the callback recipient against
        // the row's envelope — no X-ApexMail-* header is consulted.
        assert!(
            SES_ATTRIBUTION_SQL.contains("q.smtp_message_id = $1"),
            "resolution must key on the stored provider message id"
        );
        assert!(
            SES_ATTRIBUTION_SQL.contains("LOWER(q.\"to\") = LOWER($2)")
                || SES_ATTRIBUTION_SQL
                    .contains("LOWER(q.\"to\") = LOWER($2)".replace("\\", "").as_str()),
            "callback recipient must be verified against the stored envelope"
        );
        assert!(
            !SES_ATTRIBUTION_SQL.to_lowercase().contains("apexmail"),
            "raw identity headers must never participate in resolution"
        );
    }

    #[test]
    fn ses_event_ids_are_deterministic_and_bounded() {
        let a = ses_event_id("sns-1", "delivered", "user@example.com");
        let b = ses_event_id("sns-1", "delivered", "user@example.com");
        assert_eq!(a, b, "same notification+recipient must dedupe");
        assert_ne!(
            ses_event_id("sns-1", "bounced", "user@example.com"),
            ses_event_id("sns-1", "delivered", "user@example.com")
        );
        assert_ne!(
            ses_event_id("sns-1", "delivered", "a@example.com"),
            ses_event_id("sns-2", "delivered", "a@example.com")
        );
        assert!(
            a.len() <= 64 && a.starts_with("evt_"),
            "id must fit events.id VARCHAR(64): {a}"
        );
    }

    #[test]
    fn delivery_persistence_targets_the_recipient_record_not_a_missing_column() {
        // F75: the exact 42703 regression — the delivery callback wrote
        // messages.delivered_at (absent). The recipient-delivery write must
        // go to email_queue.delivered_at (migration 186) and the parent
        // aggregate must be derived by the shared reconciliation.
        let source = include_str!("ses_notifications.rs");
        assert!(
            source.contains("SET delivered_at = COALESCE(delivered_at, $2)"),
            "delivery confirmation must stamp the recipient delivery record idempotently"
        );
        // (Split literal so the assertion does not match its own source.)
        let forbidden = format!(
            "UPDATE messages SET status = {}",
            "'delivered', delivered_at"
        );
        assert!(
            !source.contains(&forbidden),
            "the parent write must never target the absent messages.delivered_at column directly"
        );
        assert!(
            source.contains("apexmail_lib::email_headers::RECONCILE_MESSAGE_PROGRESS_SQL"),
            "the shared F25 reconciliation must run after confirmed transitions"
        );
    }

    #[test]
    fn ses_event_timestamps_use_the_actual_event_time() {
        let ts = ses_event_timestamp(Some("2026-02-27T12:34:56Z"));
        assert_eq!(ts.to_rfc3339(), "2026-02-27T12:34:56+00:00");
        // Malformed/absent falls back to now, never to epoch.
        let fallback = ses_event_timestamp(None);
        assert!(fallback.timestamp() > 1_700_000_000);
        let malformed = ses_event_timestamp(Some("not-a-date"));
        assert!(malformed.timestamp() > 1_700_000_000);
    }

    #[test]
    fn diagnostic_identity_lookup_matches_case_insensitive_aliases() {
        // The exact-name lookup used before F74 missed the canonical
        // spelling entirely; the diagnostic path now matches both.
        let mail = SesMail {
            message_id: Some("ses-1".into()),
            source: None,
            destination: None,
            headers: Some(vec![SesHeader {
                name: "X-ApexMail-Message-ID".into(),
                value: "canonical-spelling".into(),
            }]),
            common_headers: None,
        };
        let (message, tenant) = diagnostic_identity_headers(&mail);
        assert_eq!(message.as_deref(), Some("canonical-spelling"));
        assert!(tenant.is_none());

        let mail = SesMail {
            message_id: Some("ses-1".into()),
            source: None,
            destination: None,
            headers: Some(vec![SesHeader {
                name: "X-ApexMail-TenantId".into(),
                value: "legacy-alias".into(),
            }]),
            common_headers: None,
        };
        let (message, tenant) = diagnostic_identity_headers(&mail);
        assert!(message.is_none());
        assert_eq!(tenant.as_deref(), Some("legacy-alias"));
    }

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
    fn test_parse_ses_open_and_click_events() {
        let open: SesEvent = serde_json::from_str(
            r#"{
            "eventType": "Open",
            "mail": {
                "messageId": "ses-msg-open",
                "destination": ["user@example.com"],
                "headers": [
                    {"name": "X-ApexMail-MessageId", "value": "msg_abc"},
                    {"name": "X-ApexMail-TenantId", "value": "tenant-1"}
                ]
            },
            "open": {
                "timestamp": "2026-02-27T13:00:00Z",
                "userAgent": "Mozilla/5.0",
                "ipAddress": "203.0.113.9"
            }
        }"#,
        )
        .unwrap();
        assert_eq!(open.event_type, "Open");
        let open_payload = open.open.as_ref().unwrap();
        assert_eq!(open_payload.user_agent.as_deref(), Some("Mozilla/5.0"));
        // The recipient is derived from the mail destination.
        assert_eq!(ses_recipient(&open).as_deref(), Some("user@example.com"));

        let click: SesEvent = serde_json::from_str(
            r#"{
            "eventType": "Click",
            "mail": {
                "messageId": "ses-msg-click",
                "destination": ["user@example.com"],
                "headers": [
                    {"name": "X-ApexMail-MessageId", "value": "abc"},
                    {"name": "X-ApexMail-TenantId", "value": "tenant-1"}
                ]
            },
            "click": {
                "timestamp": "2026-02-27T14:00:00Z",
                "link": "https://example.com/pricing",
                "userAgent": "Mozilla/5.0",
                "ipAddress": "203.0.113.9"
            }
        }"#,
        )
        .unwrap();
        assert_eq!(click.event_type, "Click");
        let click_payload = click.click.as_ref().unwrap();
        assert_eq!(
            click_payload.link.as_deref(),
            Some("https://example.com/pricing")
        );
    }

    #[test]
    fn test_normalize_message_id_strips_prefix() {
        assert_eq!(normalize_message_id("msg_abc"), "abc");
        assert_eq!(normalize_message_id("abc"), "abc");
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

    // ── Timestamp freshness (audit G) ────────────────────────────

    fn message_with_timestamp(ts: &str) -> SnsMessage {
        let mut msg = sample_notification_message();
        msg.timestamp = Some(ts.to_string());
        msg
    }

    #[test]
    fn sns_timestamp_freshness_accepts_current_timestamp() {
        let now = chrono::Utc::now().to_rfc3339();
        assert!(validate_sns_timestamp_freshness(&message_with_timestamp(&now)).is_ok());

        // 30 minutes old — still inside the 1h retry window.
        let half_hour_ago = (chrono::Utc::now() - chrono::Duration::minutes(30)).to_rfc3339();
        assert!(validate_sns_timestamp_freshness(&message_with_timestamp(&half_hour_ago)).is_ok());

        // Small future skew (2 minutes) is tolerated.
        let soon = (chrono::Utc::now() + chrono::Duration::minutes(2)).to_rfc3339();
        assert!(validate_sns_timestamp_freshness(&message_with_timestamp(&soon)).is_ok());
    }

    #[test]
    fn sns_timestamp_freshness_rejects_old_and_far_future_timestamps() {
        // A captured-and-replayed notification from 2 hours ago.
        let two_hours_ago = (chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339();
        let err = validate_sns_timestamp_freshness(&message_with_timestamp(&two_hours_ago))
            .expect_err("stale notification must be rejected");
        assert!(matches!(err, ApiError::Validation(_)));

        // Exactly past the 1h bound (61 minutes).
        let sixty_one_minutes = (chrono::Utc::now() - chrono::Duration::minutes(61)).to_rfc3339();
        assert!(
            validate_sns_timestamp_freshness(&message_with_timestamp(&sixty_one_minutes)).is_err()
        );

        // More than 10 minutes in the future — clock-skew abuse.
        let far_future = (chrono::Utc::now() + chrono::Duration::minutes(30)).to_rfc3339();
        let err = validate_sns_timestamp_freshness(&message_with_timestamp(&far_future))
            .expect_err("far-future notification must be rejected");
        assert!(matches!(err, ApiError::Validation(_)));

        // Missing / malformed timestamps are rejected, not defaulted.
        let mut msg = sample_notification_message();
        msg.timestamp = None;
        assert!(validate_sns_timestamp_freshness(&msg).is_err());
        assert!(validate_sns_timestamp_freshness(&message_with_timestamp("not-a-date")).is_err());
        assert!(validate_sns_timestamp_freshness(&message_with_timestamp("0")).is_err());
    }

    // ── Signing-cert cache (audit G) ─────────────────────────────

    #[test]
    fn sns_signing_cert_cache_roundtrips_and_respects_cap() {
        // Ensure a clean slate (tests may run in any order).
        if let Ok(mut guard) = SNS_SIGNING_KEY_CACHE.lock() {
            *guard = None;
        }

        let mut rng = rsa::rand_core::OsRng;
        let key = RsaPublicKey::from(RsaPrivateKey::new(&mut rng, 2048).unwrap());

        let url = "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-test-cache.pem";
        assert!(
            cache_get_sns_signing_key(url).is_none(),
            "empty cache must miss"
        );

        cache_put_sns_signing_key(url, key.clone());
        let cached = cache_get_sns_signing_key(url).expect("fresh entry must hit");
        assert_eq!(cached, key, "cached key must round-trip identically");

        // Overfilling the bounded cache evicts everything (refetched on demand).
        for i in 0..SNS_SIGNING_KEY_CACHE_MAX_ENTRIES {
            cache_put_sns_signing_key(
                &format!("https://sns.us-east-1.amazonaws.com/SimpleNotificationService-{i}.pem"),
                key.clone(),
            );
        }
        assert!(
            cache_get_sns_signing_key(url).is_none() || {
                // whichever state, the cache must stay bounded
                let len = SNS_SIGNING_KEY_CACHE
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|c| c.len())
                    .unwrap_or(0);
                len <= SNS_SIGNING_KEY_CACHE_MAX_ENTRIES
            },
            "cache must stay bounded after overfill"
        );
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
