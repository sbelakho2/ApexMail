//! HTTP route handlers for the edge-cases service.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{DefaultBodyLimit, Json, Path, State},
    http::StatusCode,
    middleware,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use tower_http::timeout::TimeoutLayer;

use crate::services::{
    attachment::{Attachment, AttachmentService},
    calendar::{Attendee, CalendarMethod, CalendarService, Organizer},
    delivery::{DeliveryService, SMTPResponse},
    eai::EAIService,
};

// ── shared state ───────────────────────────────────────────────────────────────

pub struct AppState {
    pub eai: EAIService,
    pub attachment: AttachmentService,
    pub calendar: CalendarService,
    pub delivery: DeliveryService,
    pub api_key: String,
}

// ── router ─────────────────────────────────────────────────────────────────────

pub fn router(state: Arc<AppState>) -> Router {
    let shared = state.clone();
    Router::new()
        // EAI
        .route("/eai/validate", post(eai_validate))
        .route("/eai/parse", post(eai_parse))
        .route("/eai/normalize", post(eai_normalize))
        // Attachments
        .route("/attachments/validate", post(attachments_validate))
        .route("/attachments/size-check", post(attachments_size_check))
        .route("/attachments/stats", post(attachments_stats))
        // Calendar
        .route("/calendar/invite", post(calendar_create_invite))
        .route("/calendar/parse", post(calendar_parse))
        .route("/calendar/generate-ics", post(calendar_generate_ics))
        // Delivery
        .route("/delivery/parse-response", post(delivery_parse_response))
        .route("/delivery/retry-schedule", post(delivery_retry_schedule))
        .route("/delivery/detect-loop", post(delivery_detect_loop))
        .route(
            "/delivery/detect-autoresponder",
            post(delivery_detect_autoresponder),
        )
        .route("/delivery/mx/:domain", get(delivery_mx))
        .route("/delivery/history/:message_id", get(delivery_history))
        .route(
            "/delivery/greylist-check/:domain",
            get(delivery_greylist_check),
        )
        // Health
        .route("/health", get(health))
        .route("/health/ready", get(health))
        .route("/health/live", get(health))
        .with_state(state)
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024)) // 10 MB — attachment validation accepts base64
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .layer(middleware::from_fn_with_state(shared, require_api_key))
}

async fn require_api_key(
    State(state): State<Arc<AppState>>,
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    let path = request.uri().path();
    if path.starts_with("/health") {
        return Ok(next.run(request).await);
    }

    if state.api_key.trim().is_empty() {
        return Ok(next.run(request).await);
    }

    let provided = request
        .headers()
        .get("x-api-key")
        .and_then(|value| value.to_str().ok());
    if !provided.is_some_and(|k| apexmail_lib::timing_safe_compare(k, &state.api_key)) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(request).await)
}

// ── request/response types ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct EAIValidateRequest {
    emails: Vec<String>,
}

#[derive(Deserialize)]
struct EAIParseRequest {
    email: String,
    #[serde(default)]
    display_name: Option<String>,
}

#[derive(Deserialize)]
struct EAINormalizeRequest {
    content: String,
    #[serde(default)]
    charset: Option<String>,
}

#[derive(Deserialize)]
struct AttachmentsValidateRequest {
    attachments: Vec<AttachmentInput>,
}

#[derive(Deserialize, Clone)]
struct AttachmentInput {
    filename: String,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default)]
    size: Option<usize>,
    #[serde(default)]
    data: Option<String>, // base64-encoded content
    #[serde(default = "default_disposition")]
    disposition: String,
    #[serde(default)]
    content_id: Option<String>,
}

fn default_disposition() -> String {
    "attachment".into()
}

#[derive(Deserialize)]
struct SizeCheckRequest {
    size: usize,
}

#[derive(Deserialize)]
struct AttachmentStatsRequest {
    attachments: Vec<AttachmentInput>,
}

#[derive(Deserialize)]
struct CalendarInviteRequest {
    method: String,
    summary: String,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    organizer_email: String,
    #[serde(default)]
    organizer_name: Option<String>,
    #[serde(default)]
    attendees: Vec<AttendeeInput>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    all_day: bool,
}

#[derive(Deserialize)]
struct AttendeeInput {
    email: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default = "default_role")]
    role: String,
    #[serde(default = "default_part_stat")]
    part_stat: String,
    #[serde(default)]
    rsvp: bool,
}

fn default_role() -> String {
    "REQ-PARTICIPANT".into()
}
fn default_part_stat() -> String {
    "NEEDS-ACTION".into()
}

#[derive(Deserialize)]
struct CalendarParseRequest {
    ics: String,
}

#[derive(Deserialize)]
struct CalendarGenerateIcsRequest {
    method: String,
    summary: String,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    organizer_email: String,
    #[serde(default)]
    organizer_name: Option<String>,
    #[serde(default)]
    attendees: Vec<AttendeeInput>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    all_day: bool,
}

#[derive(Deserialize)]
struct DeliveryParseRequest {
    code: u16,
    message: String,
}

#[derive(Deserialize)]
struct RetryScheduleRequest {
    response: SMTPResponse,
    current_attempt: u32,
}

#[derive(Deserialize)]
struct LoopDetectRequest {
    received_headers: Vec<String>,
}

#[derive(Deserialize)]
struct AutoResponderRequest {
    headers: HashMap<String, String>,
    subject: String,
    #[serde(default)]
    body: Option<String>,
}

// ── EAI handlers ───────────────────────────────────────────────────────────────

async fn eai_validate(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EAIValidateRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state.eai.validate_emails(&req.emails).await {
        Ok(results) => Ok(Json(serde_json::json!({ "results": results }))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

async fn eai_parse(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EAIParseRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state
        .eai
        .parse_email_address(&req.email, req.display_name.as_deref())
        .await
    {
        Ok(parsed) => serialize_or_500(&parsed),
        Err(e) => Err((StatusCode::BAD_REQUEST, e.to_string())),
    }
}

async fn eai_normalize(
    Json(req): Json<EAINormalizeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let result = crate::services::eai::normalize_content(&req.content, req.charset.as_deref());
    serialize_or_500(&result)
}

// ── Attachment handlers ────────────────────────────────────────────────────────

fn input_to_attachment(input: &AttachmentInput) -> Attachment {
    let content = input
        .data
        .as_deref()
        .and_then(|d| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.decode(d).ok()
        })
        .unwrap_or_default();
    let size = input.size.unwrap_or(content.len());
    Attachment {
        filename: input.filename.clone(),
        content_type: input.content_type.clone(),
        content,
        size,
        disposition: input.disposition.clone(),
        content_id: input.content_id.clone(),
    }
}

async fn attachments_validate(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AttachmentsValidateRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let attachments: Vec<Attachment> = req.attachments.iter().map(input_to_attachment).collect();
    let result = state.attachment.validate_attachments(&attachments).await;
    serialize_or_500(&result)
}

async fn attachments_size_check(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SizeCheckRequest>,
) -> Json<serde_json::Value> {
    let max = state.attachment.max_single_size();
    Json(serde_json::json!({
        "size": req.size,
        "max_single_size": max,
        "within_limit": req.size <= max,
    }))
}

async fn attachments_stats(
    Json(req): Json<AttachmentStatsRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let attachments: Vec<Attachment> = req.attachments.iter().map(input_to_attachment).collect();
    let stats = AttachmentService::get_attachment_stats(&attachments);
    serialize_or_500(&stats)
}

// ── Calendar handlers ──────────────────────────────────────────────────────────

async fn calendar_create_invite(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CalendarInviteRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let method: CalendarMethod = req
        .method
        .parse()
        .map_err(|e: String| (StatusCode::BAD_REQUEST, e))?;

    let organizer = Organizer {
        email: req.organizer_email,
        name: req.organizer_name,
    };
    let attendees: Vec<Attendee> = req
        .attendees
        .into_iter()
        .map(|a| Attendee {
            email: a.email,
            name: a.name,
            role: a.role,
            part_stat: a.part_stat,
            rsvp: a.rsvp,
        })
        .collect();

    let invite = state
        .calendar
        .create_invite(
            &req.summary,
            req.start,
            req.end,
            organizer,
            attendees,
            req.description,
            req.location,
            method,
            req.all_day,
        )
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "ics": invite.ics_content,
        "html_preview": invite.html_preview,
    })))
}

async fn calendar_parse(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CalendarParseRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let parsed = state
        .calendar
        .parse_ics(&req.ics)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    serialize_or_500(&parsed)
}

async fn calendar_generate_ics(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CalendarGenerateIcsRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let method: CalendarMethod = req
        .method
        .parse()
        .map_err(|e: String| (StatusCode::BAD_REQUEST, e))?;

    let organizer = Organizer {
        email: req.organizer_email,
        name: req.organizer_name,
    };
    let attendees: Vec<Attendee> = req
        .attendees
        .into_iter()
        .map(|a| Attendee {
            email: a.email,
            name: a.name,
            role: a.role,
            part_stat: a.part_stat,
            rsvp: a.rsvp,
        })
        .collect();

    let invite = state
        .calendar
        .create_invite(
            &req.summary,
            req.start,
            req.end,
            organizer,
            attendees,
            req.description,
            req.location,
            method,
            req.all_day,
        )
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    Ok(Json(serde_json::json!({ "ics": invite.ics_content })))
}

// ── Delivery handlers ──────────────────────────────────────────────────────────

async fn delivery_parse_response(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DeliveryParseRequest>,
) -> Json<SMTPResponse> {
    Json(state.delivery.parse_smtp_response(req.code, &req.message))
}

async fn delivery_retry_schedule(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RetryScheduleRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state
        .delivery
        .calculate_retry_schedule(&req.response, req.current_attempt)
    {
        Some(schedule) => serialize_or_500(&schedule),
        None => Ok(Json(
            serde_json::json!({"retry": false, "reason": "permanent failure or max retries reached"}),
        )),
    }
}

async fn delivery_detect_loop(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoopDetectRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let result = state.delivery.detect_loop(&req.received_headers);
    serialize_or_500(&result)
}

async fn delivery_detect_autoresponder(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AutoResponderRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let result =
        state
            .delivery
            .detect_auto_responder(&req.headers, &req.subject, req.body.as_deref());
    serialize_or_500(&result)
}

async fn delivery_mx(
    State(state): State<Arc<AppState>>,
    Path(domain): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state.delivery.resolve_mx(&domain).await {
        Ok(records) => serialize_or_500(&records),
        Err(e) => Err((StatusCode::NOT_FOUND, e.to_string())),
    }
}

async fn delivery_history(
    State(state): State<Arc<AppState>>,
    Path(message_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state.delivery.get_delivery_history(&message_id).await {
        Ok(history) => serialize_or_500(&history),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

async fn delivery_greylist_check(
    State(state): State<Arc<AppState>>,
    Path(domain): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let is_known = state
        .delivery
        .is_known_greylister(&domain)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(
        serde_json::json!({ "domain": domain, "known_greylister": is_known }),
    ))
}

// ── Health ─────────────────────────────────────────────────────────────────────

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Serialize `val` to a `Json<Value>`, returning `500` if serialization fails.
fn serialize_or_500<T: serde::Serialize>(
    val: &T,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    serde_json::to_value(val).map(Json).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("serialization error: {e}"),
        )
    })
}

// ── CalendarMethod parse from string ───────────────────────────────────────────

impl std::str::FromStr for CalendarMethod {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "REQUEST" => Ok(CalendarMethod::Request),
            "REPLY" => Ok(CalendarMethod::Reply),
            "CANCEL" => Ok(CalendarMethod::Cancel),
            "ADD" => Ok(CalendarMethod::Add),
            "REFRESH" => Ok(CalendarMethod::Refresh),
            "COUNTER" => Ok(CalendarMethod::Counter),
            "DECLINECOUNTER" => Ok(CalendarMethod::DeclineCounter),
            "PUBLISH" => Ok(CalendarMethod::Publish),
            _ => Err(format!("Unknown calendar method: {s}")),
        }
    }
}
