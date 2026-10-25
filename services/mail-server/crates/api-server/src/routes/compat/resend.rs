//! Resend compatibility: `POST /emails` and `POST /emails/batch`.
//!
//! Auth: `Authorization: Bearer <ApexMail API key>`.
//! Success: `200` `{"id":"<canonical message id>"}` (batch: `{"data":[…]}`).
//! Errors: Resend's `{"statusCode","name","message"}`.
//!
//! ## Mapping table (Resend field → canonical send field)
//!
//! | Resend | canonical |
//! |----------|-----------|
//! | `from` | `from` |
//! | `to` (string or array) | `to` |
//! | `cc` / `bcc` | `cc` / `bcc` |
//! | `subject` | `subject` |
//! | `html` / `text` | `html` / `text` |
//! | `reply_to` | `reply_to` |
//! | `headers` (object) | `headers` |
//! | `attachments[].filename`/`.content`/`.content_type` | `attachments[].filename`/`.content`/`.contentType` |
//! | `tags[].name`/`.value` | `tags` (`"name:value"`) |
//! | `scheduled_at` (ISO 8601) | `scheduled_at` |
//! | `Idempotency-Key` header | the canonical durable idempotency ledger |
//! | `X-ApexMail-Category` header | `category` (validated by the canonical normalizer) |
//!
//! ## Named refusals (never a silent drop)
//!
//! * `attachments[].path` (remote URL fetching is not offered; send the
//!   base64 `content` instead);
//! * `template`, `topic_id`, `audience_id`, `broadcast_id` (no canonical
//!   equivalent, audiences/broadcasts are ApexMail campaigns/lists);
//! * natural-language `scheduled_at` ("in 1 min"), an ISO 8601 timestamp is
//!   required;
//! * batch arrays longer than Resend's documented 100 ceiling.

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};

use super::{
    canonical_message_id, category_override, content_type, dispatch_and_decode,
    dispatch_batch_and_decode, idempotency_key, json_type_name, map_mailbox_list, map_object,
    map_required_str, map_str, provider_error, provider_error_from_outcome, read_compat_request,
    reject_unknown_fields, request_auth, string_map, unsupported, CompatRequest, MappingIssues,
    Provider,
};
use crate::routes::messages::{SendAttachment, SendMessageRequest};
use crate::state::AppState;

const PROVIDER: Provider = Provider::Resend;

/// Resend's documented batch ceiling.
const MAX_BATCH: usize = 100;

const ALLOWED_TOP_LEVEL: [&str; 16] = [
    "from",
    "to",
    "cc",
    "bcc",
    "subject",
    "html",
    "text",
    "reply_to",
    "headers",
    "attachments",
    "tags",
    "scheduled_at",
    "template",
    "topic_id",
    "audience_id",
    "broadcast_id",
];

pub fn router(state: AppState) -> Router<AppState> {
    super::provider_layers(
        Router::new()
            .route("/emails", post(send))
            .route("/emails/batch", post(send_batch)),
        state,
        PROVIDER,
    )
}

async fn send(State(state): State<AppState>, req: Request) -> Response {
    let auth = match request_auth(PROVIDER, &req) {
        Ok(auth) => auth,
        Err(refusal) => return refusal,
    };
    let CompatRequest { headers, body } = match read_compat_request(PROVIDER, req).await {
        Ok(request) => request,
        Err(refusal) => return refusal,
    };
    let root = match json_object_body(&headers, &body) {
        Ok(root) => root,
        Err(refusal) => return refusal,
    };

    let mut issues = MappingIssues::default();
    let mapped = map_email(&root, category_override(&headers), &mut issues);
    if !issues.is_empty() {
        return provider_error(
            PROVIDER,
            StatusCode::UNPROCESSABLE_ENTITY,
            &issues.into_vec().join("; "),
            &[],
        );
    }

    let outcome = match dispatch_and_decode(
        PROVIDER,
        &state,
        &auth,
        idempotency_key(&headers).as_deref(),
        mapped,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(refusal) => return refusal,
    };
    if !outcome.status.is_success() {
        return provider_error_from_outcome(PROVIDER, &outcome);
    }
    let message_id = match canonical_message_id(PROVIDER, &outcome) {
        Ok(id) => id,
        Err(refusal) => return refusal,
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({ "id": message_id })),
    )
        .into_response()
}

async fn send_batch(State(state): State<AppState>, req: Request) -> Response {
    let auth = match request_auth(PROVIDER, &req) {
        Ok(auth) => auth,
        Err(refusal) => return refusal,
    };
    let CompatRequest { headers, body } = match read_compat_request(PROVIDER, req).await {
        Ok(request) => request,
        Err(refusal) => return refusal,
    };
    if content_type(&headers) != "application/json" {
        return provider_error(
            PROVIDER,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "the Resend compatibility surface accepts application/json bodies",
            &[],
        );
    }
    let parsed: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(error) => {
            return provider_error(
                PROVIDER,
                StatusCode::BAD_REQUEST,
                &format!("invalid JSON body: {error}"),
                &[],
            )
        }
    };
    let Some(items) = parsed.as_array() else {
        return provider_error(
            PROVIDER,
            StatusCode::BAD_REQUEST,
            "the batch body must be a JSON array of emails",
            &[],
        );
    };
    if items.is_empty() {
        return provider_error(
            PROVIDER,
            StatusCode::BAD_REQUEST,
            "the batch body must contain at least one email",
            &[],
        );
    }
    if items.len() > MAX_BATCH {
        return provider_error(
            PROVIDER,
            StatusCode::BAD_REQUEST,
            &format!(
                "a Resend batch carries at most {MAX_BATCH} emails (received {})",
                items.len()
            ),
            &[],
        );
    }

    let category = category_override(&headers);
    let mut issues = Vec::new();
    let mut mapped = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let Some(item) = item.as_object() else {
            issues.push(format!("batch item {index} must be a JSON object"));
            continue;
        };
        let mut item_issues = MappingIssues::default();
        let email = map_email(item, category.clone(), &mut item_issues);
        for issue in item_issues.into_vec() {
            issues.push(format!("batch item {index}: {issue}"));
        }
        mapped.push(email);
    }
    if !issues.is_empty() {
        return provider_error(
            PROVIDER,
            StatusCode::UNPROCESSABLE_ENTITY,
            &issues.join("; "),
            &[],
        );
    }

    let outcome = match dispatch_batch_and_decode(
        PROVIDER,
        &state,
        &auth,
        idempotency_key(&headers).as_deref(),
        mapped,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(refusal) => return refusal,
    };
    if !outcome.status.is_success() {
        return provider_error_from_outcome(PROVIDER, &outcome);
    }

    // Resend answers `{"data":[{"id": …}, …]}` in request order; a rejected
    // item carries its refusal instead of an id, so a partial batch is never
    // reported as a full success.
    let requested = items.len();
    let mut data: Vec<Value> = (0..requested)
        .map(|index| {
            serde_json::json!({
                "error": {
                    "statusCode": 500,
                    "name": "internal_server_error",
                    "message": format!(
                        "the send path returned no result for batch item {index}; contact support with the ids you received"
                    ),
                }
            })
        })
        .collect();
    let canonical_results = outcome
        .success_data()
        .and_then(|data| data.get("results"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for result in canonical_results {
        let Some(index) = result.get("index").and_then(Value::as_u64) else {
            continue;
        };
        let Some(slot) = data.get_mut(index as usize) else {
            continue;
        };
        *slot = match result.get("id").and_then(Value::as_str) {
            Some(id) => serde_json::json!({ "id": id }),
            None => serde_json::json!({
                "error": {
                    "statusCode": 422,
                    "name": "validation_error",
                    "message": result
                        .get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("the message was refused"),
                }
            }),
        };
    }
    (StatusCode::OK, Json(serde_json::json!({ "data": data }))).into_response()
}

fn json_object_body(
    headers: &axum::http::HeaderMap,
    body: &[u8],
) -> Result<Map<String, Value>, Response> {
    if content_type(headers) != "application/json" {
        return Err(provider_error(
            PROVIDER,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "the Resend compatibility surface accepts application/json bodies",
            &[],
        ));
    }
    let parsed: Value = serde_json::from_slice(body).map_err(|error| {
        provider_error(
            PROVIDER,
            StatusCode::BAD_REQUEST,
            &format!("invalid JSON body: {error}"),
            &[],
        )
    })?;
    match parsed {
        Value::Object(map) => Ok(map),
        _ => Err(provider_error(
            PROVIDER,
            StatusCode::BAD_REQUEST,
            "the request body must be a JSON object",
            &[],
        )),
    }
}

fn map_email(
    root: &Map<String, Value>,
    category: Option<String>,
    issues: &mut MappingIssues,
) -> SendMessageRequest {
    reject_unknown_fields(root, &ALLOWED_TOP_LEVEL, "", issues);

    // Fields with no canonical equivalent: named refusals, never silent
    // drops (a template/broadcast id silently ignored would send the wrong
    // body).
    for field in ["template", "topic_id", "audience_id", "broadcast_id"] {
        if root.get(field).is_some_and(|value| !value.is_null()) {
            issues.push(unsupported(
                field,
                "audiences, topics, broadcasts and Resend templates have no canonical equivalent on this surface, use the ApexMail /v1 API for templates and lists",
            ));
        }
    }

    let from = map_required_str(root, "from", issues).unwrap_or_default();
    let to = map_mailbox_list(root, "to", issues).unwrap_or_default();
    if root.get("to").is_none() {
        issues.push("field 'to' is required");
    }
    let cc = map_mailbox_list(root, "cc", issues).unwrap_or_default();
    let bcc = map_mailbox_list(root, "bcc", issues).unwrap_or_default();
    let subject = map_str(root, "subject", issues).unwrap_or_default();
    let html = map_str(root, "html", issues);
    let text = map_str(root, "text", issues);
    let reply_to = map_str(root, "reply_to", issues);

    let headers = match map_object(root, "headers", issues) {
        Some(map) => string_map(&map, "headers", issues),
        None => Map::new(),
    };

    let attachments = map_attachments(root, issues);
    let tags = map_tags(root, issues);
    let scheduled_at = map_scheduled_at(root, issues);

    SendMessageRequest {
        from,
        to,
        cc: (!cc.is_empty()).then_some(cc),
        bcc: (!bcc.is_empty()).then_some(bcc),
        subject,
        html,
        text,
        tags: (!tags.is_empty()).then_some(tags),
        metadata: None,
        scheduled_at,
        reply_to,
        headers: (!headers.is_empty()).then_some(Value::Object(headers)),
        attachments: (!attachments.is_empty()).then_some(attachments),
        priority: None,
        category,
        template_id: None,
        template_data: None,
    }
}

fn map_attachments(root: &Map<String, Value>, issues: &mut MappingIssues) -> Vec<SendAttachment> {
    let mut attachments = Vec::new();
    match root.get("attachments") {
        None | Some(Value::Null) => {}
        Some(Value::Array(list)) => {
            for (index, attachment) in list.iter().enumerate() {
                let Some(attachment) = attachment.as_object() else {
                    issues.push(format!(
                        "field 'attachments[{index}]' must be a JSON object"
                    ));
                    continue;
                };
                reject_unknown_fields(
                    attachment,
                    &["filename", "content", "path", "content_type"],
                    &format!("attachments[{index}]."),
                    issues,
                );
                if attachment.get("path").is_some_and(|value| !value.is_null()) {
                    issues.push(unsupported(
                        &format!("attachments[{index}].path"),
                        "remote attachment URLs are not fetched, send the file as base64 `content`",
                    ));
                }
                let filename = map_required_str(attachment, "filename", issues);
                let content = map_required_str(attachment, "content", issues);
                let content_type = map_str(attachment, "content_type", issues)
                    .unwrap_or_else(|| "application/octet-stream".to_string());
                if let (Some(filename), Some(content)) = (filename, content) {
                    attachments.push(SendAttachment {
                        filename,
                        content,
                        content_type,
                    });
                }
            }
        }
        Some(_) => issues.push("field 'attachments' must be an array"),
    }
    attachments
}

/// Resend tags are `{name, value}` pairs; the canonical contract carries
/// free-form tag strings, so each pair becomes `"name:value"`.
fn map_tags(root: &Map<String, Value>, issues: &mut MappingIssues) -> Vec<String> {
    let Some(tags) = root.get("tags") else {
        return Vec::new();
    };
    let Some(tags) = tags.as_array() else {
        issues.push("field 'tags' must be an array of {name, value} objects");
        return Vec::new();
    };
    let mut out = Vec::new();
    for (index, tag) in tags.iter().enumerate() {
        let Some(tag) = tag.as_object() else {
            issues.push(format!("field 'tags[{index}]' must be a JSON object"));
            continue;
        };
        let name = map_required_str(tag, "name", issues);
        let value = map_str(tag, "value", issues).unwrap_or_default();
        if let Some(name) = name {
            out.push(if value.is_empty() {
                name
            } else {
                format!("{name}:{value}")
            });
        }
    }
    out
}

/// `scheduled_at`: an ISO 8601 / RFC 3339 timestamp. Resend's natural
/// language form is refused by name.
fn map_scheduled_at(
    root: &Map<String, Value>,
    issues: &mut MappingIssues,
) -> Option<DateTime<Utc>> {
    let raw = match root.get("scheduled_at") {
        None | Some(Value::Null) => return None,
        Some(Value::String(text)) => text.clone(),
        Some(other) => {
            issues.push(format!(
                "field 'scheduled_at' must be an ISO 8601 timestamp string (received {})",
                json_type_name(other)
            ));
            return None;
        }
    };
    match DateTime::parse_from_rfc3339(&raw) {
        Ok(timestamp) => Some(timestamp.with_timezone(&Utc)),
        Err(_) => {
            issues.push(format!(
                "field 'scheduled_at' ('{raw}') must be an ISO 8601 timestamp (RFC 3339); natural-language schedules are not supported"
            ));
            None
        }
    }
}
