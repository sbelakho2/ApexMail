//! Postmark compatibility: `POST /email` and `POST /email/batch`.
//!
//! Auth: `X-Postmark-Server-Token: <ApexMail API key>`.
//! Success: `200` `{"ErrorCode":0,"Message":"OK","MessageID":"<canonical id>"}`
//! (batch: the same object per message, in request order).
//! Errors: Postmark's `{"ErrorCode":<code>,"Message":"…"}`.
//!
//! ## Mapping table (Postmark field → canonical send field)
//!
//! | Postmark | canonical |
//! |----------|-----------|
//! | `From` | `from` |
//! | `To` | `to` |
//! | `Cc` / `Bcc` | `cc` / `bcc` |
//! | `Subject` | `subject` |
//! | `HtmlBody` / `TextBody` | `html` / `text` |
//! | `ReplyTo` | `reply_to` |
//! | `Headers[].Name`/`.Value` | `headers` (`Reply-To` is folded into `reply_to`) |
//! | `Attachments[].Name`/`.Content`/`.ContentType` | `attachments[].filename`/`.content`/`.contentType` |
//! | `Tag` | `tags` (one tag) |
//! | `Metadata` (string values) | `metadata` |
//! | `MessageStream` `outbound`/`broadcast` | `category` `transactional`/`marketing` |
//! | `TrackOpens`/`TrackLinks` `true` | accepted no-op (the platform tracks both) |
//! | `X-ApexMail-Category` header | `category` (validated by the canonical normalizer) |
//!
//! ## Named refusals (never a silent drop)
//!
//! * `TemplateId` / `TemplateAlias` / `TemplateModel` (Postmark template ids
//!   are not ApexMail template ids);
//! * `Attachments[].ContentID` and `InlineImages` (no canonical inline part);
//! * `TrackOpens: false` / `TrackLinks: false` (per-message tracking cannot be
//!   disabled on this surface);
//! * any other `MessageStream` value than the two above;
//! * batch arrays longer than Postmark's documented 500 ceiling.

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{Map, Value};

use super::{
    canonical_message_id, category_override, content_type, dispatch_and_decode,
    dispatch_batch_and_decode, idempotency_key, json_type_name, map_object, map_required_str,
    map_str, provider_error, provider_error_from_outcome, read_compat_request,
    reject_unknown_fields, request_auth, string_map, unsupported, CompatRequest, MappingIssues,
    Provider,
};
use crate::routes::messages::{SendAttachment, SendMessageRequest};
use crate::state::AppState;

const PROVIDER: Provider = Provider::Postmark;

/// Postmark's documented batch ceiling.
const MAX_BATCH: usize = 500;

const ALLOWED_TOP_LEVEL: [&str; 19] = [
    "From",
    "To",
    "Cc",
    "Bcc",
    "Subject",
    "HtmlBody",
    "TextBody",
    "ReplyTo",
    "Headers",
    "Attachments",
    "Tag",
    "Metadata",
    "MessageStream",
    "TrackOpens",
    "TrackLinks",
    "TemplateId",
    "TemplateAlias",
    "TemplateModel",
    "InlineImages",
];

pub fn router(state: AppState) -> Router<AppState> {
    super::provider_layers(
        Router::new()
            .route("/email", post(send))
            .route("/email/batch", post(send_batch)),
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
    let mapped = map_message(&root, category_override(&headers), &mut issues);
    let issues = issues.into_vec();
    if !issues.is_empty() {
        return provider_error_from_issues(&issues);
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
    accepted(&message_id)
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
            "the Postmark batch surface accepts application/json bodies",
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
            "the batch body must be a JSON array of messages",
            &[],
        );
    };
    if items.is_empty() {
        return provider_error(
            PROVIDER,
            StatusCode::BAD_REQUEST,
            "the batch body must contain at least one message",
            &[],
        );
    }
    if items.len() > MAX_BATCH {
        return provider_error(
            PROVIDER,
            StatusCode::BAD_REQUEST,
            &format!(
                "a Postmark batch carries at most {MAX_BATCH} messages (received {})",
                items.len()
            ),
            &[],
        );
    }

    let category = category_override(&headers);
    let mut issues = MappingIssues::default();
    let mut mapped = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let Some(item) = item.as_object() else {
            issues.push(format!("batch item {index} must be a JSON object"));
            continue;
        };
        let mut item_issues = MappingIssues::default();
        let message = map_message(item, category.clone(), &mut item_issues);
        for issue in item_issues.into_vec() {
            issues.push(format!("batch item {index}: {issue}"));
        }
        mapped.push(message);
    }
    let issues = issues.into_vec();
    if !issues.is_empty() {
        return provider_error_from_issues(&issues);
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

    // Postmark answers the batch as an ARRAY of per-message results in
    // request order. The canonical batch result carries the same per-item
    // accept/reject split and an explicit index, so the mapping is total:
    // every requested position gets exactly one result object.
    let requested = items.len();
    let mut results: Vec<Value> = (0..requested)
        .map(|index| {
            serde_json::json!({
                "ErrorCode": 500,
                "Message": format!(
                    "the send path returned no result for batch item {index}; contact support with the message ids you received"
                ),
                "MessageID": Value::Null,
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
        let Some(slot) = results.get_mut(index as usize) else {
            continue;
        };
        let id = result.get("id").and_then(Value::as_str);
        *slot = match id {
            Some(id) => serde_json::json!({
                "ErrorCode": 0,
                "Message": "OK",
                "MessageID": id,
            }),
            None => serde_json::json!({
                "ErrorCode": 406,
                "Message": result
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("the message was refused"),
                "MessageID": Value::Null,
            }),
        };
    }
    (StatusCode::OK, Json(Value::Array(results))).into_response()
}

/// `200 {"ErrorCode":0,"Message":"OK","MessageID":…}` — Postmark's single
/// send answer.
fn accepted(message_id: &str) -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ErrorCode": 0,
            "Message": "OK",
            "MessageID": message_id,
        })),
    )
        .into_response()
}

fn provider_error_from_issues(issues: &[String]) -> Response {
    // Postmark's own validation answer: ErrorCode 422 + a single Message.
    provider_error(
        PROVIDER,
        StatusCode::UNPROCESSABLE_ENTITY,
        &issues.join("; "),
        &[],
    )
}

fn json_object_body(
    headers: &axum::http::HeaderMap,
    body: &[u8],
) -> Result<Map<String, Value>, Response> {
    if content_type(headers) != "application/json" {
        return Err(provider_error(
            PROVIDER,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "the Postmark compatibility surface accepts application/json bodies",
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

fn map_message(
    root: &Map<String, Value>,
    category: Option<String>,
    issues: &mut MappingIssues,
) -> SendMessageRequest {
    reject_unknown_fields(root, &ALLOWED_TOP_LEVEL, "", issues);

    for field in ["TemplateId", "TemplateAlias"] {
        if let Some(value) = map_str(root, field, issues) {
            issues.push(unsupported(
                &format!("{field}='{value}'"),
                "a Postmark template id is not an ApexMail template id — render the body client-side or send an ApexMail `template_id` through /v1",
            ));
        }
    }
    // `TemplateModel` / `InlineImages` are objects this surface cannot honour.
    for field in ["TemplateModel", "InlineImages"] {
        if root.get(field).is_some_and(|value| !value.is_null()) {
            issues.push(unsupported(
                field,
                "the canonical send path has no equivalent for this field",
            ));
        }
    }

    let from = map_required_str(root, "From", issues).unwrap_or_default();
    let to = map_mailboxes(root, "To", issues);
    let cc = map_mailboxes(root, "Cc", issues);
    let bcc = map_mailboxes(root, "Bcc", issues);
    if root.get("To").is_none() {
        issues.push("field 'To' is required");
    }

    let subject = map_str(root, "Subject", issues).unwrap_or_default();
    let html = map_str(root, "HtmlBody", issues);
    let text = map_str(root, "TextBody", issues);

    // ── ReplyTo + Headers ───────────────────────────────────────────
    let mut reply_to = map_str(root, "ReplyTo", issues);
    let mut headers = Map::new();
    match root.get("Headers") {
        None | Some(Value::Null) => {}
        Some(Value::Array(list)) => {
            for (index, header) in list.iter().enumerate() {
                let Some(header) = header.as_object() else {
                    issues.push(format!("field 'Headers[{index}]' must be a JSON object"));
                    continue;
                };
                reject_unknown_fields(
                    header,
                    &["Name", "Value"],
                    &format!("Headers[{index}]."),
                    issues,
                );
                let name = map_required_str(header, "Name", issues);
                let value = map_required_str(header, "Value", issues);
                let (Some(name), Some(value)) = (name, value) else {
                    continue;
                };
                if name.eq_ignore_ascii_case("reply-to") {
                    // Reply-To is a protected canonical header: it maps onto
                    // the dedicated field instead.
                    if reply_to
                        .as_deref()
                        .is_some_and(|existing| existing != value)
                    {
                        issues.push(
                            "'Reply-To' is set by both 'ReplyTo' and 'Headers' with different values",
                        );
                    } else {
                        reply_to = Some(value);
                    }
                    continue;
                }
                if headers.contains_key(&name) {
                    issues.push(format!(
                        "header '{name}' appears more than once in 'Headers'"
                    ));
                    continue;
                }
                headers.insert(name, Value::String(value));
            }
        }
        Some(_) => issues.push("field 'Headers' must be an array of {Name, Value} objects"),
    }

    // ── Attachments ─────────────────────────────────────────────────
    let mut attachments = Vec::new();
    match root.get("Attachments") {
        None | Some(Value::Null) => {}
        Some(Value::Array(list)) => {
            for (index, attachment) in list.iter().enumerate() {
                let Some(attachment) = attachment.as_object() else {
                    issues.push(format!(
                        "field 'Attachments[{index}]' must be a JSON object"
                    ));
                    continue;
                };
                reject_unknown_fields(
                    attachment,
                    &["Name", "Content", "ContentType", "ContentID"],
                    &format!("Attachments[{index}]."),
                    issues,
                );
                if let Some(content_id) = map_str(attachment, "ContentID", issues) {
                    issues.push(unsupported(
                        &format!("Attachments[{index}].ContentID='{content_id}'"),
                        "the canonical send path has no inline-part concept — attach the file instead of embedding it",
                    ));
                }
                let filename = map_required_str(attachment, "Name", issues);
                let content = map_required_str(attachment, "Content", issues);
                let content_type = map_str(attachment, "ContentType", issues)
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
        Some(_) => issues.push("field 'Attachments' must be an array"),
    }

    // ── Tag / Metadata ──────────────────────────────────────────────
    let tag = map_str(root, "Tag", issues).filter(|tag| !tag.trim().is_empty());
    let metadata = match map_object(root, "Metadata", issues) {
        Some(map) => {
            let strings = string_map(&map, "Metadata", issues);
            Some(Value::Object(strings))
        }
        None => None,
    };

    // ── MessageStream → canonical category ──────────────────────────
    let category = match map_str(root, "MessageStream", issues) {
        Some(stream) => match stream.to_ascii_lowercase().as_str() {
            "outbound" => Some("transactional".to_string()),
            "broadcast" => Some("marketing".to_string()),
            other => {
                issues.push(unsupported(
                    &format!("MessageStream='{other}'"),
                    "only 'outbound' (transactional) and 'broadcast' (marketing) map onto the canonical category",
                ));
                category
            }
        },
        None => category,
    };

    // ── TrackOpens / TrackLinks ─────────────────────────────────────
    for field in ["TrackOpens", "TrackLinks"] {
        match root.get(field) {
            None | Some(Value::Null) => {}
            Some(Value::Bool(true)) => {}
            Some(Value::Bool(false)) => issues.push(unsupported(
                &format!("{field}=false"),
                "the platform tracks opens and clicks for every send; per-message tracking cannot be disabled on this surface",
            )),
            Some(other) => issues.push(format!(
                "field '{field}' must be a boolean (received {})",
                json_type_name(other)
            )),
        }
    }

    SendMessageRequest {
        from,
        to,
        cc: (!cc.is_empty()).then_some(cc),
        bcc: (!bcc.is_empty()).then_some(bcc),
        subject,
        html,
        text,
        tags: tag.map(|tag| vec![tag]),
        metadata,
        scheduled_at: None,
        reply_to,
        headers: (!headers.is_empty()).then_some(Value::Object(headers)),
        attachments: (!attachments.is_empty()).then_some(attachments),
        priority: None,
        category,
        template_id: None,
        template_data: None,
    }
}

/// Postmark recipient lists are comma-separated strings (the documented
/// form), or a JSON array of them.
fn map_mailboxes(
    root: &Map<String, Value>,
    field: &str,
    issues: &mut MappingIssues,
) -> Vec<String> {
    match root.get(field) {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(text)) => split_mailboxes(text),
        Some(Value::Array(items)) => {
            let mut out = Vec::new();
            for (index, item) in items.iter().enumerate() {
                match item {
                    Value::String(text) => out.extend(split_mailboxes(text)),
                    Value::Object(address) => {
                        let email = map_required_str(address, "email", issues).unwrap_or_default();
                        let name = map_str(address, "name", issues);
                        out.push(super::mailbox(&email, name.as_deref()));
                    }
                    other => issues.push(format!(
                        "field '{field}[{index}]' must be a mailbox string (received {})",
                        json_type_name(other)
                    )),
                }
            }
            out
        }
        Some(other) => {
            issues.push(format!(
                "field '{field}' must be a comma-separated string or an array of mailboxes (received {})",
                json_type_name(other)
            ));
            Vec::new()
        }
    }
}

/// Split Postmark's comma-separated recipient string, honouring quoted
/// display names (`"Doe, Jane" <jane@example.com>, other@example.com`).
fn split_mailboxes(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    for ch in raw.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_quotes => {
                current.push(ch);
                escaped = true;
            }
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            ',' if !in_quotes => {
                if !current.trim().is_empty() {
                    out.push(current.trim().to_string());
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        out.push(current.trim().to_string());
    }
    out
}
