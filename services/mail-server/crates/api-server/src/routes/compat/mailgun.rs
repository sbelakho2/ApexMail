//! Mailgun compatibility: `POST /v3/{domain}/messages`
//! (and the named `501` placeholder for `/v3/{domain}/messages.mime`).
//!
//! Auth: `Authorization: Basic base64("<user>:<ApexMail API key>")`.
//! Success: `200` `{"id":"<canonical id>@{domain}","message":"Queued. Thank you."}`.
//! Errors: Mailgun's `{"message":"…"}`.
//!
//! ## Mapping table (Mailgun field → canonical send field)
//!
//! | Mailgun | canonical |
//! |----------|-----------|
//! | `from` | `from` |
//! | `to` (repeatable / comma-separated) | `to` |
//! | `cc` / `bcc` | `cc` / `bcc` |
//! | `subject` | `subject` |
//! | `html` / `text` | `html` / `text` |
//! | `attachment` (multipart file part) | `attachments[]` (base64 `content`, filename, part Content-Type) |
//! | `o:tag` | `tags` |
//! | `o:deliverytime` (RFC 2822 date) | `scheduled_at` |
//! | `h:X-Foo` | `headers` (`h:Reply-To` folds into `reply_to`) |
//! | `v:my-var` | `metadata.my-var` |
//! | `X-ApexMail-Category` header | `category` (validated by the canonical normalizer) |
//!
//! The `{domain}` path segment is Mailgun's sending domain; it must equal the
//! domain of the `from` address, because the canonical send path derives the
//! DKIM identity from the sender domain (a mismatch is a named refusal rather
//! than a silent downgrade of the signing authority).
//!
//! ## Named refusals (never a silent drop)
//!
//! * `inline` (no canonical inline part), `template` (Mailgun-stored
//!   templates), `o:campaign`, `o:require-tls`, `o:skip-verification`,
//!   `o:dkim=no`, `o:testmode=true` and `o:tracking*=no/false`, delivery
//!   semantics this surface cannot honour;
//! * any other `o:*`, `h:*`-shape or unknown form field;
//! * `POST /v3/{domain}/messages.mime`, answered `501` with the reason
//!   (`messages.mime` takes a raw MIME document, and this surface maps
//!   structured fields only; see [`mime_not_implemented`]).

use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};

use super::multipart::{boundary_from_content_type, parse_multipart, MultipartPart};
use super::{
    canonical_message_id, category_override, content_type, dispatch_and_decode, idempotency_key,
    provider_error, provider_error_from_outcome, read_compat_request, request_auth, unsupported,
    CompatRequest, MappingIssues, Provider,
};
use crate::routes::messages::{SendAttachment, SendMessageRequest};
use crate::state::AppState;

const PROVIDER: Provider = Provider::Mailgun;

/// Mailgun's own acknowledgement body.
const QUEUED_MESSAGE: &str = "Queued. Thank you.";

pub fn router(state: AppState) -> Router<AppState> {
    super::provider_layers(
        Router::new()
            .route("/v3/:domain/messages", post(send))
            .route("/v3/:domain/messages.mime", post(send_mime)),
        state,
        PROVIDER,
    )
}

/// One decoded form field set: ordered text pairs (repeats preserved) plus
/// the uploaded file parts.
#[derive(Default)]
struct FormFields {
    pairs: Vec<(String, String)>,
    files: Vec<(String, String, Option<String>, Vec<u8>)>,
}

impl FormFields {
    /// Every value of a repeatable field, in order.
    fn all(&self, name: &str) -> Vec<&str> {
        self.pairs
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .collect()
    }

    /// The last value of a single-valued field (form encoders may repeat a
    /// key; the provider's contract keeps the last).
    fn last(&self, name: &str) -> Option<&str> {
        self.all(name).pop()
    }
}

async fn send(State(state): State<AppState>, Path(domain): Path<String>, req: Request) -> Response {
    let auth = match request_auth(PROVIDER, &req) {
        Ok(auth) => auth,
        Err(refusal) => return refusal,
    };
    let CompatRequest { headers, body } = match read_compat_request(PROVIDER, req).await {
        Ok(request) => request,
        Err(refusal) => return refusal,
    };

    let fields = match parse_fields(&headers, &body) {
        Ok(fields) => fields,
        Err(message) => return provider_error(PROVIDER, StatusCode::BAD_REQUEST, &message, &[]),
    };

    let mut issues = MappingIssues::default();
    let mapped = map_message(&domain, &fields, category_override(&headers), &mut issues);
    if !issues.is_empty() {
        return provider_error(
            PROVIDER,
            StatusCode::BAD_REQUEST,
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
        Json(serde_json::json!({
            "id": format!("<{message_id}@{domain}>"),
            "message": QUEUED_MESSAGE,
        })),
    )
        .into_response()
}

/// `POST /v3/{domain}/messages.mime`: Mailgun's raw-MIME endpoint.
///
/// The canonical send contract takes STRUCTURED fields (`from`/`to`/
/// `html`/`attachments`), and this compatibility layer is a field mapping —
/// it deliberately does not parse a caller-supplied MIME document (that would
/// mean a second, unreviewed MIME parser in the request path). The route is
/// therefore wired and answers a named `501`, after authentication, so the
/// caller learns the surface exists and why it is not implemented, instead
/// of a bare 404 that would look like a routing failure.
async fn send_mime(
    State(_state): State<AppState>,
    Path(_domain): Path<String>,
    req: Request,
) -> Response {
    if let Err(refusal) = request_auth(PROVIDER, &req) {
        return refusal;
    }
    // Drain the (usually large) MIME upload under the platform's send-body
    // ceiling so the refusal is a clean 501/413 instead of a connection reset
    // mid-upload, the body itself is deliberately never parsed (see the
    // rationale below).
    if let Err(refusal) = read_compat_request(PROVIDER, req).await {
        return refusal;
    }
    provider_error(
        PROVIDER,
        StatusCode::NOT_IMPLEMENTED,
        &format!(
            "POST /v3/{{domain}}/messages.mime is not implemented by the ApexMail compatibility surface: {}. Use /v3/{{domain}}/messages with structured fields (from/to/subject/html/text/attachment), or the canonical POST /v1/messages API.",
            mime_not_implemented()
        ),
        &[],
    )
}

/// The documented reason behind the `messages.mime` 501 (kept as a function
/// so the test suite asserts the same string the route answers).
pub(crate) fn mime_not_implemented() -> &'static str {
    "raw MIME passthrough would require a second MIME parser in the request path"
}

fn parse_fields(headers: &axum::http::HeaderMap, body: &[u8]) -> Result<FormFields, String> {
    let media_type = content_type(headers);
    match media_type.as_str() {
        "application/x-www-form-urlencoded" => {
            let text = std::str::from_utf8(body)
                .map_err(|_| "the form body is not valid UTF-8".to_string())?;
            let mut fields = FormFields::default();
            for (key, value) in form_urlencoded::parse(text.as_bytes()) {
                fields
                    .pairs
                    .push((key.into_owned(), value.into_owned()));
            }
            Ok(fields)
        }
        "multipart/form-data" => {
            let raw_content_type = headers
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("");
            let boundary = boundary_from_content_type(raw_content_type)?;
            let parts = parse_multipart(body, &boundary)?;
            let mut fields = FormFields::default();
            for part in parts {
                push_part(&mut fields, part)?;
            }
            Ok(fields)
        }
        other => Err(format!(
            "the Mailgun compatibility surface accepts application/x-www-form-urlencoded or multipart/form-data bodies (received '{other}')"
        )),
    }
}

fn push_part(fields: &mut FormFields, part: MultipartPart) -> Result<(), String> {
    match part.filename.as_deref() {
        Some(filename) if !filename.trim().is_empty() => {
            fields.files.push((
                part.name,
                filename.to_string(),
                part.content_type,
                part.body,
            ));
            Ok(())
        }
        _ => {
            let value = part.text()?.to_string();
            fields.pairs.push((part.name, value));
            Ok(())
        }
    }
}

fn map_message(
    domain: &str,
    fields: &FormFields,
    category: Option<String>,
    issues: &mut MappingIssues,
) -> SendMessageRequest {
    let from = fields.last("from").unwrap_or_default().to_string();
    if from.is_empty() {
        issues.push("field 'from' is required");
    } else if let Some(sender_domain) = from.rsplit('@').next() {
        let sender_domain = sender_domain
            .trim()
            .trim_end_matches('>')
            .to_ascii_lowercase();
        if sender_domain != domain.trim().to_ascii_lowercase() {
            issues.push(format!(
                "the '{{domain}}' path segment ('{domain}') must equal the domain of the 'from' address ('{sender_domain}'): the canonical send path signs with the sender domain",
            ));
        }
    }

    let mut to = Vec::new();
    for value in fields.all("to") {
        to.extend(split_addresses(value));
    }
    if to.is_empty() {
        issues.push("field 'to' is required");
    }
    let mut cc = Vec::new();
    for value in fields.all("cc") {
        cc.extend(split_addresses(value));
    }
    let mut bcc = Vec::new();
    for value in fields.all("bcc") {
        bcc.extend(split_addresses(value));
    }

    let subject = fields.last("subject").unwrap_or_default().to_string();
    let html = fields.last("html").map(str::to_string);
    let text = fields.last("text").map(str::to_string);

    // ── attachments (file parts named `attachment`) ─────────────────
    let mut attachments = Vec::new();
    for (field, filename, content_type, body) in &fields.files {
        match field.to_ascii_lowercase().as_str() {
            "attachment" => attachments.push(SendAttachment {
                filename: filename.clone(),
                content: base64::engine::general_purpose::STANDARD.encode(body),
                content_type: content_type
                    .clone()
                    .unwrap_or_else(|| "application/octet-stream".to_string()),
            }),
            "inline" => issues.push(unsupported(
                "inline",
                "the canonical send path has no inline-part concept, attach the file instead of embedding it",
            )),
            other => issues.push(unsupported(
                &format!("file field '{other}'"),
                "only the `attachment` file field is supported",
            )),
        }
    }
    // A form-encoded `attachment` text value is not a Mailgun feature:
    // attachments travel as multipart file parts, so a text field would be
    // silently dropped, name it instead.
    for _ in fields.all("attachment") {
        issues.push(unsupported(
            "attachment",
            "attachments must be sent as multipart/form-data file parts (`-F attachment=@file`), not as form values",
        ));
    }

    // ── headers (h:*), Reply-To folds into the dedicated field ─────
    let mut headers = Map::new();
    let mut reply_to: Option<String> = None;
    for (key, value) in &fields.pairs {
        let Some(name) = key.strip_prefix("h:") else {
            continue;
        };
        if name.is_empty() {
            issues.push(unsupported("h:", "the header name is empty"));
            continue;
        }
        if name.eq_ignore_ascii_case("reply-to") {
            if reply_to
                .as_deref()
                .is_some_and(|existing| existing != value)
            {
                issues.push("'Reply-To' appears more than once with different values");
            } else {
                reply_to = Some(value.clone());
            }
            continue;
        }
        if headers.contains_key(name) {
            issues.push(format!("header '{name}' appears more than once"));
            continue;
        }
        headers.insert(name.to_string(), Value::String(value.clone()));
    }

    // ── tags / metadata / schedule / toggles ────────────────────────
    let mut tags: Vec<String> = Vec::new();
    let mut metadata = Map::new();
    for (key, value) in &fields.pairs {
        match key.as_str() {
            "o:tag" => {
                if !tags.contains(value) {
                    tags.push(value.clone());
                }
            }
            "o:deliverytime" => {}
            name if name.starts_with("v:") => {
                metadata.insert(
                    name.trim_start_matches("v:").to_string(),
                    Value::String(value.clone()),
                );
            }
            _ => {}
        }
    }
    let scheduled_at = match fields.last("o:deliverytime") {
        None => None,
        Some(raw) => match DateTime::parse_from_rfc2822(raw) {
            Ok(timestamp) => Some(timestamp.with_timezone(&Utc)),
            Err(_) => {
                issues.push(format!(
                    "field 'o:deliverytime' ('{raw}') must be an RFC 2822 timestamp (e.g. 'Fri, 15 Oct 2026 12:00:00 -0000')"
                ));
                None
            }
        },
    };
    map_toggles(fields, issues);

    // ── unsupported / unknown fields ────────────────────────────────
    for (key, _) in &fields.pairs {
        let known = matches!(
            key.as_str(),
            "from"
                | "to"
                | "cc"
                | "bcc"
                | "subject"
                | "html"
                | "text"
                | "attachment"
                | "o:tag"
                | "o:deliverytime"
        ) || key.starts_with("h:")
            || key.starts_with("v:")
            || DEFAULT_ON_TOGGLES.contains(&key.as_str())
            || DEFAULT_OFF_TOGGLES.contains(&key.as_str())
            || UNSUPPORTED_FIELDS.contains(&key.as_str());
        if !known {
            issues.push(unsupported(
                key,
                "this field has no canonical equivalent on the Mailgun compatibility surface",
            ));
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
        tags: (!tags.is_empty()).then_some(tags),
        metadata: (!metadata.is_empty()).then_some(Value::Object(metadata)),
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

/// Mailgun toggles whose PROVIDER DEFAULT is already the platform
/// behaviour: an explicit `yes` is satisfied (a no-op), while `no` asks for
/// something this surface cannot disable, a named refusal, never a silent
/// "yes".
const DEFAULT_ON_TOGGLES: [&str; 4] = [
    "o:tracking",
    "o:tracking-clicks",
    "o:tracking-opens",
    "o:dkim",
];

/// Mailgun toggles whose PROVIDER DEFAULT is OFF: an explicit OFF value is a
/// no-op, while turning one ON asks for behaviour (suppressed delivery) this
/// surface does not implement, a named refusal, never a silent send.
const DEFAULT_OFF_TOGGLES: [&str; 1] = ["o:testmode"];

/// Mailgun fields this surface understands but cannot honour, named
/// refusals with the caller's own value echoed.
const UNSUPPORTED_FIELDS: [&str; 4] = [
    "template",
    "o:campaign",
    "o:require-tls",
    "o:skip-verification",
];

fn map_toggles(fields: &FormFields, issues: &mut MappingIssues) {
    for field in DEFAULT_ON_TOGGLES {
        for value in fields.all(field) {
            match value.trim().to_ascii_lowercase().as_str() {
                // Already-satisfied defaults / explicit no-ops.
                "" | "yes" | "true" | "1" | "on" => {}
                "no" | "false" | "0" | "off" => issues.push(unsupported(
                    &format!("{field}={value}"),
                    "this surface cannot disable the corresponding platform behaviour (tracking and DKIM signing are deployment-level settings)",
                )),
                other => issues.push(unsupported(
                    &format!("{field}={other}"),
                    "only yes/no-style values are understood",
                )),
            }
        }
    }
    for field in DEFAULT_OFF_TOGGLES {
        for value in fields.all(field) {
            match value.trim().to_ascii_lowercase().as_str() {
                "" | "no" | "false" | "0" | "off" => {}
                "yes" | "true" | "1" | "on" => issues.push(unsupported(
                    &format!("{field}={value}"),
                    "the canonical send path has no per-message suppressed-delivery mode, use the platform test-mode surface instead of silently sending",
                )),
                other => issues.push(unsupported(
                    &format!("{field}={other}"),
                    "only yes/no-style values are understood",
                )),
            }
        }
    }
    for field in UNSUPPORTED_FIELDS {
        if let Some(value) = fields.last(field) {
            issues.push(unsupported(
                &format!("{field}='{value}'"),
                "this field has no canonical equivalent",
            ));
        }
    }
}

/// Split a Mailgun recipient value: repeats and comma-separated lists are
/// both documented (`to=a@x.com,b@x.com`, `to=a@x.com&to=b@x.com`). Quoted
/// display names keep their commas.
fn split_addresses(raw: &str) -> Vec<String> {
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
