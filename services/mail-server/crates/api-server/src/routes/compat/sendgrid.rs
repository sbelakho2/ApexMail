//! SendGrid compatibility: `POST /v3/mail/send`.
//!
//! Auth: `Authorization: Bearer <ApexMail API key>`.
//! Success: `202 Accepted`, empty body, `X-Message-Id: <canonical message id>`.
//! Errors: SendGrid's `{"errors":[{"message","field","help"}]}`.
//!
//! ## Mapping table (SendGrid field → canonical send field)
//!
//! | SendGrid | canonical |
//! |----------|-----------|
//! | `from.email` + `from.name` | `from` (`"Name <addr>"` when a name is present) |
//! | `personalizations[0].to[]` | `to` (required; exactly one personalization) |
//! | `personalizations[0].cc[]` / `.bcc[]` | `cc` / `bcc` |
//! | `personalizations[0].subject` (else top-level `subject`) | `subject` |
//! | `personalizations[0].headers` merged under top-level `headers` | `headers` |
//! | `content[]` `text/plain` / `text/html` `value` | `text` / `html` |
//! | `attachments[].content` / `.filename` / `.type` | `attachments[].content` / `.filename` / `.contentType` (default `application/octet-stream`) |
//! | `categories[]` + `X-SMTPAPI` `category`/`categories` | `tags` |
//! | `custom_args` + `X-SMTPAPI` `unique_args` | `metadata` |
//! | `reply_to.email`/`.name` | `reply_to` |
//! | `send_at` (unix seconds) | `scheduled_at` |
//! | `X-ApexMail-Category` header | `category` (validated by the canonical normalizer) |
//!
//! ## Named refusals (never a silent drop)
//!
//! * more than one personalization, per-personalization subject/headers would
//!   be lost; send one request per personalization;
//! * `personalizations[].substitutions` / `.dynamic_template_data`,
//!   `template_id`, `dynamic_template_data` (SendGrid template ids are not
//!   ApexMail template ids);
//! * `attachments[].content_id` and `disposition: "inline"` (the canonical
//!   send path has no inline-part concept);
//! * `asm`, `batch_id`, `ip_pool_name`, `mail_settings`, `tracking_settings`
//!   (delivery/tracking semantics with no canonical equivalent), except the
//!   explicit no-op `mail_settings.sandbox_mode.enable = false`;
//! * `X-SMTPAPI` keys other than `category`/`categories`/`unique_args`.

use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use chrono::{TimeZone, Utc};
use serde_json::{Map, Value};

use super::{
    canonical_message_id, category_override, content_type, dispatch_and_decode, idempotency_key,
    json_type_name, mailbox, map_mailbox_list, map_object, map_required_str, map_str,
    map_string_list, merge_maps, provider_error, provider_error_from_outcome, read_compat_request,
    reject_unknown_fields, request_auth, string_map, unsupported, CompatRequest, MappingIssues,
    Provider,
};
use crate::routes::messages::{SendAttachment, SendMessageRequest};
use crate::state::AppState;

const PROVIDER: Provider = Provider::SendGrid;

pub fn router(state: AppState) -> Router<AppState> {
    super::provider_layers(
        Router::new().route("/v3/mail/send", post(send)),
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

    if content_type(&headers) != "application/json" {
        return provider_error(
            PROVIDER,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "the SendGrid compatibility surface accepts application/json bodies",
            &[],
        );
    }

    let root: Value = match serde_json::from_slice(&body) {
        Ok(root) => root,
        Err(error) => {
            return provider_error(
                PROVIDER,
                StatusCode::BAD_REQUEST,
                &format!("invalid JSON body: {error}"),
                &[],
            )
        }
    };
    let Some(root) = root.as_object() else {
        return provider_error(
            PROVIDER,
            StatusCode::BAD_REQUEST,
            "the request body must be a JSON object",
            &[],
        );
    };

    let smtpapi = match parse_smtpapi(&headers) {
        Ok(value) => value,
        Err(message) => return provider_error(PROVIDER, StatusCode::BAD_REQUEST, &message, &[]),
    };

    let mut issues = MappingIssues::default();
    let mapped = map_sendgrid(
        root,
        smtpapi.as_ref().and_then(Value::as_object),
        category_override(&headers),
        &mut issues,
    );
    let issues = issues.into_vec();
    if !issues.is_empty() {
        return provider_error(
            PROVIDER,
            StatusCode::BAD_REQUEST,
            "the request could not be mapped onto the ApexMail send contract",
            &issues,
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

    // SendGrid answers `202 Accepted` with an EMPTY body; the message id
    // travels in `X-Message-Id`.
    let Ok(header_value) = message_id.parse() else {
        tracing::error!("canonical message id is not a valid header value");
        return provider_error(
            PROVIDER,
            StatusCode::INTERNAL_SERVER_ERROR,
            "the send path answered an unusable message id",
            &[],
        );
    };
    let mut response = StatusCode::ACCEPTED.into_response();
    response.headers_mut().insert("x-message-id", header_value);
    response
}

/// The `X-SMTPAPI` header (SendGrid's SMTP-API JSON), when present.
fn parse_smtpapi(headers: &HeaderMap) -> Result<Option<Value>, String> {
    let Some(raw) = headers.get("x-smtpapi") else {
        return Ok(None);
    };
    let raw = raw
        .to_str()
        .map_err(|_| "the X-SMTPAPI header is not valid UTF-8".to_string())?;
    if raw.trim().is_empty() {
        return Ok(None);
    }
    let value: Value = serde_json::from_str(raw)
        .map_err(|error| format!("the X-SMTPAPI header is not valid JSON: {error}"))?;
    if !value.is_object() {
        return Err("the X-SMTPAPI header must be a JSON object".to_string());
    }
    Ok(Some(value))
}

/// Top-level keys this surface maps; everything else is a named refusal.
const ALLOWED_TOP_LEVEL: [&str; 11] = [
    "personalizations",
    "from",
    "reply_to",
    "subject",
    "content",
    "attachments",
    "categories",
    "custom_args",
    "headers",
    "send_at",
    // Only the explicit no-op `sandbox_mode.enable = false` is accepted (see
    // `map_mail_settings`); every other mail-setting is a named refusal.
    "mail_settings",
];

const ALLOWED_PERSONALIZATION: [&str; 5] = ["to", "cc", "bcc", "subject", "headers"];

const ALLOWED_SMTPAPI: [&str; 3] = ["category", "categories", "unique_args"];

const DEFAULT_ATTACHMENT_TYPE: &str = "application/octet-stream";

fn map_sendgrid(
    root: &Map<String, Value>,
    smtpapi: Option<&Map<String, Value>>,
    category: Option<String>,
    issues: &mut MappingIssues,
) -> SendMessageRequest {
    reject_unknown_fields(root, &ALLOWED_TOP_LEVEL, "", issues);

    let from = map_from(root, issues);
    let (to, cc, bcc, personalization_subject, mut headers) = map_personalizations(root, issues);
    if let Some(top_level) = map_object(root, "headers", issues) {
        let mut merged = string_map(&top_level, "headers", issues);
        merge_maps(
            &mut merged,
            headers,
            "headers",
            "personalizations[0].headers",
            issues,
        );
        headers = merged;
    }
    let subject = personalization_subject
        .or_else(|| map_str(root, "subject", issues))
        .unwrap_or_default();
    let (html, text) = map_content(root, issues);
    let attachments = map_attachments(root, issues);
    let reply_to = map_reply_to(root, issues);
    let tags = map_tags(root, smtpapi, issues);
    let metadata = map_metadata(root, smtpapi, issues);
    let scheduled_at = map_send_at(root, issues);
    map_mail_settings(root, issues);

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

fn map_from(root: &Map<String, Value>, issues: &mut MappingIssues) -> String {
    match root.get("from") {
        Some(Value::Object(address)) => {
            let email = map_required_str(address, "email", issues).unwrap_or_default();
            let name = map_str(address, "name", issues);
            mailbox(&email, name.as_deref())
        }
        Some(Value::String(address)) => address.clone(),
        Some(other) => {
            issues.push(format!(
                "field 'from' must be an object (received {})",
                json_type_name(other)
            ));
            String::new()
        }
        None => {
            issues.push("field 'from' is required");
            String::new()
        }
    }
}

fn map_personalizations(
    root: &Map<String, Value>,
    issues: &mut MappingIssues,
) -> (
    Vec<String>,
    Vec<String>,
    Vec<String>,
    Option<String>,
    Map<String, Value>,
) {
    let mut to = Vec::new();
    let mut cc = Vec::new();
    let mut bcc = Vec::new();
    let mut subject = None;
    let mut headers = Map::new();
    let mut single_personalization = false;

    match root.get("personalizations") {
        Some(Value::Array(personalizations)) => match personalizations.len() {
            0 => issues.push("field 'personalizations' must contain at least one entry"),
            1 => {
                let Some(personalization) = personalizations[0].as_object() else {
                    issues.push("each 'personalizations' entry must be a JSON object");
                    return (to, cc, bcc, subject, headers);
                };
                single_personalization = true;
                reject_unknown_fields(
                    personalization,
                    &ALLOWED_PERSONALIZATION,
                    "personalizations[0].",
                    issues,
                );
                to = map_mailbox_list(personalization, "to", issues).unwrap_or_default();
                cc = map_mailbox_list(personalization, "cc", issues).unwrap_or_default();
                bcc = map_mailbox_list(personalization, "bcc", issues).unwrap_or_default();
                subject = map_str(personalization, "subject", issues);
                if let Some(map) = map_object(personalization, "headers", issues) {
                    headers = string_map(&map, "personalizations[0].headers", issues);
                }
            }
            _ => issues.push(
                "more than one 'personalizations' entry is not supported by the ApexMail compatibility surface: per-personalization subject/headers would be dropped, send one request per personalization",
            ),
        },
        Some(Value::Null) | None => issues.push("field 'personalizations' is required"),
        Some(other) => issues.push(format!(
            "field 'personalizations' must be an array (received {})",
            json_type_name(other)
        )),
    }

    if single_personalization && to.is_empty() {
        issues.push("field 'personalizations[0].to' must name at least one recipient");
    }
    (to, cc, bcc, subject, headers)
}

fn map_content(
    root: &Map<String, Value>,
    issues: &mut MappingIssues,
) -> (Option<String>, Option<String>) {
    let mut html = None;
    let mut text = None;
    let Some(content) = root.get("content") else {
        return (html, text);
    };
    let Some(parts) = content.as_array() else {
        issues.push("field 'content' must be an array");
        return (html, text);
    };
    for (index, part) in parts.iter().enumerate() {
        let Some(part) = part.as_object() else {
            issues.push(format!("field 'content[{index}]' must be a JSON object"));
            continue;
        };
        let kind = map_str(part, "type", issues).unwrap_or_default();
        let value = map_str(part, "value", issues);
        match kind.to_ascii_lowercase().as_str() {
            "text/plain" => {
                if text.is_some() {
                    issues.push(format!(
                        "field 'content[{index}]' repeats a 'text/plain' part; the canonical send contract carries exactly one text body"
                    ));
                } else {
                    text = value;
                }
            }
            "text/html" => {
                if html.is_some() {
                    issues.push(format!(
                        "field 'content[{index}]' repeats a 'text/html' part; the canonical send contract carries exactly one HTML body"
                    ));
                } else {
                    html = value;
                }
            }
            "" => {}
            other => issues.push(unsupported(
                &format!("content[{index}].type='{other}'"),
                "only text/plain and text/html parts have a canonical equivalent",
            )),
        }
    }
    (html, text)
}

fn map_attachments(root: &Map<String, Value>, issues: &mut MappingIssues) -> Vec<SendAttachment> {
    let mut attachments = Vec::new();
    let Some(list) = root.get("attachments").and_then(Value::as_array) else {
        if root
            .get("attachments")
            .is_some_and(|value| !value.is_null() && !value.is_array())
        {
            issues.push("field 'attachments' must be an array");
        }
        return attachments;
    };
    for (index, attachment) in list.iter().enumerate() {
        let Some(attachment) = attachment.as_object() else {
            issues.push(format!(
                "field 'attachments[{index}]' must be a JSON object"
            ));
            continue;
        };
        reject_unknown_fields(
            attachment,
            &["content", "filename", "type", "disposition", "content_id"],
            &format!("attachments[{index}]."),
            issues,
        );
        if let Some(content_id) = map_str(attachment, "content_id", issues) {
            issues.push(unsupported(
                &format!("attachments[{index}].content_id='{content_id}'"),
                "the canonical send path has no inline-part concept, attach the file instead of embedding it",
            ));
        }
        if let Some(disposition) = map_str(attachment, "disposition", issues) {
            if !disposition.eq_ignore_ascii_case("attachment") {
                issues.push(unsupported(
                    &format!("attachments[{index}].disposition='{disposition}'"),
                    "only 'attachment' has a canonical equivalent",
                ));
            }
        }
        let content = map_required_str(attachment, "content", issues);
        let filename = map_required_str(attachment, "filename", issues);
        let content_type =
            map_str(attachment, "type", issues).unwrap_or_else(|| DEFAULT_ATTACHMENT_TYPE.into());
        if let (Some(content), Some(filename)) = (content, filename) {
            attachments.push(SendAttachment {
                filename,
                content,
                content_type,
            });
        }
    }
    attachments
}

fn map_reply_to(root: &Map<String, Value>, issues: &mut MappingIssues) -> Option<String> {
    match root.get("reply_to") {
        Some(Value::Object(address)) => {
            let email = map_required_str(address, "email", issues).unwrap_or_default();
            let name = map_str(address, "name", issues);
            Some(mailbox(&email, name.as_deref()))
        }
        Some(Value::String(address)) => Some(address.clone()),
        Some(other) => {
            issues.push(format!(
                "field 'reply_to' must be an object (received {})",
                json_type_name(other)
            ));
            None
        }
        None => None,
    }
}

fn map_tags(
    root: &Map<String, Value>,
    smtpapi: Option<&Map<String, Value>>,
    issues: &mut MappingIssues,
) -> Vec<String> {
    let mut tags = map_string_list(root, "categories", issues).unwrap_or_default();
    let Some(smtpapi) = smtpapi else {
        return tags;
    };
    reject_unknown_fields(smtpapi, &ALLOWED_SMTPAPI, "X-SMTPAPI.", issues);
    for key in ["category", "categories"] {
        for tag in map_string_list(smtpapi, key, issues).unwrap_or_default() {
            if !tags.contains(&tag) {
                tags.push(tag);
            }
        }
    }
    tags
}

fn map_metadata(
    root: &Map<String, Value>,
    smtpapi: Option<&Map<String, Value>>,
    issues: &mut MappingIssues,
) -> Map<String, Value> {
    let mut metadata = Map::new();
    if let Some(map) = map_object(root, "custom_args", issues) {
        metadata = string_map(&map, "custom_args", issues);
    }
    if let Some(smtpapi) = smtpapi {
        if let Some(map) = map_object(smtpapi, "unique_args", issues) {
            let unique = string_map(&map, "X-SMTPAPI.unique_args", issues);
            merge_maps(
                &mut metadata,
                unique,
                "custom_args",
                "X-SMTPAPI.unique_args",
                issues,
            );
        }
    }
    metadata
}

fn map_send_at(
    root: &Map<String, Value>,
    issues: &mut MappingIssues,
) -> Option<chrono::DateTime<Utc>> {
    match root.get("send_at") {
        None | Some(Value::Null) => None,
        Some(Value::Number(number)) => match number.as_i64() {
            Some(seconds) => match Utc.timestamp_opt(seconds, 0).single() {
                Some(timestamp) => Some(timestamp),
                None => {
                    issues.push(format!(
                        "field 'send_at' ({seconds}) is not a valid unix timestamp"
                    ));
                    None
                }
            },
            None => {
                issues.push("field 'send_at' must be an integer unix timestamp (seconds)");
                None
            }
        },
        Some(other) => {
            issues.push(format!(
                "field 'send_at' must be an integer unix timestamp in seconds (received {})",
                json_type_name(other)
            ));
            None
        }
    }
}

/// SendGrid `mail_settings`.
///
/// The ONE accepted value is the explicit no-op used by every SDK's
/// documented default, `{"sandbox_mode": {"enable": false}}` (sandbox mode
/// disabled, i.e. the message really goes out). Enabling sandbox mode, or any
/// other mail-level setting (`bcc`, `bypass_list_management`, `footer`,
/// `bypass_spam_management`, `bypass_bounce_management`, …), changes delivery
/// semantics that this surface cannot honour, so each is refused BY NAME
/// rather than silently ignored.
fn map_mail_settings(root: &Map<String, Value>, issues: &mut MappingIssues) {
    let Some(map) = map_object(root, "mail_settings", issues) else {
        return;
    };
    for (key, value) in &map {
        if key != "sandbox_mode" {
            issues.push(unsupported(
                &format!("mail_settings.{key}"),
                "this mail-level setting has no canonical equivalent",
            ));
            continue;
        }
        match value.get("enable") {
            None | Some(Value::Bool(false)) => {}
            Some(Value::Bool(true)) => issues.push(unsupported(
                "mail_settings.sandbox_mode.enable=true",
                "the canonical send path has no per-message sandbox mode, use the platform test-mode surface",
            )),
            Some(other) => issues.push(format!(
                "field 'mail_settings.sandbox_mode.enable' must be a boolean (received {})",
                json_type_name(other)
            )),
        }
    }
}
