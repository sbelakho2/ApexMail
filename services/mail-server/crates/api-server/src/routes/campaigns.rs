//! Campaign management routes.
//!
//! Campaigns are lists-based bulk mail: a campaign references an audience
//! (`listIds` / `excludeListIds`), a sender (`from`), a template and a
//! subject. `POST /:id/send` resolves the audience synchronously into
//! `campaign_recipients` and flips the campaign to `sending`;
//! `POST /:id/schedule` stores a due time. The actual delivery is the WORKER
//! campaign consumer's job (`crates/worker-processors/src/campaigns.rs`),
//! which drains recipient rows through the shared admission gate — this file
//! never enqueues mail itself, it only records intent and audience.
//!
//! Wire truth: this module is the authority for the campaigns contract; the
//! docs (`docs/api/endpoints/campaigns.md`) were rewritten from it (the
//! segmentId/A-B/settings features they promised never existed on the wire).

use super::helpers::{
    clamp_limit, compute_etag, decode_cursor, default_limit, encode_cursor, has_more,
    is_not_modified, pagination_meta,
};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(create_campaign).get(list_campaigns))
        .route(
            "/:id",
            get(get_campaign)
                .patch(update_campaign)
                .delete(delete_campaign),
        )
        .route("/:id/send", post(send_campaign))
        .route("/:id/schedule", post(schedule_campaign))
        .route("/:id/resume", post(resume_campaign))
        .route("/:id/pause", post(pause_campaign))
        .route("/:id/resend", post(resend_campaign))
        .route("/:id/stats", get(campaign_stats))
}

// ─── Keyset cursor helpers ─────────────────────────────────────
//
// The list cursor encodes the `(created_at, id)` pair of the last row of the
// previous page. A timestamp alone skips or duplicates rows that share a
// `created_at` value; the tie-break `created_at = $ts AND id < $id` makes
// the ordering total.

/// Separator between the RFC3339 timestamp and the row id inside the
/// hex-encoded cursor payload (RFC3339 and UUID ids never contain it).
const KEYSET_CURSOR_SEP: char = '\n';

/// Encode a `(created_at, id)` keyset cursor as an opaque hex string.
fn encode_keyset_cursor(created_at: &DateTime<Utc>, id: &str) -> String {
    // RFC3339, not Display: decode parses with `parse_from_rfc3339`, so a
    // cursor rendered with Display("… UTC") could never be replayed (every
    // next-page request 400'd).
    encode_cursor(&format!(
        "{}{KEYSET_CURSOR_SEP}{id}",
        created_at.to_rfc3339()
    ))
}

/// Decode and validate a `(created_at, id)` keyset cursor. Malformed
/// encodings, unparsable timestamps, or bogus ids are client errors (400) —
/// an unvalidated cursor used to reach the database and surface as a 500.
fn decode_keyset_cursor(encoded: &str) -> Result<(DateTime<Utc>, String), ApiError> {
    let Some(decoded) = decode_cursor(encoded) else {
        return Err(ApiError::BadRequest(
            "invalid cursor: malformed encoding".into(),
        ));
    };
    let Some((timestamp, id)) = decoded.split_once(KEYSET_CURSOR_SEP) else {
        return Err(ApiError::BadRequest(
            "invalid cursor: must encode a created_at timestamp and row id".into(),
        ));
    };
    let timestamp = chrono::DateTime::parse_from_rfc3339(timestamp)
        .map_err(|_| {
            ApiError::BadRequest("invalid cursor: must be an encoded created_at timestamp".into())
        })?
        .with_timezone(&Utc);
    if id.is_empty() || id.len() > 64 || id.bytes().any(|b| b.is_ascii_control()) {
        return Err(ApiError::BadRequest(
            "invalid cursor: malformed row id".into(),
        ));
    }
    Ok((timestamp, id.to_string()))
}

// ─── Types ─────────────────────────────────────────────────────

/// Upper bound of `listIds` / `excludeListIds` per campaign (an unbounded
/// array would let one request carry 10k ids into a validation query).
const MAX_LISTS_PER_CAMPAIGN: usize = 50;

/// Reject malformed campaign ids as 404 before any `::uuid` cast reaches the
/// database (an unvalidated cast used to surface as a 500).
fn parse_campaign_id(id: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(id).map_err(|_| ApiError::NotFound("campaign not found".into()))
}

/// Duplicate campaign names are an honest 409 (unique
/// `idx_campaigns_tenant_name`), never a generic database 500.
fn map_campaign_write_error(error: sqlx::Error) -> ApiError {
    if let sqlx::Error::Database(ref db_error) = error {
        if db_error.code().as_deref() == Some("23505") {
            return ApiError::Conflict("a campaign with this name already exists".into());
        }
    }
    ApiError::from(error)
}

/// Parse + bound + dedupe one audience column. Malformed entries are a clean
/// 400, never a database 500 from a `::uuid` cast.
fn parse_list_ids(raw: &[String], field: &str) -> Result<Vec<Uuid>, ApiError> {
    if raw.len() > MAX_LISTS_PER_CAMPAIGN {
        return Err(ApiError::Validation(vec![format!(
            "{field} must contain at most {MAX_LISTS_PER_CAMPAIGN} list ids"
        )]));
    }
    let mut out: Vec<Uuid> = Vec::with_capacity(raw.len());
    for id in raw {
        if id.chars().count() > 64 {
            return Err(ApiError::Validation(vec![format!(
                "{field} contains a malformed list id"
            )]));
        }
        let uuid = Uuid::parse_str(id).map_err(|_| {
            ApiError::Validation(vec![format!("{field} contains a malformed list id")])
        })?;
        if !out.contains(&uuid) {
            out.push(uuid);
        }
    }
    Ok(out)
}

/// Every referenced list must exist AND belong to the tenant — a
/// cross-tenant or unknown list id is a 404, matching the template
/// reference behavior (never a silent FK error).
async fn validate_lists_exist(
    state: &AppState,
    tenant_id: &str,
    list_ids: &[Uuid],
) -> Result<(), ApiError> {
    if list_ids.is_empty() {
        return Ok(());
    }
    let found: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM lists WHERE tenant_id = $1 AND id = ANY($2)")
            .bind(tenant_id)
            .bind(list_ids)
            .fetch_one(&state.db)
            .await?;
    if found != list_ids.len() as i64 {
        return Err(ApiError::NotFound("list not found".into()));
    }
    Ok(())
}

/// The sender address is what the worker puts on the wire; garbage here would
/// fail three layers deep. Reject it cleanly at write time.
pub(crate) fn validate_sender(from: &str) -> Result<(), ApiError> {
    let ok = !from.is_empty()
        && from.chars().count() <= 320
        && !from
            .chars()
            .any(|c| c.is_whitespace() || c == ',' || c == ';' || c == '<' || c == '>')
        && from.contains('@')
        && !from.starts_with('@')
        && !from.ends_with('@');
    if ok {
        Ok(())
    } else {
        Err(ApiError::Validation(vec![
            "from must be a single email address".into(),
        ]))
    }
}

/// JSONB rendering of a validated audience column.
fn list_ids_json(list_ids: &[Uuid]) -> Value {
    serde_json::Value::Array(
        list_ids
            .iter()
            .map(|id| serde_json::Value::String(id.to_string()))
            .collect(),
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCampaignRequest {
    pub name: String,
    pub subject: String,
    #[serde(default, alias = "templateId")]
    pub template_id: Option<String>,
    /// The verified sender address the worker sends from. The docs' `from`.
    #[serde(default, alias = "from_email")]
    pub from: Option<String>,
    /// Display name composed into the MIME `From:` header.
    #[serde(default, alias = "fromName")]
    pub from_name: Option<String>,
    #[serde(default, alias = "replyTo")]
    pub reply_to: Option<String>,
    /// Inbox preview text (preheader), rendered as a hidden preheader block
    /// ahead of the body.
    #[serde(default, alias = "previewText")]
    pub preview_text: Option<String>,
    /// Raw HTML body — the alternative to `template_id` (exactly one of the
    /// two is required before send).
    #[serde(default)]
    pub html: Option<String>,
    #[serde(default)]
    pub text: Option<String>,
    /// Global template variables merged under the contact-derived defaults.
    #[serde(default)]
    pub variables: Option<Value>,
    #[serde(default, alias = "scheduledAt")]
    pub scheduled_at: Option<DateTime<Utc>>,
    /// Audience: subscriber lists to include / exclude (docs' `listIds` /
    /// `excludeListIds`) plus an optional saved `segmentId` whose lists and
    /// match rules merge into the audience.
    #[serde(default, alias = "listIds")]
    pub list_ids: Option<Vec<String>>,
    #[serde(default, alias = "excludeListIds")]
    pub exclude_list_ids: Option<Vec<String>>,
    #[serde(default, alias = "segmentId")]
    pub segment_id: Option<String>,
    /// Per-campaign tracking toggles (docs' `trackOpens` / `trackClicks`).
    #[serde(default, alias = "trackOpens")]
    pub track_opens: Option<bool>,
    #[serde(default, alias = "trackClicks")]
    pub track_clicks: Option<bool>,
    /// UTM parameters appended to every link at render time (docs'
    /// `utmParams`): source/medium/campaign/term/content.
    #[serde(default, alias = "utmParams")]
    pub utm_params: Option<Value>,
    /// Send settings (docs' `settings`): sendTimeOptimization, timezone,
    /// throttleRate, ipPool.
    #[serde(default)]
    pub settings: Option<Value>,
    /// A/B test configuration (docs' test sends): arms of
    /// {templateId, subject}, testPercentage, metric, waitMinutes.
    #[serde(default, alias = "abTest")]
    pub ab_test: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateCampaignRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default, alias = "templateId")]
    pub template_id: Option<String>,
    #[serde(default, alias = "from_email")]
    pub from: Option<String>,
    #[serde(default, alias = "fromName")]
    pub from_name: Option<String>,
    #[serde(default, alias = "replyTo")]
    pub reply_to: Option<String>,
    #[serde(default, alias = "previewText")]
    pub preview_text: Option<String>,
    #[serde(default)]
    pub html: Option<String>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub variables: Option<Value>,
    #[serde(default, alias = "scheduledAt")]
    pub scheduled_at: Option<DateTime<Utc>>,
    #[serde(default, alias = "listIds")]
    pub list_ids: Option<Vec<String>>,
    #[serde(default, alias = "excludeListIds")]
    pub exclude_list_ids: Option<Vec<String>>,
    #[serde(default, alias = "segmentId")]
    pub segment_id: Option<String>,
    #[serde(default, alias = "trackOpens")]
    pub track_opens: Option<bool>,
    #[serde(default, alias = "trackClicks")]
    pub track_clicks: Option<bool>,
    #[serde(default, alias = "utmParams")]
    pub utm_params: Option<Value>,
    #[serde(default)]
    pub settings: Option<Value>,
    #[serde(default, alias = "abTest")]
    pub ab_test: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct CampaignResponse {
    pub id: String,
    pub name: String,
    pub subject: String,
    pub template_id: Option<String>,
    pub from_email: Option<String>,
    pub from_name: Option<String>,
    pub reply_to: Option<String>,
    pub preview_text: Option<String>,
    pub html: Option<String>,
    pub text: Option<String>,
    pub variables: Value,
    pub status: String,
    pub scheduled_at: Option<String>,
    pub list_ids: Vec<String>,
    pub exclude_list_ids: Vec<String>,
    pub segment_id: Option<String>,
    pub track_opens: bool,
    pub track_clicks: bool,
    pub utm_params: Value,
    pub settings: Value,
    pub ab_test: Option<Value>,
    pub sent_count: i64,
    pub recipient_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListCampaignsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    /// Cursor for cursor-based pagination — hex-encoded `created_at` + row id
    /// pair of the last item from the previous page. When provided, overrides
    /// `offset`.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Filter by campaign status (the documented `status` filter).
    #[serde(default)]
    pub status: Option<String>,
    /// Case-insensitive substring match on the campaign name.
    #[serde(default)]
    pub search: Option<String>,
    /// Created-at window (the documented `startDate` / `endDate` filters).
    #[serde(default, alias = "startDate")]
    pub start_date: Option<DateTime<Utc>>,
    #[serde(default, alias = "endDate")]
    pub end_date: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleCampaignRequest {
    #[serde(alias = "scheduledAt")]
    pub scheduled_at: DateTime<Utc>,
}

// ─── Shared request validation ─────────────────────────────────

/// Audience + content + sender + settings + A/B validation shared by create
/// and update. Returns the normalized pieces the handlers persist.
struct ValidatedRefs {
    list_ids: Value,
    exclude_list_ids: Value,
    segment_id: Option<Uuid>,
    from_email: Option<String>,
    from_name: Option<String>,
    reply_to: Option<String>,
    preview_text: Option<String>,
    html: Option<String>,
    text: Option<String>,
    variables: Value,
    utm_params: Value,
    settings: Value,
    ab_test: Option<Value>,
}

/// The normalized pieces of one create/update request. Optional fields are
/// `None` on update when the request omitted them (leave the column alone).
struct CampaignWriteInput<'a> {
    template_id: &'a Option<String>,
    from: &'a Option<String>,
    from_name: &'a Option<String>,
    reply_to: &'a Option<String>,
    preview_text: &'a Option<String>,
    html: &'a Option<String>,
    text: &'a Option<String>,
    variables: &'a Option<Value>,
    list_ids: &'a Option<Vec<String>>,
    exclude_list_ids: &'a Option<Vec<String>>,
    segment_id: &'a Option<String>,
    utm_params: &'a Option<Value>,
    settings: &'a Option<Value>,
    ab_test: &'a Option<Value>,
}

async fn validate_campaign_refs(
    state: &AppState,
    tenant_id: &str,
    input: CampaignWriteInput<'_>,
) -> Result<ValidatedRefs, ApiError> {
    // Verify the referenced template exists and belongs to this tenant
    // (prevents cross-tenant template_id references).
    if let Some(tid) = input.template_id {
        ensure_template_owned(state, tenant_id, tid).await?;
    }

    if let Some(sender) = input.from {
        validate_sender(sender)?;
    }
    let from_name = validate_display_header("fromName", input.from_name.as_deref())?;
    let reply_to = match input.reply_to.as_deref() {
        None => None,
        Some(value) => {
            validate_sender(value)?;
            Some(value.to_string())
        }
    };
    let preview_text = match input.preview_text.as_deref() {
        None => None,
        Some(value) => {
            if value.chars().count() > 300 || value.contains('\r') || value.contains('\n') {
                return Err(ApiError::Validation(vec![
                    "previewText must be a single line of at most 300 characters".into(),
                ]));
            }
            Some(value.to_string())
        }
    };

    // A campaign renders from EXACTLY ONE source: a stored template or the
    // raw html/text pair. Both provided is ambiguous; reject it at write time
    // instead of letting precedence guess.
    const MAX_BODY_BYTES: usize = 1_048_576;
    if let Some(html) = input.html {
        if html.len() > MAX_BODY_BYTES {
            return Err(ApiError::Validation(vec![
                "html must be at most 1 MiB".into()
            ]));
        }
    }
    if let Some(text) = input.text {
        if text.len() > MAX_BODY_BYTES {
            return Err(ApiError::Validation(vec![
                "text must be at most 1 MiB".into()
            ]));
        }
    }
    if input.html.is_some() && input.template_id.is_some() {
        return Err(ApiError::Validation(vec![
            "provide either templateId or html, not both".into(),
        ]));
    }

    let variables = validate_variables(input.variables)?;
    let utm_params = validate_utm_params(input.utm_params)?;
    let settings = validate_campaign_settings(input.settings)?;
    let ab_test = match input.ab_test {
        None => None,
        Some(value) => Some(validate_ab_test(state, tenant_id, value).await?),
    };

    let include = match input.list_ids {
        Some(raw) => parse_list_ids(raw, "listIds")?,
        None => Vec::new(),
    };
    let exclude = match input.exclude_list_ids {
        Some(raw) => parse_list_ids(raw, "excludeListIds")?,
        None => Vec::new(),
    };
    validate_lists_exist(state, tenant_id, &include).await?;
    validate_lists_exist(state, tenant_id, &exclude).await?;

    // A segment reference must exist and belong to the tenant; its lists and
    // match rules are resolved at send time (a saved audience follows edits).
    let segment_id = match input.segment_id.as_deref() {
        None => None,
        Some(raw) => {
            let uuid = Uuid::parse_str(raw)
                .map_err(|_| ApiError::Validation(vec!["segmentId is malformed".into()]))?;
            let exists: Option<bool> = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM segments WHERE id = $1 AND tenant_id = $2)",
            )
            .bind(uuid)
            .bind(tenant_id)
            .fetch_one(&state.db)
            .await?;
            if !exists.unwrap_or(false) {
                return Err(ApiError::NotFound("segment not found".into()));
            }
            Some(uuid)
        }
    };

    Ok(ValidatedRefs {
        list_ids: list_ids_json(&include),
        exclude_list_ids: list_ids_json(&exclude),
        segment_id,
        from_email: input.from.clone(),
        from_name,
        reply_to,
        preview_text,
        html: input.html.clone(),
        text: input.text.clone(),
        variables,
        utm_params,
        settings,
        ab_test,
    })
}

/// Header-bound text fields must be single-line: a CR/LF in a display name
/// or reply-to is SMTP header injection.
pub(crate) fn validate_display_header(
    field: &str,
    value: Option<&str>,
) -> Result<Option<String>, ApiError> {
    match value {
        None => Ok(None),
        Some(value) => {
            if value.contains('\r') || value.contains('\n') || value.contains('\0') {
                return Err(ApiError::Validation(vec![format!(
                    "{field} must be a single line without control characters"
                )]));
            }
            if value.chars().count() > 120 {
                return Err(ApiError::Validation(vec![format!(
                    "{field} must be at most 120 characters"
                )]));
            }
            Ok(Some(value.to_string()))
        }
    }
}

async fn ensure_template_owned(
    state: &AppState,
    tenant_id: &str,
    template_id: &str,
) -> Result<(), ApiError> {
    let exists: Option<bool> = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM templates WHERE id = $1 AND tenant_id = $2)",
    )
    .bind(template_id)
    .bind(tenant_id)
    .fetch_one(&state.db)
    .await?;
    if !exists.unwrap_or(false) {
        return Err(ApiError::NotFound("template not found".into()));
    }
    Ok(())
}

/// Global template variables: a flat object of string values (merge tags are
/// textual), bounded in both key count and value size.
pub(crate) fn validate_variables(raw: &Option<Value>) -> Result<Value, ApiError> {
    let Some(value) = raw else {
        return Ok(serde_json::json!({}));
    };
    let Some(object) = value.as_object() else {
        return Err(ApiError::Validation(vec![
            "variables must be an object of string values".into(),
        ]));
    };
    if object.len() > 200 {
        return Err(ApiError::Validation(vec![
            "variables must contain at most 200 entries".into(),
        ]));
    }
    for (key, value) in object {
        if key.is_empty() || key.chars().count() > 64 {
            return Err(ApiError::Validation(vec![
                "variable names must be 1-64 characters".into(),
            ]));
        }
        let Some(text) = value.as_str() else {
            return Err(ApiError::Validation(vec![
                "variable values must be strings".into(),
            ]));
        };
        if text.len() > 8_192 {
            return Err(ApiError::Validation(vec![
                "variable values must be at most 8 KiB".into(),
            ]));
        }
    }
    Ok(value.clone())
}

/// The documented `utmParams` object: only the five standard UTM keys,
/// string values, bounded.
pub(crate) fn validate_utm_params(raw: &Option<Value>) -> Result<Value, ApiError> {
    let Some(value) = raw else {
        return Ok(serde_json::json!({}));
    };
    let Some(object) = value.as_object() else {
        return Err(ApiError::Validation(vec![
            "utmParams must be an object".into()
        ]));
    };
    const ALLOWED: [&str; 5] = ["source", "medium", "campaign", "term", "content"];
    for (key, value) in object {
        if !ALLOWED.contains(&key.as_str()) {
            return Err(ApiError::Validation(vec![format!(
                "utmParams.{key} is not a UTM parameter (allowed: {})",
                ALLOWED.join(", ")
            )]));
        }
        let Some(text) = value.as_str() else {
            return Err(ApiError::Validation(vec![
                "utmParams values must be strings".into(),
            ]));
        };
        if text.chars().count() > 512 {
            return Err(ApiError::Validation(vec![
                "utmParams values must be at most 512 characters".into(),
            ]));
        }
    }
    Ok(value.clone())
}

/// The documented `settings` object: sendTimeOptimization, timezone,
/// throttleRate, ipPool — validated, unknown keys refused.
pub(crate) fn validate_campaign_settings(raw: &Option<Value>) -> Result<Value, ApiError> {
    let Some(value) = raw else {
        return Ok(serde_json::json!({}));
    };
    let Some(object) = value.as_object() else {
        return Err(ApiError::Validation(vec![
            "settings must be an object".into()
        ]));
    };
    for (key, value) in object {
        match key.as_str() {
            "sendTimeOptimization" => {
                if !value.is_boolean() {
                    return Err(ApiError::Validation(vec![
                        "settings.sendTimeOptimization must be a boolean".into(),
                    ]));
                }
            }
            "timezone" => {
                let Some(tz) = value.as_str() else {
                    return Err(ApiError::Validation(vec![
                        "settings.timezone must be a string".into(),
                    ]));
                };
                if tz.parse::<chrono_tz::Tz>().is_err() {
                    return Err(ApiError::Validation(vec![format!(
                        "settings.timezone is not an IANA timezone: {tz}"
                    )]));
                }
            }
            "throttleRate" => {
                let rate = value.as_i64().unwrap_or(-1);
                if !(0..=1_000_000).contains(&rate) {
                    return Err(ApiError::Validation(vec![
                        "settings.throttleRate must be an integer between 0 and 1000000 \
                         (0 = unlimited)"
                            .into(),
                    ]));
                }
            }
            "ipPool" => {
                let Some(pool) = value.as_str() else {
                    return Err(ApiError::Validation(vec![
                        "settings.ipPool must be a string".into(),
                    ]));
                };
                if pool.chars().count() > 128 {
                    return Err(ApiError::Validation(vec![
                        "settings.ipPool must be at most 128 characters".into(),
                    ]));
                }
            }
            other => {
                return Err(ApiError::Validation(vec![format!(
                    "settings.{other} is not a campaign setting (allowed: \
                     sendTimeOptimization, timezone, throttleRate, ipPool)"
                )]));
            }
        }
    }
    Ok(value.clone())
}

/// The documented A/B test contract: 2-4 arms of {templateId, subject?},
/// a 10-50% test sample, an open|click metric and a 5-1440 minute window.
async fn validate_ab_test(
    state: &AppState,
    tenant_id: &str,
    value: &Value,
) -> Result<Value, ApiError> {
    let Some(object) = value.as_object() else {
        return Err(ApiError::Validation(
            vec!["abTest must be an object".into()],
        ));
    };
    let Some(arms) = object.get("arms").and_then(|v| v.as_array()) else {
        return Err(ApiError::Validation(vec![
            "abTest.arms must be an array of 2-4 {templateId, subject?} arms".into(),
        ]));
    };
    if !(2..=4).contains(&arms.len()) {
        return Err(ApiError::Validation(vec![
            "abTest.arms must contain 2 to 4 arms".into(),
        ]));
    }
    for arm in arms {
        let Some(arm) = arm.as_object() else {
            return Err(ApiError::Validation(vec![
                "each abTest arm must be an object".into(),
            ]));
        };
        let Some(template_id) = arm.get("templateId").and_then(|v| v.as_str()) else {
            return Err(ApiError::Validation(vec![
                "each abTest arm requires a templateId".into(),
            ]));
        };
        ensure_template_owned(state, tenant_id, template_id).await?;
        if let Some(subject) = arm.get("subject") {
            let Some(subject) = subject.as_str() else {
                return Err(ApiError::Validation(vec![
                    "abTest arm subject must be a string".into(),
                ]));
            };
            if subject.is_empty() || subject.chars().count() > 500 {
                return Err(ApiError::Validation(vec![
                    "abTest arm subject must be 1-500 characters".into(),
                ]));
            }
        }
    }
    let test_percentage = object
        .get("testPercentage")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.2);
    if !(0.1..=0.5).contains(&test_percentage) {
        return Err(ApiError::Validation(vec![
            "abTest.testPercentage must be between 0.1 and 0.5".into(),
        ]));
    }
    let metric = object
        .get("metric")
        .and_then(|v| v.as_str())
        .unwrap_or("open");
    if metric != "open" && metric != "click" {
        return Err(ApiError::Validation(vec![
            "abTest.metric must be \"open\" or \"click\"".into(),
        ]));
    }
    let wait_minutes = object
        .get("waitMinutes")
        .and_then(|v| v.as_i64())
        .unwrap_or(60);
    if !(5..=1440).contains(&wait_minutes) {
        return Err(ApiError::Validation(vec![
            "abTest.waitMinutes must be between 5 and 1440".into(),
        ]));
    }
    Ok(value.clone())
}

/// The audience-expansion INSERT — the same SQL the worker's consumer runs
/// when a scheduled campaign comes due (`worker_processors::campaigns`).
/// Subscribed contacts on any `list_ids` list, minus anyone on any
/// `exclude_list_ids` list. Existing rows are never duplicated or downgraded.
async fn expand_audience(
    state: &AppState,
    tenant_id: &str,
    campaign_id: Uuid,
    list_ids: &Value,
    exclude_list_ids: &Value,
    segment_id: Option<Uuid>,
) -> Result<u64, ApiError> {
    let mut include: Vec<Uuid> = list_ids
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().and_then(|s| Uuid::parse_str(s).ok()))
                .collect()
        })
        .unwrap_or_default();
    let mut exclude: Vec<Uuid> = exclude_list_ids
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().and_then(|s| Uuid::parse_str(s).ok()))
                .collect()
        })
        .unwrap_or_default();
    let mut statuses: Vec<String> = vec!["active".into(), "subscribed".into()];
    let mut tags_all: Option<Vec<String>> = None;
    let mut tags_any: Option<Vec<String>> = None;

    // Segment merge — MUST mirror the worker's expansion semantics
    // (worker_processors::campaigns::expand_audience): union of lists and
    // excludes, status/ tag match rules from segment.match.
    if let Some(segment_id) = segment_id {
        let segment: Option<(Value, Value, Value)> = sqlx::query_as(
            "SELECT COALESCE(list_ids, '[]'::jsonb), \
                    COALESCE(exclude_list_ids, '[]'::jsonb), \
                    COALESCE(match, '{}'::jsonb) \
             FROM segments WHERE id = $1 AND tenant_id = $2",
        )
        .bind(segment_id)
        .bind(tenant_id)
        .fetch_optional(&state.db)
        .await?;
        if let Some((seg_lists, seg_excludes, match_rules)) = segment {
            for id in string_array(&seg_lists) {
                if let Ok(uuid) = Uuid::parse_str(&id) {
                    if !include.contains(&uuid) {
                        include.push(uuid);
                    }
                }
            }
            for id in string_array(&seg_excludes) {
                if let Ok(uuid) = Uuid::parse_str(&id) {
                    if !exclude.contains(&uuid) {
                        exclude.push(uuid);
                    }
                }
            }
            if let Some(list) = match_rules.get("statuses").and_then(|v| v.as_array()) {
                let parsed: Vec<String> = list
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect();
                if !parsed.is_empty() {
                    statuses = parsed;
                }
            }
            tags_all = match_rules
                .get("tags_all")
                .and_then(|v| v.as_array())
                .map(|list| {
                    list.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .filter(|v: &Vec<String>| !v.is_empty());
            tags_any = match_rules
                .get("tags_any")
                .and_then(|v| v.as_array())
                .map(|list| {
                    list.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .filter(|v: &Vec<String>| !v.is_empty());
        }
    }

    // An EMPTY include set with no segment match rules is an empty
    // audience — never "every contact". (The cardinality escape in the
    // SQL below only ever selects when tag/status rules constrain the
    // audience, i.e. a tag-targeted segment with no lists.)
    if include.is_empty() && tags_all.is_none() && tags_any.is_none() {
        return Ok(0);
    }

    let result = sqlx::query(
        "INSERT INTO campaign_recipients (tenant_id, campaign_id, contact_id, email, status) \
         SELECT $1, $2, c.id, c.email, 'queued' \
         FROM contacts c \
         WHERE c.tenant_id = $1 \
           AND c.status = ANY($5) \
           AND ($6::text[] IS NULL OR c.tags ?& $6) \
           AND ($7::text[] IS NULL OR c.tags ?| $7) \
           AND ( \
               cardinality($3::uuid[]) = 0 \
               OR EXISTS ( \
                   SELECT 1 FROM list_subscribers ls \
                   WHERE ls.contact_id = c.id AND ls.status = 'active' \
                     AND ls.list_id = ANY($3) \
               ) \
           ) \
           AND NOT EXISTS ( \
               SELECT 1 FROM list_subscribers ls \
               WHERE ls.contact_id = c.id AND ls.list_id = ANY($4) \
           ) \
         ON CONFLICT (campaign_id, contact_id) DO NOTHING",
    )
    .bind(tenant_id)
    .bind(campaign_id)
    .bind(&include)
    .bind(&exclude)
    .bind(&statuses)
    .bind(&tags_all)
    .bind(&tags_any)
    .execute(&state.db)
    .await?;
    Ok(result.rows_affected())
}

/// Assign A/B phases for a freshly expanded audience — the SAME shared
/// deterministic contract the worker applies to scheduled campaigns
/// (`apexmail_lib::ab_testing::AB_SPLIT_SQL`): a hash of
/// `(campaign_id, contact_id)` picks the test sample and its arm, so the
/// immediate-send path and the worker produce identical assignments and a
/// replay lands on the same arm. The immediate-send path splits
/// synchronously so the first drain tick already routes arms.
async fn split_ab_recipients_api(
    state: &AppState,
    campaign_id: Uuid,
    ab_config: &Value,
) -> Result<u64, ApiError> {
    let test_percentage = ab_config
        .get("testPercentage")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.2)
        .clamp(0.1, 0.5);
    let arm_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM campaign_ab_arms WHERE campaign_id = $1")
            .bind(campaign_id)
            .fetch_one(&state.db)
            .await?;
    if arm_count < 2 {
        return Ok(0);
    }
    let split = sqlx::query(apexmail_lib::ab_testing::AB_SPLIT_SQL)
        .bind(campaign_id)
        .bind(test_percentage)
        .bind(arm_count)
        .execute(&state.db)
        .await?;
    if split.rows_affected() > 0 {
        sqlx::query("UPDATE campaign_ab_arms SET updated_at = NOW() WHERE campaign_id = $1")
            .bind(campaign_id)
            .execute(&state.db)
            .await?;
    }
    Ok(split.rows_affected())
}

// ─── Handlers ──────────────────────────────────────────────────

async fn create_campaign(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateCampaignRequest>,
) -> Result<(StatusCode, Json<CampaignResponse>), ApiError> {
    require_scopes(&auth, &["campaigns:write"])?;

    // `chars().count()`, not `String::len()`: the limit (and the DB
    // VARCHAR(255/998) columns, which count characters) are character-based,
    // and the validation message below promises characters. A byte check
    // rejected legitimate 150-character CJK/cyrillic names.
    if body.name.is_empty() || body.name.chars().count() > 200 {
        return Err(ApiError::Validation(vec![
            "name is required and must be 200 characters or fewer".into(),
        ]));
    }
    if body.subject.is_empty() || body.subject.chars().count() > 500 {
        return Err(ApiError::Validation(vec![
            "subject is required and must be 500 characters or fewer".into(),
        ]));
    }

    let refs = validate_campaign_refs(
        &state,
        &auth.tenant_id,
        CampaignWriteInput {
            template_id: &body.template_id,
            from: &body.from,
            from_name: &body.from_name,
            reply_to: &body.reply_to,
            preview_text: &body.preview_text,
            html: &body.html,
            text: &body.text,
            variables: &body.variables,
            list_ids: &body.list_ids,
            exclude_list_ids: &body.exclude_list_ids,
            segment_id: &body.segment_id,
            utm_params: &body.utm_params,
            settings: &body.settings,
            ab_test: &body.ab_test,
        },
    )
    .await?;

    let id = Uuid::new_v4();
    let now = Utc::now();
    let status = if body.scheduled_at.is_some() {
        "scheduled"
    } else {
        "draft"
    };
    let template_id = body.template_id.clone();

    sqlx::query(
        "INSERT INTO campaigns (id, tenant_id, name, subject, template_id, from_email, \
             from_name, reply_to, preview_text, html_body, text_body, variables, \
             segment_id, track_opens, track_clicks, utm_params, settings, ab_config, \
             status, scheduled_at, sent_count, list_ids, exclude_list_ids, created_at, updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18, \
                 $19,$20,0,$21,$22,$23,$23)",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .bind(&body.name)
    .bind(&body.subject)
    .bind(&template_id)
    .bind(&refs.from_email)
    .bind(&refs.from_name)
    .bind(&refs.reply_to)
    .bind(&refs.preview_text)
    .bind(&refs.html)
    .bind(&refs.text)
    .bind(&refs.variables)
    .bind(refs.segment_id)
    .bind(body.track_opens.unwrap_or(true))
    .bind(body.track_clicks.unwrap_or(true))
    .bind(&refs.utm_params)
    .bind(&refs.settings)
    .bind(&refs.ab_test)
    .bind(status)
    .bind(body.scheduled_at)
    .bind(&refs.list_ids)
    .bind(&refs.exclude_list_ids)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(map_campaign_write_error)?;

    // A/B campaigns get their arm state rows at creation so the send path and
    // evaluations have stable arm identities from the first tick.
    if let Some(ab) = refs.ab_test.as_ref() {
        seed_ab_arms(&state, id, ab).await?;
    }

    Ok((
        StatusCode::CREATED,
        Json(CampaignResponse {
            id: id.to_string(),
            name: body.name,
            subject: body.subject,
            template_id,
            from_email: refs.from_email,
            from_name: refs.from_name,
            reply_to: refs.reply_to,
            preview_text: refs.preview_text,
            html: refs.html,
            text: refs.text,
            variables: refs.variables,
            status: status.into(),
            scheduled_at: body.scheduled_at.map(|t| t.to_rfc3339()),
            list_ids: string_array(&refs.list_ids),
            exclude_list_ids: string_array(&refs.exclude_list_ids),
            segment_id: refs.segment_id.map(|id| id.to_string()),
            track_opens: body.track_opens.unwrap_or(true),
            track_clicks: body.track_clicks.unwrap_or(true),
            utm_params: refs.utm_params,
            settings: refs.settings,
            ab_test: refs.ab_test,
            sent_count: 0,
            recipient_count: 0,
            created_at: now.to_rfc3339(),
            updated_at: now.to_rfc3339(),
        }),
    ))
}

/// Materialize the validated A/B config into `campaign_ab_arms` rows (the
/// per-arm Beta state the evaluation reads and updates).
async fn seed_ab_arms(
    state: &AppState,
    campaign_id: Uuid,
    ab_config: &Value,
) -> Result<(), ApiError> {
    let arms = ab_config
        .get("arms")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    for (index, arm) in arms.iter().enumerate() {
        let template_id = arm
            .get("templateId")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let subject = arm.get("subject").and_then(|v| v.as_str());
        sqlx::query(
            "INSERT INTO campaign_ab_arms (campaign_id, arm_index, template_id, subject) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (campaign_id, arm_index) DO UPDATE \
             SET template_id = EXCLUDED.template_id, subject = EXCLUDED.subject, \
                 updated_at = NOW()",
        )
        .bind(campaign_id)
        .bind(index as i32)
        .bind(template_id)
        .bind(subject)
        .execute(&state.db)
        .await?;
    }
    Ok(())
}

/// Read back a JSONB string array for the response.
fn string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

async fn list_campaigns(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: HeaderMap,
    Query(params): Query<ListCampaignsQuery>,
) -> Result<Response, ApiError> {
    require_scopes(&auth, &["campaigns:read"])?;

    let limit = clamp_limit(params.limit, 100);

    // Cursor-based pagination: decode and validate the hex-encoded
    // `created_at\nid` pair BEFORE binding — a bogus cursor used to reach the
    // `::timestamp` cast and surface as a database 500 instead of a client 400.
    let cursor_value = match params.cursor.as_deref() {
        Some(encoded) => Some(decode_keyset_cursor(encoded)?),
        None => None,
    };

    let fetch_limit = limit + 1; // fetch one extra to detect has_more

    // Documented list filters: status (validated against the wire's status
    // vocabulary), case-insensitive name search, and a created-at window.
    if let Some(status) = params.status.as_deref() {
        const STATUSES: [&str; 9] = [
            "draft",
            "scheduled",
            "sending",
            "paused",
            "sent",
            "partial",
            "resending",
            "canceled",
            "canceled_held",
        ];
        if !STATUSES.contains(&status) {
            return Err(ApiError::Validation(vec![format!(
                "status must be one of: {}",
                STATUSES.join(", ")
            )]));
        }
    }
    if let (Some(start), Some(end)) = (params.start_date, params.end_date) {
        if start > end {
            return Err(ApiError::Validation(vec![
                "startDate must not be after endDate".into(),
            ]));
        }
    }
    let search_pattern = params
        .search
        .as_deref()
        .map(|s| format!("%{}%", s.to_lowercase()));

    let rows = if let Some((ref cursor_ts, ref cursor_id)) = cursor_value {
        // campaigns.id is UUID — the VALUE is cast once, never the column,
        // so the primary-key index remains usable for the tie-break.
        sqlx::query_as::<_, CampaignRow>(
            &format!(
            "SELECT {} FROM campaigns c WHERE c.tenant_id = $1 \
               AND (c.created_at < $2::timestamp OR (c.created_at = $2::timestamp AND c.id < $3::uuid)) \
               AND ($5::text IS NULL OR c.status = $5) \
               AND ($6::text IS NULL OR LOWER(c.name) LIKE $6) \
               AND ($7::timestamptz IS NULL OR c.created_at >= $7) \
               AND ($8::timestamptz IS NULL OR c.created_at <= $8) \
             ORDER BY c.created_at DESC, c.id DESC LIMIT $4",
            CAMPAIGN_SELECT_COLUMNS
        ),
        )
        .bind(&auth.tenant_id)
        .bind(cursor_ts)
        .bind(cursor_id)
        .bind(fetch_limit)
        .bind(params.status.as_deref())
        .bind(search_pattern.as_deref())
        .bind(params.start_date)
        .bind(params.end_date)
        .fetch_all(&state.db)
        .await?
    } else {
        // Fallback to offset-based pagination for backward compatibility
        let offset = params.offset.clamp(0, 100_000);
        sqlx::query_as::<_, CampaignRow>(&format!(
            "SELECT {} FROM campaigns c WHERE c.tenant_id = $1 \
               AND ($4::text IS NULL OR c.status = $4) \
               AND ($5::text IS NULL OR LOWER(c.name) LIKE $5) \
               AND ($6::timestamptz IS NULL OR c.created_at >= $6) \
               AND ($7::timestamptz IS NULL OR c.created_at <= $7) \
             ORDER BY c.created_at DESC, c.id DESC LIMIT $2 OFFSET $3",
            CAMPAIGN_SELECT_COLUMNS
        ))
        .bind(&auth.tenant_id)
        .bind(fetch_limit)
        .bind(offset)
        .bind(params.status.as_deref())
        .bind(search_pattern.as_deref())
        .bind(params.start_date)
        .bind(params.end_date)
        .fetch_all(&state.db)
        .await?
    };

    // Build the response rows and detect has_more
    let mut details: Vec<CampaignResponse> = rows.into_iter().map(Into::into).collect();
    let more = has_more(&mut details, limit as usize);

    // Compute the next cursor from the last row's (created_at, id) pair.
    let next_cursor = details.last().and_then(|r| {
        chrono::DateTime::parse_from_rfc3339(&r.created_at)
            .ok()
            .map(|ts| encode_keyset_cursor(&ts.with_timezone(&Utc), &r.id))
    });
    let meta = pagination_meta(more, next_cursor);

    // Build the response body and compute ETag
    let body = serde_json::json!({
        "data": details,
        "error": null,
        "meta": meta,
    });
    let body_bytes = serde_json::to_vec(&body)?;
    let etag = compute_etag(&body_bytes);

    // Check If-None-Match for 304
    if is_not_modified(&headers, &etag) {
        return Ok(axum::response::Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header("ETag", &etag)
            .body(axum::body::Body::empty())
            .expect("invariant: Response builder with valid status/headers should not fail"));
    }

    Ok(axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("ETag", &etag)
        .header("Cache-Control", "private, max-age=0, must-revalidate")
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(body_bytes))
        .expect("invariant: Response builder with valid status/headers/body should not fail"))
}

async fn get_campaign(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<CampaignResponse>, ApiError> {
    require_scopes(&auth, &["campaigns:read"])?;
    let row = fetch_campaign(&state, &auth.tenant_id, id).await?;
    Ok(Json(row.into()))
}

/// PATCH /:id — update a not-yet-drained campaign. Docs contract: "Cannot
/// update campaigns that are sending or completed". Only draft/scheduled/
/// paused campaigns are editable (a `paused` mid-drain campaign resumes into
/// its edited audience on the next tick).
async fn update_campaign(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<UpdateCampaignRequest>,
) -> Result<Json<CampaignResponse>, ApiError> {
    require_scopes(&auth, &["campaigns:write"])?;

    if body.name.is_none()
        && body.subject.is_none()
        && body.template_id.is_none()
        && body.from.is_none()
        && body.scheduled_at.is_none()
        && body.list_ids.is_none()
        && body.exclude_list_ids.is_none()
    {
        return Err(ApiError::Validation(vec![
            "at least one field is required to update".into(),
        ]));
    }
    if let Some(name) = &body.name {
        if name.is_empty() || name.chars().count() > 200 {
            return Err(ApiError::Validation(vec![
                "name must be 200 characters or fewer and not empty".into(),
            ]));
        }
    }
    if let Some(subject) = &body.subject {
        if subject.is_empty() || subject.chars().count() > 500 {
            return Err(ApiError::Validation(vec![
                "subject must be 500 characters or fewer and not empty".into(),
            ]));
        }
    }

    let refs = validate_campaign_refs(
        &state,
        &auth.tenant_id,
        CampaignWriteInput {
            template_id: &body.template_id,
            from: &body.from,
            from_name: &body.from_name,
            reply_to: &body.reply_to,
            preview_text: &body.preview_text,
            html: &body.html,
            text: &body.text,
            variables: &body.variables,
            list_ids: &body.list_ids,
            exclude_list_ids: &body.exclude_list_ids,
            segment_id: &body.segment_id,
            utm_params: &body.utm_params,
            settings: &body.settings,
            ab_test: &body.ab_test,
        },
    )
    .await?;

    // Atomically guard the edit against a concurrent drain/pause: the UPDATE
    // only fires while the status is still editable. A 0-row outcome is
    // disambiguated afterward (404 vs 409).
    let sets_schedule = body.scheduled_at.is_some();
    let result = sqlx::query(
        "UPDATE campaigns SET \
            name = COALESCE($3, name), \
            subject = COALESCE($4, subject), \
            template_id = CASE WHEN $5::text IS NOT NULL THEN $5 \
                               WHEN $11::text IS NOT NULL THEN NULL \
                               ELSE template_id END, \
            from_email = COALESCE($6, from_email), \
            from_name = COALESCE($13, from_name), \
            reply_to = COALESCE($14, reply_to), \
            preview_text = COALESCE($15, preview_text), \
            html_body = CASE WHEN $11::text IS NOT NULL THEN $11 ELSE html_body END, \
            text_body = CASE WHEN $12::text IS NOT NULL THEN $12 ELSE text_body END, \
            variables = COALESCE($16, variables), \
            segment_id = COALESCE($17, segment_id), \
            track_opens = COALESCE($18, track_opens), \
            track_clicks = COALESCE($19, track_clicks), \
            utm_params = COALESCE($20, utm_params), \
            settings = COALESCE($21, settings), \
            ab_config = COALESCE($22, ab_config), \
            list_ids = COALESCE($7, list_ids), \
            exclude_list_ids = COALESCE($8, exclude_list_ids), \
            scheduled_at = CASE WHEN $9 THEN $10 ELSE scheduled_at END, \
            status = CASE WHEN $9 AND status = 'draft' THEN 'scheduled' ELSE status END, \
            updated_at = NOW() \
         WHERE id = $1::uuid AND tenant_id = $2 AND status IN ('draft', 'scheduled', 'paused')",
    )
    .bind(parse_campaign_id(&id)?)
    .bind(&auth.tenant_id)
    .bind(&body.name)
    .bind(&body.subject)
    .bind(&body.template_id)
    .bind(&refs.from_email)
    .bind(&refs.list_ids)
    .bind(&refs.exclude_list_ids)
    .bind(sets_schedule)
    .bind(body.scheduled_at)
    .bind(&refs.html)
    .bind(&refs.text)
    .bind(&refs.from_name)
    .bind(&refs.reply_to)
    .bind(&refs.preview_text)
    .bind(&refs.variables)
    .bind(refs.segment_id)
    .bind(body.track_opens)
    .bind(body.track_clicks)
    .bind(&refs.utm_params)
    .bind(&refs.settings)
    .bind(&refs.ab_test)
    .execute(&state.db)
    .await
    .map_err(map_campaign_write_error)?;

    if result.rows_affected() == 0 {
        let Some(status): Option<String> = sqlx::query_scalar(
            "SELECT status FROM campaigns WHERE id = $1::uuid AND tenant_id = $2",
        )
        .bind(parse_campaign_id(&id)?)
        .bind(&auth.tenant_id)
        .fetch_optional(&state.db)
        .await?
        else {
            return Err(ApiError::NotFound("campaign not found".into()));
        };
        return Err(ApiError::Conflict(format!(
            "campaigns in status '{status}' cannot be updated; only draft, scheduled or paused campaigns can be"
        )));
    }

    // Re-seed arm state when an A/B config was supplied (identity-stable
    // upsert; Beta state is preserved across config edits).
    if let Some(ab) = refs.ab_test.as_ref() {
        seed_ab_arms(&state, parse_campaign_id(&id)?, ab).await?;
    }

    let row = fetch_campaign(&state, &auth.tenant_id, id).await?;
    Ok(Json(row.into()))
}

async fn delete_campaign(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["campaigns:write"])?;

    // Documented contract (docs/api/endpoints/campaigns.md "Delete
    // Campaign"): only draft or canceled campaigns may be deleted. The
    // conditional DELETE guards the transition atomically, and a 0-row
    // outcome is disambiguated afterward so a live campaign yields an
    // honest 409 while an unknown/cross-tenant one stays a 404.
    let result = sqlx::query(
        "DELETE FROM campaigns
         WHERE id = $1::uuid AND tenant_id = $2 AND status IN ('draft', 'canceled')",
    )
    .bind(parse_campaign_id(&id)?)
    .bind(&auth.tenant_id)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        let Some(status): Option<String> = sqlx::query_scalar(
            "SELECT status FROM campaigns WHERE id = $1::uuid AND tenant_id = $2",
        )
        .bind(parse_campaign_id(&id)?)
        .bind(&auth.tenant_id)
        .fetch_optional(&state.db)
        .await?
        else {
            return Err(ApiError::NotFound("campaign not found".into()));
        };
        return Err(ApiError::Conflict(format!(
            "campaigns in status '{status}' cannot be deleted; only draft or canceled campaigns can be"
        )));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// POST /:id/send — resolve the audience and start sending. DRAFT-only; the
/// response reflects the REAL outcome: recipientCount is the audience the
/// worker will drain, and a zero-audience send converges to `sent`
/// immediately instead of pretending to start.
async fn send_campaign(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<CampaignResponse>, ApiError> {
    require_scopes(&auth, &["campaigns:write"])?;
    let campaign_id = parse_campaign_id(&id)?;

    let row = fetch_campaign(&state, &auth.tenant_id, id.clone()).await?;
    if row.status != "draft" {
        return Err(ApiError::Validation(vec![format!(
            "cannot send from status '{}'; only draft campaigns can be sent",
            row.status
        )]));
    }
    // The worker's send ladder needs a sender and a template; refuse now with
    // a clean 400 instead of parking every recipient row in `failed`.
    if row.from_email.as_deref().unwrap_or("").is_empty() {
        return Err(ApiError::Validation(vec![
            "campaign has no sender address; set 'from' before sending".into(),
        ]));
    }
    // Content may live on the campaign (template or raw html) OR on the
    // A/B arms (an abTest campaign with no campaign-level template renders
    // per-arm content — the arm templates were validated at write time).
    if row.template_id.as_deref().unwrap_or("").is_empty()
        && row.html_body.as_deref().unwrap_or("").is_empty()
        && row.ab_config.is_none()
    {
        return Err(ApiError::Validation(vec![
            "campaign has no content; set 'templateId', 'html' or an abTest before sending".into(),
        ]));
    }

    // Atomic claim: two racing sends must not both report success.
    let claimed = sqlx::query(
        "UPDATE campaigns SET status = 'sending', updated_at = NOW() \
         WHERE id = $1::uuid AND tenant_id = $2 AND status = 'draft'",
    )
    .bind(campaign_id)
    .bind(&auth.tenant_id)
    .execute(&state.db)
    .await?;
    if claimed.rows_affected() == 0 {
        return Err(ApiError::Conflict(
            "campaign status changed before send; only draft campaigns can be sent".into(),
        ));
    }

    // Resolve the audience synchronously so the response is honest.
    let (list_ids, exclude_list_ids, segment_id, ab_config): (
        Value,
        Value,
        Option<String>,
        Option<Value>,
    ) = sqlx::query_as(
        "SELECT COALESCE(list_ids, '[]'::jsonb), COALESCE(exclude_list_ids, '[]'::jsonb), \
                segment_id::text, ab_config \
         FROM campaigns WHERE id = $1::uuid AND tenant_id = $2",
    )
    .bind(campaign_id)
    .bind(&auth.tenant_id)
    .fetch_one(&state.db)
    .await?;
    let segment_uuid = segment_id.as_deref().and_then(|s| Uuid::parse_str(s).ok());
    expand_audience(
        &state,
        &auth.tenant_id,
        campaign_id,
        &list_ids,
        &exclude_list_ids,
        segment_uuid,
    )
    .await?;
    if let Some(config) = ab_config.as_ref() {
        split_ab_recipients_api(&state, campaign_id, config).await?;
    }

    let recipient_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM campaign_recipients WHERE campaign_id = $1")
            .bind(campaign_id)
            .fetch_one(&state.db)
            .await?;

    if recipient_count == 0 {
        // Nothing to drain. Converging silently to `sent` reported a "send"
        // that reached nobody (adversarial dogfood: `a campaign start with no
        // audience is a named refusal, never a silent success`). Revert the
        // claim and refuse with an actionable named error instead — the
        // caller can add a list/segment/recipients and start for real.
        sqlx::query(
            "UPDATE campaigns SET status = 'draft', updated_at = NOW() \
             WHERE id = $1::uuid AND tenant_id = $2 AND status = 'sending'",
        )
        .bind(campaign_id)
        .bind(&auth.tenant_id)
        .execute(&state.db)
        .await?;
        return Err(ApiError::Validation(vec![
            "campaign has no recipients: add a list, a segment or explicit recipients before \
             sending (nothing was sent)"
                .into(),
        ]));
    }

    let row = fetch_campaign(&state, &auth.tenant_id, id).await?;
    Ok(Json(row.into()))
}

/// POST /:id/schedule — store a due time; the WORKER sends when due
/// (`status = 'scheduled' AND scheduled_at <= NOW()` is claimed by the
/// campaign consumer each tick).
async fn schedule_campaign(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<ScheduleCampaignRequest>,
) -> Result<Json<CampaignResponse>, ApiError> {
    require_scopes(&auth, &["campaigns:write"])?;
    let campaign_id = parse_campaign_id(&id)?;

    let claimed = sqlx::query(
        "UPDATE campaigns SET status = 'scheduled', scheduled_at = $3, updated_at = NOW() \
         WHERE id = $1::uuid AND tenant_id = $2 AND status = 'draft'",
    )
    .bind(campaign_id)
    .bind(&auth.tenant_id)
    .bind(body.scheduled_at)
    .execute(&state.db)
    .await?;

    if claimed.rows_affected() == 0 {
        let Some(status): Option<String> = sqlx::query_scalar(
            "SELECT status FROM campaigns WHERE id = $1::uuid AND tenant_id = $2",
        )
        .bind(campaign_id)
        .bind(&auth.tenant_id)
        .fetch_optional(&state.db)
        .await?
        else {
            return Err(ApiError::NotFound("campaign not found".into()));
        };
        return Err(ApiError::Validation(vec![format!(
            "cannot schedule from status '{status}'; only draft campaigns can be scheduled"
        )]));
    }

    let row = fetch_campaign(&state, &auth.tenant_id, id).await?;
    Ok(Json(row.into()))
}

async fn resume_campaign(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<CampaignResponse>, ApiError> {
    require_scopes(&auth, &["campaigns:write"])?;
    let current = fetch_campaign(&state, &auth.tenant_id, id.clone()).await?;
    // A `scheduled` campaign is already queued for its due time — resume is
    // idempotent and returns it unchanged (the consumer will start it when
    // due). This is the state a paused-scheduled campaign resumes INTO, so
    // an immediate follow-up resume must not be a validation error.
    if current.status == "scheduled" {
        return Ok(Json(current.into()));
    }
    if !matches!(current.status.as_str(), "paused" | "draft") {
        return Err(ApiError::Validation(vec![format!(
            "cannot transition from '{}' to a sending state",
            current.status
        )]));
    }
    // A paused SCHEDULED campaign whose due time is still in the future
    // resumes into `scheduled` (the consumer will start it when due), not
    // into an immediate send.
    let new_status = match (current.status.as_str(), current.scheduled_at) {
        ("paused", Some(due)) if due > Utc::now() => "scheduled",
        _ => "sending",
    };
    transition_campaign_status(
        &state,
        &auth.tenant_id,
        &id,
        new_status,
        &["paused", "draft"],
    )
    .await
}

async fn pause_campaign(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<CampaignResponse>, ApiError> {
    require_scopes(&auth, &["campaigns:write"])?;
    // `resending` is pausable too: pausing between the resend request and the
    // consumer tick must defer the job, not race it.
    transition_campaign_status(
        &state,
        &auth.tenant_id,
        &id,
        "paused",
        &["sending", "scheduled", "resending"],
    )
    .await
}

/// Atomically guarded transition (the UPDATE re-checks the allowed source
/// states, closing the SELECT→UPDATE race).
async fn transition_campaign_status(
    state: &AppState,
    tenant_id: &str,
    id: &str,
    new_status: &str,
    valid_current_states: &[&str],
) -> Result<Json<CampaignResponse>, ApiError> {
    let allowed: Vec<&str> = valid_current_states.to_vec();
    let result = sqlx::query(
        "UPDATE campaigns SET status = $1, updated_at = NOW()
         WHERE id = $2::uuid AND tenant_id = $3 AND status = ANY($4)",
    )
    .bind(new_status)
    .bind(parse_campaign_id(id)?)
    .bind(tenant_id)
    .bind(&allowed)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        let Some(current): Option<String> = sqlx::query_scalar(
            "SELECT status FROM campaigns WHERE id = $1::uuid AND tenant_id = $2",
        )
        .bind(parse_campaign_id(id)?)
        .bind(tenant_id)
        .fetch_optional(&state.db)
        .await?
        else {
            return Err(ApiError::NotFound("campaign not found".into()));
        };
        return Err(ApiError::Validation(vec![format!(
            "cannot transition from '{current}' to '{new_status}'"
        )]));
    }

    let row = fetch_campaign(state, tenant_id, id.to_string()).await?;
    Ok(Json(row.into()))
}

// ─── Row types ─────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct CampaignRow {
    id: String,
    name: String,
    subject: String,
    template_id: Option<String>,
    from_email: Option<String>,
    from_name: Option<String>,
    reply_to: Option<String>,
    preview_text: Option<String>,
    html_body: Option<String>,
    text_body: Option<String>,
    variables: Value,
    status: String,
    scheduled_at: Option<DateTime<Utc>>,
    // campaigns.sent_count is INT4 — sqlx refuses to decode INT4 into i64.
    sent_count: i32,
    list_ids: Value,
    exclude_list_ids: Value,
    segment_id: Option<String>,
    track_opens: bool,
    track_clicks: bool,
    utm_params: Value,
    settings: Value,
    ab_config: Option<Value>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    recipient_count: i64,
}

/// The shared SELECT list for every campaign read, so the three queries can
/// never drift from [`CampaignRow`].
const CAMPAIGN_SELECT_COLUMNS: &str =
    "c.id::text, c.name, c.subject, c.template_id, c.from_email, \
     c.from_name, c.reply_to, c.preview_text, c.html_body, c.text_body, c.variables, \
     c.status, c.scheduled_at, c.sent_count, \
     COALESCE(c.list_ids, '[]'::jsonb) AS list_ids, \
     COALESCE(c.exclude_list_ids, '[]'::jsonb) AS exclude_list_ids, \
     c.segment_id::text AS segment_id, \
     c.track_opens, c.track_clicks, \
     COALESCE(c.utm_params, '{}'::jsonb) AS utm_params, \
     COALESCE(c.settings, '{}'::jsonb) AS settings, \
     c.ab_config, \
     c.created_at, c.updated_at, \
     (SELECT COUNT(*) FROM campaign_recipients cr WHERE cr.campaign_id = c.id) AS recipient_count";

impl From<CampaignRow> for CampaignResponse {
    fn from(r: CampaignRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            subject: r.subject,
            template_id: r.template_id,
            from_email: r.from_email,
            from_name: r.from_name,
            reply_to: r.reply_to,
            preview_text: r.preview_text,
            html: r.html_body,
            text: r.text_body,
            variables: r.variables,
            status: r.status,
            scheduled_at: r.scheduled_at.map(|t| t.to_rfc3339()),
            list_ids: string_array(&r.list_ids),
            exclude_list_ids: string_array(&r.exclude_list_ids),
            segment_id: r.segment_id,
            track_opens: r.track_opens,
            track_clicks: r.track_clicks,
            utm_params: r.utm_params,
            settings: r.settings,
            ab_test: r.ab_config,
            sent_count: r.sent_count as i64,
            recipient_count: r.recipient_count,
            created_at: r.created_at.to_rfc3339(),
            updated_at: r.updated_at.to_rfc3339(),
        }
    }
}

async fn fetch_campaign(
    state: &AppState,
    tenant_id: &str,
    id: String,
) -> Result<CampaignRow, ApiError> {
    sqlx::query_as::<_, CampaignRow>(&format!(
        "SELECT {} FROM campaigns c WHERE c.id = $1::uuid AND c.tenant_id = $2",
        CAMPAIGN_SELECT_COLUMNS
    ))
    .bind(parse_campaign_id(&id)?)
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("campaign not found".into()))
}

// ─── Resend Handler ────────────────────────────────────────────

async fn resend_campaign(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["campaigns:write"])?;

    // Verify campaign exists and belongs to tenant, and is in a resendable state
    let campaign_status = sqlx::query_scalar::<_, String>(
        "SELECT status FROM campaigns WHERE id = $1::uuid AND tenant_id = $2",
    )
    .bind(id)
    .bind(auth.tenant_id.to_string())
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("campaign not found".into()))?;

    if campaign_status != "sent" && campaign_status != "partial" {
        return Err(ApiError::BadRequest(format!(
            "Campaign status '{}' is not resendable. Must be 'sent' or 'partial'.",
            campaign_status
        )));
    }

    // Create a new send job for failed/unsent recipients. The WORKER campaign
    // consumer drains this row (job_type 'resend'): failed recipients are
    // requeued, suppressed recipients stay terminal, and the campaign returns
    // to the drain pipeline. Before the consumer existed (dogfood DF-3) this
    // row sat 'queued' forever and the campaign never resent.
    // job_type is NOT NULL with no default, so it must be supplied explicitly.
    let new_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO campaign_jobs (id, campaign_id, tenant_id, job_type, status, created_at)
         VALUES ($1, $2, $3, 'resend', 'queued', NOW())",
    )
    .bind(new_id)
    .bind(id)
    .bind(auth.tenant_id.to_string())
    .execute(&state.db)
    .await?;

    // Update campaign status
    sqlx::query("UPDATE campaigns SET status = 'resending', updated_at = NOW() WHERE id = $1::uuid AND tenant_id = $2")
        .bind(id)
        .bind(auth.tenant_id.to_string())
        .execute(&state.db)
        .await?;

    Ok(Json(serde_json::json!({
        "job_id": new_id,
        "campaign_id": id,
        "status": "queued",
    })))
}

// ─── Stats Handler ─────────────────────────────────────────────

/// GET /:id/stats — real per-campaign delivery + engagement numbers, joined
/// through the `campaign_recipients.message_id` back-reference the send
/// pipeline writes. The docs' device/client/geo/timeline breakdowns have no
/// wire implementation and were removed from the contract.
async fn campaign_stats(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["campaigns:read"])?;
    let campaign_id = parse_campaign_id(&id)?;

    let row = fetch_campaign(&state, &auth.tenant_id, id).await?;

    let (total, queued, inflight, sent, failed, suppressed): (i64, i64, i64, i64, i64, i64) =
        sqlx::query_as(
            "SELECT COUNT(*), \
                    COUNT(*) FILTER (WHERE status = 'queued'), \
                    COUNT(*) FILTER (WHERE status = 'sending'), \
                    COUNT(*) FILTER (WHERE status = 'sent'), \
                    COUNT(*) FILTER (WHERE status = 'failed'), \
                    COUNT(*) FILTER (WHERE status = 'suppressed') \
             FROM campaign_recipients WHERE campaign_id = $1",
        )
        .bind(campaign_id)
        .fetch_one(&state.db)
        .await?;

    let (
        delivered,
        bounced,
        msg_failed,
        opens,
        unique_opens,
        clicks,
        unique_clicks,
        unsubscribes,
    ): (i64, i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT \
            COUNT(m.id) FILTER (WHERE m.status = 'sent'), \
            COUNT(m.id) FILTER (WHERE m.status = 'bounced'), \
            COUNT(m.id) FILTER (WHERE m.status = 'failed'), \
            COALESCE(SUM(m.open_count), 0), \
            COUNT(m.id) FILTER (WHERE m.first_opened_at IS NOT NULL), \
            COALESCE(SUM(m.click_count), 0), \
            COUNT(m.id) FILTER (WHERE m.first_clicked_at IS NOT NULL), \
            COALESCE(SUM(m.unsubscribe_count), 0) \
         FROM campaign_recipients cr \
         LEFT JOIN messages m ON m.id = cr.message_id \
         WHERE cr.campaign_id = $1 AND cr.tenant_id = $2",
    )
    .bind(campaign_id)
    .bind(&auth.tenant_id)
    .fetch_one(&state.db)
    .await?;

    // Per-device open breakdown (documented "per-device stats"): classify
    // the open events' user agents into desktop/mobile/tablet/other, counted
    // per unique message so one device reloading the pixel five times is
    // still one open.
    let (desktop_opens, mobile_opens, tablet_opens, other_opens): (i64, i64, i64, i64) =
        sqlx::query_as(
            "SELECT \
                COUNT(DISTINCT message_id) FILTER (WHERE device = 'desktop'), \
                COUNT(DISTINCT message_id) FILTER (WHERE device = 'mobile'), \
                COUNT(DISTINCT message_id) FILTER (WHERE device = 'tablet'), \
                COUNT(DISTINCT message_id) FILTER (WHERE device = 'other') \
             FROM ( \
                 SELECT message_id, \
                        CASE \
                            WHEN COALESCE(user_agent, '') = '' THEN 'other' \
                            WHEN user_agent ILIKE '%ipad%' OR user_agent ILIKE '%tablet%' \
                                THEN 'tablet' \
                            WHEN user_agent ILIKE '%iphone%' OR user_agent ILIKE '%android%' \
                                OR user_agent ILIKE '%mobile%' OR user_agent ILIKE '%windows phone%' \
                                THEN 'mobile' \
                            WHEN user_agent ILIKE '%mozilla%' OR user_agent ILIKE '%applewebkit%' \
                                OR user_agent ILIKE '%outlook%' OR user_agent ILIKE '%thunderbird%' \
                                THEN 'desktop' \
                            ELSE 'other' \
                        END AS device \
                 FROM events \
                 WHERE campaign_id = $1 AND event_type = 'opened' AND tenant_id = $2 \
             ) classified",
        )
        .bind(campaign_id.to_string())
        .bind(&auth.tenant_id)
        .fetch_one(&state.db)
        .await?;

    // Rates are honest zeros with no delivery denominator.
    let rate = |numerator: i64, denominator: i64| -> f64 {
        if denominator > 0 {
            numerator as f64 / denominator as f64
        } else {
            0.0
        }
    };

    Ok(Json(serde_json::json!({
        "id": row.id,
        "name": row.name,
        "status": row.status,
        "audience": {
            "total": total,
            "queued": queued,
            "in_flight": inflight,
            "sent": sent,
            "failed": failed,
            "suppressed": suppressed,
        },
        "delivery": {
            "enqueued": sent,
            "delivered": delivered,
            "bounced": bounced,
            "failed": msg_failed,
            "bounce_rate": rate(bounced, sent),
        },
        "engagement": {
            "opens": opens,
            "unique_opens": unique_opens,
            "open_rate": rate(unique_opens, sent),
            "clicks": clicks,
            "unique_clicks": unique_clicks,
            "click_rate": rate(unique_clicks, sent),
            "unsubscribes": unsubscribes,
            "devices": {
                "desktop": desktop_opens,
                "mobile": mobile_opens,
                "tablet": tablet_opens,
                "other": other_opens,
            },
        },
    })))
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_campaign_deser() {
        let json = r#"{"name":"Summer Sale","subject":"50% Off!"}"#;
        let req: CreateCampaignRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "Summer Sale");
        assert!(req.template_id.is_none());
    }

    /// The docs' camelCase field names parse too (serde aliases) — the
    /// documented request bodies must not 400 against the real wire.
    #[test]
    fn test_create_campaign_deser_accepts_documented_camel_case() {
        let json = r#"{"name":"N","subject":"S","templateId":"tmpl_1","from":"news@acme.test","scheduledAt":"2026-01-20T09:00:00Z","listIds":["11111111-1111-1111-1111-111111111111"],"excludeListIds":[]}"#;
        let req: CreateCampaignRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.template_id.as_deref(), Some("tmpl_1"));
        assert_eq!(req.from.as_deref(), Some("news@acme.test"));
        assert_eq!(req.list_ids.as_deref().map(<[String]>::len), Some(1));
    }

    /// The documented full-fidelity fields all parse on the wire: segmentId,
    /// previewText, fromName, replyTo, raw html/text, variables, tracking
    /// toggles, utmParams, settings and the A/B config.
    #[test]
    fn test_documented_fidelity_fields_parse() {
        let req: CreateCampaignRequest = serde_json::from_str(
            r#"{"name":"n","subject":"s",
                "segmentId":"11111111-1111-1111-1111-111111111111",
                "previewText":"See what's new",
                "fromName":"Your Company","replyTo":"support@acme.test",
                "html":"<p>hi</p>","text":"hi",
                "variables":{"month":"January"},
                "trackOpens":false,"trackClicks":true,
                "utmParams":{"source":"email","medium":"newsletter"},
                "settings":{"sendTimeOptimization":true,"timezone":"America/New_York","throttleRate":1000,"ipPool":"pool-a"},
                "abTest":{"arms":[{"templateId":"t1"},{"templateId":"t2","subject":"B"}],"testPercentage":0.2,"metric":"open","waitMinutes":60}}"#,
        )
        .expect("documented fidelity fields must parse");
        assert!(req.segment_id.is_some());
        assert_eq!(req.from_name.as_deref(), Some("Your Company"));
        assert_eq!(req.track_opens, Some(false));
        assert!(req.ab_test.is_some());
    }

    #[test]
    fn test_campaign_response_serialisation() {
        let resp = CampaignResponse {
            id: String::new(),
            name: "Test".into(),
            subject: "Sub".into(),
            template_id: None,
            from_email: None,
            status: "draft".into(),
            scheduled_at: None,
            list_ids: vec![],
            exclude_list_ids: vec![],
            sent_count: 0,
            recipient_count: 0,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),

            from_name: None,
            reply_to: None,
            preview_text: None,
            html: None,
            text: None,
            variables: serde_json::json!([]),
            segment_id: None,
            track_opens: true,
            track_clicks: true,
            utm_params: serde_json::json!([]),
            settings: serde_json::json!([]),
            ab_test: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["sent_count"], 0);
        assert_eq!(json["recipient_count"], 0);
    }

    #[test]
    fn list_id_validation_rejects_malformed_and_oversized() {
        let good = parse_list_ids(
            &[
                "11111111-1111-1111-1111-111111111111".to_string(),
                "11111111-1111-1111-1111-111111111111".to_string(),
            ],
            "listIds",
        )
        .unwrap();
        assert_eq!(good.len(), 1, "duplicates are deduped");

        assert!(parse_list_ids(&["not-a-uuid".to_string()], "listIds").is_err());
        assert!(parse_list_ids(&["x".repeat(65)], "listIds").is_err());
        let too_many: Vec<String> = (0..=MAX_LISTS_PER_CAMPAIGN)
            .map(|i| format!("{:08x}-1111-1111-1111-111111111111", i as u32))
            .collect();
        assert!(parse_list_ids(&too_many, "listIds").is_err());
    }

    #[test]
    fn sender_validation_rejects_junk() {
        assert!(validate_sender("news@acme.test").is_ok());
        for bad in [
            "",
            "@acme.test",
            "news@",
            "no-at-sign",
            "a b@acme.test",
            "a,b@acme.test",
            "a\nb@acme.test",
            &"x".repeat(321),
        ] {
            assert!(validate_sender(bad).is_err(), "{bad:?} must be refused");
        }
    }
}

// ─── Adversarial CRUD / pagination / transition tests ──────────

#[cfg(test)]
mod adversarial_tests {
    use super::*;

    fn auth_for(tenant: &str, scopes: &[&str]) -> AuthUser {
        AuthUser {
            tenant_id: tenant.to_string(),
            user_id: None,
            api_key_id: Some("key_adversarial".into()),
            session_id: None,
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
        }
    }

    async fn state_and_pool(name: &str) -> Option<(AppState, sqlx::PgPool)> {
        let pool = crate::test_db::optional_pg_pool(name).await?;
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        Some((state, pool))
    }

    async fn seed_tenant(pool: &sqlx::PgPool, tenant: &str) {
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status, created_at, updated_at)
             VALUES ($1, 'campaigns adversarial', 'free', 'active', NOW(), NOW())
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(tenant)
        .execute(pool)
        .await
        .expect("seed tenant");
    }

    async fn seed_campaign(
        pool: &sqlx::PgPool,
        tenant: &str,
        name: &str,
        status: &str,
        created_at: DateTime<Utc>,
    ) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO campaigns (id, tenant_id, name, subject, status, sent_count, created_at, updated_at)
             VALUES ($1, $2, $3, 'Subject', $4, 0, $5, $5)",
        )
        .bind(id)
        .bind(tenant)
        .bind(name)
        .bind(status)
        .bind(created_at)
        .execute(pool)
        .await
        .expect("seed campaign");
        id
    }

    async fn cleanup(pool: &sqlx::PgPool, tenants: &[&str]) {
        for tenant in tenants {
            sqlx::query("DELETE FROM campaigns WHERE tenant_id = $1")
                .bind(tenant)
                .execute(pool)
                .await
                .expect("cleanup campaigns");
            sqlx::query("DELETE FROM campaign_jobs WHERE tenant_id = $1")
                .bind(tenant)
                .execute(pool)
                .await
                .expect("cleanup jobs");
            sqlx::query("DELETE FROM tenants WHERE id = $1")
                .bind(tenant)
                .execute(pool)
                .await
                .expect("cleanup tenants");
        }
    }

    #[test]
    fn keyset_cursor_rejects_every_malformed_shape() {
        let ts = Utc::now();
        let encoded = encode_keyset_cursor(&ts, "11111111-1111-1111-1111-111111111111");
        let (decoded_ts, decoded_id) = decode_keyset_cursor(&encoded).expect("roundtrip");
        assert_eq!(decoded_id, "11111111-1111-1111-1111-111111111111");
        assert_eq!(decoded_ts.timestamp(), ts.timestamp());

        assert!(matches!(
            decode_keyset_cursor("!!!not-hex!!!"),
            Err(ApiError::BadRequest(_))
        ));
        // Hex but no separator.
        let no_sep = encode_cursor("just-a-timestamp");
        assert!(matches!(
            decode_keyset_cursor(&no_sep),
            Err(ApiError::BadRequest(_))
        ));
        // Unparsable timestamp.
        let bad_ts = encode_cursor("yesterday\nsomeid");
        assert!(matches!(
            decode_keyset_cursor(&bad_ts),
            Err(ApiError::BadRequest(_))
        ));
        // Empty id / oversize id / control byte in id.
        for bad in [
            format!("{ts}\n"),
            format!("{ts}\n{}", "x".repeat(65)),
            format!("{ts}\nsome\u{7}id"),
        ] {
            let encoded = encode_cursor(&bad);
            assert!(
                matches!(decode_keyset_cursor(&encoded), Err(ApiError::BadRequest(_))),
                "cursor payload {bad:?} must be refused"
            );
        }
    }

    #[tokio::test]
    async fn create_validates_bounds_and_references_before_insert() {
        let Some((state, pool)) = state_and_pool("adv_campaigns_create").await else {
            return;
        };
        let tenant = apexmail_lib::id::generate_id("", 26);
        seed_tenant(&pool, &tenant).await;
        let auth = auth_for(&tenant, &["campaigns:write"]);
        let tag = uuid::Uuid::new_v4().simple().to_string();
        let campaign_name = format!("Launch {tag}");

        let empty_name = create_campaign(
            State(state.clone()),
            auth.clone(),
            Json(CreateCampaignRequest {
                name: String::new(),
                subject: "s".into(),
                template_id: None,
                from: None,
                scheduled_at: None,
                list_ids: None,
                exclude_list_ids: None,

                from_name: None,
                reply_to: None,
                preview_text: None,
                html: None,
                text: None,
                variables: None,
                segment_id: None,
                track_opens: None,
                track_clicks: None,
                utm_params: None,
                settings: None,
                ab_test: None,
            }),
        )
        .await;
        assert!(matches!(empty_name, Err(ApiError::Validation(_))));

        let long_name = create_campaign(
            State(state.clone()),
            auth.clone(),
            Json(CreateCampaignRequest {
                name: "n".repeat(201),
                subject: "s".into(),
                template_id: None,
                from: None,
                scheduled_at: None,
                list_ids: None,
                exclude_list_ids: None,

                from_name: None,
                reply_to: None,
                preview_text: None,
                html: None,
                text: None,
                variables: None,
                segment_id: None,
                track_opens: None,
                track_clicks: None,
                utm_params: None,
                settings: None,
                ab_test: None,
            }),
        )
        .await;
        assert!(matches!(long_name, Err(ApiError::Validation(_))));

        let empty_subject = create_campaign(
            State(state.clone()),
            auth.clone(),
            Json(CreateCampaignRequest {
                name: "ok".into(),
                subject: String::new(),
                template_id: None,
                from: None,
                scheduled_at: None,
                list_ids: None,
                exclude_list_ids: None,

                from_name: None,
                reply_to: None,
                preview_text: None,
                html: None,
                text: None,
                variables: None,
                segment_id: None,
                track_opens: None,
                track_clicks: None,
                utm_params: None,
                settings: None,
                ab_test: None,
            }),
        )
        .await;
        assert!(matches!(empty_subject, Err(ApiError::Validation(_))));

        let long_subject = create_campaign(
            State(state.clone()),
            auth.clone(),
            Json(CreateCampaignRequest {
                name: "ok".into(),
                subject: "s".repeat(501),
                template_id: None,
                from: None,
                scheduled_at: None,
                list_ids: None,
                exclude_list_ids: None,

                from_name: None,
                reply_to: None,
                preview_text: None,
                html: None,
                text: None,
                variables: None,
                segment_id: None,
                track_opens: None,
                track_clicks: None,
                utm_params: None,
                settings: None,
                ab_test: None,
            }),
        )
        .await;
        assert!(matches!(long_subject, Err(ApiError::Validation(_))));

        // Limits count CHARACTERS (the documented contract and the response
        // message), not bytes: a 200-cyrillic-character name (400 bytes) is
        // valid, a 201-character one is not.
        let unicode_200 = create_campaign(
            State(state.clone()),
            auth.clone(),
            Json(CreateCampaignRequest {
                name: "а".repeat(200),
                subject: "s".into(),
                template_id: None,
                from: None,
                scheduled_at: None,
                list_ids: None,
                exclude_list_ids: None,

                from_name: None,
                reply_to: None,
                preview_text: None,
                html: None,
                text: None,
                variables: None,
                segment_id: None,
                track_opens: None,
                track_clicks: None,
                utm_params: None,
                settings: None,
                ab_test: None,
            }),
        )
        .await;
        assert!(
            unicode_200.is_ok(),
            "200-character unicode name must be accepted, got {unicode_200:?}"
        );
        let unicode_201 = create_campaign(
            State(state.clone()),
            auth.clone(),
            Json(CreateCampaignRequest {
                name: "а".repeat(201),
                subject: "s".into(),
                template_id: None,
                from: None,
                scheduled_at: None,
                list_ids: None,
                exclude_list_ids: None,

                from_name: None,
                reply_to: None,
                preview_text: None,
                html: None,
                text: None,
                variables: None,
                segment_id: None,
                track_opens: None,
                track_clicks: None,
                utm_params: None,
                settings: None,
                ab_test: None,
            }),
        )
        .await;
        assert!(matches!(unicode_201, Err(ApiError::Validation(_))));

        // An unknown / cross-tenant template_id is a 404, never a silent FK.
        let missing_template = create_campaign(
            State(state.clone()),
            auth.clone(),
            Json(CreateCampaignRequest {
                name: "ok".into(),
                subject: "s".into(),
                template_id: Some(Uuid::new_v4().to_string()),
                from: None,
                scheduled_at: None,
                list_ids: None,
                exclude_list_ids: None,

                from_name: None,
                reply_to: None,
                preview_text: None,
                html: None,
                text: None,
                variables: None,
                segment_id: None,
                track_opens: None,
                track_clicks: None,
                utm_params: None,
                settings: None,
                ab_test: None,
            }),
        )
        .await;
        assert!(matches!(missing_template, Err(ApiError::NotFound(_))));

        // An unknown / malformed audience list id is refused: malformed is a
        // 400, well-formed-but-missing is a 404.
        let malformed_list = create_campaign(
            State(state.clone()),
            auth.clone(),
            Json(CreateCampaignRequest {
                name: "ok".into(),
                subject: "s".into(),
                template_id: None,
                from: None,
                scheduled_at: None,
                list_ids: Some(vec!["garbage".into()]),
                exclude_list_ids: None,

                from_name: None,
                reply_to: None,
                preview_text: None,
                html: None,
                text: None,
                variables: None,
                segment_id: None,
                track_opens: None,
                track_clicks: None,
                utm_params: None,
                settings: None,
                ab_test: None,
            }),
        )
        .await;
        assert!(matches!(malformed_list, Err(ApiError::Validation(_))));

        let missing_list = create_campaign(
            State(state.clone()),
            auth.clone(),
            Json(CreateCampaignRequest {
                name: "ok".into(),
                subject: "s".into(),
                template_id: None,
                from: None,
                scheduled_at: None,
                list_ids: Some(vec![Uuid::new_v4().to_string()]),
                exclude_list_ids: None,

                from_name: None,
                reply_to: None,
                preview_text: None,
                html: None,
                text: None,
                variables: None,
                segment_id: None,
                track_opens: None,
                track_clicks: None,
                utm_params: None,
                settings: None,
                ab_test: None,
            }),
        )
        .await;
        assert!(matches!(missing_list, Err(ApiError::NotFound(_))));

        // A junk sender is a clean 400 at write time.
        let bad_sender = create_campaign(
            State(state.clone()),
            auth.clone(),
            Json(CreateCampaignRequest {
                name: "ok".into(),
                subject: "s".into(),
                template_id: None,
                from: Some("not an address".into()),
                scheduled_at: None,
                list_ids: None,
                exclude_list_ids: None,

                from_name: None,
                reply_to: None,
                preview_text: None,
                html: None,
                text: None,
                variables: None,
                segment_id: None,
                track_opens: None,
                track_clicks: None,
                utm_params: None,
                settings: None,
                ab_test: None,
            }),
        )
        .await;
        assert!(matches!(bad_sender, Err(ApiError::Validation(_))));

        // A scheduled campaign is born in `scheduled`, a plain one is `draft`,
        // and the audience + sender round-trip.
        let (status, Json(created)) = create_campaign(
            State(state.clone()),
            auth.clone(),
            Json(CreateCampaignRequest {
                name: campaign_name.clone(),
                subject: "Hello {{first_name}}".into(),
                from_name: None,
                reply_to: None,
                preview_text: None,
                html: None,
                text: None,
                variables: None,
                segment_id: None,
                track_opens: None,
                track_clicks: None,
                utm_params: None,
                settings: None,
                ab_test: None,
                template_id: None,
                from: Some(format!("news+{tag}@example.test")),
                scheduled_at: Some(Utc::now() + chrono::Duration::hours(1)),
                list_ids: Some(vec![]),
                exclude_list_ids: Some(vec![]),
            }),
        )
        .await
        .expect("create scheduled");
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(created.status, "scheduled");
        assert_eq!(created.list_ids, Vec::<String>::new());
        assert!(created.from_email.is_some());

        // Duplicate names within a tenant are an honest 409, not a 500.
        let duplicate = create_campaign(
            State(state.clone()),
            auth.clone(),
            Json(CreateCampaignRequest {
                name: campaign_name,
                subject: "Again".into(),
                template_id: None,
                from: None,
                scheduled_at: None,
                list_ids: None,
                exclude_list_ids: None,

                from_name: None,
                reply_to: None,
                preview_text: None,
                html: None,
                text: None,
                variables: None,
                segment_id: None,
                track_opens: None,
                track_clicks: None,
                utm_params: None,
                settings: None,
                ab_test: None,
            }),
        )
        .await;
        assert!(
            matches!(duplicate, Err(ApiError::Conflict(_))),
            "duplicate campaign name must conflict, got {duplicate:?}"
        );

        cleanup(&pool, &[&tenant]).await;
    }

    #[tokio::test]
    async fn list_paginates_by_offset_and_cursor_with_etag_revalidation() {
        let Some((state, pool)) = state_and_pool("adv_campaigns_list").await else {
            return;
        };
        let tenant_a = apexmail_lib::id::generate_id("", 26);
        let tenant_b = apexmail_lib::id::generate_id("", 26);
        seed_tenant(&pool, &tenant_a).await;
        seed_tenant(&pool, &tenant_b).await;
        let base = Utc::now();
        let tag_a = uuid::Uuid::new_v4().simple().to_string();
        let tag_b = uuid::Uuid::new_v4().simple().to_string();
        for i in 0..3 {
            seed_campaign(
                &pool,
                &tenant_a,
                &format!("A{i}-{tag_a}"),
                "draft",
                base - chrono::Duration::minutes(i),
            )
            .await;
        }
        // Tenant B's row must never leak.
        seed_campaign(
            &pool,
            &tenant_b,
            &format!("B-secret-{tag_b}"),
            "draft",
            base,
        )
        .await;

        let auth = auth_for(&tenant_a, &["campaigns:read"]);
        let page1 = list_campaigns(
            State(state.clone()),
            auth.clone(),
            HeaderMap::new(),
            Query(ListCampaignsQuery {
                limit: 2,
                offset: 0,
                cursor: None,

                status: None,
                search: None,
                start_date: None,
                end_date: None,
            }),
        )
        .await
        .expect("page 1");
        assert_eq!(page1.status(), StatusCode::OK);
        let etag = page1
            .headers()
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .expect("etag")
            .to_string();
        let bytes = axum::body::to_bytes(page1.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["data"].as_array().unwrap().len(), 2);
        assert_eq!(body["meta"]["hasMore"], true);
        let all_text = body.to_string();
        assert!(!all_text.contains(&tag_b), "tenant isolation");

        // Conditional GET with the same ETag → 304 with no body.
        let mut headers = HeaderMap::new();
        headers.insert("if-none-match", etag.parse().unwrap());
        let not_modified = list_campaigns(
            State(state.clone()),
            auth.clone(),
            headers,
            Query(ListCampaignsQuery {
                limit: 2,
                offset: 0,
                cursor: None,

                status: None,
                search: None,
                start_date: None,
                end_date: None,
            }),
        )
        .await
        .expect("conditional get");
        assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);

        // Cursor page walks the remaining row; the keyset cursor never
        // repeats the first page.
        let cursor = body["meta"]["nextCursor"]
            .as_str()
            .expect("next cursor")
            .to_string();
        let page2 = list_campaigns(
            State(state.clone()),
            auth.clone(),
            HeaderMap::new(),
            Query(ListCampaignsQuery {
                limit: 2,
                offset: 0,
                cursor: Some(cursor),

                status: None,
                search: None,
                start_date: None,
                end_date: None,
            }),
        )
        .await
        .expect("page 2");
        let bytes = axum::body::to_bytes(page2.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let body2: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body2["data"].as_array().unwrap().len(), 1);
        assert_eq!(body2["meta"]["hasMore"], false);

        // Garbage cursors are 400s before touching SQL.
        for bad in ["zzzz", &encode_cursor("2026-01-01T00:00:00Z")] {
            let resp = list_campaigns(
                State(state.clone()),
                auth.clone(),
                HeaderMap::new(),
                Query(ListCampaignsQuery {
                    limit: 2,
                    offset: 0,
                    cursor: Some(bad.to_string()),

                    status: None,
                    search: None,
                    start_date: None,
                    end_date: None,
                }),
            )
            .await;
            assert!(
                matches!(resp, Err(ApiError::BadRequest(_))),
                "cursor {bad:?} must be refused"
            );
        }

        // Limit / offset clamps are honoured (limit 0 → 1, negative → 1).
        for (limit, offset) in [(0i64, 0i64), (-3, -10), (i64::MAX, 0)] {
            let resp = list_campaigns(
                State(state.clone()),
                auth.clone(),
                HeaderMap::new(),
                Query(ListCampaignsQuery {
                    limit,
                    offset,
                    cursor: None,

                    status: None,
                    search: None,
                    start_date: None,
                    end_date: None,
                }),
            )
            .await
            .expect("clamped list");
            assert_eq!(resp.status(), StatusCode::OK);
        }

        cleanup(&pool, &[&tenant_a, &tenant_b]).await;
    }

    #[tokio::test]
    async fn get_delete_and_transitions_are_tenant_scoped_with_honest_errors() {
        let Some((state, pool)) = state_and_pool("adv_campaigns_flow").await else {
            return;
        };
        let tenant_a = apexmail_lib::id::generate_id("", 26);
        let tenant_b = apexmail_lib::id::generate_id("", 26);
        seed_tenant(&pool, &tenant_a).await;
        seed_tenant(&pool, &tenant_b).await;
        let tag = uuid::Uuid::new_v4().simple().to_string();
        let own = seed_campaign(&pool, &tenant_a, &format!("Own-{tag}"), "draft", Utc::now()).await;
        let foreign = seed_campaign(
            &pool,
            &tenant_b,
            &format!("Foreign-{tag}"),
            "draft",
            Utc::now(),
        )
        .await;

        let read = auth_for(&tenant_a, &["campaigns:read"]);
        let write = auth_for(&tenant_a, &["campaigns:write"]);

        let Json(fetched) = get_campaign(State(state.clone()), read.clone(), Path(own.to_string()))
            .await
            .expect("own read");
        assert_eq!(fetched.name, format!("Own-{tag}"));
        assert_eq!(fetched.recipient_count, 0);
        assert_eq!(fetched.list_ids, Vec::<String>::new());

        // Malformed ids are 404s, not database 500s.
        for bad in ["not-a-uuid", "", "123"] {
            let resp =
                get_campaign(State(state.clone()), read.clone(), Path(bad.to_string())).await;
            assert!(
                matches!(resp, Err(ApiError::NotFound(_))),
                "GET {bad:?} must be 404, got {resp:?}"
            );
            let resp =
                delete_campaign(State(state.clone()), write.clone(), Path(bad.to_string())).await;
            assert!(
                matches!(resp, Err(ApiError::NotFound(_))),
                "DELETE {bad:?} must be 404, got {resp:?}"
            );
        }

        let cross = get_campaign(
            State(state.clone()),
            read.clone(),
            Path(foreign.to_string()),
        )
        .await;
        assert!(matches!(cross, Err(ApiError::NotFound(_))));

        // Status transitions: draft→sending→paused, then illegal ones refused.
        let Json(resumed) =
            resume_campaign(State(state.clone()), write.clone(), Path(own.to_string()))
                .await
                .expect("resume draft");
        assert_eq!(resumed.status, "sending");
        let Json(paused) =
            pause_campaign(State(state.clone()), write.clone(), Path(own.to_string()))
                .await
                .expect("pause sending");
        assert_eq!(paused.status, "paused");
        let double_pause =
            pause_campaign(State(state.clone()), write.clone(), Path(own.to_string())).await;
        assert!(
            matches!(double_pause, Err(ApiError::Validation(_))),
            "pausing a paused campaign is invalid, got {double_pause:?}"
        );
        let cross_resume = resume_campaign(
            State(state.clone()),
            write.clone(),
            Path(foreign.to_string()),
        )
        .await;
        assert!(matches!(cross_resume, Err(ApiError::NotFound(_))));

        // Resend requires a sent/partial campaign.
        let draft_resend = resend_campaign(State(state.clone()), write.clone(), Path(own)).await;
        assert!(matches!(draft_resend, Err(ApiError::BadRequest(_))));
        sqlx::query("UPDATE campaigns SET status = 'sent' WHERE id = $1")
            .bind(own)
            .execute(&pool)
            .await
            .expect("mark sent");
        let Json(resend) = resend_campaign(State(state.clone()), write.clone(), Path(own))
            .await
            .expect("resend sent");
        assert_eq!(resend["status"], "queued");
        let (job_count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM campaign_jobs WHERE campaign_id = $1")
                .bind(own)
                .fetch_one(&pool)
                .await
                .expect("job count");
        assert_eq!(job_count, 1);
        let (status,): (String,) =
            sqlx::query_as("SELECT status FROM campaigns WHERE id = $1 AND tenant_id = $2")
                .bind(own)
                .bind(&tenant_a)
                .fetch_one(&pool)
                .await
                .expect("status");
        assert_eq!(status, "resending");

        // A paused resend campaign is pausable; the job defers (worker side).
        let Json(repaused) =
            pause_campaign(State(state.clone()), write.clone(), Path(own.to_string()))
                .await
                .expect("pause resending");
        assert_eq!(repaused.status, "paused");

        let foreign_resend =
            resend_campaign(State(state.clone()), write.clone(), Path(foreign)).await;
        assert!(matches!(foreign_resend, Err(ApiError::NotFound(_))));

        // Cross-tenant delete is a 404 and leaves the row.
        let cross_delete = delete_campaign(
            State(state.clone()),
            write.clone(),
            Path(foreign.to_string()),
        )
        .await;
        assert!(matches!(cross_delete, Err(ApiError::NotFound(_))));
        let (still_there,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM campaigns WHERE id = $1 AND tenant_id = $2")
                .bind(foreign)
                .bind(&tenant_b)
                .fetch_one(&pool)
                .await
                .expect("foreign still exists");
        assert_eq!(still_there, 1);

        // A campaign that is not draft/canceled can no longer be deleted —
        // `own` is 'paused' after the pause block above.
        let delete_live =
            delete_campaign(State(state.clone()), write.clone(), Path(own.to_string())).await;
        assert!(
            matches!(delete_live, Err(ApiError::Conflict(_))),
            "deleting a 'paused' campaign must conflict, got {delete_live:?}"
        );

        // Own draft delete → 204, second delete → 404.
        let deletable = seed_campaign(
            &pool,
            &tenant_a,
            &format!("Deletable-{tag}"),
            "draft",
            Utc::now(),
        )
        .await;
        let deleted = delete_campaign(
            State(state.clone()),
            write.clone(),
            Path(deletable.to_string()),
        )
        .await
        .expect("delete own draft");
        assert_eq!(deleted, StatusCode::NO_CONTENT);
        let deleted_again = delete_campaign(
            State(state.clone()),
            write.clone(),
            Path(deletable.to_string()),
        )
        .await;
        assert!(matches!(deleted_again, Err(ApiError::NotFound(_))));

        // Scope gates.
        assert!(matches!(
            get_campaign(
                State(state.clone()),
                auth_for(&tenant_a, &[]),
                Path(foreign.to_string())
            )
            .await,
            Err(ApiError::Forbidden(_))
        ));
        assert!(matches!(
            resume_campaign(
                State(state.clone()),
                auth_for(&tenant_a, &["campaigns:read"]),
                Path(foreign.to_string())
            )
            .await,
            Err(ApiError::Forbidden(_))
        ));

        cleanup(&pool, &[&tenant_a, &tenant_b]).await;
    }

    #[tokio::test]
    async fn patch_send_schedule_and_stats_have_real_outcomes() {
        let Some((state, pool)) = state_and_pool("adv_campaigns_send").await else {
            return;
        };
        let tenant = apexmail_lib::id::generate_id("", 26);
        seed_tenant(&pool, &tenant).await;
        let write = auth_for(&tenant, &["campaigns:write"]);
        let read = auth_for(&tenant, &["campaigns:read"]);
        let tag = uuid::Uuid::new_v4().simple().to_string();

        // Seed the audience: one list with two subscribed contacts, one
        // excluded list with one of them (via direct SQL — the lists API has
        // its own route tests). One INSERT per row: a multi-row VALUES with
        // reused parameters makes Postgres infer parameter types across rows
        // and mis-type the uuid columns.
        let list_id = Uuid::new_v4();
        let excluded_id = Uuid::new_v4();
        for (id, name) in [
            (list_id, format!("Launch list {tag}")),
            (excluded_id, format!("Excluded list {tag}")),
        ] {
            sqlx::query(
                "INSERT INTO lists (id, tenant_id, name, opt_in_mode, created_at, updated_at) \
                 VALUES ($1::uuid, $2, $3, 'single_opt_in', NOW(), NOW())",
            )
            .bind(id)
            .bind(&tenant)
            .bind(name)
            .execute(&pool)
            .await
            .expect("seed list");
        }
        let subscribed_a = Uuid::new_v4();
        let subscribed_b = Uuid::new_v4();
        let excluded_contact = Uuid::new_v4();
        for (id, email, name, status) in [
            (subscribed_a, format!("a-{tag}@example.test"), "A", "active"),
            (
                subscribed_b,
                format!("b-{tag}@example.test"),
                "B",
                "subscribed",
            ),
            (
                excluded_contact,
                format!("c-{tag}@example.test"),
                "C",
                "unsubscribed",
            ),
        ] {
            sqlx::query(
                "INSERT INTO contacts (id, tenant_id, email, name, status, created_at, updated_at) \
                 VALUES ($1::uuid, $2, $3, $4, $5, NOW(), NOW())",
            )
            .bind(id)
            .bind(&tenant)
            .bind(email)
            .bind(name)
            .bind(status)
            .execute(&pool)
            .await
            .expect("seed contact");
        }
        for (list, contact) in [
            (list_id, subscribed_a),
            (list_id, subscribed_b),
            (list_id, excluded_contact),
            (excluded_id, excluded_contact),
        ] {
            sqlx::query(
                "INSERT INTO list_subscribers (list_id, contact_id, status, created_at) \
                 VALUES ($1::uuid, $2::uuid, 'active', NOW())",
            )
            .bind(list)
            .bind(contact)
            .execute(&pool)
            .await
            .expect("seed subscriber");
        }

        // A template so the send ladder has something to render.
        let template_id = apexmail_lib::id::generate_id("", 26);
        sqlx::query(
            "INSERT INTO templates (id, tenant_id, name, subject, html_body, text_body, created_at, updated_at) \
             VALUES ($1, $2, $3, 'Hi {{first_name}}', '<p>Hello {{name}}</p>', 'Hello {{email}}', NOW(), NOW())",
        )
        .bind(&template_id)
        .bind(&tenant)
        .bind(format!("Launch template {tag}"))
        .execute(&pool)
        .await
        .expect("seed template");

        // Create the campaign referencing the audience.
        let (_status, Json(created)) = create_campaign(
            State(state.clone()),
            write.clone(),
            Json(CreateCampaignRequest {
                name: format!("Send me {tag}"),
                from_name: None,
                reply_to: None,
                preview_text: None,
                html: None,
                text: None,
                variables: None,
                segment_id: None,
                track_opens: None,
                track_clicks: None,
                utm_params: None,
                settings: None,
                ab_test: None,
                subject: "Launch".into(),
                template_id: Some(template_id.clone()),
                from: Some(format!("news-{tag}@example.test")),
                scheduled_at: None,
                list_ids: Some(vec![list_id.to_string()]),
                exclude_list_ids: Some(vec![excluded_id.to_string()]),
            }),
        )
        .await
        .expect("create campaign");
        assert_eq!(created.status, "draft");
        assert_eq!(created.list_ids, vec![list_id.to_string()]);
        let campaign_id: Uuid = created.id.parse().expect("campaign id");

        // Sending without sender/template is a clean 400 — a campaign created
        // without them must not strand its recipients in `failed`.
        let (_s, Json(incomplete)) = create_campaign(
            State(state.clone()),
            write.clone(),
            Json(CreateCampaignRequest {
                name: format!("Incomplete {tag}"),
                from_name: None,
                reply_to: None,
                preview_text: None,
                html: None,
                text: None,
                variables: None,
                segment_id: None,
                track_opens: None,
                track_clicks: None,
                utm_params: None,
                settings: None,
                ab_test: None,
                subject: "Launch".into(),
                template_id: None,
                from: None,
                scheduled_at: None,
                list_ids: None,
                exclude_list_ids: None,
            }),
        )
        .await
        .expect("create incomplete");
        let incomplete_send = send_campaign(
            State(state.clone()),
            write.clone(),
            Path(incomplete.id.clone()),
        )
        .await;
        assert!(
            matches!(incomplete_send, Err(ApiError::Validation(_))),
            "send without sender/template must be a clean 400, got {incomplete_send:?}"
        );

        // Schedule from draft, then PATCH the draft fields.
        let due = Utc::now() + chrono::Duration::hours(2);
        let Json(scheduled) = schedule_campaign(
            State(state.clone()),
            write.clone(),
            Path(created.id.clone()),
            Json(ScheduleCampaignRequest { scheduled_at: due }),
        )
        .await
        .expect("schedule");
        assert_eq!(scheduled.status, "scheduled");
        assert_eq!(
            scheduled.scheduled_at.as_deref(),
            Some(due.to_rfc3339().as_str())
        );

        // PATCH while scheduled: rename + set an exclude list. NOTE: the
        // include list itself must NOT appear in the exclude set — excluding
        // it would empty the audience, and the send below asserts the
        // include/exclude/status rules yield exactly the two eligible
        // contacts.
        let Json(updated) = update_campaign(
            State(state.clone()),
            write.clone(),
            Path(created.id.clone()),
            Json(UpdateCampaignRequest {
                name: Some(format!("Renamed {tag}")),
                from_name: None,
                reply_to: None,
                preview_text: None,
                html: None,
                text: None,
                variables: None,
                segment_id: None,
                track_opens: None,
                track_clicks: None,
                utm_params: None,
                settings: None,
                ab_test: None,
                subject: None,
                template_id: None,
                from: None,
                scheduled_at: None,
                list_ids: Some(vec![list_id.to_string()]),
                exclude_list_ids: Some(vec![excluded_id.to_string()]),
            }),
        )
        .await
        .expect("patch");
        assert_eq!(updated.name, format!("Renamed {tag}"));
        assert_eq!(updated.exclude_list_ids.len(), 1);

        // PATCH on a sending/sent campaign is refused; here it's still
        // scheduled, so flip it back to draft via SQL to test the happy path.
        let Json(unpaused) = resume_campaign(
            State(state.clone()),
            write.clone(),
            Path(created.id.clone()),
        )
        .await
        .expect("resume scheduled");
        // The due time is in the future → resumes into `scheduled`, not a
        // premature send.
        assert_eq!(unpaused.status, "scheduled");

        // Send: draft-only. Flip to draft first.
        sqlx::query("UPDATE campaigns SET status = 'draft', scheduled_at = NULL WHERE id = $1")
            .bind(campaign_id)
            .execute(&pool)
            .await
            .expect("back to draft");
        let Json(sent_campaign) = send_campaign(
            State(state.clone()),
            write.clone(),
            Path(created.id.clone()),
        )
        .await
        .expect("send");
        assert_eq!(sent_campaign.status, "sending");
        // Audience = the two active/subscribed members of the include list,
        // minus the excluded contact (still a member of the include list but
        // on the exclude list) — the unsubscribed contact is never eligible.
        assert_eq!(
            sent_campaign.recipient_count, 2,
            "audience must honor include, exclude and contact status"
        );
        let (queued_rows,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM campaign_recipients WHERE campaign_id = $1 AND status = 'queued'",
        )
        .bind(campaign_id)
        .fetch_one(&pool)
        .await
        .expect("queued rows");
        assert_eq!(queued_rows, 2);

        // Double send is refused (no longer draft).
        let double_send = send_campaign(
            State(state.clone()),
            write.clone(),
            Path(created.id.clone()),
        )
        .await;
        assert!(matches!(double_send, Err(ApiError::Validation(_))));

        // PATCH a sending campaign is refused.
        let patch_sending = update_campaign(
            State(state.clone()),
            write.clone(),
            Path(created.id.clone()),
            Json(UpdateCampaignRequest {
                name: Some("nope".into()),
                subject: None,
                template_id: None,
                from: None,
                scheduled_at: None,
                list_ids: None,
                exclude_list_ids: None,

                from_name: None,
                reply_to: None,
                preview_text: None,
                html: None,
                text: None,
                variables: None,
                segment_id: None,
                track_opens: None,
                track_clicks: None,
                utm_params: None,
                settings: None,
                ab_test: None,
            }),
        )
        .await;
        assert!(matches!(patch_sending, Err(ApiError::Conflict(_))));

        // Empty-body PATCH is a 400.
        let empty_patch = update_campaign(
            State(state.clone()),
            write.clone(),
            Path(created.id.clone()),
            Json(UpdateCampaignRequest {
                name: None,
                subject: None,
                template_id: None,
                from: None,
                scheduled_at: None,
                list_ids: None,
                exclude_list_ids: None,

                from_name: None,
                reply_to: None,
                preview_text: None,
                html: None,
                text: None,
                variables: None,
                segment_id: None,
                track_opens: None,
                track_clicks: None,
                utm_params: None,
                settings: None,
                ab_test: None,
            }),
        )
        .await;
        assert!(matches!(empty_patch, Err(ApiError::Validation(_))));

        // Stats: audience counts are real; delivery/engagement are zero until
        // the worker drains.
        let Json(stats) =
            campaign_stats(State(state.clone()), read.clone(), Path(created.id.clone()))
                .await
                .expect("stats");
        assert_eq!(stats["audience"]["total"], 2);
        assert_eq!(stats["audience"]["queued"], 2);
        assert_eq!(stats["delivery"]["enqueued"], 0);

        // Cross-tenant stats are a 404.
        let other = apexmail_lib::id::generate_id("", 26);
        seed_tenant(&pool, &other).await;
        let cross_stats = campaign_stats(
            State(state.clone()),
            auth_for(&other, &["campaigns:read"]),
            Path(created.id.clone()),
        )
        .await;
        assert!(matches!(cross_stats, Err(ApiError::NotFound(_))));
        // Missing scope is a 403.
        let no_scope = campaign_stats(
            State(state.clone()),
            auth_for(&tenant, &[]),
            Path(created.id.clone()),
        )
        .await;
        assert!(matches!(no_scope, Err(ApiError::Forbidden(_))));

        // Zero-audience send converges to `sent` immediately instead of
        // reporting a drain that will never happen.
        let (_s, Json(empty)) = create_campaign(
            State(state.clone()),
            write.clone(),
            Json(CreateCampaignRequest {
                name: format!("Empty audience {tag}"),
                from_name: None,
                reply_to: None,
                preview_text: None,
                html: None,
                text: None,
                variables: None,
                segment_id: None,
                track_opens: None,
                track_clicks: None,
                utm_params: None,
                settings: None,
                ab_test: None,
                subject: "Launch".into(),
                template_id: Some(template_id.clone()),
                from: Some(format!("news-{tag}@example.test")),
                scheduled_at: None,
                list_ids: Some(vec![]),
                exclude_list_ids: Some(vec![]),
            }),
        )
        .await
        .expect("create empty");
        // An audience-less start is a NAMED refusal (never a silent success):
        // the claim is reverted and nothing is sent.
        let empty_refused =
            send_campaign(State(state.clone()), write.clone(), Path(empty.id.clone())).await;
        match empty_refused {
            Err(ApiError::Validation(messages)) => assert!(
                messages.iter().any(|m| m.contains("no recipients")),
                "{messages:?}"
            ),
            other => panic!("an audience-less send must refuse, got {other:?}"),
        }
        let Json(reverted) =
            get_campaign(State(state.clone()), read.clone(), Path(empty.id.clone()))
                .await
                .expect("fetch after refused send");
        assert_eq!(reverted.status, "draft", "the claim must be reverted");

        // Malformed path ids are 404s everywhere.
        for handler_result in [
            send_campaign(State(state.clone()), write.clone(), Path("junk".into())).await,
            schedule_campaign(
                State(state.clone()),
                write.clone(),
                Path("junk".into()),
                Json(ScheduleCampaignRequest {
                    scheduled_at: Utc::now(),
                }),
            )
            .await,
        ] {
            assert!(matches!(handler_result, Err(ApiError::NotFound(_))));
        }
        let junk_stats =
            campaign_stats(State(state.clone()), read.clone(), Path("junk".into())).await;
        assert!(matches!(junk_stats, Err(ApiError::NotFound(_))));

        cleanup(&pool, &[&tenant, &other]).await;
    }

    #[test]
    fn unknown_fields_are_refused_at_deserialization() {
        assert!(serde_json::from_str::<CreateCampaignRequest>(
            r#"{"name":"n","subject":"s","tenant_id":"other"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<ListCampaignsQuery>(r#"{"limit":1,"evil":true}"#).is_err());
        // The documented fidelity fields are REAL fields now (settings,
        // segmentId, html, ...) — an unknown key is still refused.
        assert!(serde_json::from_str::<UpdateCampaignRequest>(r#"{"settings":{}}"#).is_ok());
        assert!(serde_json::from_str::<UpdateCampaignRequest>(r#"{"bogusField":1}"#).is_err());
        assert!(serde_json::from_str::<UpdateCampaignRequest>(r#"{"segmentId":"x"}"#).is_ok());
    }
}
