//! Tenant-owned review surface for AI-generated inbound-reply drafts.
//!
//! The control-plane queue (`/v1/admin/ai/drafts`, `/reviews/ai-drafts`) is
//! the OPERATOR surface: a system-tenant credential reviews every workspace's
//! queue. At real customer counts that model makes the founder the approval
//! queue for every tenant (fifth external audit, Tier-2 item 16). This module
//! is the missing tenant-owned surface:
//!
//! * `GET /v1/ai/drafts` — the AUTHENTICATED tenant's pending drafts, newest
//!   first, bounded limit/offset pagination. Every row carries the
//!   deterministic multi-label purpose classification
//!   (`sales_autopilot::purpose::classify_all`: `purposes[]`, `primary`,
//!   `risk`, autonomy requirement), the inbound excerpt, the drafted reply
//!   and the stored `suggested_action`.
//! * `GET /v1/ai/drafts/:id` — the full record for review, including
//!   `bodyText`, plus the `sources` object (the inbound excerpt, every
//!   matched purpose with the classifier's structural evidence — the literal
//!   rule markers and the machine-mail header kind) and the `why` object
//!   (risk level + autonomy + primary purpose, in human sentences composed
//!   ONLY from the classification data).
//! * `POST /v1/ai/drafts/:id/approve` — the SAME workflow core the operator
//!   path runs (`approve_draft_core_scoped`: atomic claim, service-class
//!   admission, both-suppression-store probe, system-sender queueing and
//!   audit-in-tx), pinned to the authenticated tenant. Edit & Send (sixth
//!   external audit, item 7): an OPTIONAL `{replyText, replyHtml}` payload
//!   sends the EDITED content through that same core; the approval records
//!   `edited: true` plus the char edit distance in the audit entry. An edit
//!   that empties the body is refused.
//! * `POST /v1/ai/drafts/:id/reject` — the same atomic rejection core, with a
//!   STRUCTURED rejection reason (`wrong_facts | wrong_tone | missing_info |
//!   wrong_action | other`) plus a free-text note persisted in the audit
//!   evidence, so correction reasons accumulate as evaluation evidence.
//! * `POST /v1/ai/drafts/:id/regenerate` — re-runs the SAME draft-generation
//!   pipeline the mailbot runs (the ai-service email agent) for this inbound
//!   message; the new draft is a NEW VERSION that supersedes the old one
//!   (the old row is retired, NEVER deleted). When the deployment env-gates
//!   the generation backend, the honest answer is a 503 naming the gate —
//!   this surface never fabricates a draft.
//! * `POST /v1/ai/drafts/:id/escalate` — flags a still-pending draft for
//!   operator attention: the escalator identity and the optional structured
//!   reason are recorded on the row and in the audit entry, and the OPERATOR
//!   queue surfaces escalated drafts first (and filterable via
//!   `?escalated=true`).
//!
//! Authorization is the tenant-admin wildcard scope (the same scope the
//! console's admin/owner roles carry, and the `/v1/journal` house pattern).
//! A non-admin tenant credential is refused (403). Every statement pins
//! `tenant_id = $authenticated_tenant` in SQL, so a draft id belonging to
//! another tenant matches no row and is INDISTINGUISHABLE FROM A MISSING ROW
//! (404) on every method: list, detail, approve, reject, regenerate and
//! escalate all answer the same way for "another tenant's id" and "no such
//! id", which is the cross-tenant refusal contract `/v1/journal` documents.
//! The system tenant's operator routes keep their own scope and stay
//! unchanged.

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::{success, success_with_meta, ApiError, ApiResponse};
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::routes::admin::ai_drafts::{
    approve_draft_core_scoped_with_edit, escalate_draft_core_scoped, regenerate_draft_core_scoped,
    reject_draft_core_scoped, DraftApprovalEdit, DraftDecisionScope, DraftDecisionSurface,
};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/drafts", get(list_drafts))
        .route("/drafts/:id", get(get_draft))
        .route("/drafts/:id/approve", post(approve_draft))
        .route("/drafts/:id/reject", post(reject_draft))
        .route("/drafts/:id/regenerate", post(regenerate_draft))
        .route("/drafts/:id/escalate", post(escalate_draft))
}

/// Reviewing and releasing AI drafts is a tenant-administrator action, the
/// same wildcard scope the console's admin/owner roles carry.
pub const AI_DRAFT_ADMIN_SCOPE: &str = "*";

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 100;
const MAX_OFFSET: i64 = 10_000_000;
/// List excerpts stay short enough for a review queue card; the full body is
/// one detail request away (`GET /v1/ai/drafts/:id`).
const BODY_EXCERPT_CHARS: usize = 280;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DraftsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    DEFAULT_LIMIT
}

fn validate_paging(limit: i64, offset: i64) -> Result<(), ApiError> {
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(ApiError::BadRequest(format!(
            "limit must be between 1 and {MAX_LIMIT}"
        )));
    }
    if !(0..=MAX_OFFSET).contains(&offset) {
        return Err(ApiError::BadRequest(format!(
            "offset must be between 0 and {MAX_OFFSET}"
        )));
    }
    Ok(())
}

/// The tenant's pending queue, NEWEST first. Offset pagination is bounded
/// (the shared `/v1/journal` house pattern); `LIMIT $2` carries one extra
/// row so the response can answer `hasMore` without a second count query.
/// Superseded rows never appear: they are retired (`pending_approval =
/// false`) the moment a regenerated version replaces them.
const LIST_DRAFTS_SQL: &str = r#"
        SELECT id, from_email, subject, body_text, ai_response, suggested_action,
               received_at, headers, escalated_at, escalated_by, draft_version
        FROM inbound_messages
        WHERE tenant_id = $1
          AND pending_approval = true
          AND ai_response IS NOT NULL
        ORDER BY received_at DESC, id DESC
        LIMIT $2 OFFSET $3
"#;

/// The detail read: the SAME tenant predicate and pending-draft contract as
/// the list. Another tenant's id selects nothing (404).
const GET_DRAFT_SQL: &str = r#"
        SELECT id, from_email, subject, body_text, ai_response, suggested_action,
               received_at, headers, escalated_at, escalated_by, draft_version
        FROM inbound_messages
        WHERE id = $1
          AND tenant_id = $2
          AND pending_approval = true
          AND ai_response IS NOT NULL
"#;

#[derive(Debug, sqlx::FromRow)]
struct DraftRow {
    id: String,
    from_email: Option<String>,
    subject: Option<String>,
    body_text: Option<String>,
    ai_response: Option<String>,
    suggested_action: Option<serde_json::Value>,
    received_at: chrono::DateTime<chrono::Utc>,
    headers: Option<serde_json::Value>,
    escalated_at: Option<chrono::DateTime<chrono::Utc>>,
    escalated_by: Option<String>,
    draft_version: i32,
}

/// The deterministic review classification the tenant surface renders and
/// serializes. It is the SAME policy authority the operator path and the
/// autonomous sweep read (`sales_autopilot::purpose`); this is presentation
/// of that verdict, not a second classifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DraftReviewClassification {
    pub purposes: Vec<String>,
    pub primary: String,
    pub risk: String,
    pub autonomy_requirement: String,
}

pub(crate) fn classify_draft_for_review(
    subject: &str,
    body: &str,
    headers: Option<&serde_json::Value>,
) -> DraftReviewClassification {
    let classification = sales_autopilot::purpose::classify_all(subject, body, headers);
    DraftReviewClassification {
        purposes: classification
            .purposes
            .iter()
            .map(|purpose| purpose.as_str().to_string())
            .collect(),
        primary: classification.primary.as_str().to_string(),
        risk: classification.risk.as_str().to_string(),
        autonomy_requirement: classification.autonomy.as_str().to_string(),
    }
}

/// The first-response marker uses the same `suggested_action ->>
/// 'first_response' = 'true'` semantics the SQL claims use, tolerating the
/// JSONB boolean and the legacy string spelling. Shared with the console
/// page loader so the badge and the API never disagree.
pub(crate) fn first_response_marker(suggested_action: Option<&serde_json::Value>) -> bool {
    suggested_action
        .and_then(|value| value.get("first_response"))
        .and_then(|value| {
            value
                .as_bool()
                .or_else(|| value.as_str().map(|text| text == "true"))
        })
        .unwrap_or(false)
}

/// A char-boundary-safe excerpt of the inbound body. Never panics on
/// multibyte input.
fn body_excerpt(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.chars().count() <= BODY_EXCERPT_CHARS {
        return trimmed.to_string();
    }
    let mut excerpt: String = trimmed.chars().take(BODY_EXCERPT_CHARS).collect();
    excerpt.push('…');
    excerpt
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DraftSummary {
    pub id: String,
    pub received_from: String,
    pub subject: String,
    pub body_excerpt: String,
    pub purposes: Vec<String>,
    pub primary_purpose: String,
    pub risk: String,
    pub autonomy_requirement: String,
    pub draft_reply: String,
    pub suggested_action: Option<serde_json::Value>,
    pub first_response: bool,
    pub received_at: String,
    /// Mailbot review UX (sixth external audit, item 7): the version and
    /// escalation state of the draft in the queue.
    pub draft_version: i32,
    pub escalated: bool,
}

/// One matched purpose with the classifier's structural evidence (item 4):
/// the literal rule markers that matched the subject+body and, for the
/// `automated` label, WHICH machine-mail signal fired.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MatchedPurposeEvidence {
    pub purpose: String,
    pub matched_markers: Vec<String>,
    pub machine_header_evidence: Option<String>,
    pub subject_template: bool,
}

/// The `sources` object (item 4): what the classifier actually read. Nothing
/// here is invented — the excerpt is the stored inbound body, the matched
/// purposes and their markers come from the SAME deterministic matching pass
/// that produced the verdict (`classify_all_with_evidence`).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DraftSources {
    pub inbound_excerpt: String,
    pub matched_purposes: Vec<MatchedPurposeEvidence>,
    pub headers_available: bool,
}

/// The `why` object (item 4): the risk level, autonomy requirement and
/// primary purpose in human sentences, composed ONLY from the
/// classification data.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DraftWhy {
    pub risk_level: String,
    pub autonomy: String,
    pub primary_purpose: String,
    pub matched_purposes: Vec<String>,
    pub sentence: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DraftDetail {
    pub id: String,
    pub received_from: String,
    pub subject: String,
    /// The complete inbound message body for review (never an excerpt).
    pub body_text: String,
    pub body_excerpt: String,
    pub purposes: Vec<String>,
    pub primary_purpose: String,
    pub risk: String,
    pub autonomy_requirement: String,
    pub draft_reply: String,
    pub suggested_action: Option<serde_json::Value>,
    pub first_response: bool,
    pub received_at: String,
    pub draft_version: i32,
    pub escalated: bool,
    pub escalated_at: Option<String>,
    pub escalated_by: Option<String>,
    pub sources: DraftSources,
    pub why: DraftWhy,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DraftList {
    pub drafts: Vec<DraftSummary>,
    pub limit: i64,
    pub offset: i64,
    pub has_more: bool,
}

/// Human sentences for the `why` object, composed ONLY from the
/// classification data (item 4): the primary purpose, the effective risk
/// and the autonomy requirement, plus the reduction rule that produced
/// them. No new facts, no invented labels.
fn why_from_classification(classification: &DraftReviewClassification) -> DraftWhy {
    let autonomy_sentence = match classification.autonomy_requirement.as_str() {
        "human_review" => "a human must review the reply before it is sent",
        "no_autonomous_response" => "only a human decision can release a reply",
        "promotion_gate" => "the promotion gate decides whether the reply may send autonomously",
        other => other,
    };
    let sentence = format!(
        "The inbound message's primary purpose is {}. The effective risk level is {} and {}. \
         Risk and autonomy are reduced over every matched purpose ({}), so compound intents \
         cannot hide behind their lightest label.",
        classification.primary,
        classification.risk,
        autonomy_sentence,
        classification.purposes.join(", "),
    );
    DraftWhy {
        risk_level: classification.risk.clone(),
        autonomy: classification.autonomy_requirement.clone(),
        primary_purpose: classification.primary.clone(),
        matched_purposes: classification.purposes.clone(),
        sentence,
    }
}

fn summary_from_row(row: DraftRow) -> DraftSummary {
    let subject = row.subject.clone().unwrap_or_default();
    let body = row.body_text.clone().unwrap_or_default();
    let classification = classify_draft_for_review(&subject, &body, row.headers.as_ref());
    DraftSummary {
        id: row.id,
        received_from: row.from_email.unwrap_or_default(),
        subject,
        body_excerpt: body_excerpt(&body),
        purposes: classification.purposes,
        primary_purpose: classification.primary,
        risk: classification.risk,
        autonomy_requirement: classification.autonomy_requirement,
        draft_reply: row.ai_response.unwrap_or_default(),
        first_response: first_response_marker(row.suggested_action.as_ref()),
        suggested_action: row.suggested_action,
        received_at: row.received_at.to_rfc3339(),
        draft_version: row.draft_version,
        escalated: row.escalated_at.is_some(),
    }
}

fn detail_from_row(row: DraftRow) -> DraftDetail {
    let subject = row.subject.clone().unwrap_or_default();
    let body = row.body_text.clone().unwrap_or_default();
    let (classification, evidence) =
        sales_autopilot::purpose::classify_all_with_evidence(&subject, &body, row.headers.as_ref());
    let classification = DraftReviewClassification {
        purposes: classification
            .purposes
            .iter()
            .map(|purpose| purpose.as_str().to_string())
            .collect(),
        primary: classification.primary.as_str().to_string(),
        risk: classification.risk.as_str().to_string(),
        autonomy_requirement: classification.autonomy.as_str().to_string(),
    };
    let matched_purposes: Vec<MatchedPurposeEvidence> = evidence
        .iter()
        .map(|item| MatchedPurposeEvidence {
            purpose: item.purpose.as_str().to_string(),
            matched_markers: item.matched_markers.clone(),
            machine_header_evidence: item
                .machine_header_evidence
                .map(std::borrow::ToOwned::to_owned),
            subject_template: item.subject_template,
        })
        .collect();
    let headers_available = row
        .headers
        .as_ref()
        .is_some_and(|value| value.as_object().is_some());
    let excerpt = body_excerpt(&body);
    DraftDetail {
        id: row.id,
        received_from: row.from_email.unwrap_or_default(),
        subject,
        body_excerpt: excerpt.clone(),
        body_text: body,
        purposes: classification.purposes.clone(),
        primary_purpose: classification.primary.clone(),
        risk: classification.risk.clone(),
        autonomy_requirement: classification.autonomy_requirement.clone(),
        draft_reply: row.ai_response.unwrap_or_default(),
        first_response: first_response_marker(row.suggested_action.as_ref()),
        suggested_action: row.suggested_action,
        received_at: row.received_at.to_rfc3339(),
        draft_version: row.draft_version,
        escalated: row.escalated_at.is_some(),
        escalated_at: row.escalated_at.map(|at| at.to_rfc3339()),
        escalated_by: row.escalated_by,
        sources: DraftSources {
            inbound_excerpt: excerpt,
            matched_purposes,
            headers_available,
        },
        why: why_from_classification(&classification),
    }
}

/// The authenticated tenant pin. The tenant surface NEVER asks whether the
/// caller is the system tenant: a system credential on this route is scoped
/// to its own tenant id exactly like every other caller.
fn tenant_scope(auth: &AuthUser) -> DraftDecisionScope {
    DraftDecisionScope {
        is_system_tenant: false,
        tenant_id: auth.tenant_id.clone(),
    }
}

async fn list_drafts(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(query): Query<DraftsQuery>,
) -> Result<Json<ApiResponse<DraftList>>, ApiError> {
    require_scopes(&auth, &[AI_DRAFT_ADMIN_SCOPE])?;
    validate_paging(query.limit, query.offset)?;
    let tenant = auth.tenant_id.as_str();

    // One extra row answers `hasMore` honestly; it is not returned.
    let rows: Vec<DraftRow> = sqlx::query_as(LIST_DRAFTS_SQL)
        .bind(tenant)
        .bind(query.limit + 1)
        .bind(query.offset)
        .fetch_all(&state.db)
        .await?;
    let has_more = rows.len() as i64 > query.limit;
    let drafts: Vec<DraftSummary> = rows
        .into_iter()
        .take(query.limit as usize)
        .map(summary_from_row)
        .collect();

    Ok(success_with_meta(
        DraftList {
            drafts,
            limit: query.limit,
            offset: query.offset,
            has_more,
        },
        serde_json::json!({
            "limit": query.limit,
            "offset": query.offset,
            "hasMore": has_more,
        }),
    ))
}

async fn get_draft(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<DraftDetail>>, ApiError> {
    require_scopes(&auth, &[AI_DRAFT_ADMIN_SCOPE])?;
    let row: Option<DraftRow> = sqlx::query_as(GET_DRAFT_SQL)
        .bind(&id)
        .bind(auth.tenant_id.as_str())
        .fetch_optional(&state.db)
        .await?;
    let row = row.ok_or_else(|| ApiError::NotFound("draft not found".into()))?;
    Ok(success(detail_from_row(row)))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApproveBody {
    #[serde(default)]
    pub note: String,
    /// Edit & Send (sixth external audit, item 7): the OPTIONAL edited reply.
    /// When either field is present the EDITED content is what gets sent,
    /// through the SAME consent/claims/audit core; the approval records
    /// `edited: true` plus the char edit distance. An edit that empties the
    /// body is refused.
    #[serde(default)]
    pub reply_text: Option<String>,
    #[serde(default)]
    pub reply_html: Option<String>,
}

async fn approve_draft(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    body: Option<Json<ApproveBody>>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    require_scopes(&auth, &[AI_DRAFT_ADMIN_SCOPE])?;
    let (note, edit) = body
        .map(|Json(body)| {
            let edit = DraftApprovalEdit::new(body.reply_text, body.reply_html)?;
            Ok::<_, ApiError>((body.note, edit))
        })
        .transpose()?
        .unwrap_or_else(|| (String::new(), None));
    let scope = tenant_scope(&auth);
    // The decision core is the operator core, pinned to the authenticated
    // tenant: claim, service-class admission, suppression probe, queueing
    // and audit-in-tx are the single shared implementation. An Edit & Send
    // payload rides the SAME core — the edited content replaces the draft at
    // send time and the audit records the edit telemetry.
    let Json(result) = approve_draft_core_scoped_with_edit(
        &state,
        &auth,
        &scope,
        &id,
        &note,
        edit.as_ref(),
        DraftDecisionSurface::Tenant,
        &serde_json::json!({ "surface": "tenant" }),
    )
    .await?;
    let queued = result
        .get("queued_message_id")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let edited = result
        .get("edited")
        .cloned()
        .unwrap_or(serde_json::Value::Bool(false));
    let edit_distance = result
        .get("edit_distance_chars")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    Ok(success(serde_json::json!({
        "approved": true,
        "queuedMessageId": queued,
        "edited": edited,
        "editDistanceChars": edit_distance,
    })))
}

/// The structured correction vocabulary. `other` covers reasons outside the
/// four named classes; the free-text note carries the detail either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    WrongFacts,
    WrongTone,
    MissingInfo,
    WrongAction,
    Other,
}

impl RejectionReason {
    pub const ALL: [RejectionReason; 5] = [
        Self::WrongFacts,
        Self::WrongTone,
        Self::MissingInfo,
        Self::WrongAction,
        Self::Other,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::WrongFacts => "wrong_facts",
            Self::WrongTone => "wrong_tone",
            Self::MissingInfo => "missing_info",
            Self::WrongAction => "wrong_action",
            Self::Other => "other",
        }
    }

    /// Human label for the console selector (the wire value stays the enum
    /// spelling above).
    pub fn label(self) -> &'static str {
        match self {
            Self::WrongFacts => "Wrong facts",
            Self::WrongTone => "Wrong tone",
            Self::MissingInfo => "Missing information",
            Self::WrongAction => "Wrong action",
            Self::Other => "Other",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|reason| reason.as_str() == value.trim())
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RejectBody {
    /// The structured correction class, persisted in the audit evidence.
    pub reason: RejectionReason,
    #[serde(default)]
    pub note: String,
}

fn parse_reject_body(
    body: Result<Json<RejectBody>, JsonRejection>,
) -> Result<RejectBody, ApiError> {
    let Json(body) = body.map_err(|rejection| {
        ApiError::Validation(vec![format!("invalid rejection body: {rejection}")])
    })?;
    Ok(body)
}

async fn reject_draft(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    body: Result<Json<RejectBody>, JsonRejection>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    require_scopes(&auth, &[AI_DRAFT_ADMIN_SCOPE])?;
    let body = parse_reject_body(body)?;
    let scope = tenant_scope(&auth);
    // The structured reason rides the audit evidence ADDITIVELY: the shared
    // rejection core still records the note and the routed tenant, and the
    // category becomes a queryable evaluation signal.
    let Json(result) = reject_draft_core_scoped(
        &state,
        &auth,
        &scope,
        &id,
        &body.note,
        DraftDecisionSurface::Tenant,
        &serde_json::json!({
            "surface": "tenant",
            "rejectionReason": {
                "category": body.reason.as_str(),
                "note": body.note,
            },
        }),
    )
    .await?;
    let rejected = result
        .get("rejected")
        .cloned()
        .unwrap_or(serde_json::Value::Bool(true));
    Ok(success(serde_json::json!({
        "rejected": rejected,
        "reason": body.reason.as_str(),
    })))
}

/// Regeneration is REAL (sixth external audit, item 7): the route re-runs
/// the SAME draft-generation pipeline the mailbot runs (the ai-service email
/// agent) for this inbound message, and the new draft becomes a NEW VERSION
/// superseding the old one (retired, never deleted). The shared core checks
/// the draft FIRST, tenant-pinned, so a cross-tenant id is a 404 exactly
/// like a missing one. When the deployment env-gates the generation backend
/// (`AI_EMAIL_AGENT_ENABLED` off, or no ai-service configured), the honest
/// answer is a 503 naming the gate — this surface NEVER fabricates a draft.
async fn regenerate_draft(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    require_scopes(&auth, &[AI_DRAFT_ADMIN_SCOPE])?;
    let scope = tenant_scope(&auth);
    let Json(result) = regenerate_draft_core_scoped(
        &state,
        &auth,
        &scope,
        &id,
        DraftDecisionSurface::Tenant,
        &serde_json::json!({ "surface": "tenant" }),
    )
    .await?;
    let draft = result
        .get("draft")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    Ok(success(serde_json::json!({
        "regenerated": true,
        "draft": {
            "id": draft["id"],
            "draftVersion": draft["draft_version"],
            "supersedes": draft["supersedes"],
            "receivedFrom": draft["received_from"],
            "subject": draft["subject"],
            "draftReply": draft["draft_reply"],
            "pendingApproval": draft["pending_approval"],
        },
    })))
}

/// The escalation body: an optional STRUCTURED reason. An object is the
/// intended shape (machine-queryable); a short string is accepted for the
/// console's free-text case. Anything else is a named validation refusal.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EscalateBody {
    #[serde(default)]
    pub reason: Option<serde_json::Value>,
}

/// Escalate a still-pending draft for operator attention (sixth external
/// audit, item 7): records the escalator identity plus the optional
/// structured reason on the row and in the audit entry, and the OPERATOR
/// queue (`/v1/admin/ai/drafts`) surfaces the draft first and filterable
/// (`?escalated=true`). The draft itself stays pending and decidable on
/// both surfaces.
async fn escalate_draft(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    body: Option<Json<EscalateBody>>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    require_scopes(&auth, &[AI_DRAFT_ADMIN_SCOPE])?;
    let reason = body.and_then(|Json(body)| body.reason);
    if let Some(reason) = reason.as_ref() {
        if !reason.is_object() && !reason.is_string() {
            return Err(ApiError::Validation(vec![
                "reason, when supplied, must be a structured object or a short text".into(),
            ]));
        }
    }
    let scope = tenant_scope(&auth);
    let Json(result) = escalate_draft_core_scoped(
        &state,
        &auth,
        &scope,
        &id,
        reason.as_ref(),
        DraftDecisionSurface::Tenant,
        &serde_json::json!({ "surface": "tenant" }),
    )
    .await?;
    Ok(success(serde_json::json!({
        "escalated": result.get("escalated").cloned()
            .unwrap_or(serde_json::Value::Bool(true)),
        "draftId": result.get("draft_id").cloned()
            .unwrap_or(serde_json::Value::Null),
        "escalatedBy": result.get("escalated_by").cloned()
            .unwrap_or(serde_json::Value::Null),
        "escalatedAt": result.get("escalated_at").cloned()
            .unwrap_or(serde_json::Value::Null),
    })))
}

// ─── Tests ─────────────────────────────────────────────────────────────
//
// Pure tests pin the vocabulary/excerpt contracts; the DB-backed tests are
// soft-skips unless `TEST_DATABASE_URL` is set (listed in the report as the
// DB-gated proof). HTTP tests exercise the REAL router with tenant API keys
// so the scope mapping, tenant pin and shared workflow core are covered
// together.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejection_vocabulary_round_trips() {
        for reason in RejectionReason::ALL {
            assert_eq!(RejectionReason::parse(reason.as_str()), Some(reason));
            assert!(!reason.label().is_empty());
        }
        assert_eq!(
            RejectionReason::parse("wrong_facts"),
            Some(RejectionReason::WrongFacts)
        );
        assert_eq!(
            RejectionReason::parse("  wrong_tone "),
            Some(RejectionReason::WrongTone)
        );
        assert_eq!(RejectionReason::parse("not_a_reason"), None);
        // The wire spelling is the documented enum, snake_case.
        assert_eq!(
            serde_json::to_value(RejectionReason::MissingInfo).unwrap(),
            serde_json::json!("missing_info")
        );
    }

    #[test]
    fn body_excerpt_is_bounded_and_char_safe() {
        assert_eq!(body_excerpt("  short body  "), "short body");
        let long = "ä".repeat(BODY_EXCERPT_CHARS + 10);
        let excerpt = body_excerpt(&long);
        assert_eq!(excerpt.chars().count(), BODY_EXCERPT_CHARS + 1);
        assert!(excerpt.ends_with('…'));
        // Multibyte input never panics.
        let _ = body_excerpt(&"漢字かな交じり文".repeat(100));
    }

    #[test]
    fn paging_bounds_are_validated() {
        assert!(validate_paging(1, 0).is_ok());
        assert!(validate_paging(MAX_LIMIT, 0).is_ok());
        assert!(validate_paging(0, 0).is_err());
        assert!(validate_paging(MAX_LIMIT + 1, 0).is_err());
        assert!(validate_paging(10, -1).is_err());
        assert!(validate_paging(10, MAX_OFFSET + 1).is_err());
    }

    #[test]
    fn classification_exposes_purposes_primary_risk_and_autonomy() {
        let classification = classify_draft_for_review(
            "The dashboard errors on import",
            "every CSV import fails",
            None,
        );
        assert!(classification
            .purposes
            .contains(&"technical_support".to_string()));
        assert_eq!(classification.primary, "technical_support");
        assert_eq!(classification.risk, "low");
        assert_eq!(classification.autonomy_requirement, "promotion_gate");

        // A refund/deadline wording escalates the effective risk/autonomy.
        let escalated = classify_draft_for_review(
            "Refund and legal notice",
            "We demand a refund and our lawyer will call. This is a legal notice.",
            None,
        );
        assert!(!escalated.purposes.is_empty());
        assert_eq!(escalated.risk, "high");
        assert_ne!(escalated.autonomy_requirement, "promotion_gate");
    }

    #[test]
    fn first_response_marker_accepts_bool_and_legacy_string() {
        assert!(first_response_marker(Some(&serde_json::json!({
            "first_response": true
        }))));
        assert!(first_response_marker(Some(&serde_json::json!({
            "first_response": "true"
        }))));
        assert!(!first_response_marker(Some(&serde_json::json!({
            "first_response": false
        }))));
        assert!(!first_response_marker(None));
    }

    #[test]
    fn tenant_scope_never_admits_the_system_arm() {
        let auth = AuthUser {
            tenant_id: "system".into(),
            user_id: None,
            api_key_id: Some("key".into()),
            session_id: None,
            scopes: vec!["*".into()],
        };
        let scope = tenant_scope(&auth);
        assert!(
            !scope.is_system_tenant,
            "the tenant surface never uses the cross-tenant arm"
        );
        assert_eq!(
            scope.tenant_id, "system",
            "even system is pinned to its own id"
        );
    }

    /// The console selector's values/labels are the API's structured
    /// rejection vocabulary, byte for byte. ui-foundation cannot depend on
    /// api-server, so this test is the cross-check that keeps the two lists
    /// from drifting.
    #[test]
    fn rejection_selector_matches_the_api_enum() {
        let selector = ui_foundation::leptos_views::AI_DRAFT_REJECTION_REASONS;
        assert_eq!(selector.len(), RejectionReason::ALL.len());
        for (value, label) in selector {
            let reason = RejectionReason::parse(value)
                .unwrap_or_else(|| panic!("selector value {value} is not an API enum value"));
            assert_eq!(
                label,
                reason.label(),
                "selector label for {value} must match the API label"
            );
        }
    }

    /// The `why` sentence is composed ONLY from the classification data
    /// (item 4): it names the primary purpose, the risk and the autonomy
    /// requirement, and invents no new labels.
    #[test]
    fn why_sentence_is_composed_only_from_the_classification() {
        let classification = DraftReviewClassification {
            purposes: vec!["refund".into(), "invoice".into()],
            primary: "refund".into(),
            risk: "high".into(),
            autonomy_requirement: "human_review".into(),
        };
        let why = why_from_classification(&classification);
        assert_eq!(why.risk_level, "high");
        assert_eq!(why.autonomy, "human_review");
        assert_eq!(why.primary_purpose, "refund");
        assert_eq!(why.matched_purposes, vec!["refund", "invoice"]);
        for fact in ["refund", "high", "human", "invoice"] {
            assert!(
                why.sentence.contains(fact),
                "the sentence names {fact}: {}",
                why.sentence
            );
        }
        // The autonomy phrasing follows the enum, per value.
        let gated = why_from_classification(&DraftReviewClassification {
            purposes: vec!["technical_support".into()],
            primary: "technical_support".into(),
            risk: "low".into(),
            autonomy_requirement: "promotion_gate".into(),
        });
        assert!(gated.sentence.contains("promotion gate"));
        assert!(gated.sentence.contains("technical_support"));
    }

    /// The Edit & Send normalization (item 1): absent fields mean no edit;
    /// an edit that empties the body (or the html) is refused by name; a
    /// real edit trims and survives.
    #[test]
    fn edit_payload_normalizes_and_refuses_empty_bodies() {
        use crate::routes::admin::ai_drafts::DraftApprovalEdit;

        assert_eq!(DraftApprovalEdit::new(None, None).unwrap(), None);
        let refused = DraftApprovalEdit::new(Some("   ".into()), None)
            .expect_err("an emptying edit is refused");
        assert!(matches!(refused, ApiError::Validation(_)));
        assert!(
            DraftApprovalEdit::new(Some("ok".into()), Some("  ".into())).is_err(),
            "an empty html edit is refused too"
        );
        let edit = DraftApprovalEdit::new(Some("  fixed reply  ".into()), Some("<p>x</p>".into()))
            .expect("a real edit normalizes")
            .expect("and is an edit");
        assert_eq!(edit.reply_text, "fixed reply");
        assert_eq!(edit.reply_html.as_deref(), Some("<p>x</p>"));
    }

    /// The edit-distance telemetry (item 1): char-level Levenshtein against
    /// the stored draft, 0 for identical texts, bounded for hostile sizes.
    #[test]
    fn char_edit_distance_measures_the_human_delta() {
        use crate::routes::admin::ai_drafts::char_edit_distance;

        assert_eq!(char_edit_distance("same", "same"), 0);
        assert_eq!(char_edit_distance("", "abc"), 3);
        assert_eq!(char_edit_distance("abc", ""), 3);
        assert_eq!(char_edit_distance("kitten", "sitting"), 3);
        assert_eq!(char_edit_distance("abc", "abx"), 1);
        // Multibyte input counts CHARS, never bytes.
        assert_eq!(char_edit_distance("äöü", "äö"), 1);
        // Beyond the cap the honest bounded answer is the length delta.
        let huge = "x".repeat(9000);
        assert_eq!(char_edit_distance(&huge, ""), 9000);
    }
}

/// The DB-gated proof (soft-skips without `TEST_DATABASE_URL`): the REAL
/// router with tenant API keys, over the canonical migrated schema.
///
/// DB-gated tests in this module:
/// * `tenant_admin_lists_only_own_pending_drafts_with_purpose_and_risk`
/// * `cross_tenant_draft_is_404_on_every_method`
/// * `non_admin_tenant_member_is_refused`
/// * `structured_rejection_reason_lands_in_audit_details`
/// * `tenant_approval_keeps_service_class_semantics_and_suppression_gates`
/// * `tenant_approval_refuses_a_suppressed_recipient_and_stays_recoverable`
/// * `regeneration_is_honestly_unavailable_when_the_generation_backend_is_gated`
/// * `regeneration_with_a_live_backend_supersedes_the_old_version`
/// * `edited_approval_sends_the_edited_content_and_records_the_telemetry`
/// * `edited_approval_refuses_an_edit_that_empties_the_body`
/// * `escalation_records_identity_reason_and_surfaces_in_the_operator_queue`
#[cfg(test)]
mod tenant_db_tests {
    use crate::app::test_support::adv::AdvEnv;
    use crate::routes::system_sender::{SYSTEM_DOMAIN, SYSTEM_DOMAIN_ID, SYSTEM_TENANT_ID};

    fn draft_id() -> String {
        format!("inb_{}", &uuid::Uuid::new_v4().simple().to_string()[..22])
    }

    async fn seed_draft(
        pool: &sqlx::PgPool,
        id: &str,
        tenant: &str,
        from: &str,
        subject: &str,
        body: &str,
        received_at: chrono::DateTime<chrono::Utc>,
    ) {
        sqlx::query(
            "INSERT INTO inbound_messages
                 (id, tenant_id, from_email, subject, body_text, ai_response,
                  pending_approval, is_verp_reply, received_at)
             VALUES ($1, $2, $3, $4, $5, 'Thanks for reaching out, we are on it.',
                     true, false, $6)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(id)
        .bind(tenant)
        .bind(from)
        .bind(subject)
        .bind(body)
        .bind(received_at)
        .execute(pool)
        .await
        .expect("seed draft");
    }

    /// Seed the system sender domain exactly as the signup fixture does:
    /// real DKIM material, encrypted under the test key.
    async fn seed_system_sender(db: &sqlx::PgPool) {
        let key_pair = apexmail_lib::dkim::generate_dkim_keypair()
            .expect("test DKIM keypair generation must not fail");
        let aad = apexmail_lib::dkim::dkim_private_key_aad(SYSTEM_TENANT_ID, SYSTEM_DOMAIN_ID);
        let encrypted =
            apexmail_lib::dkim::encrypt_dkim_private_key(&key_pair.private_key_pem, &aad)
                .expect("test DKIM private key encryption must not fail");
        let public_key =
            apexmail_lib::dkim::public_key_base64_from_private_key_pem(&key_pair.private_key_pem)
                .expect("test DKIM public key derivation must not fail");
        sqlx::query(
            "INSERT INTO domains (id, tenant_id, name, status, verified, ses_verified,
                                  dkim_enabled, dkim_selector, dkim_public_key, dkim_private_key)
             VALUES ($1, $2, $3, 'verified', true, true, true, 'testsel', $4, $5)
             ON CONFLICT (tenant_id, lower(name)) DO UPDATE
               SET status = 'verified', verified = true, ses_verified = true,
                   dkim_enabled = true, dkim_selector = 'testsel',
                   dkim_public_key = EXCLUDED.dkim_public_key,
                   dkim_private_key = EXCLUDED.dkim_private_key",
        )
        .bind(uuid::Uuid::parse_str(SYSTEM_DOMAIN_ID).expect("system domain id"))
        .bind(SYSTEM_TENANT_ID)
        .bind(SYSTEM_DOMAIN)
        .bind(&public_key)
        .bind(&encrypted)
        .execute(db)
        .await
        .expect("seed system sender");
    }

    fn install_test_dkim_key() {
        std::env::set_var(
            apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
            "3f7a1c9e2b5d48f01a6c3e792d4b8f15a0c6e3917d2f4b8a5c1e7309d4f2b6a8",
        );
    }

    async fn pending(pool: &sqlx::PgPool, id: &str) -> bool {
        sqlx::query_scalar("SELECT pending_approval FROM inbound_messages WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("draft row must exist")
    }

    #[tokio::test]
    async fn tenant_admin_lists_only_own_pending_drafts_with_purpose_and_risk() {
        let Some(pool) = crate::test_db::canonical_pool("tenant_ai_drafts_list").await else {
            eprintln!(
                "skipping tenant_admin_lists_only_own_pending_drafts_with_purpose_and_risk: \
                 TEST_DATABASE_URL not set"
            );
            return;
        };
        let (env_a, tenant_a) = AdvEnv::tenant(pool.clone(), &["*"]).await;
        let (_env_b, tenant_b) = AdvEnv::tenant(pool.clone(), &["*"]).await;

        let older = draft_id();
        let newer = draft_id();
        let foreign = draft_id();
        let now = chrono::Utc::now();
        seed_draft(
            &pool,
            &older,
            &tenant_a,
            "old@corp.example",
            "Hello",
            "Just checking in.",
            now - chrono::Duration::minutes(5),
        )
        .await;
        seed_draft(
            &pool,
            &newer,
            &tenant_a,
            "refund@corp.example",
            "Refund request",
            "I want a refund for the last invoice.",
            now,
        )
        .await;
        seed_draft(
            &pool,
            &foreign,
            &tenant_b,
            "foreign@corp.example",
            "Other workspace",
            "This must never appear in another workspace's queue.",
            now,
        )
        .await;

        let (status, body) = env_a.get("/v1/ai/drafts").await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        let drafts = body["data"]["drafts"]
            .as_array()
            .unwrap_or_else(|| panic!("drafts array: {body}"));
        assert_eq!(drafts.len(), 2, "only this tenant's pending drafts: {body}");
        assert_eq!(drafts[0]["id"], newer, "newest first: {body}");
        assert_eq!(drafts[1]["id"], older);
        assert!(
            drafts.iter().all(|draft| draft["id"] != foreign),
            "another tenant's draft must never be listed: {body}"
        );

        let refund = &drafts[0];
        assert_eq!(refund["receivedFrom"], "refund@corp.example");
        assert_eq!(refund["subject"], "Refund request");
        assert_eq!(
            refund["draftReply"],
            "Thanks for reaching out, we are on it."
        );
        assert!(
            refund["bodyExcerpt"]
                .as_str()
                .unwrap_or_default()
                .contains("refund"),
            "the list carries an inbound excerpt: {body}"
        );
        let purposes = refund["purposes"]
            .as_array()
            .unwrap_or_else(|| panic!("purposes: {body}"));
        assert!(
            purposes.iter().any(|purpose| purpose == "refund"),
            "the refund purpose must be exposed: {body}"
        );
        assert_eq!(refund["primaryPurpose"], "refund");
        assert_eq!(refund["risk"], "high");
        assert_eq!(refund["autonomyRequirement"], "human_review");
        assert_eq!(refund["firstResponse"], false);

        // The detail read carries the FULL body for review.
        let (status, body) = env_a.get(&format!("/v1/ai/drafts/{newer}")).await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        assert_eq!(
            body["data"]["bodyText"],
            "I want a refund for the last invoice."
        );
        assert_eq!(body["data"]["primaryPurpose"], "refund");
        assert_eq!(body["data"]["risk"], "high");
        // Sixth external audit (item 4): the detail carries the SOURCES —
        // the inbound excerpt and every matched purpose with the literal
        // markers the classifier matched — and the WHY — risk, autonomy and
        // primary purpose in human sentences composed from that data.
        assert_eq!(body["data"]["draftVersion"], 1);
        assert_eq!(body["data"]["escalated"], false);
        assert!(
            body["data"]["sources"]["inboundExcerpt"]
                .as_str()
                .unwrap_or_default()
                .contains("refund"),
            "the sources carry the stored inbound excerpt: {body}"
        );
        let matched = body["data"]["sources"]["matchedPurposes"]
            .as_array()
            .unwrap_or_else(|| panic!("matchedPurposes: {body}"));
        let labels: Vec<&str> = matched
            .iter()
            .filter_map(|item| item["purpose"].as_str())
            .collect();
        assert!(
            labels.contains(&"refund"),
            "the refund label evidence: {body}"
        );
        assert!(
            labels.contains(&"invoice"),
            "the invoice label evidence: {body}"
        );
        let refund_evidence = matched
            .iter()
            .find(|item| item["purpose"] == "refund")
            .expect("refund evidence");
        assert_eq!(
            refund_evidence["matchedMarkers"],
            serde_json::json!(["refund"]),
            "the literal rule marker that matched: {body}"
        );
        assert_eq!(body["data"]["why"]["riskLevel"], "high");
        assert_eq!(body["data"]["why"]["autonomy"], "human_review");
        assert_eq!(body["data"]["why"]["primaryPurpose"], "refund");
        let sentence = body["data"]["why"]["sentence"].as_str().unwrap_or_default();
        assert!(
            sentence.contains("refund"),
            "the why names the purpose: {sentence}"
        );
        assert!(
            sentence.contains("high"),
            "the why names the risk: {sentence}"
        );

        // Another tenant's id is indistinguishable from a missing one.
        let (status, _body) = env_a.get(&format!("/v1/ai/drafts/{foreign}")).await;
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);

        pool.close().await;
    }

    #[tokio::test]
    async fn cross_tenant_draft_is_404_on_every_method() {
        let Some(pool) = crate::test_db::canonical_pool("tenant_ai_drafts_cross").await else {
            eprintln!(
                "skipping cross_tenant_draft_is_404_on_every_method: TEST_DATABASE_URL not set"
            );
            return;
        };
        let (env_a, _tenant_a) = AdvEnv::tenant(pool.clone(), &["*"]).await;
        let (_env_b, tenant_b) = AdvEnv::tenant(pool.clone(), &["*"]).await;
        let foreign = draft_id();
        seed_draft(
            &pool,
            &foreign,
            &tenant_b,
            "foreign@corp.example",
            "Private draft",
            "Never reachable from another tenant.",
            chrono::Utc::now(),
        )
        .await;

        for (method, status) in [
            (
                "GET",
                env_a.get(&format!("/v1/ai/drafts/{foreign}")).await.0,
            ),
            (
                "APPROVE",
                env_a
                    .post(&format!("/v1/ai/drafts/{foreign}/approve"), "{}")
                    .await
                    .0,
            ),
            (
                "REJECT",
                env_a
                    .post(
                        &format!("/v1/ai/drafts/{foreign}/reject"),
                        r#"{"reason":"wrong_facts"}"#,
                    )
                    .await
                    .0,
            ),
            (
                "REGENERATE",
                env_a
                    .post(&format!("/v1/ai/drafts/{foreign}/regenerate"), "{}")
                    .await
                    .0,
            ),
            (
                "ESCALATE",
                env_a
                    .post(&format!("/v1/ai/drafts/{foreign}/escalate"), "{}")
                    .await
                    .0,
            ),
        ] {
            assert_eq!(
                status,
                axum::http::StatusCode::NOT_FOUND,
                "{method} of another tenant's draft must be a 404 (indistinguishable from missing)"
            );
        }

        assert!(
            pending(&pool, &foreign).await,
            "the refused methods must not consume another tenant's draft"
        );
        let audit_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE resource = 'ai_draft' AND resource_id = $1",
        )
        .bind(&foreign)
        .fetch_one(&pool)
        .await
        .expect("audit count");
        assert_eq!(
            audit_rows, 0,
            "no decision evidence for a refused foreign id"
        );

        pool.close().await;
    }

    #[tokio::test]
    async fn non_admin_tenant_member_is_refused() {
        let Some(pool) = crate::test_db::canonical_pool("tenant_ai_drafts_member").await else {
            eprintln!("skipping non_admin_tenant_member_is_refused: TEST_DATABASE_URL not set");
            return;
        };
        let (member_env, tenant) = AdvEnv::tenant(pool.clone(), &["messages:read"]).await;
        let id = draft_id();
        seed_draft(
            &pool,
            &id,
            &tenant,
            "customer@corp.example",
            "Question",
            "How do I rotate my API key?",
            chrono::Utc::now(),
        )
        .await;

        for (label, status) in [
            ("list", member_env.get("/v1/ai/drafts").await.0),
            (
                "get",
                member_env.get(&format!("/v1/ai/drafts/{id}")).await.0,
            ),
            (
                "approve",
                member_env
                    .post(&format!("/v1/ai/drafts/{id}/approve"), "{}")
                    .await
                    .0,
            ),
            (
                "reject",
                member_env
                    .post(
                        &format!("/v1/ai/drafts/{id}/reject"),
                        r#"{"reason":"wrong_tone"}"#,
                    )
                    .await
                    .0,
            ),
            (
                "regenerate",
                member_env
                    .post(&format!("/v1/ai/drafts/{id}/regenerate"), "{}")
                    .await
                    .0,
            ),
            (
                "escalate",
                member_env
                    .post(&format!("/v1/ai/drafts/{id}/escalate"), "{}")
                    .await
                    .0,
            ),
        ] {
            assert_eq!(
                status,
                axum::http::StatusCode::FORBIDDEN,
                "a non-admin tenant member must be refused on {label}"
            );
        }
        assert!(
            pending(&pool, &id).await,
            "a refused member decision consumes nothing"
        );

        pool.close().await;
    }

    #[tokio::test]
    async fn structured_rejection_reason_lands_in_audit_details() {
        let Some(pool) = crate::test_db::canonical_pool("tenant_ai_drafts_reject").await else {
            eprintln!(
                "skipping structured_rejection_reason_lands_in_audit_details: \
                 TEST_DATABASE_URL not set"
            );
            return;
        };
        let (env, tenant) = AdvEnv::tenant(pool.clone(), &["*"]).await;
        let id = draft_id();
        seed_draft(
            &pool,
            &id,
            &tenant,
            "customer@corp.example",
            "Re: your plan",
            "What does the Pro plan include?",
            chrono::Utc::now(),
        )
        .await;

        // The reason is a closed vocabulary: an unknown value is a named
        // validation refusal and the draft stays pending.
        let (status, body) = env
            .post(
                &format!("/v1/ai/drafts/{id}/reject"),
                r#"{"reason":"vibes","note":"nope"}"#,
            )
            .await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
        assert!(
            pending(&pool, &id).await,
            "an invalid rejection reason consumes nothing"
        );

        let (status, body) = env
            .post(
                &format!("/v1/ai/drafts/{id}/reject"),
                r#"{"reason":"wrong_tone","note":"too casual for a billing reply"}"#,
            )
            .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["data"]["rejected"], true);
        assert_eq!(body["data"]["reason"], "wrong_tone");
        assert!(
            !pending(&pool, &id).await,
            "the rejection consumed the draft"
        );

        let evidence: (String, String, String, String) = sqlx::query_as(
            "SELECT action, details->>'surface', \
                    details->'rejectionReason'->>'category', \
                    details->'rejectionReason'->>'note' \
             FROM audit_logs WHERE resource = 'ai_draft' AND resource_id = $1",
        )
        .bind(&id)
        .fetch_one(&pool)
        .await
        .expect("structured rejection evidence");
        assert_eq!(evidence.0, "tenant.ai_draft.rejected");
        assert_eq!(evidence.1, "tenant");
        assert_eq!(evidence.2, "wrong_tone");
        assert_eq!(evidence.3, "too casual for a billing reply");

        pool.close().await;
    }

    /// The tenant approval runs the SAME workflow: service-class admission
    /// (no marketing consent needed), the explicit 'service' message
    /// category on the queue rows, and the purpose/risk audit evidence,
    /// attributed to the tenant review surface.
    #[test]
    fn tenant_approval_keeps_service_class_semantics_and_suppression_gates() {
        let _dkim_guard = crate::test_db::DKIM_ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        install_test_dkim_key();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let Some(pool) = crate::test_db::canonical_pool("tenant_ai_drafts_approve").await
            else {
                eprintln!(
                    "skipping tenant_approval_keeps_service_class_semantics_and_suppression_gates: \
                     TEST_DATABASE_URL not set"
                );
                return;
            };
            seed_system_sender(&pool).await;
            let (env, tenant) = AdvEnv::tenant(pool.clone(), &["*"]).await;
            let id = draft_id();
            let recipient = format!(
                "support-{}@corp.example",
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            );
            seed_draft(
                &pool,
                &id,
                &tenant,
                &recipient,
                "The dashboard errors on import",
                "every CSV import fails with an error",
                chrono::Utc::now(),
            )
            .await;

            let (status, body) = env
                .post(
                    &format!("/v1/ai/drafts/{id}/approve"),
                    r#"{"note":"send it"}"#,
                )
                .await;
            assert_eq!(status, axum::http::StatusCode::OK, "{body}");
            assert_eq!(body["data"]["approved"], true);
            assert!(
                body["data"]["queuedMessageId"].is_string(),
                "the queued message id is returned: {body}"
            );
            assert!(!pending(&pool, &id).await);

            // The queue rows carry the EXPLICIT service category, never the
            // 'marketing' schema default.
            let categories: Vec<(String, String)> = sqlx::query_as(
                "SELECT m.message_category, q.message_category \
                 FROM messages m JOIN email_queue q ON q.message_id = m.id \
                 WHERE m.tenant_id = $1 AND m.subject = 'The dashboard errors on import'",
            )
            .bind(SYSTEM_TENANT_ID)
            .fetch_all(&pool)
            .await
            .expect("queued rows");
            assert_eq!(categories.len(), 1, "exactly one reply queued");
            assert_eq!(categories[0].0, "service");
            assert_eq!(categories[0].1, "service");

            let evidence: (String, String, String, String) = sqlx::query_as(
                "SELECT action, details->>'surface', details->>'deliveryClass', \
                        details->>'messageCategory' \
                 FROM audit_logs WHERE resource = 'ai_draft' AND resource_id = $1",
            )
            .bind(&id)
            .fetch_one(&pool)
            .await
            .expect("approval evidence");
            assert_eq!(evidence.0, "tenant.ai_draft.approved");
            assert_eq!(evidence.1, "tenant");
            assert_eq!(evidence.2, "service");
            assert_eq!(evidence.3, "service");

            pool.close().await;
        });
    }

    /// A suppressed (bounce/complaint/opt-out) recipient is refused on the
    /// tenant path exactly as on the operator path: nothing is consumed or
    /// queued, the draft stays pending and the refusal is durable evidence.
    #[test]
    fn tenant_approval_refuses_a_suppressed_recipient_and_stays_recoverable() {
        let _dkim_guard = crate::test_db::DKIM_ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        install_test_dkim_key();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let Some(pool) =
                crate::test_db::canonical_pool("tenant_ai_drafts_suppressed").await
            else {
                eprintln!(
                    "skipping tenant_approval_refuses_a_suppressed_recipient_and_stays_recoverable: \
                     TEST_DATABASE_URL not set"
                );
                return;
            };
            seed_system_sender(&pool).await;
            let (env, tenant) = AdvEnv::tenant(pool.clone(), &["*"]).await;
            let id = draft_id();
            let recipient = format!(
                "bounced-{}@corp.example",
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            );
            seed_draft(
                &pool,
                &id,
                &tenant,
                &recipient,
                "Re: invoice",
                "please approve",
                chrono::Utc::now(),
            )
            .await;
            sqlx::query(
                "INSERT INTO suppression_list (id, tenant_id, email, reason) \
                 VALUES ($1, $2, $3, 'hard bounce')",
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&tenant)
            .bind(&recipient)
            .execute(&pool)
            .await
            .expect("seed bounce suppression");

            let (status, body) = env
                .post(&format!("/v1/ai/drafts/{id}/approve"), "{}")
                .await;
            assert_eq!(
                status,
                axum::http::StatusCode::BAD_REQUEST,
                "a suppressed recipient must be refused on the tenant path: {body}"
            );
            assert!(
                body.to_string().contains("suppressed"),
                "the refusal names the suppression: {body}"
            );
            assert!(
                pending(&pool, &id).await,
                "the suppression refusal consumes nothing"
            );
            let queued: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM email_queue WHERE lower(\"to\") = lower($1)",
            )
            .bind(&recipient)
            .fetch_one(&pool)
            .await
            .expect("queue count");
            assert_eq!(queued, 0, "nothing was queued");

            let evidence: (String, String) = sqlx::query_as(
                "SELECT action, details->>'surface' FROM audit_logs \
                 WHERE resource = 'ai_draft' AND resource_id = $1",
            )
            .bind(&id)
            .fetch_one(&pool)
            .await
            .expect("refusal evidence");
            assert_eq!(evidence.0, "tenant.ai_draft.approval_refused");
            assert_eq!(evidence.1, "tenant");

            pool.close().await;
        });
    }

    /// The generation backend's env gate is process-global
    /// (`AI_EMAIL_AGENT_ENABLED`): serialise the regeneration tests that
    /// flip or clear it.
    static MAILBOT_AGENT_ENV_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// The default test configuration has NO ai-service backend configured
    /// (`ai_service_base_url` empty), so regeneration is HONESTLY
    /// unavailable: a named 503 `SERVICE_UNAVAILABLE` carrying the reason,
    /// never a fabricated draft and never the old blanket 501. The draft is
    /// untouched: still pending, no version row, no audit entry.
    #[tokio::test]
    async fn regeneration_is_honestly_unavailable_when_the_generation_backend_is_gated() {
        let Some(pool) = crate::test_db::canonical_pool("tenant_ai_drafts_regenerate").await else {
            eprintln!(
                "skipping regeneration_is_honestly_unavailable_when_the_generation_backend_is_gated: \
                 TEST_DATABASE_URL not set"
            );
            return;
        };
        let (env, tenant) = AdvEnv::tenant(pool.clone(), &["*"]).await;
        let id = draft_id();
        seed_draft(
            &pool,
            &id,
            &tenant,
            "customer@corp.example",
            "Question",
            "Can you explain the invoice?",
            chrono::Utc::now(),
        )
        .await;

        let (status, body) = env
            .post(&format!("/v1/ai/drafts/{id}/regenerate"), "{}")
            .await;
        assert_eq!(
            status,
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "an env-gated generation backend is an honest 503 with the reason: {body}"
        );
        assert_eq!(body["error"]["code"], "SERVICE_UNAVAILABLE");
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("never fabricates a draft"),
            "the refusal names its contract: {body}"
        );
        assert!(
            pending(&pool, &id).await,
            "an unavailable regeneration leaves the draft untouched"
        );
        let (superseded_by, version): (Option<String>, i32) = sqlx::query_as(
            "SELECT superseded_by, draft_version FROM inbound_messages WHERE id = $1",
        )
        .bind(&id)
        .fetch_one(&pool)
        .await
        .expect("draft row");
        assert_eq!(superseded_by, None, "nothing superseded anything");
        assert_eq!(version, 1);
        let audit_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE resource = 'ai_draft' AND resource_id = $1",
        )
        .bind(&id)
        .fetch_one(&pool)
        .await
        .expect("audit count");
        assert_eq!(audit_rows, 0, "a refused regeneration writes no evidence");

        pool.close().await;
    }

    /// A mock of the ai-service generation endpoint the regenerate core
    /// calls: the SAME pipeline contract (a generated `replyText`), served
    /// from loopback for the live-backend test.
    async fn mock_generation_service(reply_text: &'static str) -> String {
        let app = axum::Router::new().route(
            "/email-agent/drafts/:id/regenerate",
            axum::routing::post(move |_id: axum::extract::Path<String>| async move {
                axum::Json(serde_json::json!({
                    "replyText": reply_text,
                    "tokensUsed": 42,
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock generation service");
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        base_url
    }

    /// The LIVE-backend arm: with the ai-service configured and the mailbot
    /// agent gate on, regeneration re-runs the generation pipeline, the new
    /// draft becomes a NEW VERSION superseding the old one (retired, NEVER
    /// deleted), the swap is on the audit record, and the old id stops
    /// being reachable. The URL-configured-but-agent-gated arm names the
    /// exact env gate.
    #[tokio::test]
    async fn regeneration_with_a_live_backend_supersedes_the_old_version() {
        let Some(pool) = crate::test_db::canonical_pool("tenant_ai_drafts_regen_live").await else {
            eprintln!(
                "skipping regeneration_with_a_live_backend_supersedes_the_old_version: \
                 TEST_DATABASE_URL not set"
            );
            return;
        };
        let _env_guard = MAILBOT_AGENT_ENV_MUTEX.lock().await;

        let ai_url = mock_generation_service(
            "The invoice covers the Pro plan for October; the breakdown is attached.",
        )
        .await;
        let mut config = crate::app::test_support::test_config();
        config.ai_service_base_url = ai_url.clone();

        // Gate arm 2 first: the URL is configured but the mailbot agent env
        // gate is off, so the honest 503 names THAT gate.
        std::env::remove_var("AI_EMAIL_AGENT_ENABLED");
        let (env, tenant) = AdvEnv::tenant_with_config(pool.clone(), &["*"], config.clone()).await;
        let id = draft_id();
        seed_draft(
            &pool,
            &id,
            &tenant,
            "customer@corp.example",
            "Question",
            "Can you explain the invoice?",
            chrono::Utc::now(),
        )
        .await;
        let (status, body) = env
            .post(&format!("/v1/ai/drafts/{id}/regenerate"), "{}")
            .await;
        assert_eq!(
            status,
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "the agent env gate is a named 503: {body}"
        );
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("AI_EMAIL_AGENT_ENABLED"),
            "the refusal names the exact env gate: {body}"
        );

        // The live arm: gate on, backend serving a generated reply.
        std::env::set_var("AI_EMAIL_AGENT_ENABLED", "true");
        let (status, body) = env
            .post(&format!("/v1/ai/drafts/{id}/regenerate"), "{}")
            .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["data"]["regenerated"], true);
        let new_id = body["data"]["draft"]["id"]
            .as_str()
            .expect("the new draft id")
            .to_string();
        assert_ne!(new_id, id, "the new draft is a NEW row");
        assert_eq!(body["data"]["draft"]["draftVersion"], 2);
        assert_eq!(body["data"]["draft"]["supersedes"], id.as_str());
        assert_eq!(body["data"]["draft"]["pendingApproval"], true);
        assert_eq!(
            body["data"]["draft"]["draftReply"],
            "The invoice covers the Pro plan for October; the breakdown is attached."
        );
        std::env::remove_var("AI_EMAIL_AGENT_ENABLED");

        // The OLD draft: retired, superseded, NEVER deleted. The NEW draft:
        // pending review, version 2, same inbound message.
        let old: (bool, Option<String>, i32) = sqlx::query_as(
            "SELECT pending_approval, superseded_by, draft_version \
             FROM inbound_messages WHERE id = $1",
        )
        .bind(&id)
        .fetch_one(&pool)
        .await
        .expect("old draft row");
        assert!(!old.0, "the old version is retired");
        assert_eq!(old.1.as_deref(), Some(new_id.as_str()));
        assert_eq!(old.2, 1, "the old version keeps its version number");
        let new: (bool, Option<String>, i32, String, String) = sqlx::query_as(
            "SELECT pending_approval, superseded_by, draft_version, ai_response, tenant_id \
             FROM inbound_messages WHERE id = $1",
        )
        .bind(&new_id)
        .fetch_one(&pool)
        .await
        .expect("new draft row");
        assert!(new.0, "the new version awaits review");
        assert_eq!(new.1, None);
        assert_eq!(new.2, 2);
        assert_eq!(
            new.3,
            "The invoice covers the Pro plan for October; the breakdown is attached."
        );
        assert_eq!(new.4, tenant);

        // The swap is durable decision evidence, committed with the rows.
        let details: serde_json::Value = sqlx::query_scalar(
            "SELECT details FROM audit_logs \
             WHERE resource = 'ai_draft' AND action = 'tenant.ai_draft.regenerated' \
               AND resource_id = $1",
        )
        .bind(&id)
        .fetch_one(&pool)
        .await
        .expect("regeneration audit row");
        assert_eq!(details["oldDraftVersion"], 1);
        assert_eq!(details["newDraftId"], new_id.as_str());
        assert_eq!(details["newDraftVersion"], 2);
        assert_eq!(details["supersededBy"], new_id.as_str());
        assert_eq!(details["edited"], false, "uniform telemetry shape");

        // The tenant queue lists the NEW version; the old id is unreachable.
        let (status, body) = env.get("/v1/ai/drafts").await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        let drafts = body["data"]["drafts"].as_array().expect("drafts");
        assert!(drafts.iter().any(|draft| draft["id"] == new_id.as_str()));
        assert!(drafts.iter().all(|draft| draft["id"] != id.as_str()));
        let (status, _body) = env.get(&format!("/v1/ai/drafts/{id}")).await;
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
        // And the retired version cannot be regenerated again.
        let (status, _body) = env
            .post(&format!("/v1/ai/drafts/{id}/regenerate"), "{}")
            .await;
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);

        pool.close().await;
    }

    /// Edit & Send (sixth external audit, item 7): an approval carrying
    /// `replyText` sends the EDITED content through the same core — the
    /// queue carries the edited text — and the audit records `edited: true`
    /// plus the char edit distance from the generated draft.
    #[test]
    fn edited_approval_sends_the_edited_content_and_records_the_telemetry() {
        let _dkim_guard = crate::test_db::DKIM_ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        install_test_dkim_key();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let Some(pool) = crate::test_db::canonical_pool("tenant_ai_drafts_edit_send").await
            else {
                eprintln!(
                    "skipping edited_approval_sends_the_edited_content_and_records_the_telemetry: \
                     TEST_DATABASE_URL not set"
                );
                return;
            };
            seed_system_sender(&pool).await;
            let (env, tenant) = AdvEnv::tenant(pool.clone(), &["*"]).await;
            let id = draft_id();
            let recipient = format!(
                "edit-{}@corp.example",
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            );
            seed_draft(
                &pool,
                &id,
                &tenant,
                &recipient,
                "The dashboard errors on import",
                "every CSV import fails with an error",
                chrono::Utc::now(),
            )
            .await;

            let original = "Thanks for reaching out, we are on it.";
            let edited = "Thanks for reaching out — the fix ships tomorrow morning.";
            let expected_distance =
                crate::routes::admin::ai_drafts::char_edit_distance(original, edited);

            let (status, body) = env
                .post(
                    &format!("/v1/ai/drafts/{id}/approve"),
                    &format!(r#"{{"replyText": {}}}"#, serde_json::json!(edited)),
                )
                .await;
            assert_eq!(status, axum::http::StatusCode::OK, "{body}");
            assert_eq!(body["data"]["approved"], true);
            assert_eq!(
                body["data"]["edited"], true,
                "the approval is an EDIT: {body}"
            );
            assert_eq!(
                body["data"]["editDistanceChars"], expected_distance,
                "the edit distance rides the response: {body}"
            );
            assert!(!pending(&pool, &id).await);

            // The EDITED content is what was queued.
            let queued_text: String =
                sqlx::query_scalar("SELECT text FROM email_queue WHERE lower(\"to\") = lower($1)")
                    .bind(&recipient)
                    .fetch_one(&pool)
                    .await
                    .expect("queued reply");
            assert_eq!(queued_text, edited, "the edited content was sent");

            // The audit telemetry (item 5): edited flag + char diff count.
            let evidence: (bool, Option<i64>, String) = sqlx::query_as(
                "SELECT details->>'edited' = 'true', \
                        (details->>'editDistanceChars')::bigint, \
                        details->>'deliveryClass' \
                 FROM audit_logs WHERE resource = 'ai_draft' AND resource_id = $1",
            )
            .bind(&id)
            .fetch_one(&pool)
            .await
            .expect("approval evidence");
            assert!(evidence.0, "the audit records edited=true");
            assert_eq!(evidence.1, Some(expected_distance));
            assert_eq!(evidence.2, "service", "the same service-class core");

            pool.close().await;
        });
    }

    /// An edit may change the reply, NEVER empty it: a whitespace-only
    /// `replyText` is a named validation refusal that consumes nothing and
    /// queues nothing, and the draft stays approvable afterwards.
    #[tokio::test]
    async fn edited_approval_refuses_an_edit_that_empties_the_body() {
        let Some(pool) = crate::test_db::canonical_pool("tenant_ai_drafts_edit_empty").await else {
            eprintln!(
                "skipping edited_approval_refuses_an_edit_that_empties_the_body: \
                 TEST_DATABASE_URL not set"
            );
            return;
        };
        let (env, tenant) = AdvEnv::tenant(pool.clone(), &["*"]).await;
        let id = draft_id();
        let recipient = format!(
            "empty-{}@corp.example",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        );
        seed_draft(
            &pool,
            &id,
            &tenant,
            &recipient,
            "Question",
            "How do I rotate my API key?",
            chrono::Utc::now(),
        )
        .await;

        for empty_edit in [r#"{"replyText": "   "}"#, r#"{"replyText": ""}"#] {
            let (status, body) = env
                .post(&format!("/v1/ai/drafts/{id}/approve"), empty_edit)
                .await;
            assert_eq!(
                status,
                axum::http::StatusCode::BAD_REQUEST,
                "an edit that empties the body is a named validation refusal: {body}"
            );
            assert_eq!(body["error"]["code"], "VALIDATION_ERROR");
            assert!(
                body.to_string().contains("replyText"),
                "the refusal names the field: {body}"
            );
            assert!(pending(&pool, &id).await, "an empty edit consumes nothing");
        }
        let queued: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM email_queue WHERE lower(\"to\") = lower($1)")
                .bind(&recipient)
                .fetch_one(&pool)
                .await
                .expect("queue count");
        assert_eq!(queued, 0, "nothing was queued for an empty edit");
        let audit_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE resource = 'ai_draft' AND resource_id = $1",
        )
        .bind(&id)
        .fetch_one(&pool)
        .await
        .expect("audit count");
        assert_eq!(audit_rows, 0, "a refused edit leaves no decision evidence");

        pool.close().await;
    }

    /// Escalation (sixth external audit, item 7): the tenant flags a
    /// still-pending draft — the escalator identity and the structured
    /// reason land on the row and in the audit entry, the draft stays
    /// decidable, and the OPERATOR queue surfaces it FIRST and filterable.
    #[tokio::test]
    async fn escalation_records_identity_reason_and_surfaces_in_the_operator_queue() {
        let Some(pool) = crate::test_db::canonical_pool("tenant_ai_drafts_escalate").await else {
            eprintln!(
                "skipping escalation_records_identity_reason_and_surfaces_in_the_operator_queue: \
                 TEST_DATABASE_URL not set"
            );
            return;
        };
        let (env, tenant) = AdvEnv::tenant(pool.clone(), &["*"]).await;
        let now = chrono::Utc::now();
        let older = draft_id();
        let flagged = draft_id();
        seed_draft(
            &pool,
            &older,
            &tenant,
            "old@corp.example",
            "Older question",
            "An older, unescalated question.",
            now - chrono::Duration::minutes(10),
        )
        .await;
        seed_draft(
            &pool,
            &flagged,
            &tenant,
            "legal@corp.example",
            "We want a refund",
            "please refund my invoice, the charge was wrong",
            now,
        )
        .await;

        // An invalid reason shape is a named refusal that escalates nothing.
        let (status, body) = env
            .post(
                &format!("/v1/ai/drafts/{flagged}/escalate"),
                r#"{"reason": 42}"#,
            )
            .await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");

        let (status, body) = env
            .post(
                &format!("/v1/ai/drafts/{flagged}/escalate"),
                r#"{"reason": {"category": "needs_human", "note": "the customer is angry"}}"#,
            )
            .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["data"]["escalated"], true);
        let escalated_by = body["data"]["escalatedBy"]
            .as_str()
            .expect("the escalator identity is returned")
            .to_string();
        assert!(
            escalated_by.starts_with("api_key:"),
            "a machine credential's escalation names the key: {escalated_by}"
        );

        // The row: flagged, with identity and the structured reason. The
        // draft is STILL pending — escalation asks for attention, it is not
        // a decision.
        let row: (
            bool,
            Option<String>,
            Option<chrono::DateTime<chrono::Utc>>,
            serde_json::Value,
        ) = sqlx::query_as(
            "SELECT pending_approval, escalated_by, escalated_at, escalation_reason \
                 FROM inbound_messages WHERE id = $1",
        )
        .bind(&flagged)
        .fetch_one(&pool)
        .await
        .expect("escalated row");
        assert!(row.0, "an escalated draft stays decidable");
        assert_eq!(row.1.as_deref(), Some(escalated_by.as_str()));
        assert!(row.2.is_some());
        assert_eq!(row.3["category"], "needs_human");
        assert_eq!(row.3["note"], "the customer is angry");

        // The audit entry carries the same evidence with the uniform
        // telemetry shape.
        let evidence: (String, String, serde_json::Value) = sqlx::query_as(
            "SELECT action, details->>'escalatedBy', details \
             FROM audit_logs WHERE resource = 'ai_draft' AND resource_id = $1",
        )
        .bind(&flagged)
        .fetch_one(&pool)
        .await
        .expect("escalation evidence");
        assert_eq!(evidence.0, "tenant.ai_draft.escalated");
        assert_eq!(evidence.1, escalated_by);
        assert_eq!(evidence.2["reason"]["category"], "needs_human");
        assert_eq!(evidence.2["edited"], false);

        // The tenant queue shows the escalation state.
        let (status, body) = env.get("/v1/ai/drafts").await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        let drafts = body["data"]["drafts"].as_array().expect("drafts");
        let flagged_entry = drafts
            .iter()
            .find(|draft| draft["id"] == flagged.as_str())
            .expect("the escalated draft is still in the tenant queue");
        assert_eq!(flagged_entry["escalated"], true);
        assert!(drafts
            .iter()
            .find(|draft| draft["id"] == older.as_str())
            .is_some_and(|draft| draft["escalated"] == false));

        // The OPERATOR queue surfaces the escalation FIRST (the FIFO order
        // would list `older` first) and filterable.
        let admin = AdvEnv::admin(pool.clone()).await;
        let (status, body) = admin.get("/v1/admin/ai/drafts").await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        let queue = body["drafts"].as_array().expect("operator queue");
        assert_eq!(queue[0]["id"], flagged.as_str(), "escalated first: {body}");
        assert_eq!(queue[0]["escalated"], true);
        assert_eq!(
            queue.iter().position(|draft| draft["id"] == older.as_str()),
            Some(1),
            "the unescalated draft follows: {body}"
        );
        let (status, body) = admin.get("/v1/admin/ai/drafts?escalated=true").await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        let filtered = body["drafts"].as_array().expect("filtered queue");
        assert_eq!(filtered.len(), 1, "the filter is escalated-only: {body}");
        assert_eq!(filtered[0]["id"], flagged.as_str());

        // The escalated draft is still decidable: a rejection consumes it
        // and it leaves both queues.
        let (status, body) = env
            .post(
                &format!("/v1/ai/drafts/{flagged}/reject"),
                r#"{"reason":"wrong_tone"}"#,
            )
            .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        let (status, body) = admin.get("/v1/admin/ai/drafts?escalated=true").await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["count"], 0, "the decided draft left the queue: {body}");

        pool.close().await;
    }
}
