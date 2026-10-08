//! Time-travel debugging — reconstruct a message's state AS OF a timestamp
//! from the append-only sources the system already persists.
//!
//! `GET /v1/messages/:id/timeline?at=<rfc3339>` answers "what did this
//! message look like at T?" without inventing a parallel history store.
//!
//! # Reconstruction contract
//!
//! Sources (every row is append-only evidence; nothing is derived twice):
//!
//! | Source | Timestamp key | Evidence |
//! |---|---|---|
//! | `messages` | `created_at`, `sent_at`, `delivered_at`, `scheduled_at` | acceptance; the aggregate stamps written when every recipient copy reaches the state |
//! | `email_queue` | `created_at`, `sent_at`, `delivered_at`, `updated_at`(+`status`) | per-copy enqueue/attempt/delivery lifecycle |
//! | `email_delivery_log` | `attempted_at` | one row per SMTP attempt (`success`, `error_message`, attempt number, `email_queue.max_attempts` for the terminal judgement) |
//! | `events` | `timestamp` | analytics/provider facts: `sent`, `delivered`, `opened`, `clicked`, `bounced`, `complained`, `unsubscribed`, `failed` |
//! | `campaign_recipients` | `created_at`, `updated_at`(+`status`) | campaign send bookkeeping by `message_id` back-reference |
//!
//! Ordering: every entry is ordered by `(at ASC, source_rank ASC, row id
//! ASC)` with source ranks `messages`=1 < `campaign_recipients`=2 <
//! `email_queue`=3 < `email_delivery_log`=4 < `events`=5, so at one identical
//! timestamp the more downstream fact (the provider event) wins. The
//! reconstructed state is the status of the LAST entry with `at <= T`.
//!
//! Statuses produced: `accepted` (message row created), `scheduled` (T is
//! before `scheduled_at`), `queued`, `sending`, `sent`, `delivered`,
//! `opened`, `clicked`, `bounced`, `complained`, `unsubscribed`, `failed`,
//! `deferred` (a failed attempt that may still retry), `suppressed`,
//! `not_yet_accepted` (T precedes acceptance — provably did not exist).
//!
//! Honesty rules (never fabricate):
//!
//! * `at` earlier than `messages.created_at` → state `not_yet_accepted`,
//!   empty timeline (`history_complete: true` — absence is provable).
//! * If NONE of `email_queue` / `email_delivery_log` / `events` /
//!   `campaign_recipients` holds a single row for the message, and the
//!   message row itself shows progress beyond acceptance (`sent_at` /
//!   `delivered_at` set, or a status beyond the pre-send set), the sources
//!   cannot prove the post-acceptance state → `history_complete: false`
//!   with an `insufficient_history` block naming the reason and the checked
//!   sources. Only the provable prefix (acceptance) is returned.
//! * Unknown event types never change the reconstructed state; they appear
//!   as timeline entries with a null status.
//!
//! # RBAC / tenancy
//!
//! Scope `messages:read`. A tenant may replay only its own messages; a
//! mismatched id is refused as 404 (no existence leak). Platform operators
//! (system tenant + `*` scope) may cross tenants, and the entitlement gate
//! then runs against the MESSAGE's tenant (the replay is over that tenant's
//! data).
//!
//! Gated on `FeatureKey::TimeTravelDebugging` (Growth and above per
//! `docs/pricing.md`) through the canonical entitlement gate
//! ([`crate::entitlements::require_feature`]).

use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use billing_entitlements::FeatureKey;

use crate::error::{success, ApiError, ApiResponse};
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/:id/timeline", get(message_timeline))
}

/// Per-source row cap: an event-heavy message cannot return an unbounded
/// document; a hit cap is reported as `truncated`.
const PER_SOURCE_LIMIT: i64 = 200;

/// Source ranks for the same-timestamp tie-break (see the module docs).
const RANK_MESSAGES: i32 = 1;
const RANK_CAMPAIGN_RECIPIENT: i32 = 2;
const RANK_QUEUE: i32 = 3;
const RANK_DELIVERY_LOG: i32 = 4;
const RANK_EVENTS: i32 = 5;

#[derive(Debug, Deserialize)]
pub struct TimelineQuery {
    /// RFC 3339 timestamp the state is reconstructed at. Required: time
    /// travel without a destination is not a replay.
    #[serde(default)]
    pub at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TimelineEntry {
    pub at: String,
    pub source: &'static str,
    pub kind: String,
    /// The status this entry establishes, when it establishes one.
    pub status: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ReconstructedState {
    pub status: String,
    pub since: Option<String>,
    pub source: Option<&'static str>,
    pub description: String,
}

#[derive(Debug, Serialize)]
pub struct InsufficientHistory {
    pub reason: String,
    pub checked_sources: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct MessageTimelineResponse {
    pub message_id: String,
    pub at: String,
    pub state: ReconstructedState,
    pub history_complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insufficient_history: Option<InsufficientHistory>,
    /// Whether a source hit [`PER_SOURCE_LIMIT`] and older/newer evidence
    /// was cut.
    pub truncated: bool,
    pub timeline: Vec<TimelineEntry>,
    pub current: CurrentMessageState,
}

#[derive(Debug, Serialize)]
pub struct CurrentMessageState {
    pub status: String,
    pub created_at: String,
    pub scheduled_at: Option<String>,
    pub sent_at: Option<String>,
    pub delivered_at: Option<String>,
}

pub(crate) struct MessageRow {
    pub(crate) tenant_id: String,
    status: String,
    created_at: DateTime<Utc>,
    scheduled_at: Option<DateTime<Utc>>,
    sent_at: Option<DateTime<Utc>>,
    delivered_at: Option<DateTime<Utc>>,
}

struct RawEntry {
    at: DateTime<Utc>,
    rank: i32,
    id: String,
    source: &'static str,
    kind: String,
    status: Option<String>,
    detail: Option<String>,
}

async fn message_timeline(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Query(params): Query<TimelineQuery>,
) -> Result<Json<ApiResponse<MessageTimelineResponse>>, ApiError> {
    require_scopes(&auth, &["messages:read"])?;
    let Ok(message_id) = Uuid::parse_str(&id) else {
        return Err(ApiError::NotFound("message not found".into()));
    };
    let Some(at_raw) = params.at.as_deref() else {
        return Err(ApiError::Validation(vec![
            "the `at` query parameter (an RFC 3339 timestamp) is required".into(),
        ]));
    };
    let at = DateTime::parse_from_rfc3339(at_raw)
        .map_err(|_| {
            ApiError::Validation(vec![
                "`at` must be an RFC 3339 timestamp, e.g. 2026-10-07T12:00:00Z".into(),
            ])
        })?
        .with_timezone(&Utc);

    let message = load_message(&state, message_id).await?;

    // Tenant isolation: own messages only, except a platform operator
    // (system tenant + wildcard scope) who may cross. A mismatch is a 404 —
    // never a 403 that confirms the row exists in another workspace.
    if message.tenant_id != auth.tenant_id {
        let operator = auth.scopes.iter().any(|scope| scope == "*")
            && crate::middleware::auth::require_system_tenant(&state, &auth)
                .await
                .is_ok();
        if !operator {
            return Err(ApiError::NotFound("message not found".into()));
        }
    }

    // The entitlement belongs to the tenant whose data is replayed.
    crate::entitlements::require_feature(
        &state,
        &message.tenant_id,
        FeatureKey::TimeTravelDebugging,
    )
    .await?;

    Ok(success(reconstruct_timeline(&state, message_id, at).await?))
}

/// Reconstruct one message's state at `at` from the append-only sources.
///
/// Shared by the JSON replay API and the console timeline page — ONE
/// reconstruction implementation, one contract (see the module docs).
/// Callers own the authorization checks (scope, tenant isolation, the
/// entitlement gate).
pub(crate) async fn reconstruct_timeline(
    state: &AppState,
    message_id: Uuid,
    at: DateTime<Utc>,
) -> Result<MessageTimelineResponse, ApiError> {
    let message = load_message(state, message_id).await?;

    // Provably not existing at `at`: absence is a fact, not a gap.
    if at < message.created_at {
        return Ok(MessageTimelineResponse {
            message_id: message_id.to_string(),
            at: at.to_rfc3339(),
            state: ReconstructedState {
                status: "not_yet_accepted".into(),
                since: None,
                source: None,
                description: "the message did not exist yet at this timestamp".into(),
            },
            history_complete: true,
            insufficient_history: None,
            truncated: false,
            timeline: Vec::new(),
            current: current_state(&message),
        });
    }

    let (mut entries, source_counts) = collect_entries(state, message_id, &message, at).await?;
    let truncated = source_counts.iter().any(|count| *count >= PER_SOURCE_LIMIT);

    entries.sort_by(|a, b| {
        a.at.cmp(&b.at)
            .then(a.rank.cmp(&b.rank))
            .then(a.id.cmp(&b.id))
    });

    let timeline: Vec<TimelineEntry> = entries
        .iter()
        .map(|entry| TimelineEntry {
            at: entry.at.to_rfc3339(),
            source: entry.source,
            kind: entry.kind.clone(),
            status: entry.status.clone(),
            detail: entry.detail.clone(),
        })
        .collect();

    // The provable state: the last explicit status at/before `at`. A message
    // whose only evidence is acceptance but whose `scheduled_at` is still in
    // the future is `scheduled`; otherwise acceptance means `queued`.
    let last = entries.iter().rev().find(|entry| entry.status.is_some());
    let (mut status, since, source) = match last {
        Some(entry) => (
            entry.status.clone().unwrap_or_default(),
            Some(entry.at.to_rfc3339()),
            Some(entry.source),
        ),
        None => (
            "queued".to_string(),
            Some(message.created_at.to_rfc3339()),
            None,
        ),
    };
    if status == "accepted" && message.scheduled_at.map(|scheduled| at < scheduled) == Some(true) {
        status = "scheduled".to_string();
    }

    // Insufficiency: acceptance is provable, but the message row shows
    // progress no surviving source can describe. (Acceptance itself —
    // source_counts[0] — is not a pipeline source: it proves existence only.)
    let has_pipeline_sources = source_counts[1..].iter().any(|count| *count > 0);
    let progressed_beyond_acceptance = message.sent_at.is_some()
        || message.delivered_at.is_some()
        || !matches!(
            message.status.as_str(),
            "queued" | "pending" | "scheduled" | "accepted" | "processing"
        );
    let insufficient = if !has_pipeline_sources && progressed_beyond_acceptance {
        Some(InsufficientHistory {
            reason: "the append-only delivery sources (email_queue, email_delivery_log, \
                     events, campaign_recipients) hold no rows for this message; its state \
                     after acceptance cannot be reconstructed — only acceptance itself is \
                     provable"
                .into(),
            checked_sources: vec![
                "messages",
                "email_queue",
                "email_delivery_log",
                "events",
                "campaign_recipients",
            ],
        })
    } else {
        None
    };

    let description = match (status.as_str(), insufficient.is_some()) {
        ("not_yet_accepted", _) => "the message did not exist yet at this timestamp".into(),
        ("accepted", _) => "the message was accepted into the system".into(),
        ("scheduled", _) => "the message is scheduled and has not entered the send queue".into(),
        ("queued", _) => "the message is waiting in the send queue".into(),
        ("sending", _) => "the message is being delivered".into(),
        ("sent", _) => "the message was sent (accepted by the delivery route)".into(),
        ("delivered", _) => "the message was delivered to the recipient".into(),
        ("opened", _) => "the message was delivered and opened".into(),
        ("clicked", _) => "the message was delivered, opened and clicked".into(),
        ("bounced", _) => "the delivery bounced".into(),
        ("complained", _) => "the recipient marked the message as spam".into(),
        ("unsubscribed", _) => "the recipient unsubscribed from this message".into(),
        ("failed", _) => "the message failed terminally".into(),
        ("deferred", _) => "the delivery attempt failed and a retry is pending".into(),
        ("suppressed", _) => "the message was suppressed (compliance gate)".into(),
        (other, _) => format!("the recorded state at this timestamp is `{other}`"),
    };
    if insufficient.is_some() {
        return Ok(MessageTimelineResponse {
            message_id: message_id.to_string(),
            at: at.to_rfc3339(),
            state: ReconstructedState {
                status: "accepted".into(),
                since: Some(message.created_at.to_rfc3339()),
                source: Some("messages"),
                description: format!(
                    "only acceptance is provable; {}",
                    insufficient
                        .as_ref()
                        .map(|gap| gap.reason.as_str())
                        .unwrap_or_default()
                ),
            },
            history_complete: false,
            insufficient_history: insufficient,
            truncated,
            timeline,
            current: current_state(&message),
        });
    }

    Ok(MessageTimelineResponse {
        message_id: message_id.to_string(),
        at: at.to_rfc3339(),
        state: ReconstructedState {
            status,
            since,
            source,
            description,
        },
        history_complete: true,
        insufficient_history: None,
        truncated,
        timeline,
        current: current_state(&message),
    })
}

fn current_state(message: &MessageRow) -> CurrentMessageState {
    CurrentMessageState {
        status: message.status.clone(),
        created_at: message.created_at.to_rfc3339(),
        scheduled_at: message.scheduled_at.map(|t| t.to_rfc3339()),
        sent_at: message.sent_at.map(|t| t.to_rfc3339()),
        delivered_at: message.delivered_at.map(|t| t.to_rfc3339()),
    }
}

pub(crate) async fn load_message(
    state: &AppState,
    message_id: Uuid,
) -> Result<MessageRow, ApiError> {
    // Tenant is part of the row, not the predicate: the operator path needs
    // the owner's tenant to run the entitlement gate against it.
    let row: Option<(
        String,
        String,
        DateTime<Utc>,
        Option<DateTime<Utc>>,
        Option<DateTime<Utc>>,
        Option<DateTime<Utc>>,
    )> = sqlx::query_as(
        "SELECT tenant_id, status, created_at, scheduled_at, sent_at, delivered_at \
         FROM messages WHERE id = $1::uuid",
    )
    .bind(message_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((tenant_id, status, created_at, scheduled_at, sent_at, delivered_at)) = row else {
        return Err(ApiError::NotFound("message not found".into()));
    };
    Ok(MessageRow {
        tenant_id,
        status,
        created_at,
        scheduled_at,
        sent_at,
        delivered_at,
    })
}

/// Gather the per-source evidence with `at <= T`. Returns the raw entries
/// and the per-source row counts (for the `truncated` flag and the
/// insufficient-history judgement).
async fn collect_entries(
    state: &AppState,
    message_id: Uuid,
    message: &MessageRow,
    at: DateTime<Utc>,
) -> Result<(Vec<RawEntry>, [i64; 5]), ApiError> {
    let mut entries: Vec<RawEntry> = Vec::new();
    let mut counts = [0_i64; 5];

    // 1. messages — acceptance (and the aggregate stamps, when they are at
    //    or before T).
    entries.push(RawEntry {
        at: message.created_at,
        rank: RANK_MESSAGES,
        id: "messages:created_at".into(),
        source: "messages",
        kind: "message.accepted".into(),
        status: Some("accepted".into()),
        detail: message
            .scheduled_at
            .map(|scheduled| format!("scheduled for {}", scheduled.to_rfc3339())),
    });
    counts[0] += 1;
    if let Some(sent_at) = message.sent_at.filter(|ts| *ts <= at) {
        entries.push(RawEntry {
            at: sent_at,
            rank: RANK_MESSAGES,
            id: "messages:sent_at".into(),
            source: "messages",
            kind: "message.sent".into(),
            status: Some("sent".into()),
            detail: Some("every recipient copy reached the delivered route".into()),
        });
        counts[0] += 1;
    }
    if let Some(delivered_at) = message.delivered_at.filter(|ts| *ts <= at) {
        entries.push(RawEntry {
            at: delivered_at,
            rank: RANK_MESSAGES,
            id: "messages:delivered_at".into(),
            source: "messages",
            kind: "message.delivered".into(),
            status: Some("delivered".into()),
            detail: Some("every recipient copy was confirmed delivered".into()),
        });
        counts[0] += 1;
    }

    // 2. campaign_recipients — campaign bookkeeping by message back-ref.
    let campaign_rows: Vec<(Uuid, String, i32, DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, status, COALESCE(arm_index, -1), created_at, updated_at \
         FROM campaign_recipients WHERE message_id = $1::uuid \
         ORDER BY created_at LIMIT $2",
    )
    .bind(message_id)
    .bind(PER_SOURCE_LIMIT)
    .fetch_all(&state.db)
    .await?;
    for (row_id, status, arm_index, created_at, updated_at) in campaign_rows {
        counts[1] += 1;
        if created_at <= at {
            entries.push(RawEntry {
                at: created_at,
                rank: RANK_CAMPAIGN_RECIPIENT,
                id: format!("campaign_recipients:{row_id}:created"),
                source: "campaign_recipients",
                kind: "campaign.recipient_queued".into(),
                status: Some("queued".into()),
                detail: (arm_index >= 0).then(|| format!("A/B arm {arm_index}")),
            });
        }
        if updated_at <= at {
            let mapped = campaign_recipient_status(&status);
            entries.push(RawEntry {
                at: updated_at,
                rank: RANK_CAMPAIGN_RECIPIENT,
                id: format!("campaign_recipients:{row_id}:updated"),
                source: "campaign_recipients",
                kind: format!("campaign.recipient_{status}"),
                status: mapped.map(str::to_string),
                detail: None,
            });
        }
    }

    // 3. email_queue — the per-copy lifecycle.
    let queue_rows: Vec<(
        Uuid,
        String,
        i32,
        i32,
        Option<String>,
        DateTime<Utc>,
        Option<DateTime<Utc>>,
        Option<DateTime<Utc>>,
        DateTime<Utc>,
    )> = sqlx::query_as(
        "SELECT id, status, attempts, max_attempts, last_error, created_at, sent_at, \
                delivered_at, updated_at \
         FROM email_queue WHERE message_id = $1::uuid \
         ORDER BY created_at LIMIT $2",
    )
    .bind(message_id)
    .bind(PER_SOURCE_LIMIT)
    .fetch_all(&state.db)
    .await?;
    let queue_attempt_caps: std::collections::HashMap<Uuid, i32> =
        queue_rows.iter().map(|row| (row.0, row.3)).collect();
    let mut queue_ids: Vec<Uuid> = Vec::new();
    for (
        row_id,
        status,
        attempts,
        max_attempts,
        last_error,
        created_at,
        sent_at,
        delivered_at,
        updated_at,
    ) in queue_rows
    {
        queue_ids.push(row_id);
        counts[2] += 1;
        if created_at <= at {
            entries.push(RawEntry {
                at: created_at,
                rank: RANK_QUEUE,
                id: format!("email_queue:{row_id}:created"),
                source: "email_queue",
                kind: "queue.enqueued".into(),
                status: Some("queued".into()),
                detail: None,
            });
        }
        if let Some(sent_at) = sent_at.filter(|ts| *ts <= at) {
            entries.push(RawEntry {
                at: sent_at,
                rank: RANK_QUEUE,
                id: format!("email_queue:{row_id}:sent"),
                source: "email_queue",
                kind: "queue.sent".into(),
                status: Some("sent".into()),
                detail: None,
            });
        }
        if let Some(delivered_at) = delivered_at.filter(|ts| *ts <= at) {
            entries.push(RawEntry {
                at: delivered_at,
                rank: RANK_QUEUE,
                id: format!("email_queue:{row_id}:delivered"),
                source: "email_queue",
                kind: "queue.delivered".into(),
                status: Some("delivered".into()),
                detail: None,
            });
        }
        // The status/updated_at row state only adds information when it is
        // not already covered by a timestamped transition above.
        if updated_at <= at && updated_at != created_at {
            let mapped = queue_status(&status);
            let covered = (status == "sent" && sent_at.is_some_and(|ts| ts == updated_at))
                || (status == "delivered" && delivered_at.is_some_and(|ts| ts == updated_at));
            if !covered {
                entries.push(RawEntry {
                    at: updated_at,
                    rank: RANK_QUEUE,
                    id: format!("email_queue:{row_id}:updated"),
                    source: "email_queue",
                    kind: format!("queue.{status}"),
                    status: mapped.map(str::to_string),
                    detail: last_error.clone().or_else(|| {
                        (attempts > 0).then(|| format!("attempt {attempts}/{max_attempts}"))
                    }),
                });
            }
        }
    }

    // 4. email_delivery_log — SMTP attempts for the queue rows above.
    if !queue_ids.is_empty() {
        let attempt_rows: Vec<(
            Uuid,
            Uuid,
            i32,
            bool,
            Option<String>,
            Option<String>,
            DateTime<Utc>,
        )> = sqlx::query_as(
            "SELECT dl.id, dl.email_id, dl.attempt_number, dl.success, dl.smtp_response, \
                    dl.error_message, dl.attempted_at \
             FROM email_delivery_log dl \
             WHERE dl.email_id = ANY($1) AND dl.attempted_at <= $2 \
             ORDER BY dl.attempted_at LIMIT $3",
        )
        .bind(&queue_ids)
        .bind(at)
        .bind(PER_SOURCE_LIMIT)
        .fetch_all(&state.db)
        .await?;
        for (
            row_id,
            email_id,
            attempt_number,
            success,
            smtp_response,
            error_message,
            attempted_at,
        ) in attempt_rows
        {
            counts[3] += 1;
            let max_attempts = queue_attempt_caps.get(&email_id).copied().unwrap_or(5);
            let status = if success {
                "sent"
            } else if attempt_number >= max_attempts {
                "failed"
            } else {
                "deferred"
            };
            entries.push(RawEntry {
                at: attempted_at,
                rank: RANK_DELIVERY_LOG,
                id: format!("email_delivery_log:{row_id}"),
                source: "email_delivery_log",
                kind: if success {
                    "delivery.attempt_succeeded".into()
                } else {
                    "delivery.attempt_failed".into()
                },
                status: Some(status.into()),
                detail: error_message.or(smtp_response),
            });
        }
    }

    // 5. events — provider/analytics facts.
    let event_rows: Vec<(
        String,
        String,
        Option<String>,
        Option<String>,
        DateTime<Utc>,
    )> = sqlx::query_as(
        "SELECT id, event_type, link_url, bounce_type, timestamp \
             FROM events WHERE message_id = $1 AND timestamp <= $2 \
             ORDER BY timestamp LIMIT $3",
    )
    .bind(message_id.to_string())
    .bind(at)
    .bind(PER_SOURCE_LIMIT)
    .fetch_all(&state.db)
    .await?;
    for (row_id, event_type, link_url, bounce_type, timestamp) in event_rows {
        counts[4] += 1;
        entries.push(RawEntry {
            at: timestamp,
            rank: RANK_EVENTS,
            id: format!("events:{row_id}"),
            source: "events",
            kind: format!("event.{event_type}"),
            status: event_status(&event_type).map(str::to_string),
            detail: link_url.or(bounce_type),
        });
    }

    Ok((entries, counts))
}

/// Queue status vocabulary → reconstructed status. Unknown statuses do not
/// invent a state.
fn queue_status(status: &str) -> Option<&'static str> {
    match status {
        "pending" | "processing" | "retrying" => Some("queued"),
        "sent" => Some("sent"),
        "delivered" => Some("delivered"),
        "failed" => Some("failed"),
        "suppressed" => Some("suppressed"),
        _ => None,
    }
}

fn campaign_recipient_status(status: &str) -> Option<&'static str> {
    match status {
        "queued" => Some("queued"),
        "sending" => Some("sending"),
        "sent" => Some("sent"),
        "failed" => Some("failed"),
        "suppressed" => Some("suppressed"),
        _ => None,
    }
}

/// The documented event vocabulary → reconstructed status. Unknown event
/// types return `None` (the entry is still listed; the state is unchanged).
fn event_status(event_type: &str) -> Option<&'static str> {
    match event_type {
        "sent" => Some("sent"),
        "delivered" => Some("delivered"),
        "opened" => Some("opened"),
        "clicked" => Some("clicked"),
        "bounced" => Some("bounced"),
        "complained" => Some("complained"),
        "unsubscribed" => Some("unsubscribed"),
        "failed" => Some("failed"),
        "suppressed" => Some("suppressed"),
        _ => None,
    }
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Path, Query, State};

    const SCOPE_READ: &[&str] = &["messages:read"];

    fn auth_for(tenant: &str, scopes: &[&str]) -> AuthUser {
        AuthUser {
            tenant_id: tenant.to_string(),
            user_id: None,
            api_key_id: Some("key_timeline".into()),
            session_id: None,
            scopes: scopes.iter().map(|scope| scope.to_string()).collect(),
        }
    }

    async fn state_and_pool(name: &str) -> Option<(AppState, sqlx::PgPool)> {
        let pool = crate::test_db::optional_pg_pool(name).await?;
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        Some((state, pool))
    }

    fn plan_features(time_travel_debugging: bool) -> serde_json::Value {
        serde_json::json!({
            "dedicated_ip": false,
            "dedicated_ip_count": 0,
            "max_sending_domains": 1,
            "sso_enabled": false,
            "audit_logs": false,
            "api_access": true,
            "webhooks_enabled": false,
            "inbound_email": false,
            "advanced_analytics": false,
            "send_time_optimization": false,
            "ab_testing": false,
            "time_travel_debugging": time_travel_debugging,
            "data_export": false,
            "custom_tracking_domain": false,
            "custom_templates": false,
            "template_approval_workflow": false,
            "white_label": false,
            "powered_by_footer": true,
            "custom_retention": false,
            "max_retention_days": 7,
            "max_team_members": 3,
            "subaccounts": false,
            "max_subaccounts": 0,
            "support_level": "community",
            "dedicated_csm": false,
            "priority_onboarding": false,
            "byoip": false,
            "sla_guarantee": false,
            "sla_credit_percentage": 0,
            "hipaa_compliance": false,
            "soc2_compliance": false,
            "private_cloud": false
        })
    }

    async fn seed_tenant_with_plan(
        pool: &sqlx::PgPool,
        tenant: &str,
        plan_name: &str,
        features: serde_json::Value,
    ) {
        sqlx::query(
            "INSERT INTO plans (id, name, display_name, features) VALUES ($1, $2, $2, $3::jsonb) \
             ON CONFLICT (name) DO UPDATE SET features = EXCLUDED.features",
        )
        .bind(apexmail_lib::id::generate_id("", 26))
        .bind(plan_name)
        .bind(&features)
        .execute(pool)
        .await
        .expect("seed fixture plan");
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status) \
             VALUES ($1, $2, $3, $4, 'active') ON CONFLICT (id) DO NOTHING",
        )
        .bind(tenant)
        .bind(format!("Timeline {tenant}"))
        .bind(format!("tl-{tenant}"))
        .bind(plan_name)
        .execute(pool)
        .await
        .expect("seed tenant");
    }

    fn unique_plan_name(prefix: &str) -> String {
        format!("{prefix}_{}", &Uuid::new_v4().simple().to_string()[..10])
    }

    async fn cleanup(pool: &sqlx::PgPool, tenant: &str) {
        sqlx::query("DELETE FROM messages WHERE tenant_id = $1")
            .bind(tenant)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM contacts WHERE tenant_id = $1")
            .bind(tenant)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant)
            .execute(pool)
            .await
            .ok();
    }

    /// One crafted message with its queue copy, a delivery attempt and the
    /// full provider-event sequence: accepted → sent → delivered → bounced.
    /// Returns (message_id, base_time).
    async fn seed_delivered_then_bounced(
        pool: &sqlx::PgPool,
        tenant: &str,
    ) -> (Uuid, DateTime<Utc>) {
        let message_id = Uuid::new_v4();
        let queue_id = Uuid::new_v4();
        let base = Utc::now() - chrono::Duration::seconds(120);
        let sent_at = base + chrono::Duration::seconds(30);
        let delivered_at = base + chrono::Duration::seconds(60);
        let bounced_at = base + chrono::Duration::seconds(90);
        let recipient = format!("timeline-{}@example.test", &message_id.simple());

        sqlx::query(
            "INSERT INTO messages (id, tenant_id, from_email, to_emails, subject, status, \
             created_at, updated_at, sent_at, delivered_at) \
             VALUES ($1, $2, 'news@timeline.test', $3, 'Timeline', 'bounced', $4, $5, $6, $7)",
        )
        .bind(message_id)
        .bind(tenant)
        .bind(serde_json::json!([recipient]))
        .bind(base)
        .bind(bounced_at)
        .bind(sent_at)
        .bind(delivered_at)
        .execute(pool)
        .await
        .expect("seed message");

        sqlx::query(
            "INSERT INTO email_queue (id, message_id, tenant_id, from_address, to_addresses, \
             subject, status, created_at, updated_at, sent_at, delivered_at, attempts, max_attempts) \
             VALUES ($1, $2, $3, 'news@timeline.test', ARRAY[$4], 'Timeline', 'sent', $5, $6, $7, $8, 1, 5)",
        )
        .bind(queue_id)
        .bind(message_id)
        .bind(tenant)
        .bind(&recipient)
        .bind(base)
        .bind(bounced_at)
        .bind(sent_at)
        .bind(delivered_at)
        .execute(pool)
        .await
        .expect("seed queue row");

        sqlx::query(
            "INSERT INTO email_delivery_log (id, email_id, attempt_number, success, status, \
             created_at, attempted_at, smtp_response) \
             VALUES ($1, $2, 1, true, 'sent', $3, $4, '250 2.0.0 OK')",
        )
        .bind(Uuid::new_v4())
        .bind(queue_id)
        .bind(base)
        .bind(sent_at)
        .execute(pool)
        .await
        .expect("seed delivery attempt");

        for (event_type, at) in [
            ("sent", sent_at),
            ("delivered", delivered_at),
            ("bounced", bounced_at),
        ] {
            sqlx::query(
                "INSERT INTO events (id, tenant_id, message_id, event_type, recipient, timestamp) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(format!("evt_{}", Uuid::new_v4().simple()))
            .bind(tenant)
            .bind(message_id.to_string())
            .bind(event_type)
            .bind(&recipient)
            .bind(at)
            .execute(pool)
            .await
            .expect("seed event");
        }
        (message_id, base)
    }

    async fn reconstruct(
        state: &AppState,
        message_id: Uuid,
        at: DateTime<Utc>,
    ) -> MessageTimelineResponse {
        reconstruct_timeline(state, message_id, at)
            .await
            .expect("reconstruction")
    }

    /// The crafted sequence replays deterministically at every timestamp:
    /// not-yet-accepted → queued → sent → delivered → bounced.
    #[tokio::test]
    async fn timeline_replays_the_crafted_sequence_at_every_timestamp() {
        let Some((state, pool)) = state_and_pool("timeline_sequence").await else {
            return;
        };
        let tenant = apexmail_lib::id::generate_id("", 26);
        seed_tenant_with_plan(
            &pool,
            &tenant,
            &unique_plan_name("tl_state"),
            plan_features(true),
        )
        .await;
        let (message_id, base) = seed_delivered_then_bounced(&pool, &tenant).await;

        let second = |offset: i64| base + chrono::Duration::seconds(offset);
        let cases = [
            (-5, "not_yet_accepted"),
            (5, "queued"),
            (45, "sent"),
            (75, "delivered"),
            (100, "bounced"),
        ];
        for (offset, expected) in cases {
            let at = second(offset);
            let first = reconstruct(&state, message_id, at).await;
            assert_eq!(
                first.state.status, expected,
                "state at base{offset:+}s: {}",
                first.state.description
            );
            assert!(first.history_complete, "the crafted chain is complete");
            // Deterministic: the same query returns byte-identical data.
            let again = reconstruct(&state, message_id, at).await;
            assert_eq!(
                serde_json::to_value(&first).expect("serialize"),
                serde_json::to_value(&again).expect("serialize"),
                "reconstruction must be deterministic"
            );
        }

        // The full timeline at the last timestamp orders by (at, source
        // rank) and names every source that contributed.
        let full = reconstruct(&state, message_id, second(100)).await;
        let sources: Vec<&str> = full.timeline.iter().map(|entry| entry.source).collect();
        for expected in ["messages", "email_queue", "email_delivery_log", "events"] {
            assert!(
                sources.contains(&expected),
                "missing source {expected}: {sources:?}"
            );
        }
        let instants: Vec<&str> = full
            .timeline
            .iter()
            .map(|entry| entry.at.as_str())
            .collect();
        let mut sorted = instants.clone();
        sorted.sort_unstable();
        assert_eq!(instants, sorted, "entries are chronological");

        cleanup(&pool, &tenant).await;
        pool.close().await;
    }

    /// The suppressed arm of the state machine: a sent message whose last
    /// fact is a suppression event reconstructs as `suppressed`.
    #[tokio::test]
    async fn timeline_reconstructs_the_suppressed_arm() {
        let Some((state, pool)) = state_and_pool("timeline_suppressed").await else {
            return;
        };
        let tenant = apexmail_lib::id::generate_id("", 26);
        seed_tenant_with_plan(
            &pool,
            &tenant,
            &unique_plan_name("tl_supp"),
            plan_features(true),
        )
        .await;
        let message_id = Uuid::new_v4();
        let base = Utc::now() - chrono::Duration::seconds(60);
        let suppressed_at = base + chrono::Duration::seconds(20);
        sqlx::query(
            "INSERT INTO messages (id, tenant_id, from_email, to_emails, subject, status, \
             created_at, updated_at) \
             VALUES ($1, $2, 'news@timeline.test', $3, 'Timeline', 'queued', $4, $5)",
        )
        .bind(message_id)
        .bind(&tenant)
        .bind(serde_json::json!(["suppressed-recipient@example.test"]))
        .bind(base)
        .bind(suppressed_at)
        .execute(&pool)
        .await
        .expect("seed message");
        sqlx::query(
            "INSERT INTO events (id, tenant_id, message_id, event_type, recipient, timestamp) \
             VALUES ($1, $2, $3, 'suppressed', 'suppressed-recipient@example.test', $4)",
        )
        .bind(format!("evt_{}", Uuid::new_v4().simple()))
        .bind(&tenant)
        .bind(message_id.to_string())
        .bind(suppressed_at)
        .execute(&pool)
        .await
        .expect("seed suppression event");

        let at = reconstruct(&state, message_id, base + chrono::Duration::seconds(30)).await;
        assert_eq!(at.state.status, "suppressed");
        assert_eq!(at.state.source, Some("events"));

        cleanup(&pool, &tenant).await;
        pool.close().await;
    }

    /// A foreign tenant's id is refused as not-found (no existence leak);
    /// a platform operator with the wildcard scope may cross.
    #[tokio::test]
    async fn timeline_refuses_cross_tenant_ids_but_operators_may_cross() {
        let Some((state, pool)) = state_and_pool("timeline_tenancy").await else {
            return;
        };
        let owner = apexmail_lib::id::generate_id("", 26);
        let other = apexmail_lib::id::generate_id("", 26);
        seed_tenant_with_plan(
            &pool,
            &owner,
            &unique_plan_name("tl_owner"),
            plan_features(true),
        )
        .await;
        seed_tenant_with_plan(
            &pool,
            &other,
            &unique_plan_name("tl_other"),
            plan_features(true),
        )
        .await;
        let (message_id, base) = seed_delivered_then_bounced(&pool, &owner).await;
        let at = (base + chrono::Duration::seconds(100)).to_rfc3339();

        // A different entitled tenant: not-found, never a confirmation.
        let denied = message_timeline(
            State(state.clone()),
            auth_for(&other, SCOPE_READ),
            Path(message_id.to_string()),
            Query(TimelineQuery {
                at: Some(at.clone()),
            }),
        )
        .await;
        match denied {
            Err(ApiError::NotFound(_)) => {}
            other => panic!("cross-tenant replay must be refused, got {other:?}"),
        }

        // The system tenant literal + wildcard scope is the operator path.
        let allowed = message_timeline(
            State(state.clone()),
            auth_for("system", &["*"]),
            Path(message_id.to_string()),
            Query(TimelineQuery { at: Some(at) }),
        )
        .await
        .expect("an operator may replay another tenant's message");
        let body = allowed.0.data.expect("data");
        assert_eq!(body.state.status, "bounced");

        cleanup(&pool, &owner).await;
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(&other)
            .execute(&pool)
            .await
            .ok();
        pool.close().await;
    }

    /// Insufficient history answers honestly: acceptance is provable, the
    /// post-acceptance state is not — never fabricated.
    #[tokio::test]
    async fn timeline_answers_insufficient_history_honestly() {
        let Some((state, pool)) = state_and_pool("timeline_gap").await else {
            return;
        };
        let tenant = apexmail_lib::id::generate_id("", 26);
        seed_tenant_with_plan(
            &pool,
            &tenant,
            &unique_plan_name("tl_gap"),
            plan_features(true),
        )
        .await;
        let message_id = Uuid::new_v4();
        let base = Utc::now() - chrono::Duration::seconds(60);
        // A message that claims progress (sent) with NO pipeline source rows.
        sqlx::query(
            "INSERT INTO messages (id, tenant_id, from_email, to_emails, subject, status, \
             created_at, updated_at, sent_at) \
             VALUES ($1, $2, 'news@timeline.test', $3, 'Timeline', 'sent', $4, $4, $4)",
        )
        .bind(message_id)
        .bind(&tenant)
        .bind(serde_json::json!(["legacy@example.test"]))
        .bind(base)
        .execute(&pool)
        .await
        .expect("seed legacy message");

        let gap = reconstruct(&state, message_id, base + chrono::Duration::seconds(10)).await;
        assert!(!gap.history_complete);
        let insufficient = gap.insufficient_history.expect("the honest gap block");
        assert!(
            insufficient.reason.contains("cannot be reconstructed"),
            "the reason states the gap: {}",
            insufficient.reason
        );
        assert!(insufficient.checked_sources.contains(&"email_delivery_log"));
        assert_eq!(gap.state.status, "accepted", "only acceptance is provable");

        cleanup(&pool, &tenant).await;
        pool.close().await;
    }

    /// The gate refuses non-entitled plans with the named reason; a missing
    /// `at` is a named client error.
    #[tokio::test]
    async fn timeline_gate_refuses_non_entitled_plans_with_the_named_reason() {
        let Some((state, pool)) = state_and_pool("timeline_gate").await else {
            return;
        };
        let tenant = apexmail_lib::id::generate_id("", 26);
        seed_tenant_with_plan(
            &pool,
            &tenant,
            &unique_plan_name("tl_denied"),
            plan_features(false),
        )
        .await;
        let (message_id, base) = seed_delivered_then_bounced(&pool, &tenant).await;
        let at = (base + chrono::Duration::seconds(100)).to_rfc3339();

        let denied = message_timeline(
            State(state.clone()),
            auth_for(&tenant, SCOPE_READ),
            Path(message_id.to_string()),
            Query(TimelineQuery {
                at: Some(at.clone()),
            }),
        )
        .await;
        match denied {
            Err(ApiError::Forbidden(message)) => assert!(
                message.contains("does not include `time_travel_debugging`"),
                "the refusal names the capability: {message}"
            ),
            other => panic!("expected 403, got {other:?}"),
        }

        // A missing `at` is a named client error (validated before the
        // entitlement and the reconstruction run).
        let error = message_timeline(
            State(state.clone()),
            auth_for(&tenant, SCOPE_READ),
            Path(message_id.to_string()),
            Query(TimelineQuery { at: None }),
        )
        .await
        .expect_err("missing at must be refused");
        match error {
            ApiError::Validation(messages) => assert!(
                messages[0].contains("`at`"),
                "the refusal names the parameter: {messages:?}"
            ),
            other => panic!("expected 400 Validation, got {other:?}"),
        }

        cleanup(&pool, &tenant).await;
        pool.close().await;
    }
}
