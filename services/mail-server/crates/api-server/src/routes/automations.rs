//! Automation / workflow routes.
//!
//! # Send admission (audit implementation-order item 3)
//!
//! This module is CRUD only: it persists `automations` rows and their ordered
//! `actions` JSON. The EXECUTOR now exists —
//! `sales_autopilot::automations::AutomationExecutor` (migration 224 provides
//! the event inbox, run log and per-action log) claims due trigger events,
//! evaluates `trigger_config`/`conditions` and executes `actions`. Every
//! `send_email` action passes the ONE shared admission gate before
//! enqueueing: `billing_service::send_admission::SendAdmissionService::admit`
//! with the tenant, an EXPLICIT category, the run's stable idempotency
//! identity (so a retry cannot double-reserve), and the same
//! commit-after-enqueue / rollback-on-refusal settlement the REST, SMTP
//! submission and sales paths use. Refusals are classified like sales: quota
//! and metering/suppression-store unavailability are retryable deferrals, a
//! suppression is a non-retryable skip.
//!
//! [`AUTOMATION_MESSAGE_CATEGORY`] is the category of automation/nurture
//! mail (every contact-lifecycle trigger): commercial mail, so `marketing`
//! and deliberately NOT preference-exempt. The executor's ONLY transactional
//! automation sends are 1:1 replies to a message the recipient sent
//! (`message.received`), which carry
//! `sales_autopilot::automations::AUTOMATION_REPLY_CATEGORY` instead.

use super::helpers::{clamp_limit, decode_cursor, encode_cursor, has_more};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

/// The message category every contact-lifecycle automation `send_email`
/// action carries through the ONE admission gate.
///
/// Automations are CUSTOMER-configured, trigger-driven lifecycle messages
/// (welcome series, onboarding, re-engagement): commercial mail. The category
/// is `marketing` — declared EXPLICITLY rather than defaulted — and is NOT
/// preference-exempt, exactly like the sales campaign path. Global
/// suppression still applies to it (admission checks the canonical
/// suppression list for every category). The ONLY transactional automation
/// sends are 1:1 replies to an inbound message (`message.received`), which
/// `sales_autopilot::automations` admits under
/// `AUTOMATION_REPLY_CATEGORY`.
pub const AUTOMATION_MESSAGE_CATEGORY: &str =
    apexmail_lib::email_headers::message_category::MARKETING;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(create_automation).get(list_automations))
        .route(
            "/:id",
            get(get_automation)
                .put(update_automation)
                .delete(delete_automation),
        )
        .route("/:id/enable", post(enable_automation))
        .route("/:id/disable", post(disable_automation))
}

// ─── Keyset cursor helpers ─────────────────────────────────────
//
// The list cursor encodes the `(created_at, id)` pair of the last row of the
// previous page (automations.id is UUID, migration 075). The previous
// implementation returned a numeric OFFSET as "nextCursor" while calling it
// a cursor — rows were skipped or duplicated whenever rows shared a
// created_at value, and the "cursor" restarted the scan on every page.

/// Separator between the RFC3339 timestamp and the row id inside the
/// hex-encoded cursor payload (RFC3339 and UUID ids never contain it).
const KEYSET_CURSOR_SEP: char = '\n';

/// Encode a `(created_at, id)` keyset cursor as an opaque hex string.
fn encode_keyset_cursor(created_at: &DateTime<Utc>, id: &str) -> String {
    // RFC3339: decode parses with `parse_from_rfc3339`, so the Display
    // rendering ("… UTC") could never be replayed (every next page 400'd).
    encode_cursor(&format!(
        "{}{KEYSET_CURSOR_SEP}{id}",
        created_at.to_rfc3339()
    ))
}

/// Decode and validate a `(created_at, id)` keyset cursor. Malformed input
/// is a client error (400), never a database 500.
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

/// Parse an automation path id; malformed ids are honest 404s (automations.id
/// is UUID in the canonical schema, not text).
fn parse_automation_id(id: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(id).map_err(|_| ApiError::NotFound("automation not found".into()))
}

/// Duplicate automation names are an honest 409 (unique
/// `idx_automations_tenant_name`), never a database 500.
fn map_automation_write_error(error: sqlx::Error) -> ApiError {
    if let sqlx::Error::Database(ref db_error) = error {
        if db_error.code().as_deref() == Some("23505") {
            return ApiError::Conflict("an automation with this name already exists".into());
        }
    }
    ApiError::from(error)
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAutomationRequest {
    pub name: String,
    pub trigger: serde_json::Value,
    pub actions: Vec<serde_json::Value>,
    #[serde(default)]
    pub conditions: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateAutomationRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub trigger: Option<serde_json::Value>,
    #[serde(default)]
    pub actions: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub conditions: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct AutomationResponse {
    pub id: String,
    pub name: String,
    pub trigger: serde_json::Value,
    pub actions: serde_json::Value,
    pub conditions: Option<serde_json::Value>,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListAutomationsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    /// Cursor for cursor-based pagination — hex-encoded `created_at` + row id
    /// pair of the last item from the previous page. When provided, overrides
    /// `offset`.
    #[serde(default)]
    pub cursor: Option<String>,
}

fn default_limit() -> i64 {
    50
}

// ─── Handlers ──────────────────────────────────────────────────

async fn create_automation(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateAutomationRequest>,
) -> Result<(StatusCode, Json<AutomationResponse>), ApiError> {
    require_scopes(&auth, &["automations:write"])?;

    if body.name.is_empty() || body.actions.is_empty() {
        return Err(ApiError::Validation(vec![
            "name and at least one action are required".into(),
        ]));
    }

    let id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query(
        "INSERT INTO automations (id, tenant_id, name, trigger_config, actions, conditions, status, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,'disabled',$7,$7)",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .bind(&body.name)
    .bind(&body.trigger)
    .bind(serde_json::json!(body.actions))
    .bind(&body.conditions)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(map_automation_write_error)?;

    Ok((
        StatusCode::CREATED,
        Json(AutomationResponse {
            id: id.to_string(),
            name: body.name,
            trigger: body.trigger,
            actions: serde_json::json!(body.actions),
            conditions: body.conditions,
            status: "disabled".into(),
            created_at: now.to_rfc3339(),
            updated_at: now.to_rfc3339(),
        }),
    ))
}

async fn list_automations(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ListAutomationsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["automations:read"])?;

    let limit = clamp_limit(params.limit, 100);

    // Real keyset pagination on (created_at, id): decode and validate the
    // cursor BEFORE binding, and page with a total-ordering tuple
    // comparison instead of the numeric offset this endpoint used to
    // return under the "nextCursor" name.
    let cursor_value = match params.cursor.as_deref() {
        Some(encoded) => Some(decode_keyset_cursor(encoded)?),
        None => None,
    };

    let total: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint FROM automations WHERE tenant_id = $1",
    )
    .bind(&auth.tenant_id)
    .fetch_one(&state.db)
    .await?;

    // Fetch limit + 1 rows so we can detect whether another page exists.
    let rows = if let Some((ref cursor_ts, ref cursor_id)) = cursor_value {
        sqlx::query_as::<_, AutomationRow>(
            "SELECT id::text, name, trigger_config, actions, conditions, status, created_at, updated_at
             FROM automations WHERE tenant_id = $1
               AND (created_at < $2::timestamp OR (created_at = $2::timestamp AND id < $3::uuid))
             ORDER BY created_at DESC, id DESC LIMIT $4",
        )
        .bind(&auth.tenant_id)
        .bind(cursor_ts)
        .bind(cursor_id)
        .bind(limit + 1)
        .fetch_all(&state.db)
        .await?
    } else {
        let offset = params.offset.clamp(0, 100_000);
        sqlx::query_as::<_, AutomationRow>(
            "SELECT id::text, name, trigger_config, actions, conditions, status, created_at, updated_at
             FROM automations WHERE tenant_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3",
        )
        .bind(&auth.tenant_id)
        .bind(limit + 1)
        .bind(offset)
        .fetch_all(&state.db)
        .await?
    };

    let mut details: Vec<AutomationResponse> = rows.into_iter().map(Into::into).collect();
    let has_more = has_more(&mut details, limit as usize);

    // Next (created_at, id) keyset cursor — a genuine cursor, not an offset.
    let next_cursor = details.last().and_then(|r| {
        chrono::DateTime::parse_from_rfc3339(&r.created_at)
            .ok()
            .map(|ts| encode_keyset_cursor(&ts.with_timezone(&Utc), &r.id))
    });

    // Wrap in the standard {data, error, meta} envelope with pagination meta.
    Ok(Json(serde_json::json!({
        "data": details,
        "error": null,
        "meta": {
            "total": total,
            "hasMore": has_more,
            "nextCursor": next_cursor,
        },
    })))
}

async fn get_automation(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<AutomationResponse>, ApiError> {
    require_scopes(&auth, &["automations:read"])?;
    let row = fetch_automation(&state, &auth.tenant_id, id).await?;
    Ok(Json(row.into()))
}

async fn update_automation(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<UpdateAutomationRequest>,
) -> Result<Json<AutomationResponse>, ApiError> {
    require_scopes(&auth, &["automations:write"])?;

    let existing = fetch_automation(&state, &auth.tenant_id, id.clone()).await?;

    let name = body.name.unwrap_or(existing.name);
    let trigger = body.trigger.unwrap_or(existing.trigger_config);
    let actions = body
        .actions
        .map(|a| serde_json::json!(a))
        .unwrap_or(existing.actions);
    let conditions = body.conditions.or(existing.conditions);

    sqlx::query(
        "UPDATE automations SET name=$1, trigger_config=$2, actions=$3, conditions=$4, updated_at=NOW()
         WHERE id=$5 AND tenant_id=$6",
    )
    .bind(&name)
    .bind(&trigger)
    .bind(&actions)
    .bind(&conditions)
    .bind(parse_automation_id(&id)?)
    .bind(&auth.tenant_id)
    .execute(&state.db)
    .await
    .map_err(map_automation_write_error)?;

    Ok(Json(AutomationResponse {
        id,
        name,
        trigger,
        actions,
        conditions,
        status: existing.status,
        created_at: existing.created_at.to_rfc3339(),
        updated_at: Utc::now().to_rfc3339(),
    }))
}

async fn delete_automation(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["automations:write"])?;

    let result = sqlx::query("DELETE FROM automations WHERE id = $1 AND tenant_id = $2")
        .bind(parse_automation_id(&id)?)
        .bind(&auth.tenant_id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("automation not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn enable_automation(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<AutomationResponse>, ApiError> {
    require_scopes(&auth, &["automations:write"])?;
    set_automation_status(&state, &auth.tenant_id, id, "enabled").await
}

async fn disable_automation(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<AutomationResponse>, ApiError> {
    require_scopes(&auth, &["automations:write"])?;
    set_automation_status(&state, &auth.tenant_id, id, "disabled").await
}

async fn set_automation_status(
    state: &AppState,
    tenant_id: &str,
    id: String,
    new_status: &str,
) -> Result<Json<AutomationResponse>, ApiError> {
    let result = sqlx::query(
        "UPDATE automations SET status = $1, updated_at = NOW() WHERE id = $2 AND tenant_id = $3",
    )
    .bind(new_status)
    .bind(parse_automation_id(&id)?)
    .bind(tenant_id)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("automation not found".into()));
    }

    let row = fetch_automation(state, tenant_id, id).await?;
    Ok(Json(row.into()))
}

// ─── Row types ─────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct AutomationRow {
    id: String,
    name: String,
    trigger_config: serde_json::Value,
    actions: serde_json::Value,
    conditions: Option<serde_json::Value>,
    status: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<AutomationRow> for AutomationResponse {
    fn from(r: AutomationRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            trigger: r.trigger_config,
            actions: r.actions,
            conditions: r.conditions,
            status: r.status,
            created_at: r.created_at.to_rfc3339(),
            updated_at: r.updated_at.to_rfc3339(),
        }
    }
}

async fn fetch_automation(
    state: &AppState,
    tenant_id: &str,
    id: String,
) -> Result<AutomationRow, ApiError> {
    sqlx::query_as::<_, AutomationRow>(
        "SELECT id::text, name, trigger_config, actions, conditions, status, created_at, updated_at
         FROM automations WHERE id = $1 AND tenant_id = $2",
    )
    .bind(parse_automation_id(&id)?)
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("automation not found".into()))
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_automation_deser() {
        let json = r#"{
            "name": "Welcome Series",
            "trigger": {"type": "contact_created"},
            "actions": [{"type": "send_email", "template_id": "abc"}]
        }"#;
        let req: CreateAutomationRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "Welcome Series");
        assert_eq!(req.actions.len(), 1);
    }

    /// Audit implementation-order item 3: the automation send category is
    /// declared explicitly and validated by the SAME shared helper the
    /// admission gate uses — it is never the `message_category` schema
    /// default. Contact-lifecycle automations are commercial mail: the
    /// category is `marketing` and gets NO opt-out exemption (the executor's
    /// only transactional automation sends are `message.received` replies,
    /// admitted under `sales_autopilot::automations::AUTOMATION_REPLY_CATEGORY`).
    #[test]
    fn automation_send_category_is_explicitly_marketing() {
        use apexmail_lib::email_headers::message_category;
        assert_eq!(
            AUTOMATION_MESSAGE_CATEGORY, "marketing",
            "automation/nurture mail is commercial mail"
        );
        assert_eq!(
            message_category::validate(AUTOMATION_MESSAGE_CATEGORY).as_deref(),
            Some("marketing"),
            "the constant must pass the ONE shared validator admission uses"
        );
        assert!(
            !message_category::is_preference_exempt(AUTOMATION_MESSAGE_CATEGORY),
            "an automation must not acquire an opt-out exemption"
        );
    }

    #[test]
    fn test_automation_response_serialisation() {
        let resp = AutomationResponse {
            id: String::new(),
            name: "Follow-up".into(),
            trigger: serde_json::json!({"type": "event"}),
            actions: serde_json::json!([]),
            conditions: None,
            status: "enabled".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "enabled");
    }
}

// ─── Adversarial automation CRUD tests ─────────────────────────

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
             VALUES ($1, 'automations adversarial', 'free', 'active', NOW(), NOW())
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(tenant)
        .execute(pool)
        .await
        .expect("seed tenant");
    }

    async fn create_ok(state: &AppState, tenant: &str, name: &str) -> AutomationResponse {
        let (status, Json(auto)) = create_automation(
            State(state.clone()),
            auth_for(tenant, &["automations:write"]),
            Json(CreateAutomationRequest {
                name: name.into(),
                trigger: serde_json::json!({"type": "contact_created"}),
                actions: vec![serde_json::json!({"type": "send_email"})],
                conditions: None,
            }),
        )
        .await
        .expect("create automation");
        assert_eq!(status, StatusCode::CREATED);
        auto
    }

    async fn cleanup(pool: &sqlx::PgPool, tenants: &[&str]) {
        for tenant in tenants {
            sqlx::query("DELETE FROM automations WHERE tenant_id = $1")
                .bind(tenant)
                .execute(pool)
                .await
                .expect("cleanup automations");
            sqlx::query("DELETE FROM tenants WHERE id = $1")
                .bind(tenant)
                .execute(pool)
                .await
                .expect("cleanup tenant");
        }
    }

    #[test]
    fn keyset_cursor_round_trips_and_rejects_malformed_input() {
        let ts = Utc::now();
        let id = "11111111-1111-1111-1111-111111111111";
        let encoded = encode_keyset_cursor(&ts, id);
        let (decoded_ts, decoded_id) = decode_keyset_cursor(&encoded).expect("roundtrip");
        assert_eq!(decoded_id, id);
        assert_eq!(decoded_ts.timestamp(), ts.timestamp());

        for bad in [
            "!!!not-hex!!!".to_string(),
            encode_cursor("no-separator"),
            encode_cursor("not-a-timestamp\nsomeid"),
            encode_cursor(&format!("{ts}\n")),
            encode_cursor(&format!("{ts}\n{}", "x".repeat(65))),
            encode_cursor(&format!("{ts}\nhas\u{1}control")),
        ] {
            assert!(
                matches!(decode_keyset_cursor(&bad), Err(ApiError::BadRequest(_))),
                "cursor {bad:?} must be refused"
            );
        }
    }

    #[tokio::test]
    async fn crud_flow_is_tenant_scoped_with_honest_errors() {
        let Some((state, pool)) = state_and_pool("adv_automations_crud").await else {
            return;
        };
        let tenant_a = apexmail_lib::id::generate_id("", 26);
        let tenant_b = apexmail_lib::id::generate_id("", 26);
        seed_tenant(&pool, &tenant_a).await;
        seed_tenant(&pool, &tenant_b).await;
        let tag = uuid::Uuid::new_v4().simple().to_string();
        let name = format!("Welcome flow {tag}");

        let auto = create_ok(&state, &tenant_a, &name).await;
        assert_eq!(auto.status, "disabled");
        assert_eq!(auto.trigger["type"], "contact_created");

        // Blank name / no actions are validation errors.
        assert!(matches!(
            create_automation(
                State(state.clone()),
                auth_for(&tenant_a, &["automations:write"]),
                Json(CreateAutomationRequest {
                    name: String::new(),
                    trigger: serde_json::json!({}),
                    actions: vec![serde_json::json!({"type": "x"})],
                    conditions: None,
                })
            )
            .await,
            Err(ApiError::Validation(_))
        ));
        assert!(matches!(
            create_automation(
                State(state.clone()),
                auth_for(&tenant_a, &["automations:write"]),
                Json(CreateAutomationRequest {
                    name: "no actions".into(),
                    trigger: serde_json::json!({}),
                    actions: vec![],
                    conditions: None,
                })
            )
            .await,
            Err(ApiError::Validation(_))
        ));

        // Duplicate names for the same tenant clash on the unique index → 409.
        let duplicate = create_automation(
            State(state.clone()),
            auth_for(&tenant_a, &["automations:write"]),
            Json(CreateAutomationRequest {
                name: name.clone(),
                trigger: serde_json::json!({}),
                actions: vec![serde_json::json!({"type": "x"})],
                conditions: None,
            }),
        )
        .await;
        assert!(
            matches!(duplicate, Err(ApiError::Conflict(_))),
            "duplicate name must conflict, got {duplicate:?}"
        );

        // Cross-tenant reads and writes are 404s and leak nothing.
        let foreign = create_ok(&state, &tenant_b, &format!("Foreign flow {tag}")).await;
        let read = auth_for(&tenant_a, &["automations:read"]);
        let cross =
            get_automation(State(state.clone()), read.clone(), Path(foreign.id.clone())).await;
        assert!(matches!(cross, Err(ApiError::NotFound(_))));
        let cross_update = update_automation(
            State(state.clone()),
            auth_for(&tenant_a, &["automations:write"]),
            Path(foreign.id.clone()),
            Json(UpdateAutomationRequest {
                name: Some("stolen".into()),
                trigger: None,
                actions: None,
                conditions: None,
            }),
        )
        .await;
        assert!(matches!(cross_update, Err(ApiError::NotFound(_))));
        let cross_delete = delete_automation(
            State(state.clone()),
            auth_for(&tenant_a, &["automations:write"]),
            Path(foreign.id.clone()),
        )
        .await;
        assert!(matches!(cross_delete, Err(ApiError::NotFound(_))));
        let cross_toggle = enable_automation(
            State(state.clone()),
            auth_for(&tenant_a, &["automations:write"]),
            Path(foreign.id.clone()),
        )
        .await;
        assert!(matches!(cross_toggle, Err(ApiError::NotFound(_))));

        // Malformed ids are 404s, never 500s.
        for bad in ["", "not-a-uuid", &"f".repeat(400)] {
            assert!(matches!(
                get_automation(State(state.clone()), read.clone(), Path(bad.to_string())).await,
                Err(ApiError::NotFound(_))
            ));
            assert!(matches!(
                delete_automation(
                    State(state.clone()),
                    auth_for(&tenant_a, &["automations:write"]),
                    Path(bad.to_string())
                )
                .await,
                Err(ApiError::NotFound(_))
            ));
            assert!(matches!(
                enable_automation(
                    State(state.clone()),
                    auth_for(&tenant_a, &["automations:write"]),
                    Path(bad.to_string())
                )
                .await,
                Err(ApiError::NotFound(_))
            ));
        }

        // Update merges fields; enable/disable toggles status.
        let Json(updated) = update_automation(
            State(state.clone()),
            auth_for(&tenant_a, &["automations:write"]),
            Path(auto.id.clone()),
            Json(UpdateAutomationRequest {
                name: Some(format!("Renamed {tag}")),
                trigger: None,
                actions: Some(vec![serde_json::json!({"type": "send_sms"})]),
                conditions: Some(serde_json::json!({"all": []})),
            }),
        )
        .await
        .expect("update");
        assert_eq!(updated.name, format!("Renamed {tag}"));
        assert_eq!(updated.actions[0]["type"], "send_sms");
        assert_eq!(updated.status, "disabled");
        let Json(enabled) = enable_automation(
            State(state.clone()),
            auth_for(&tenant_a, &["automations:write"]),
            Path(auto.id.clone()),
        )
        .await
        .expect("enable");
        assert_eq!(enabled.status, "enabled");
        let Json(disabled) = disable_automation(
            State(state.clone()),
            auth_for(&tenant_a, &["automations:write"]),
            Path(auto.id.clone()),
        )
        .await
        .expect("disable");
        assert_eq!(disabled.status, "disabled");

        // Delete → 204 then 404.
        let status = delete_automation(
            State(state.clone()),
            auth_for(&tenant_a, &["automations:write"]),
            Path(auto.id.clone()),
        )
        .await
        .expect("delete");
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(matches!(
            delete_automation(
                State(state.clone()),
                auth_for(&tenant_a, &["automations:write"]),
                Path(auto.id.clone())
            )
            .await,
            Err(ApiError::NotFound(_))
        ));

        // Scopes.
        assert!(matches!(
            create_automation(
                State(state.clone()),
                auth_for(&tenant_a, &["automations:read"]),
                Json(CreateAutomationRequest {
                    name: "x".into(),
                    trigger: serde_json::json!({}),
                    actions: vec![serde_json::json!({})],
                    conditions: None,
                })
            )
            .await,
            Err(ApiError::Forbidden(_))
        ));
        assert!(matches!(
            get_automation(
                State(state.clone()),
                auth_for(&tenant_a, &[]),
                Path(auto.id)
            )
            .await,
            Err(ApiError::Forbidden(_))
        ));

        cleanup(&pool, &[&tenant_a, &tenant_b]).await;
    }

    #[tokio::test]
    async fn list_reports_total_and_pages_with_a_real_cursor() {
        let Some((state, pool)) = state_and_pool("adv_automations_list").await else {
            return;
        };
        let tenant = apexmail_lib::id::generate_id("", 26);
        seed_tenant(&pool, &tenant).await;
        let tag = uuid::Uuid::new_v4().simple().to_string();
        let base = Utc::now();
        for i in 0..3 {
            let id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO automations (id, tenant_id, name, trigger_config, actions, status, created_at, updated_at)
                 VALUES ($1, $2, $3, '{}'::jsonb, '[]'::jsonb, 'disabled', $4, $4)",
            )
            .bind(id)
            .bind(&tenant)
            .bind(format!("Page flow {i} {tag}"))
            .bind(base - chrono::Duration::minutes(i))
            .execute(&pool)
            .await
            .expect("seed automation");
        }

        let auth = auth_for(&tenant, &["automations:read"]);
        let Json(page1) = list_automations(
            State(state.clone()),
            auth.clone(),
            Query(ListAutomationsQuery {
                limit: 2,
                offset: 0,
                cursor: None,
            }),
        )
        .await
        .expect("page 1");
        assert_eq!(page1["meta"]["total"], 3);
        assert_eq!(page1["meta"]["hasMore"], true);
        assert_eq!(page1["data"].as_array().unwrap().len(), 2);
        let cursor = page1["meta"]["nextCursor"]
            .as_str()
            .expect("cursor")
            .to_string();

        // The emitted cursor is genuinely replayable (RFC3339-encoded).
        let Json(page2) = list_automations(
            State(state.clone()),
            auth.clone(),
            Query(ListAutomationsQuery {
                limit: 2,
                offset: 0,
                cursor: Some(cursor),
            }),
        )
        .await
        .expect("page 2 must accept the server's own cursor");
        assert_eq!(page2["data"].as_array().unwrap().len(), 1);
        assert_eq!(page2["meta"]["hasMore"], false);

        // Clamps and malformed cursors.
        for (limit, offset) in [(0i64, -3i64), (i64::MAX, 0)] {
            let resp = list_automations(
                State(state.clone()),
                auth.clone(),
                Query(ListAutomationsQuery {
                    limit,
                    offset,
                    cursor: None,
                }),
            )
            .await
            .expect("clamped list");
            assert!(resp.0["data"].is_array());
        }
        assert!(matches!(
            list_automations(
                State(state.clone()),
                auth.clone(),
                Query(ListAutomationsQuery {
                    limit: 2,
                    offset: 0,
                    cursor: Some("garbage".into())
                })
            )
            .await,
            Err(ApiError::BadRequest(_))
        ));

        // Unknown fields are refused at deserialization.
        assert!(serde_json::from_str::<CreateAutomationRequest>(
            r#"{"name":"n","trigger":{},"actions":[{}],"tenant_id":"x"}"#
        )
        .is_err());
        assert!(
            serde_json::from_str::<ListAutomationsQuery>(r#"{"limit":1,"evil":true}"#).is_err()
        );

        cleanup(&pool, &[&tenant]).await;
    }
}
