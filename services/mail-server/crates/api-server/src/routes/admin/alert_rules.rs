//! Operator alert-rule management: CRUD over the EXISTING evaluated
//! usage-alert store (`usage_alert_configs`, migrations 024 + 246).
//!
//! There is deliberately no second rule table: every rule created here is
//! read by the billing-service maintenance sweep
//! (`billing_service::maintenance::process_usage_alerts`) and fires into
//! `system_alerts` — the store the control plane's `/alerts` page renders.
//! A rule that never reached the evaluator would be a claim-vs-code gap, so
//! the metric whitelist below is exactly the set the evaluator can resolve
//! (`emails`, `api_calls`); `storage` is rejected with the honest reason
//! instead of being stored as a rule that can never fire.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, require_system_tenant, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_rules).post(create_rule))
        .route("/:id", get(get_rule).patch(update_rule).delete(delete_rule))
        .route("/:id/enable", post(enable_rule))
        .route("/:id/disable", post(disable_rule))
}

/// Severity vocabulary shared with `system_alerts` (migration 020's CHECK):
/// the fired incident must be storable exactly as the rule declares it.
const SEVERITIES: [&str; 3] = ["info", "warning", "critical"];
/// Channels the maintenance sweep can actually deliver over
/// (`send_usage_alert`): email enqueues, webhook POSTs, both does each.
const CHANNELS: [&str; 3] = ["email", "webhook", "both"];
/// Metrics `resolve_usage_alert_metric` resolves against the live usage
/// summary. The tenant-facing upsert also accepts `storage`, but the
/// evaluator skips it — offering it on the operator surface would create
/// rules that can never fire.
const METRICS: [&str; 2] = ["emails", "api_calls"];
const RULE_NAME_MAX: usize = 80;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertRuleDto {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub metric_type: String,
    pub threshold_percent: i32,
    pub notification_channel: String,
    pub severity: String,
    pub enabled: bool,
    pub last_triggered_at: Option<String>,
    pub created_at: Option<String>,
}

/// Row shape shared by every query:
/// id, tenant_id, name, metric_type, threshold_percent, channel, severity,
/// enabled, last_triggered_at, created_at.
type RuleRow = (
    String,
    String,
    Option<String>,
    String,
    i32,
    String,
    String,
    bool,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
);

const RULE_COLUMNS: &str = "id::text AS id, tenant_id, name, metric_type, \
     threshold_percent, notification_channel, severity, enabled, \
     last_triggered_at, created_at";

impl From<RuleRow> for AlertRuleDto {
    fn from(row: RuleRow) -> Self {
        Self {
            id: row.0,
            tenant_id: row.1,
            name: row.2.unwrap_or_default().trim().to_string(),
            metric_type: row.3,
            threshold_percent: row.4,
            notification_channel: row.5,
            severity: row.6,
            enabled: row.7,
            last_triggered_at: row.8.map(|ts| ts.to_rfc3339()),
            created_at: row.9.map(|ts| ts.to_rfc3339()),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RulesQuery {
    /// Optional tenant scope for the fleet-wide list.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Optional enabled/disabled filter.
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateRuleBody {
    pub tenant_id: String,
    pub name: String,
    pub metric_type: String,
    pub threshold_percent: i32,
    pub notification_channel: String,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

/// Update the editable fields; omitted fields keep their stored value.
/// Tenant and metric are identity (the evaluator's key and the unique
/// `(tenant_id, metric_type, threshold_percent)` index), so they are not
/// editable — delete and recreate to move a rule.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UpdateRuleBody {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub threshold_percent: Option<i32>,
    #[serde(default)]
    pub notification_channel: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

fn default_severity() -> String {
    "warning".into()
}

fn default_enabled() -> bool {
    true
}

/// Validators return the caller-facing message as a plain string: the JSON
/// handlers wrap it in [`ApiError::BadRequest`], while the CP form handlers
/// put it straight into the field-error map. One implementation, both
/// surfaces — validation cannot drift between the API and the page.
pub(crate) fn validate_name(name: &str) -> Result<String, String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("Rule name is required.".into());
    }
    if trimmed.chars().count() > RULE_NAME_MAX {
        return Err(format!(
            "Rule name must be at most {RULE_NAME_MAX} characters."
        ));
    }
    Ok(trimmed.to_string())
}

pub(crate) fn validate_metric(metric: &str) -> Result<(), String> {
    if METRICS.contains(&metric) {
        return Ok(());
    }
    Err(format!(
        "Unsupported metricType \"{metric}\". The evaluator resolves {}; \
         other metrics would create a rule that can never fire.",
        METRICS.join(", ")
    ))
}

pub(crate) fn validate_threshold(threshold: i32) -> Result<(), String> {
    if (1..=100).contains(&threshold) {
        return Ok(());
    }
    Err("The threshold must be between 1 and 100.".into())
}

pub(crate) fn validate_channel(channel: &str) -> Result<(), String> {
    if CHANNELS.contains(&channel) {
        return Ok(());
    }
    Err(format!(
        "Unsupported notificationChannel \"{channel}\"; expected one of {}.",
        CHANNELS.join(", ")
    ))
}

pub(crate) fn validate_severity(severity: &str) -> Result<(), String> {
    if SEVERITIES.contains(&severity) {
        return Ok(());
    }
    Err(format!(
        "Unsupported severity \"{severity}\"; expected one of {}.",
        SEVERITIES.join(", ")
    ))
}

/// Actor-attributed audit for rule mutations: a rule change alters what
/// pages operators, so the operator who ordered it must be on record.
pub(crate) async fn log_rule_audit(
    state: &AppState,
    auth: &AuthUser,
    action: &str,
    rule_id: &str,
    metadata: serde_json::Value,
) {
    crate::audit_log::insert_audit_log_best_effort_with_env(
        &state.db,
        state.config.environment.is_production(),
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
        action,
        "alert_rule",
        Some(rule_id),
        metadata,
        None,
        None,
    )
    .await;
}

/// Map a unique-key collision on `(tenant_id, metric_type,
/// threshold_percent)` to an honest 409; other database failures keep their
/// 500 path.
pub(crate) fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}

async fn list_rules(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<RulesQuery>,
) -> Result<Json<Vec<AlertRuleDto>>, ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&state, &auth).await?;

    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);
    let sql = format!(
        "SELECT {RULE_COLUMNS}
         FROM usage_alert_configs
         WHERE ($1::text IS NULL OR tenant_id = $1)
           AND ($2::bool IS NULL OR enabled = $2)
         ORDER BY created_at DESC NULLS LAST, id
         LIMIT $3 OFFSET $4"
    );
    let rows: Vec<RuleRow> = sqlx::query_as(&sql)
        .bind(params.tenant_id.as_deref())
        .bind(params.enabled)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await?;
    Ok(Json(rows.into_iter().map(AlertRuleDto::from).collect()))
}

async fn get_rule(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<AlertRuleDto>, ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&state, &auth).await?;

    let sql = format!("SELECT {RULE_COLUMNS} FROM usage_alert_configs WHERE id = $1::uuid");
    let row: RuleRow = sqlx::query_as(&sql)
        .bind(&id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("No alert rule with that id.".into()))?;
    Ok(Json(AlertRuleDto::from(row)))
}

async fn create_rule(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateRuleBody>,
) -> Result<(StatusCode, Json<AlertRuleDto>), ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&state, &auth).await?;

    let name = validate_name(&body.name).map_err(ApiError::BadRequest)?;
    validate_metric(&body.metric_type).map_err(ApiError::BadRequest)?;
    validate_threshold(body.threshold_percent).map_err(ApiError::BadRequest)?;
    validate_channel(&body.notification_channel).map_err(ApiError::BadRequest)?;
    validate_severity(&body.severity).map_err(ApiError::BadRequest)?;

    // A rule must belong to a real tenant: the evaluator resolves usage per
    // tenant, so a typo'd tenant id would silently never fire.
    let tenant_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1)")
            .bind(&body.tenant_id)
            .fetch_one(&state.db)
            .await?;
    if !tenant_exists {
        return Err(ApiError::BadRequest(format!(
            "Unknown tenant \"{}\". A rule must reference an existing tenant.",
            body.tenant_id
        )));
    }

    let sql = format!(
        "INSERT INTO usage_alert_configs
             (tenant_id, name, metric_type, threshold_percent,
              notification_channel, severity, enabled)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING {RULE_COLUMNS}"
    );
    let row: RuleRow = sqlx::query_as(&sql)
        .bind(&body.tenant_id)
        .bind(&name)
        .bind(&body.metric_type)
        .bind(body.threshold_percent)
        .bind(&body.notification_channel)
        .bind(&body.severity)
        .bind(body.enabled)
        .fetch_one(&state.db)
        .await
        .map_err(|error| {
            if is_unique_violation(&error) {
                ApiError::Conflict(format!(
                    "A {} rule for tenant {} at {}% already exists.",
                    body.metric_type, body.tenant_id, body.threshold_percent
                ))
            } else {
                error.into()
            }
        })?;
    let dto = AlertRuleDto::from(row);
    log_rule_audit(
        &state,
        &auth,
        "control_plane.alert_rule.created",
        &dto.id,
        serde_json::json!({
            "tenantId": dto.tenant_id,
            "name": dto.name,
            "metricType": dto.metric_type,
            "thresholdPercent": dto.threshold_percent,
            "notificationChannel": dto.notification_channel,
            "severity": dto.severity,
            "enabled": dto.enabled,
        }),
    )
    .await;
    Ok((StatusCode::CREATED, Json(dto)))
}

async fn update_rule(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<UpdateRuleBody>,
) -> Result<Json<AlertRuleDto>, ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&state, &auth).await?;

    let name = match body.name.as_deref() {
        Some(name) => Some(validate_name(name).map_err(ApiError::BadRequest)?),
        None => None,
    };
    if let Some(threshold) = body.threshold_percent {
        validate_threshold(threshold).map_err(ApiError::BadRequest)?;
    }
    if let Some(channel) = body.notification_channel.as_deref() {
        validate_channel(channel).map_err(ApiError::BadRequest)?;
    }
    if let Some(severity) = body.severity.as_deref() {
        validate_severity(severity).map_err(ApiError::BadRequest)?;
    }

    let sql = format!(
        "UPDATE usage_alert_configs
         SET name = COALESCE($2, name),
             threshold_percent = COALESCE($3, threshold_percent),
             notification_channel = COALESCE($4, notification_channel),
             severity = COALESCE($5, severity),
             enabled = COALESCE($6, enabled),
             updated_at = NOW()
         WHERE id = $1::uuid
         RETURNING {RULE_COLUMNS}"
    );
    let row: RuleRow = sqlx::query_as(&sql)
        .bind(&id)
        .bind(name.as_deref())
        .bind(body.threshold_percent)
        .bind(body.notification_channel.as_deref())
        .bind(body.severity.as_deref())
        .bind(body.enabled)
        .fetch_optional(&state.db)
        .await
        .map_err(|error| {
            if is_unique_violation(&error) {
                ApiError::Conflict(
                    "Another rule for this tenant and metric already uses that threshold.".into(),
                )
            } else {
                error.into()
            }
        })?
        .ok_or_else(|| ApiError::NotFound("No alert rule with that id.".into()))?;
    let dto = AlertRuleDto::from(row);
    log_rule_audit(
        &state,
        &auth,
        "control_plane.alert_rule.updated",
        &dto.id,
        serde_json::json!({
            "tenantId": dto.tenant_id,
            "name": dto.name,
            "metricType": dto.metric_type,
            "thresholdPercent": dto.threshold_percent,
            "notificationChannel": dto.notification_channel,
            "severity": dto.severity,
            "enabled": dto.enabled,
        }),
    )
    .await;
    Ok(Json(dto))
}

async fn set_enabled(
    state: &AppState,
    auth: &AuthUser,
    id: &str,
    enabled: bool,
) -> Result<Json<AlertRuleDto>, ApiError> {
    let sql = format!(
        "UPDATE usage_alert_configs
         SET enabled = $2, updated_at = NOW()
         WHERE id = $1::uuid
         RETURNING {RULE_COLUMNS}"
    );
    let row: RuleRow = sqlx::query_as(&sql)
        .bind(id)
        .bind(enabled)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("No alert rule with that id.".into()))?;
    let dto = AlertRuleDto::from(row);
    log_rule_audit(
        state,
        auth,
        if enabled {
            "control_plane.alert_rule.enabled"
        } else {
            "control_plane.alert_rule.disabled"
        },
        &dto.id,
        serde_json::json!({ "tenantId": dto.tenant_id, "name": dto.name, "enabled": enabled }),
    )
    .await;
    Ok(Json(dto))
}

async fn enable_rule(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<AlertRuleDto>, ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&state, &auth).await?;
    set_enabled(&state, &auth, &id, true).await
}

async fn disable_rule(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<AlertRuleDto>, ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&state, &auth).await?;
    set_enabled(&state, &auth, &id, false).await
}

async fn delete_rule(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&state, &auth).await?;

    let deleted: Option<(String, String, Option<String>)> = sqlx::query_as(
        "DELETE FROM usage_alert_configs
         WHERE id = $1::uuid
         RETURNING id::text, tenant_id, name",
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await?;
    let Some((rule_id, tenant_id, name)) = deleted else {
        return Err(ApiError::NotFound("No alert rule with that id.".into()));
    };
    log_rule_audit(
        &state,
        &auth,
        "control_plane.alert_rule.deleted",
        &rule_id,
        serde_json::json!({ "tenantId": tenant_id, "name": name.unwrap_or_default() }),
    )
    .await;
    Ok(Json(serde_json::json!({ "deleted": true, "id": rule_id })))
}

#[cfg(test)]
mod adversarial_tests {
    use axum::http::StatusCode;

    use crate::app::test_support::adv::AdvEnv;

    /// Seed an active tenant on a plan with a real email limit so the
    /// evaluator can resolve a percentage. Returns the tenant id.
    async fn seed_tenant_with_plan(pool: &sqlx::PgPool, tenant: &str, email_limit: i64) -> String {
        let plan = format!("{tenant}_plan");
        // plans.id is VARCHAR(26): a prefixed tenant name can overflow it, so
        // mint the id independently of the (long) plan name.
        sqlx::query(
            "INSERT INTO plans (id, name, display_name, price_cents, email_limit, api_call_limit, features)
             VALUES ($1, $2, $2, 0, $3, 100000, '{}'::jsonb)
             ON CONFLICT (name) DO UPDATE SET email_limit = EXCLUDED.email_limit",
        )
        .bind(apexmail_lib::id::generate_id("pln", 22))
        .bind(&plan)
        .bind(email_limit)
        .execute(pool)
        .await
        .expect("seed plan");
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at)
             VALUES ($1, 'Alert rule eval tenant', $2, $3, 'active', NOW(), NOW())
             ON CONFLICT (id) DO UPDATE SET plan = EXCLUDED.plan, status = 'active'",
        )
        .bind(tenant)
        .bind(format!("slug-{tenant}"))
        .bind(&plan)
        .execute(pool)
        .await
        .expect("seed tenant");
        tenant.to_string()
    }

    fn rule_json(tenant: &str) -> String {
        serde_json::json!({
            "tenantId": tenant,
            "name": "Emails near plan limit",
            "metricType": "emails",
            "thresholdPercent": 50,
            "notificationChannel": "email",
            "severity": "critical",
        })
        .to_string()
    }

    #[tokio::test]
    async fn rule_crud_lifecycle_persists_and_audits_every_mutation() {
        let Some(pool) = crate::test_db::canonical_pool("adm_alert_rules_crud").await else {
            return;
        };
        let tenant = seed_tenant_with_plan(&pool, "alert_rules_crud", 1_000).await;
        let env = AdvEnv::admin(pool.clone()).await;

        // Create.
        let (status, created) = env
            .post("/v1/admin/alerts/rules", &rule_json(&tenant))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        assert_eq!(created["tenantId"], tenant);
        assert_eq!(created["name"], "Emails near plan limit");
        assert_eq!(created["metricType"], "emails");
        assert_eq!(created["thresholdPercent"], 50);
        assert_eq!(created["notificationChannel"], "email");
        assert_eq!(created["severity"], "critical");
        assert_eq!(created["enabled"], true);
        assert!(created["lastTriggeredAt"].is_null());
        let id = created["id"].as_str().expect("rule id").to_string();

        // The row the evaluator reads is the row the API wrote.
        let stored: (String, i32, String, bool) = sqlx::query_as(
            "SELECT metric_type, threshold_percent, severity, enabled
             FROM usage_alert_configs WHERE id = $1::uuid",
        )
        .bind(&id)
        .fetch_one(&pool)
        .await
        .expect("stored rule");
        assert_eq!(stored, ("emails".into(), 50, "critical".into(), true));

        // List (fleet-wide and tenant-filtered).
        let (status, listed) = env.get("/v1/admin/alerts/rules").await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert_eq!(listed.as_array().map(Vec::len), Some(1));
        let (status, filtered) = env
            .get(&format!("/v1/admin/alerts/rules?tenantId={tenant}"))
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(filtered.as_array().map(Vec::len), Some(1));
        let (status, empty) = env.get("/v1/admin/alerts/rules?tenantId=nope").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(empty.as_array().map(Vec::len), Some(0));

        // Get.
        let (status, fetched) = env.get(&format!("/v1/admin/alerts/rules/{id}")).await;
        assert_eq!(status, StatusCode::OK, "{fetched}");
        assert_eq!(fetched["id"], id);

        // Update the editable fields.
        let (status, updated) = env
            .patch(
                &format!("/v1/admin/alerts/rules/{id}"),
                r#"{"name":"Emails at half the plan","thresholdPercent":60,"severity":"warning"}"#,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{updated}");
        assert_eq!(updated["name"], "Emails at half the plan");
        assert_eq!(updated["thresholdPercent"], 60);
        assert_eq!(updated["severity"], "warning");
        // Untouched fields keep their stored values.
        assert_eq!(updated["notificationChannel"], "email");
        assert_eq!(updated["enabled"], true);

        // Disable / enable are explicit, idempotent operations.
        let (status, disabled) = env
            .post(&format!("/v1/admin/alerts/rules/{id}/disable"), "")
            .await;
        assert_eq!(status, StatusCode::OK, "{disabled}");
        assert_eq!(disabled["enabled"], false);
        let (status, disabled_again) = env
            .post(&format!("/v1/admin/alerts/rules/{id}/disable"), "")
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(disabled_again["enabled"], false, "disable is idempotent");
        let (status, enabled) = env
            .post(&format!("/v1/admin/alerts/rules/{id}/enable"), "")
            .await;
        assert_eq!(status, StatusCode::OK, "{enabled}");
        assert_eq!(enabled["enabled"], true);

        // Every mutation is attributed on the audit trail.
        let audits: Vec<(String, String)> = sqlx::query_as(
            "SELECT action, COALESCE(resource_id, '') FROM audit_logs
             WHERE resource = 'alert_rule' AND resource_id = $1
             ORDER BY created_at",
        )
        .bind(&id)
        .fetch_all(&pool)
        .await
        .expect("audit rows");
        let actions: Vec<&str> = audits.iter().map(|(action, _)| action.as_str()).collect();
        for expected in [
            "control_plane.alert_rule.created",
            "control_plane.alert_rule.updated",
            "control_plane.alert_rule.disabled",
            "control_plane.alert_rule.enabled",
        ] {
            assert!(
                actions.contains(&expected),
                "missing {expected}: {actions:?}"
            );
        }

        // Delete removes the exact row and is audited too.
        let (status, deleted) = env.delete(&format!("/v1/admin/alerts/rules/{id}")).await;
        assert_eq!(status, StatusCode::OK, "{deleted}");
        assert_eq!(deleted["deleted"], true);
        let remaining: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM usage_alert_configs WHERE id = $1::uuid")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .expect("count");
        assert_eq!(remaining, 0);
        let delete_audits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs
             WHERE resource = 'alert_rule' AND resource_id = $1 AND action = 'control_plane.alert_rule.deleted'",
        )
        .bind(&id)
        .fetch_one(&pool)
        .await
        .expect("delete audit");
        assert_eq!(delete_audits, 1);

        // A second delete is an honest 404, never a silent success.
        let (status, missing) = env.delete(&format!("/v1/admin/alerts/rules/{id}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{missing}");
    }

    #[tokio::test]
    async fn rule_validation_refuses_unfireable_or_unknown_input() {
        let Some(pool) = crate::test_db::canonical_pool("adm_alert_rules_valid").await else {
            return;
        };
        let tenant = seed_tenant_with_plan(&pool, "alert_rules_valid", 1_000).await;
        let env = AdvEnv::admin(pool.clone()).await;

        let base = serde_json::json!({
            "tenantId": tenant,
            "name": "Valid baseline",
            "metricType": "emails",
            "thresholdPercent": 50,
            "notificationChannel": "email",
            "severity": "warning",
        });
        let cases: Vec<(serde_json::Value, &str)> = vec![
            (
                serde_json::json!({"tenantId": "ghost-tenant"}),
                "Unknown tenant",
            ),
            (
                serde_json::json!({"metricType": "storage"}),
                "can never fire",
            ),
            (
                serde_json::json!({"metricType": "bogus"}),
                "Unsupported metricType",
            ),
            (
                serde_json::json!({"thresholdPercent": 0}),
                "between 1 and 100",
            ),
            (
                serde_json::json!({"thresholdPercent": 101}),
                "between 1 and 100",
            ),
            (
                serde_json::json!({"notificationChannel": "carrier-pigeon"}),
                "Unsupported notificationChannel",
            ),
            (
                serde_json::json!({"severity": "page-everyone"}),
                "Unsupported severity",
            ),
            (serde_json::json!({"name": "   "}), "Rule name is required"),
            (
                serde_json::json!({"name": "x".repeat(81)}),
                "at most 80 characters",
            ),
        ];
        for (overrides, needle) in cases {
            let mut body = base.clone();
            let object = body.as_object_mut().expect("object");
            for (key, value) in overrides.as_object().expect("overrides") {
                object.insert(key.clone(), value.clone());
            }
            let (status, response) = env.post("/v1/admin/alerts/rules", &body.to_string()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {response}");
            let message = response["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            assert!(
                message.contains(needle),
                "{body}: expected {needle:?}, got {message:?}"
            );
        }
        // A body missing required fields is refused by the extractor as a
        // client error — never silently defaulted into a stored rule.
        let (status, _) = env
            .post("/v1/admin/alerts/rules", r#"{"name":"only a name"}"#)
            .await;
        assert!(
            matches!(
                status,
                StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
            ),
            "a truncated body must be a client error, got {status}"
        );
        let written: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM usage_alert_configs WHERE tenant_id = $1")
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .expect("count");
        assert_eq!(written, 0, "rejected rules must never be stored");

        // The duplicate unique key is an honest 409, not a 500.
        let (status, created) = env.post("/v1/admin/alerts/rules", &base.to_string()).await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let (status, conflict) = env.post("/v1/admin/alerts/rules", &base.to_string()).await;
        assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
        assert!(
            conflict["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("already exists"),
            "{conflict}"
        );
    }

    #[tokio::test]
    async fn rules_require_wildcard_scope_and_the_system_tenant() {
        let Some(pool) = crate::test_db::canonical_pool("adm_alert_rules_scope").await else {
            return;
        };
        // A system key without "*" is refused.
        let scoped =
            crate::app::test_support::seed_api_key_for(&pool, "system", &["alerts:read"]).await;
        let env = AdvEnv::over(pool.clone(), scoped).await;
        let (status, body) = env.get("/v1/admin/alerts/rules").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

        // A customer tenant's own "*" key must never reach the control plane.
        let (env, _tenant) = AdvEnv::tenant(pool, &["*"]).await;
        let (status, body) = env.get("/v1/admin/alerts/rules").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("system tenant"),
            "the refusal must name the tenant gate: {body}"
        );
    }

    /// End-to-end proof for the whole surface: a rule CREATED THROUGH THIS
    /// API is evaluated by the RUNNING maintenance sweep and produces the
    /// `system_alerts` incident the CP /alerts page renders. This is the
    /// claim "rules actually fire" made executable.
    #[tokio::test]
    async fn created_rule_is_evaluated_by_the_running_sweep_and_fires() {
        let Some(pool) = crate::test_db::canonical_pool("adm_alert_rules_fire").await else {
            return;
        };
        let tenant = seed_tenant_with_plan(&pool, "alert_rules_fire", 1_000).await;
        let env = AdvEnv::admin(pool.clone()).await;
        let (status, created) = env
            .post("/v1/admin/alerts/rules", &rule_json(&tenant))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let rule_id = created["id"].as_str().expect("rule id").to_string();

        // Usage crosses the rule's threshold: 800 / 1000 = 80% >= 50%.
        sqlx::query(
            "INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp)
             VALUES (gen_random_uuid(), $1, 'emails_sent', 800, NOW())",
        )
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("usage");

        // The cooldown key lives in the shared Redis and survives a prior
        // run: clear it so this sweep is judged on this run's data alone.
        // Soft-skip (workspace convention) when no test Redis is configured.
        let Ok(redis_url) = std::env::var("TEST_REDIS_URL") else {
            return;
        };
        let redis_pool = deadpool_redis::Config::from_url(&redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("redis pool");
        {
            let mut conn = redis_pool.get().await.expect("redis connection");
            let cooldown = format!("alert:cooldown:{tenant}:emails:50");
            let _: () = deadpool_redis::redis::cmd("DEL")
                .arg(&cooldown)
                .query_async(&mut *conn)
                .await
                .expect("clear cooldown");
        }

        // Drive the SAME evaluation the periodic loop runs.
        let billing_state = billing_service::AppState::new(
            pool.clone(),
            redis_pool.clone(),
            billing_service::config::BillingConfig::default(),
        );
        let sweep = billing_service::maintenance::process_usage_alerts(
            billing_state.as_ref(),
            &reqwest::Client::new(),
        )
        .await
        .expect("the running sweep must not fail");
        assert!(
            sweep.alerts_triggered >= 1,
            "the created rule must trigger: {sweep:?}"
        );

        // The incident the CP /alerts page (and its SSE stream) reads.
        let (alert_type, severity, message, recorded_tenant): (String, String, String, String) =
            sqlx::query_as(
                "SELECT alert_type, severity, message, COALESCE(tenant_id, '')
                 FROM system_alerts
                 WHERE source = 'usage_alert' AND fingerprint = $1",
            )
            .bind(&rule_id)
            .fetch_one(&pool)
            .await
            .expect("the fired rule must produce a system_alerts row");
        assert_eq!(alert_type, "usage_alert");
        assert_eq!(severity, "critical", "the rule's severity rides along");
        assert!(
            message.contains("Emails near plan limit"),
            "the rule's name must ride the incident message: {message}"
        );
        assert_eq!(recorded_tenant, tenant);

        // A disabled rule stops firing: disable through the API, clear the
        // cooldown, sweep again — no second incident.
        let (status, disabled) = env
            .post(&format!("/v1/admin/alerts/rules/{rule_id}/disable"), "")
            .await;
        assert_eq!(status, StatusCode::OK, "{disabled}");
        {
            let mut conn = redis_pool.get().await.expect("redis connection");
            let cooldown = format!("alert:cooldown:{tenant}:emails:50");
            let _: () = deadpool_redis::redis::cmd("DEL")
                .arg(&cooldown)
                .query_async(&mut *conn)
                .await
                .expect("clear cooldown");
        }
        let second = billing_service::maintenance::process_usage_alerts(
            billing_state.as_ref(),
            &reqwest::Client::new(),
        )
        .await
        .expect("second sweep");
        assert_eq!(
            second.alerts_triggered, 0,
            "a disabled rule is not evaluated: {second:?}"
        );
        let incidents: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM system_alerts WHERE source = 'usage_alert' AND fingerprint = $1",
        )
        .bind(&rule_id)
        .fetch_one(&pool)
        .await
        .expect("incident count");
        assert_eq!(incidents, 1, "still exactly the one raised incident");
    }
}
