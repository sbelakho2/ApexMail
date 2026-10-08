//! Campaign A/B experiment results — the read/declare surface over the real
//! send-pipeline execution (`worker-processors::campaigns`).
//!
//! * `GET /v1/campaigns/:id/experiment` returns the per-arm outcome table
//!   (trials / successes / rate, aggregated from the append-only `events`
//!   stream by `apexmail_lib::ab_testing::AB_OUTCOMES_SELECT_SQL`), the
//!   recipient phase split, the test-window state, and the honest decision
//!   produced by the shared rule (`apexmail_lib::ab_testing::decide_winner`:
//!   per-arm minimum sample + two-proportion z-test at the two-sided 95%
//!   level). Below the guard the response carries the refusal code and the
//!   human reason — it never names an under-powered "winner".
//! * `POST /v1/campaigns/:id/experiment/winner` is the audited manual
//!   declaration for experiments the automatic rule refuses to conclude
//!   (e.g. an audience too small to reach the minimum sample). It promotes
//!   the holdout recipients to the declared arm, records the provenance on
//!   `campaigns.ab_config`, and writes an audit row.
//!
//! Gated on `FeatureKey::AbTesting` (Growth and above per `docs/pricing.md`)
//! through the canonical entitlement gate
//! ([`crate::entitlements::require_feature`]).
//! Tenant-isolated: the campaign is always looked up with the caller's
//! tenant; there is no cross-tenant arm on this surface.

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use billing_entitlements::FeatureKey;

use crate::error::{success, ApiError, ApiResponse};
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/:id/experiment", get(get_experiment))
        .route("/:id/experiment/winner", post(declare_winner))
}

/// A malformed campaign id can never name a row: 404, not a database 500
/// from the `::uuid` cast.
fn parse_campaign_id(id: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(id).map_err(|_| ApiError::NotFound("campaign not found".into()))
}

// ─── Response types ────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ExperimentArmResult {
    pub arm_index: i32,
    pub template_id: String,
    pub subject: Option<String>,
    pub trials: i64,
    pub successes: i64,
    pub rate: f64,
}

#[derive(Debug, Serialize)]
pub struct ExperimentDecision {
    /// `pending` | `winner` | `insufficient_arms` | `insufficient_sample` |
    /// `no_signal` | `no_significant_leader`.
    pub state: String,
    pub winner_arm: Option<i32>,
    /// `auto` (worker rule) | `manual` (audited declaration) | null.
    pub source: Option<String>,
    pub metric: String,
    pub reason: String,
    /// The operator's next honest step when the automatic rule refuses.
    pub hint: Option<String>,
    pub z: Option<f64>,
    pub z_critical: f64,
    pub min_arm_trials: i64,
    pub decided_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExperimentRecipients {
    pub test: i64,
    pub holdout: i64,
    pub winner: i64,
    pub unassigned: i64,
    pub total: i64,
}

#[derive(Debug, Serialize)]
pub struct CampaignExperimentResponse {
    pub campaign_id: String,
    pub campaign_status: String,
    pub metric: String,
    pub test_percentage: f64,
    pub wait_minutes: i64,
    /// When the test window opened (the split landed) and when it closes.
    pub window_opened_at: Option<String>,
    pub window_closes_at: Option<String>,
    pub window_elapsed: bool,
    /// Every test recipient has left the queue (`queued`/`sending`).
    pub test_drained: bool,
    pub test_in_flight: i64,
    /// True when the winning arm has been written to `ab_config` (the worker
    /// or a manual declaration promoted the holdout).
    pub holdout_promoted: bool,
    pub recipients: ExperimentRecipients,
    pub arms: Vec<ExperimentArmResult>,
    pub decision: ExperimentDecision,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclareWinnerRequest {
    #[serde(alias = "armIndex")]
    pub arm_index: i32,
    /// Operator-supplied justification recorded on the campaign + audit row.
    #[serde(default)]
    pub reason: Option<String>,
}

// ─── Handlers ──────────────────────────────────────────────────

async fn get_experiment(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<CampaignExperimentResponse>>, ApiError> {
    require_scopes(&auth, &["campaigns:read"])?;
    crate::entitlements::require_feature(&state, &auth.tenant_id, FeatureKey::AbTesting).await?;
    let campaign_id = parse_campaign_id(&id)?;
    let campaign = load_experiment_campaign(&state, &auth.tenant_id, campaign_id).await?;
    let response = build_experiment_response(&state, campaign).await?;
    Ok(success(response))
}

async fn declare_winner(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<DeclareWinnerRequest>,
) -> Result<Json<ApiResponse<CampaignExperimentResponse>>, ApiError> {
    require_scopes(&auth, &["campaigns:write"])?;
    crate::entitlements::require_feature(&state, &auth.tenant_id, FeatureKey::AbTesting).await?;
    let campaign_id = parse_campaign_id(&id)?;
    let campaign = load_experiment_campaign(&state, &auth.tenant_id, campaign_id).await?;

    let arm_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM campaign_ab_arms WHERE campaign_id = $1")
            .bind(campaign_id)
            .fetch_one(&state.db)
            .await?;
    if body.arm_index < 0 || i64::from(body.arm_index) >= arm_count {
        return Err(ApiError::Validation(vec![format!(
            "armIndex must name one of the experiment's arms (0..{})",
            arm_count.max(1) - 1
        )]));
    }
    let reason = match body.reason.as_deref() {
        None => "manual declaration by an operator".to_string(),
        Some(reason) => {
            if reason.is_empty() || reason.chars().count() > 500 || reason.contains(['\r', '\n']) {
                return Err(ApiError::Validation(vec![
                    "reason must be a single line of 1-500 characters".into(),
                ]));
            }
            reason.to_string()
        }
    };

    // Promote the held holdout onto the declared arm and record the
    // provenance in one transaction with the declaration.
    let mut tx = state.db.begin().await?;
    let promoted = sqlx::query(
        "UPDATE campaign_recipients \
         SET phase = 'winner', arm_index = $2, updated_at = NOW() \
         WHERE campaign_id = $1 AND phase = 'holdout'",
    )
    .bind(campaign_id)
    .bind(body.arm_index)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    let declared_at = Utc::now().to_rfc3339();
    let declared_by = auth
        .user_id
        .clone()
        .or_else(|| auth.api_key_id.clone())
        .unwrap_or_else(|| "api-key".to_string());
    sqlx::query(
        "UPDATE campaigns \
         SET ab_config = ab_config || jsonb_build_object( \
                 'winnerArm', $2::int, \
                 'winnerSource', 'manual', \
                 'winnerReason', $3::text, \
                 'winnerAt', $4::text, \
                 'winnerDeclaredBy', $5::text \
             ), \
             updated_at = NOW() \
         WHERE id = $1 AND tenant_id = $6",
    )
    .bind(campaign_id)
    .bind(body.arm_index)
    .bind(&reason)
    .bind(&declared_at)
    .bind(&declared_by)
    .bind(&auth.tenant_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    if let Err(error) = crate::audit_log::insert_audit_log_with_env(
        &state.db,
        state.config.environment.is_production(),
        Some(&auth.tenant_id),
        auth.user_id.as_deref(),
        "campaign.experiment.winner_declared",
        "campaign",
        Some(&campaign_id.to_string()),
        serde_json::json!({
            "arm_index": body.arm_index,
            "reason": reason,
            "holdout_promoted": promoted,
            "metric": campaign
                .ab_config
                .get("metric")
                .and_then(|value| value.as_str())
                .unwrap_or("open"),
        }),
        None,
        None,
    )
    .await
    {
        // The declaration stands (the row is the truth); the audit gap is
        // loud but never undoes a committed mutation.
        tracing::warn!(
            campaign_id = %campaign_id,
            tenant_id = %auth.tenant_id,
            error = %error,
            "failed to write experiment winner audit log"
        );
    }

    let campaign = load_experiment_campaign(&state, &auth.tenant_id, campaign_id).await?;
    let response = build_experiment_response(&state, campaign).await?;
    Ok(success(response))
}

// ─── Loading / computation ─────────────────────────────────────

struct ExperimentCampaign {
    id: Uuid,
    status: String,
    ab_config: serde_json::Value,
}

/// Load the campaign and require a configured A/B experiment. A campaign
/// without one is an honest 404 (there is no experiment resource).
async fn load_experiment_campaign(
    state: &AppState,
    tenant_id: &str,
    campaign_id: Uuid,
) -> Result<ExperimentCampaign, ApiError> {
    let row: Option<(String, Option<serde_json::Value>)> = sqlx::query_as(
        "SELECT status, ab_config FROM campaigns WHERE id = $1 AND tenant_id = $2",
    )
    .bind(campaign_id)
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((status, ab_config)) = row else {
        return Err(ApiError::NotFound("campaign not found".into()));
    };
    let Some(config) = ab_config.filter(|value| value.is_object()) else {
        return Err(ApiError::NotFound(
            "no A/B experiment is configured for this campaign".into(),
        ));
    };
    Ok(ExperimentCampaign {
        id: campaign_id,
        status,
        ab_config: config,
    })
}

async fn build_experiment_response(
    state: &AppState,
    campaign: ExperimentCampaign,
) -> Result<CampaignExperimentResponse, ApiError> {
    let campaign_id = campaign.id;
    let config = &campaign.ab_config;
    let metric_wire = config
        .get("metric")
        .and_then(|value| value.as_str())
        .unwrap_or("open");
    let metric_event = if metric_wire == "click" {
        "clicked"
    } else {
        "opened"
    };
    let test_percentage = config
        .get("testPercentage")
        .and_then(|value| value.as_f64())
        .unwrap_or(0.2)
        .clamp(0.1, 0.5);
    let wait_minutes = config
        .get("waitMinutes")
        .and_then(|value| value.as_i64())
        .unwrap_or(60)
        .clamp(5, 1440);

    // Arm content + the live outcome table (the read-only twin of the
    // worker's refresh SQL — same aggregation, same rule input).
    let arm_content: Vec<(i32, String, Option<String>)> = sqlx::query_as(
        "SELECT arm_index, template_id, subject FROM campaign_ab_arms \
         WHERE campaign_id = $1 ORDER BY arm_index",
    )
    .bind(campaign_id)
    .fetch_all(&state.db)
    .await?;
    let outcomes: Vec<(i32, i64, i64)> =
        sqlx::query_as(apexmail_lib::ab_testing::AB_OUTCOMES_SELECT_SQL)
            .bind(campaign_id)
            .bind(metric_event)
            .fetch_all(&state.db)
            .await?;
    let outcome_by_arm: std::collections::HashMap<i32, (i64, i64)> = outcomes
        .into_iter()
        .map(|(arm, trials, successes)| (arm, (trials, successes)))
        .collect();
    let mut arms: Vec<ExperimentArmResult> = arm_content
        .into_iter()
        .map(|(arm_index, template_id, subject)| {
            let (trials, successes) = outcome_by_arm.get(&arm_index).copied().unwrap_or((0, 0));
            ExperimentArmResult {
                arm_index,
                template_id,
                subject,
                trials,
                successes,
                rate: if trials > 0 {
                    successes as f64 / trials as f64
                } else {
                    0.0
                },
            }
        })
        .collect();
    arms.sort_by_key(|arm| arm.arm_index);

    // Recipient split + test-window state.
    let (test, holdout, winner, unassigned, total): (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT \
             COUNT(*) FILTER (WHERE phase = 'test')::bigint, \
             COUNT(*) FILTER (WHERE phase = 'holdout')::bigint, \
             COUNT(*) FILTER (WHERE phase = 'winner')::bigint, \
             COUNT(*) FILTER (WHERE phase IS NULL)::bigint, \
             COUNT(*)::bigint \
         FROM campaign_recipients WHERE campaign_id = $1",
    )
    .bind(campaign_id)
    .fetch_one(&state.db)
    .await?;
    let test_in_flight: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM campaign_recipients \
         WHERE campaign_id = $1 AND phase = 'test' AND status IN ('queued', 'sending')",
    )
    .bind(campaign_id)
    .fetch_one(&state.db)
    .await?;
    let window_opened_at: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT MIN(updated_at) FROM campaign_ab_arms WHERE campaign_id = $1")
            .bind(campaign_id)
            .fetch_one(&state.db)
            .await?;
    let window_closes_at =
        window_opened_at.map(|opened| opened + Duration::minutes(wait_minutes));
    let window_elapsed = window_closes_at
        .map(|closes| Utc::now() >= closes)
        .unwrap_or(false);
    let test_drained = test_in_flight == 0;

    // Decision. A recorded declaration wins; otherwise the shared rule runs
    // exactly as the worker runs it, once the test is drained and the window
    // has elapsed.
    let declared_arm = config.get("winnerArm").and_then(|value| value.as_i64());
    let decision = if let Some(arm) = declared_arm {
        let source = config
            .get("winnerSource")
            .and_then(|value| value.as_str())
            .unwrap_or("auto")
            .to_string();
        let reason = config
            .get("winnerReason")
            .and_then(|value| value.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| {
                format!(
                    "arm {arm} was declared the winner by the {} experiment rule \
                     (two-proportion z-test at the two-sided 95% level)",
                    if source == "manual" { "manual" } else { "automatic" }
                )
            });
        ExperimentDecision {
            state: "winner".into(),
            winner_arm: Some(arm as i32),
            source: Some(source),
            metric: metric_wire.into(),
            reason,
            hint: None,
            z: config.get("winnerZ").and_then(|value| value.as_f64()),
            z_critical: apexmail_lib::ab_testing::Z_CRITICAL,
            min_arm_trials: apexmail_lib::ab_testing::MIN_ARM_TRIALS,
            decided_at: config
                .get("winnerAt")
                .and_then(|value| value.as_str())
                .map(str::to_string),
        }
    } else if !test_drained {
        pending_decision(
            metric_wire,
            format!(
                "the test sample is still sending ({test_in_flight} recipient(s) in flight)"
            ),
        )
    } else if !window_elapsed {
        pending_decision(
            metric_wire,
            match window_closes_at {
                Some(closes) => format!(
                    "the test window closes at {} — the winner is evaluated after it",
                    closes.to_rfc3339()
                ),
                None => "the test sample has not been split yet".to_string(),
            },
        )
    } else {
        let rule_arms: Vec<apexmail_lib::ab_testing::ArmOutcome> = arms
            .iter()
            .map(|arm| apexmail_lib::ab_testing::ArmOutcome {
                arm_index: arm.arm_index,
                trials: arm.trials,
                successes: arm.successes,
            })
            .collect();
        match apexmail_lib::ab_testing::decide_winner(&rule_arms) {
            apexmail_lib::ab_testing::AbVerdict::Winner {
                arm_index, z, rate, ..
            } => ExperimentDecision {
                state: "winner".into(),
                winner_arm: Some(arm_index),
                source: Some("auto".into()),
                metric: metric_wire.into(),
                reason: format!(
                    "arm {arm_index} leads with a {:.1}% {metric_wire} rate and the lead is \
                     significant at the two-sided 95% level (z = {z:.2})",
                    rate * 100.0
                ),
                hint: None,
                z: Some(z),
                z_critical: apexmail_lib::ab_testing::Z_CRITICAL,
                min_arm_trials: apexmail_lib::ab_testing::MIN_ARM_TRIALS,
                decided_at: None,
            },
            apexmail_lib::ab_testing::AbVerdict::Refused { code, reason } => ExperimentDecision {
                state: code.into(),
                winner_arm: None,
                source: None,
                metric: metric_wire.into(),
                reason,
                hint: Some(format!(
                    "The automatic rule will not declare a winner here. To conclude the \
                     experiment manually, POST /v1/campaigns/{campaign_id}/experiment/winner \
                     with the armIndex to promote onto the holdout; the declaration is audited."
                )),
                z: None,
                z_critical: apexmail_lib::ab_testing::Z_CRITICAL,
                min_arm_trials: apexmail_lib::ab_testing::MIN_ARM_TRIALS,
                decided_at: None,
            },
        }
    };

    let holdout_promoted = declared_arm.is_some();
    Ok(CampaignExperimentResponse {
        campaign_id: campaign_id.to_string(),
        campaign_status: campaign.status,
        metric: metric_wire.into(),
        test_percentage,
        wait_minutes,
        window_opened_at: window_opened_at.map(|opened| opened.to_rfc3339()),
        window_closes_at: window_closes_at.map(|closes| closes.to_rfc3339()),
        window_elapsed,
        test_drained,
        test_in_flight,
        holdout_promoted,
        recipients: ExperimentRecipients {
            test,
            holdout,
            winner,
            unassigned,
            total,
        },
        arms,
        decision,
    })
}

fn pending_decision(metric: &str, reason: String) -> ExperimentDecision {
    ExperimentDecision {
        state: "pending".into(),
        winner_arm: None,
        source: None,
        metric: metric.into(),
        reason,
        hint: None,
        z: None,
        z_critical: apexmail_lib::ab_testing::Z_CRITICAL,
        min_arm_trials: apexmail_lib::ab_testing::MIN_ARM_TRIALS,
        decided_at: None,
    }
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;

    fn auth_for(tenant: &str, scopes: &[&str]) -> AuthUser {
        AuthUser {
            tenant_id: tenant.to_string(),
            user_id: None,
            api_key_id: Some("key_experiments".into()),
            session_id: None,
            scopes: scopes.iter().map(|scope| scope.to_string()).collect(),
        }
    }

    async fn state_and_pool(name: &str) -> Option<(AppState, sqlx::PgPool)> {
        let pool = crate::test_db::optional_pg_pool(name).await?;
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        Some((state, pool))
    }

    /// The full `PlanFeatures` fixture the entitlement resolver deserializes
    /// (missing fields fail the plan parse closed).
    fn plan_features(ab_testing: bool, time_travel_debugging: bool) -> serde_json::Value {
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
            "ab_testing": ab_testing,
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

    /// Fixture-seeded entitlement: a unique plan row carrying the flag, with
    /// the tenant on that plan.
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
        .bind(format!("Experiment {tenant}"))
        .bind(format!("exp-{tenant}"))
        .bind(plan_name)
        .execute(pool)
        .await
        .expect("seed tenant");
    }

    async fn seed_campaign(pool: &sqlx::PgPool, tenant: &str, arms: usize) -> Uuid {
        let campaign = Uuid::new_v4();
        let templates: Vec<String> = (0..arms)
            .map(|_| format!("tpl_{}", Uuid::new_v4().simple()))
            .collect();
        let arm_json: Vec<serde_json::Value> = templates
            .iter()
            .map(|template| serde_json::json!({"templateId": template}))
            .collect();
        let config = serde_json::json!({
            "arms": arm_json,
            "testPercentage": 0.2,
            "metric": "open",
            "waitMinutes": 60,
        });
        sqlx::query(
            "INSERT INTO campaigns (id, tenant_id, name, subject, status, sent_count, ab_config) \
             VALUES ($1, $2, $3, 'Subject', 'sending', 0, $4)",
        )
        .bind(campaign)
        .bind(tenant)
        .bind(format!("Experiment {campaign}"))
        .bind(&config)
        .execute(pool)
        .await
        .expect("seed campaign");
        for (index, template) in templates.iter().enumerate() {
            sqlx::query(
                "INSERT INTO campaign_ab_arms (campaign_id, arm_index, template_id) \
                 VALUES ($1, $2, $3)",
            )
            .bind(campaign)
            .bind(index as i32)
            .bind(template)
            .execute(pool)
            .await
            .expect("seed arm");
        }
        campaign
    }

    /// `trials` sent test recipients on `arm`, `successes` of them with an
    /// `opened` event.
    async fn seed_arm_outcome(
        pool: &sqlx::PgPool,
        tenant: &str,
        campaign: Uuid,
        arm: i32,
        label: &str,
        trials: usize,
        successes: usize,
    ) {
        for index in 0..trials {
            let contact_id = Uuid::new_v4();
            let email = format!("{label}-{index}@exp.test");
            sqlx::query(
                "INSERT INTO contacts (id, tenant_id, email, name, status) \
                 VALUES ($1, $2, $3, $4, 'active')",
            )
            .bind(contact_id)
            .bind(tenant)
            .bind(&email)
            .bind(format!("Exp {index}"))
            .execute(pool)
            .await
            .expect("seed contact");
            let message_id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO campaign_recipients \
                 (tenant_id, campaign_id, contact_id, email, status, phase, arm_index, message_id) \
                 VALUES ($1, $2, $3, $4, 'sent', 'test', $5, $6)",
            )
            .bind(tenant)
            .bind(campaign)
            .bind(contact_id)
            .bind(&email)
            .bind(arm)
            .bind(message_id)
            .execute(pool)
            .await
            .expect("seed test recipient");
            if index < successes {
                sqlx::query(
                    "INSERT INTO events (id, tenant_id, message_id, campaign_id, event_type, recipient, timestamp) \
                     VALUES ($1, $2, $3, $4, 'opened', $5, NOW() - INTERVAL '1 minute')",
                )
                .bind(format!("evt_{}", Uuid::new_v4().simple()))
                .bind(tenant)
                .bind(message_id.to_string())
                .bind(campaign.to_string())
                .bind(&email)
                .execute(pool)
                .await
                .expect("seed event");
            }
        }
    }

    async fn seed_holdout(pool: &sqlx::PgPool, tenant: &str, campaign: Uuid, label: &str, count: usize) {
        for index in 0..count {
            let contact_id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO contacts (id, tenant_id, email, name, status) \
                 VALUES ($1, $2, $3, $4, 'active')",
            )
            .bind(contact_id)
            .bind(tenant)
            .bind(format!("{label}-{index}@exp.test"))
            .bind(format!("Hold {index}"))
            .execute(pool)
            .await
            .expect("seed contact");
            sqlx::query(
                "INSERT INTO campaign_recipients \
                 (tenant_id, campaign_id, contact_id, email, status, phase) \
                 VALUES ($1, $2, $3, $4, 'queued', 'holdout')",
            )
            .bind(tenant)
            .bind(campaign)
            .bind(contact_id)
            .bind(format!("{label}-{index}@exp.test"))
            .execute(pool)
            .await
            .expect("seed holdout");
        }
    }

    fn unique_plan_name(prefix: &str) -> String {
        format!("{prefix}_{}", &Uuid::new_v4().simple().to_string()[..10])
    }

    /// Open the experiment window: the split stamps the arms at `NOW()`, so
    /// a fixture that wants the rule to run backdates the clock past
    /// `waitMinutes = 60`.
    async fn backdate_ab_window(pool: &sqlx::PgPool, campaign: Uuid) {
        sqlx::query(
            "UPDATE campaign_ab_arms SET updated_at = NOW() - INTERVAL '2 hours' \
             WHERE campaign_id = $1",
        )
        .bind(campaign)
        .execute(pool)
        .await
        .expect("backdate ab window");
    }

    /// A non-entitled plan is refused with the named reason (the fixture
    /// seeds NO ab_testing) — before any experiment data is touched.
    #[tokio::test]
    async fn experiment_results_refuse_a_non_entitled_plan_with_the_named_reason() {
        let Some((state, pool)) = state_and_pool("exp_gate_denied").await else {
            return;
        };
        let tenant = apexmail_lib::id::generate_id("", 26);
        seed_tenant_with_plan(
            &pool,
            &tenant,
            &unique_plan_name("exp_denied"),
            plan_features(false, false),
        )
        .await;
        let campaign = seed_campaign(&pool, &tenant, 2).await;
        let auth = auth_for(&tenant, &["campaigns:read"]);

        let error = get_experiment(State(state.clone()), auth, Path(campaign.to_string()))
            .await
            .expect_err("a non-entitled plan must be refused");
        match error {
            ApiError::Forbidden(message) => assert!(
                message.contains("does not include `ab_testing`"),
                "the refusal must name the capability: {message}"
            ),
            other => panic!("expected 403 Forbidden, got {other:?}"),
        }

        sqlx::query("DELETE FROM campaigns WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .ok();
        sqlx::query("DELETE FROM contacts WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .ok();
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .ok();
        pool.close().await;
    }

    /// Above the guard with a significant lead, the results surface declares
    /// the winner under the documented rule and lists the per-arm table.
    #[tokio::test]
    async fn experiment_results_declare_the_winner_above_the_guard() {
        let Some((state, pool)) = state_and_pool("exp_decision_winner").await else {
            return;
        };
        let tenant = apexmail_lib::id::generate_id("", 26);
        seed_tenant_with_plan(
            &pool,
            &tenant,
            &unique_plan_name("exp_winner"),
            plan_features(true, false),
        )
        .await;
        let campaign = seed_campaign(&pool, &tenant, 2).await;
        seed_arm_outcome(&pool, &tenant, campaign, 0, "wa", 100, 30).await;
        seed_arm_outcome(&pool, &tenant, campaign, 1, "wb", 100, 10).await;
        seed_holdout(&pool, &tenant, campaign, "wh", 6).await;
        backdate_ab_window(&pool, campaign).await;
        let auth = auth_for(&tenant, &["campaigns:read"]);

        let Json(envelope) = get_experiment(State(state.clone()), auth, Path(campaign.to_string()))
            .await
            .expect("entitled fixture replays");
        let body = envelope.data.expect("data");
        assert_eq!(body.decision.state, "winner");
        assert_eq!(body.decision.winner_arm, Some(0));
        assert_eq!(body.decision.source.as_deref(), Some("auto"));
        let z = body.decision.z.expect("z recorded");
        assert!(z >= apexmail_lib::ab_testing::Z_CRITICAL, "z = {z}");
        assert_eq!(body.arms.len(), 2);
        assert_eq!(body.arms[0].trials, 100);
        assert_eq!(body.arms[0].successes, 30);
        assert!((body.arms[0].rate - 0.3).abs() < 1e-9);
        assert_eq!(body.recipients.test, 200);
        assert_eq!(body.recipients.holdout, 6);
        assert!(!body.holdout_promoted, "the API only reports; it never promotes");

        sqlx::query("DELETE FROM campaigns WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .ok();
        sqlx::query("DELETE FROM contacts WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .ok();
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .ok();
        pool.close().await;
    }

    /// Below the minimum per-arm sample the surface refuses with the reason
    /// and points at the audited manual declaration.
    #[tokio::test]
    async fn experiment_results_refuse_below_the_minimum_sample_with_the_reason() {
        let Some((state, pool)) = state_and_pool("exp_decision_below").await else {
            return;
        };
        let tenant = apexmail_lib::id::generate_id("", 26);
        seed_tenant_with_plan(
            &pool,
            &tenant,
            &unique_plan_name("exp_below"),
            plan_features(true, false),
        )
        .await;
        let campaign = seed_campaign(&pool, &tenant, 2).await;
        seed_arm_outcome(&pool, &tenant, campaign, 0, "sa", 10, 3).await;
        seed_arm_outcome(&pool, &tenant, campaign, 1, "sb", 10, 0).await;
        seed_holdout(&pool, &tenant, campaign, "sh", 4).await;
        backdate_ab_window(&pool, campaign).await;
        let auth = auth_for(&tenant, &["campaigns:read"]);

        let Json(envelope) = get_experiment(State(state.clone()), auth, Path(campaign.to_string()))
            .await
            .expect("entitled fixture replays");
        let body = envelope.data.expect("data");
        assert_eq!(body.decision.state, "insufficient_sample");
        assert_eq!(body.decision.winner_arm, None);
        assert!(
            body.decision.reason.contains("30") && body.decision.reason.contains("arm"),
            "the reason names the guard: {}",
            body.decision.reason
        );
        let hint = body.decision.hint.expect("an honest next step");
        assert!(
            hint.contains(&format!("/v1/campaigns/{campaign}/experiment/winner")),
            "the hint points at the manual declaration: {hint}"
        );

        sqlx::query("DELETE FROM campaigns WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .ok();
        sqlx::query("DELETE FROM contacts WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .ok();
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .ok();
        pool.close().await;
    }

    /// The manual declaration promotes the holdout onto the chosen arm,
    /// records the provenance, and writes the audit row.
    #[tokio::test]
    async fn manual_winner_declaration_promotes_the_holdout_and_is_audited() {
        let Some((state, pool)) = state_and_pool("exp_manual_winner").await else {
            return;
        };
        let tenant = apexmail_lib::id::generate_id("", 26);
        seed_tenant_with_plan(
            &pool,
            &tenant,
            &unique_plan_name("exp_manual"),
            plan_features(true, false),
        )
        .await;
        let campaign = seed_campaign(&pool, &tenant, 2).await;
        seed_arm_outcome(&pool, &tenant, campaign, 0, "ma", 5, 1).await;
        seed_arm_outcome(&pool, &tenant, campaign, 1, "mb", 5, 1).await;
        seed_holdout(&pool, &tenant, campaign, "mh", 4).await;
        let auth = auth_for(&tenant, &["campaigns:write"]);

        // An arm outside the experiment is refused as a client error.
        let bad = declare_winner(
            State(state.clone()),
            auth.clone(),
            Path(campaign.to_string()),
            Json(DeclareWinnerRequest {
                arm_index: 7,
                reason: None,
            }),
        )
        .await;
        assert!(matches!(bad, Err(ApiError::Validation(_))));

        let Json(envelope) = declare_winner(
            State(state.clone()),
            auth,
            Path(campaign.to_string()),
            Json(DeclareWinnerRequest {
                arm_index: 1,
                reason: Some("small list; declaring the tested leader".into()),
            }),
        )
        .await
        .expect("manual declaration succeeds");
        let body = envelope.data.expect("data");
        assert_eq!(body.decision.state, "winner");
        assert_eq!(body.decision.winner_arm, Some(1));
        assert_eq!(body.decision.source.as_deref(), Some("manual"));
        assert!(body.holdout_promoted);

        let phases: Vec<(String, i32)> = sqlx::query_as(
            "SELECT phase, arm_index FROM campaign_recipients \
             WHERE campaign_id = $1 AND email LIKE 'mh-%'",
        )
        .bind(campaign)
        .fetch_all(&pool)
        .await
        .expect("holdout phases");
        assert_eq!(phases.len(), 4);
        assert!(phases.iter().all(|(phase, arm)| phase == "winner" && *arm == 1));

        let audited: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs \
             WHERE action = 'campaign.experiment.winner_declared' AND resource_id = $1",
        )
        .bind(campaign.to_string())
        .fetch_one(&pool)
        .await
        .expect("audit rows");
        assert_eq!(audited, 1, "the declaration is audited");

        sqlx::query("DELETE FROM campaigns WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .ok();
        sqlx::query("DELETE FROM contacts WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .ok();
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .ok();
        pool.close().await;
    }

    /// The real router mounts BOTH the base campaign surface and the
    /// experiment surface at `/v1/campaigns` (and the message timeline at
    /// `/v1/messages`): an unauthenticated probe must be answered by the
    /// auth layer (401), never by a 404 from an unmounted path.
    #[tokio::test]
    async fn experiment_and_timeline_routes_are_mounted_on_the_real_router() {
        use axum::body::Body;
        use axum::http::{Method, Request, StatusCode};
        use tower::ServiceExt;

        let Some((state, pool)) = state_and_pool("capabilities_router_mount").await else {
            return;
        };
        let app = crate::app::build_app(state.clone());
        for (method, path) in [
            (
                Method::GET,
                "/v1/campaigns/11111111-1111-1111-1111-111111111111/experiment",
            ),
            (
                Method::POST,
                "/v1/campaigns/11111111-1111-1111-1111-111111111111/experiment/winner",
            ),
            (Method::GET, "/v1/messages/11111111-1111-1111-1111-111111111111/timeline?at=2026-10-07T00:00:00Z"),
            (Method::GET, "/messages/11111111-1111-1111-1111-111111111111/timeline"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method.clone())
                        .uri(path)
                        .body(Body::empty())
                        .expect("probe request"),
                )
                .await
                .expect("router responds");
            assert_ne!(
                response.status(),
                StatusCode::NOT_FOUND,
                "{method} {path} must be mounted"
            );
        }
        pool.close().await;
    }
}
