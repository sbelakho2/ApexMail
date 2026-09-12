//! The ONE typed read model for the sales-autopilot control surface.
//!
//! Both consumers answer the CP's questions from here:
//!
//! 1. the authenticated `/control/*` HTTP surface ([`crate::control`]), whose
//!    JSON responses are built by serializing these snapshot structs; and
//! 2. the api-server's SSR control-plane page (`cp_sales_autopilot`), which
//!    used to issue its own direct `sales_*` queries — a second, silently
//!    drifting read contract. The finding was exactly that duplication: the
//!    admin mutations/read APIs proxied this service while SSR queried the
//!    canonical tables itself. The shared module lives in this crate because
//!    the api-server already sits above `sales-autopilot` in the dependency
//!    graph (no cycle), whereas `control` cannot reach into api-server.
//!
//! Every loader returns the same typed value the control API serializes, so
//! "what does the engine report?" has one answer regardless of caller. The
//! SQL predicates, column lists and ordering live here and nowhere else.
//!
//! Serialization contract: the `Serialize` derives reproduce the control
//! API's existing camelCase JSON exactly, including RFC 3339 timestamp
//! formatting, so unifying the callers did not change the admin API payloads.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer};
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::{AutonomyMode, SalesError};

/// Serialize a timestamp exactly as the control API always has (RFC 3339).
fn serialize_rfc3339<S: Serializer>(
    value: &DateTime<Utc>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&value.to_rfc3339())
}

/// [`serialize_rfc3339`] for optional timestamps.
fn serialize_rfc3339_opt<S: Serializer>(
    value: &Option<DateTime<Utc>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => serializer.serialize_str(&value.to_rfc3339()),
        None => serializer.serialize_none(),
    }
}

fn db_error(error: sqlx::Error) -> SalesError {
    SalesError::Database(error.to_string())
}

/// The canonical, operator-facing description of an autonomy mode. Shared so
/// the admin API and the SSR page cannot describe the same mode differently.
pub(crate) fn mode_description(mode: AutonomyMode) -> &'static str {
    match mode {
        AutonomyMode::Disabled => "The engine does nothing: no thinking, no generation, no sending.",
        AutonomyMode::Shadow => {
            "The engine runs the whole brain and records what it would have done, but sends nothing."
        }
        AutonomyMode::Assisted => "The engine plans and drafts; an operator sends.",
        AutonomyMode::ApprovalRequired => "The engine executes only decisions an operator approved.",
        AutonomyMode::AutonomousGuarded => {
            "The engine executes automatically when every policy and confidence constraint passes."
        }
    }
}

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------

/// `overview.autonomy` — the engine's steering state.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutonomySnapshot {
    pub mode: String,
    pub mode_description: String,
    pub kill_switch: bool,
    pub runs_brain: bool,
    pub may_execute: bool,
    pub last_action: Option<String>,
    #[serde(serialize_with = "serialize_rfc3339_opt")]
    pub last_action_at: Option<DateTime<Utc>>,
}

/// `overview.actions` — durable action-queue stats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionStatsSnapshot {
    pub total: i64,
    pub due_now: i64,
    pub dead_lettered: i64,
    /// `byState` as a JSON object; `BTreeMap` keeps the SQL's `ORDER BY state`
    /// ordering through serialization.
    pub by_state: BTreeMap<String, i64>,
}

/// `overview.enrollments[]` — one state count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnrollmentCountSnapshot {
    pub state: String,
    pub count: i64,
}

/// `overview.decisions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionCountsSnapshot {
    pub last24h: i64,
    pub blocked_last24h: i64,
}

/// `outcomes30d.revenueEur[]`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RevenueSnapshot {
    pub outcome: String,
    pub eur: f64,
}

/// `overview.outcomes30d`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeStatsSnapshot {
    pub meetings_booked: i64,
    pub revenue_eur: Vec<RevenueSnapshot>,
}

/// The complete `GET /control/overview` snapshot.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct OverviewSnapshot {
    pub autonomy: AutonomySnapshot,
    pub actions: ActionStatsSnapshot,
    pub enrollments: Vec<EnrollmentCountSnapshot>,
    pub decisions: DecisionCountsSnapshot,
    #[serde(rename = "outcomes30d")]
    pub outcomes30d: OutcomeStatsSnapshot,
}

/// Load the overview snapshot for one tenant.
pub async fn load_overview(db: &PgPool, tenant: &str) -> Result<OverviewSnapshot, SalesError> {
    let autonomy = crate::autonomy::load(db, tenant).await?;
    let actions = load_action_stats(db, tenant).await?;

    let enrollments_by_state: Vec<(String, i64)> = sqlx::query_as(
        "SELECT state, COUNT(*)::bigint FROM sales_enrollments \
         WHERE tenant_id = $1 GROUP BY state ORDER BY state",
    )
    .bind(tenant)
    .fetch_all(db)
    .await
    .map_err(db_error)?;

    let decisions_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM sales_decisions \
         WHERE tenant_id = $1 AND created_at >= NOW() - INTERVAL '24 hours'",
    )
    .bind(tenant)
    .fetch_one(db)
    .await
    .map_err(db_error)?;

    let blocked_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM sales_decisions \
         WHERE tenant_id = $1 AND blocked AND created_at >= NOW() - INTERVAL '24 hours'",
    )
    .bind(tenant)
    .fetch_one(db)
    .await
    .map_err(db_error)?;

    // Revenue is the objective. Activities (sends) are context, not the goal.
    // Ordered by outcome so every caller (and the SSR page) sees one stable
    // order for the same database state.
    let revenue: Vec<(String, f64)> = sqlx::query_as(
        "SELECT outcome, COALESCE(SUM(value_eur), 0)::float8 FROM sales_outcomes \
         WHERE tenant_id = $1 AND occurred_at >= NOW() - INTERVAL '30 days' \
           AND outcome IN ('paid_subscription', 'retained_mrr', 'trial') \
         GROUP BY outcome ORDER BY outcome",
    )
    .bind(tenant)
    .fetch_all(db)
    .await
    .map_err(db_error)?;

    let meetings_booked: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM sales_meetings \
         WHERE tenant_id = $1 AND created_at >= NOW() - INTERVAL '30 days'",
    )
    .bind(tenant)
    .fetch_one(db)
    .await
    .map_err(db_error)?;

    Ok(OverviewSnapshot {
        autonomy: AutonomySnapshot {
            mode: autonomy.mode.as_str().to_string(),
            mode_description: mode_description(autonomy.mode).to_string(),
            kill_switch: autonomy.kill_switch,
            runs_brain: autonomy.mode.runs_brain(),
            // The control API's "mayExecute" semantics: the engine may perform
            // an external action at all (approved or autonomous), and the kill
            // switch blocks it. The SSR page previously derived this
            // differently (only `autonomous_guarded` was true); unifying the
            // readers makes the admin JSON authoritative.
            may_execute: autonomy.permits_execution(),
            last_action: autonomy.last_action,
            last_action_at: autonomy.last_action_at,
        },
        actions,
        enrollments: enrollments_by_state
            .into_iter()
            .map(|(state, count)| EnrollmentCountSnapshot { state, count })
            .collect(),
        decisions: DecisionCountsSnapshot {
            last24h: decisions_24h,
            blocked_last24h: blocked_24h,
        },
        outcomes30d: OutcomeStatsSnapshot {
            meetings_booked,
            revenue_eur: revenue
                .into_iter()
                .map(|(outcome, eur)| RevenueSnapshot { outcome, eur })
                .collect(),
        },
    })
}

/// The durable action queue's counts for one tenant.
pub async fn load_action_stats(
    db: &PgPool,
    tenant: &str,
) -> Result<ActionStatsSnapshot, SalesError> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT state, COUNT(*)::bigint FROM sales_actions \
         WHERE tenant_id = $1 GROUP BY state ORDER BY state",
    )
    .bind(tenant)
    .fetch_all(db)
    .await
    .map_err(db_error)?;

    let mut by_state = BTreeMap::new();
    let mut total = 0i64;
    for (state, count) in rows {
        total += count;
        by_state.insert(state, count);
    }

    let due_now: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM sales_actions \
         WHERE tenant_id = $1 AND state = 'queued' AND due_at <= NOW()",
    )
    .bind(tenant)
    .fetch_one(db)
    .await
    .map_err(db_error)?;

    let dead_lettered: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM sales_actions \
         WHERE tenant_id = $1 AND state = 'dead_letter'",
    )
    .bind(tenant)
    .fetch_one(db)
    .await
    .map_err(db_error)?;

    Ok(ActionStatsSnapshot {
        total,
        due_now,
        dead_lettered,
        by_state,
    })
}

// ---------------------------------------------------------------------------
// Decisions / exceptions
// ---------------------------------------------------------------------------

/// One `sales_decisions` row, exactly as the control JSON has always carried
/// it. Superset of what the SSR page renders.
#[derive(Debug, Clone, PartialEq, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct DecisionSnapshot {
    pub id: Uuid,
    pub account_id: Option<Uuid>,
    pub contact_id: Option<Uuid>,
    pub action: String,
    pub expected_value_eur: f64,
    pub confidence: f64,
    pub score_total: f64,
    pub selected_offer: Option<String>,
    pub selected_sequence: Option<String>,
    pub selected_variant: Option<String>,
    pub selected_sender: Option<String>,
    pub evidence_ids: Vec<String>,
    pub policy_id: Option<String>,
    pub model_version: Option<String>,
    pub autonomy_mode: String,
    pub rationale: String,
    pub blocked: bool,
    pub block_reasons: serde_json::Value,
    #[serde(serialize_with = "serialize_rfc3339_opt")]
    pub execute_after: Option<DateTime<Utc>>,
    #[serde(serialize_with = "serialize_rfc3339")]
    pub created_at: DateTime<Utc>,
}

const DECISION_COLUMNS: &str = "id, account_id, contact_id, action, expected_value_eur::float8, \
     confidence::float8, score_total::float8, selected_offer, selected_sequence, \
     selected_variant, selected_sender, evidence_ids::text[] AS evidence_ids, \
     policy_id, model_version, autonomy_mode, rationale, blocked, block_reasons, \
     execute_after, created_at";

/// `GET /control/decisions` — what did it decide, and why?
pub async fn load_decisions(
    db: &PgPool,
    tenant: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<DecisionSnapshot>, SalesError> {
    let sql = format!(
        "SELECT {DECISION_COLUMNS} FROM sales_decisions \
         WHERE tenant_id = $1 \
         ORDER BY created_at DESC LIMIT $2 OFFSET $3"
    );
    sqlx::query_as(&sql)
        .bind(tenant)
        .bind(limit.clamp(1, 200))
        .bind(offset.max(0))
        .fetch_all(db)
        .await
        .map_err(db_error)
}

/// `GET /control/exceptions` — decisions a human must act on.
///
/// Two kinds qualify: decisions a hard gate refused
/// (`enforcement = 'denied'`) and decisions waiting for an operator
/// (`enforcement = 'await_approval'`, or any decision whose review is still
/// `pending`). The predicate is the decision's OWN recorded state — autonomy
/// mode is context, not authority, and an `execute` decision recorded under an
/// old mode must not surface as an exception forever.
pub async fn load_exceptions(
    db: &PgPool,
    tenant: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<DecisionSnapshot>, SalesError> {
    let sql = format!(
        "SELECT {DECISION_COLUMNS} FROM sales_decisions \
         WHERE tenant_id = $1 \
           AND (enforcement IN ('denied', 'await_approval') OR review_status = 'pending') \
         ORDER BY created_at DESC LIMIT $2 OFFSET $3"
    );
    sqlx::query_as(&sql)
        .bind(tenant)
        .bind(limit.clamp(1, 200))
        .bind(offset.max(0))
        .fetch_all(db)
        .await
        .map_err(db_error)
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

/// One `sales_actions` row as the control surface reports it.
#[derive(Debug, Clone, PartialEq, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct ActionSnapshot {
    pub id: Uuid,
    pub action_type: String,
    pub entity_type: String,
    pub entity_id: Uuid,
    pub state: String,
    pub attempt: i32,
    pub max_attempts: i32,
    pub last_error: Option<String>,
    #[serde(serialize_with = "serialize_rfc3339")]
    pub due_at: DateTime<Utc>,
    #[serde(serialize_with = "serialize_rfc3339_opt")]
    pub lease_expires_at: Option<DateTime<Utc>>,
    #[serde(serialize_with = "serialize_rfc3339")]
    pub created_at: DateTime<Utc>,
}

const ACTION_COLUMNS: &str = "id, action_type, entity_type, entity_id, state, attempt, \
     max_attempts, last_error, due_at, lease_expires_at, created_at";

/// The non-succeeded slice of the durable queue for one tenant.
pub async fn load_actions(
    db: &PgPool,
    tenant: &str,
    limit: i64,
) -> Result<Vec<ActionSnapshot>, SalesError> {
    let sql = format!(
        "SELECT {ACTION_COLUMNS} FROM sales_actions \
         WHERE tenant_id = $1 AND state <> 'succeeded' \
         ORDER BY due_at ASC LIMIT $2"
    );
    sqlx::query_as(&sql)
        .bind(tenant)
        .bind(limit.clamp(1, 200))
        .fetch_all(db)
        .await
        .map_err(db_error)
}

/// Dead-lettered work: the class of thing a human must see.
pub async fn load_dead_letters(
    db: &PgPool,
    tenant: &str,
    limit: i64,
) -> Result<Vec<ActionSnapshot>, SalesError> {
    let sql = format!(
        "SELECT {ACTION_COLUMNS} FROM sales_actions \
         WHERE tenant_id = $1 AND state = 'dead_letter' \
         ORDER BY created_at DESC LIMIT $2"
    );
    sqlx::query_as(&sql)
        .bind(tenant)
        .bind(limit.clamp(1, 200))
        .fetch_all(db)
        .await
        .map_err(db_error)
}

// ---------------------------------------------------------------------------
// The SSR page snapshot
// ---------------------------------------------------------------------------

/// Rows the SSR console renders per section (matches the page's historical
/// `LIMIT 25`).
pub const CONSOLE_ROW_LIMIT: i64 = 25;

/// Everything the CP sales page needs, loaded through the same loaders the
/// `/control/*` API serves.
///
/// Each section is independently `None`-able so a single failing table
/// degrades to the page's explicit "unavailable" state instead of a
/// zero-filled dashboard that would read as real activity (`Some(vec![])` is
/// an honest empty answer, `None` is "the read failed").
#[derive(Debug, Clone, PartialEq)]
pub struct SalesControlSnapshot {
    pub overview: Option<OverviewSnapshot>,
    pub decisions: Option<Vec<DecisionSnapshot>>,
    pub exceptions: Option<Vec<DecisionSnapshot>>,
    pub dead_letters: Option<Vec<ActionSnapshot>>,
}

/// Load [`SalesControlSnapshot`] for the SSR console.
pub async fn load_sales_control_snapshot(db: &PgPool, tenant: &str) -> SalesControlSnapshot {
    SalesControlSnapshot {
        overview: load_overview(db, tenant).await.ok(),
        decisions: load_decisions(db, tenant, CONSOLE_ROW_LIMIT, 0).await.ok(),
        exceptions: load_exceptions(db, tenant, CONSOLE_ROW_LIMIT, 0).await.ok(),
        dead_letters: load_dead_letters(db, tenant, CONSOLE_ROW_LIMIT).await.ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_description_is_specific_for_every_mode() {
        for mode in AutonomyMode::all() {
            let text = mode_description(mode);
            assert!(!text.is_empty(), "mode {mode} needs a description");
        }
        // Shadow must be described in a way that makes clear the brain runs.
        assert!(mode_description(AutonomyMode::Shadow).contains("whole brain"));
    }

    /// The control API's JSON is these structs; pin the key names so a
    /// rename cannot silently change the admin contract.
    #[test]
    fn overview_snapshot_serializes_with_the_control_api_key_names() {
        let snapshot = OverviewSnapshot {
            autonomy: AutonomySnapshot {
                mode: "shadow".into(),
                mode_description: mode_description(AutonomyMode::Shadow).into(),
                kill_switch: true,
                runs_brain: true,
                may_execute: false,
                last_action: Some("pause".into()),
                last_action_at: Some(
                    DateTime::parse_from_rfc3339("2026-01-02T03:04:05+00:00")
                        .unwrap()
                        .with_timezone(&Utc),
                ),
            },
            actions: ActionStatsSnapshot {
                total: 3,
                due_now: 1,
                dead_lettered: 0,
                by_state: BTreeMap::from([("queued".to_string(), 3)]),
            },
            enrollments: vec![EnrollmentCountSnapshot {
                state: "active".into(),
                count: 2,
            }],
            decisions: DecisionCountsSnapshot {
                last24h: 7,
                blocked_last24h: 1,
            },
            outcomes30d: OutcomeStatsSnapshot {
                meetings_booked: 4,
                revenue_eur: vec![RevenueSnapshot {
                    outcome: "trial".into(),
                    eur: 12.5,
                }],
            },
        };
        let value = serde_json::to_value(&snapshot).expect("snapshot serializes");
        assert_eq!(value["autonomy"]["killSwitch"], true);
        assert_eq!(value["autonomy"]["runsBrain"], true);
        assert_eq!(value["autonomy"]["lastAction"], "pause");
        assert_eq!(
            value["autonomy"]["lastActionAt"],
            "2026-01-02T03:04:05+00:00"
        );
        assert_eq!(value["actions"]["dueNow"], 1);
        assert_eq!(value["actions"]["deadLettered"], 0);
        assert_eq!(value["actions"]["byState"]["queued"], 3);
        assert_eq!(value["decisions"]["last24h"], 7);
        assert_eq!(value["decisions"]["blockedLast24h"], 1);
        assert_eq!(value["outcomes30d"]["meetingsBooked"], 4);
        assert_eq!(value["outcomes30d"]["revenueEur"][0]["outcome"], "trial");
    }

    /// A decision row must serialize to the exact keys the admin API has
    /// always returned.
    #[test]
    fn decision_snapshot_serializes_with_the_control_api_key_names() {
        let snapshot = DecisionSnapshot {
            id: Uuid::nil(),
            account_id: None,
            contact_id: None,
            action: "enrich".into(),
            expected_value_eur: 1.0,
            confidence: 0.5,
            score_total: 2.0,
            selected_offer: None,
            selected_sequence: None,
            selected_variant: None,
            selected_sender: None,
            evidence_ids: vec!["e1".into()],
            policy_id: None,
            model_version: None,
            autonomy_mode: "shadow".into(),
            rationale: "because".into(),
            blocked: false,
            block_reasons: serde_json::json!(["none"]),
            execute_after: None,
            created_at: DateTime::parse_from_rfc3339("2026-01-02T03:04:05+00:00")
                .unwrap()
                .with_timezone(&Utc),
        };
        let value = serde_json::to_value(&snapshot).expect("snapshot serializes");
        assert_eq!(value["accountId"], serde_json::Value::Null);
        assert_eq!(value["expectedValueEur"], 1.0);
        assert_eq!(value["scoreTotal"], 2.0);
        assert_eq!(value["evidenceIds"][0], "e1");
        assert_eq!(value["autonomyMode"], "shadow");
        assert_eq!(value["blockReasons"][0], "none");
        assert_eq!(value["executeAfter"], serde_json::Value::Null);
        assert_eq!(value["createdAt"], "2026-01-02T03:04:05+00:00");
    }
}
