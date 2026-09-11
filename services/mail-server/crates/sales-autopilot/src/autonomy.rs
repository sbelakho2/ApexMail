//! Autonomy control state.
//!
//! `sales_autonomy_state` replaces the old `safe_mode: bool`. A boolean could
//! not express the state that matters most — "run the whole brain and generate
//! the copy, but do not send" — so the most valuable validation dataset was
//! thrown away every time an operator reached for safe mode.
//!
//! The mode is read on every decision (never cached across requests) so an
//! operator engaging the kill switch stops new outbound work immediately.
//! Inbound reply processing is deliberately unaffected: a kill switch that
//! also dropped replies would corrupt the very data needed to recover.

use sqlx::PgPool;

use crate::types::{AutonomyMode, AutonomyState, SalesError};

/// Load the autonomy state for a tenant.
///
/// A tenant with no row gets [`AutonomyState::default`] — `Disabled`, the
/// fail-closed value. It is never persisted by a read, so simply asking the
/// question cannot grant authority.
pub async fn load(db: &PgPool, tenant_id: &str) -> Result<AutonomyState, SalesError> {
    let row: Option<StateRow> = sqlx::query_as(
        "SELECT mode, kill_switch, rules, last_action, last_action_at \
         FROM sales_autonomy_state WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_optional(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    Ok(match row {
        Some(row) => AutonomyState {
            tenant_id: tenant_id.to_string(),
            // Unknown persisted values fail closed to Disabled (see parse).
            mode: AutonomyMode::parse(&row.mode),
            kill_switch: row.kill_switch,
            rules: row.rules,
            last_action: row.last_action,
            last_action_at: row.last_action_at,
        },
        None => AutonomyState {
            tenant_id: tenant_id.to_string(),
            ..AutonomyState::default()
        },
    })
}

/// Persist a mode change.
pub async fn set_mode(
    db: &PgPool,
    tenant_id: &str,
    mode: AutonomyMode,
    action: &str,
) -> Result<AutonomyState, SalesError> {
    upsert(db, tenant_id, Some(mode), None, None, action).await
}

/// Engage or release the global kill switch.
pub async fn set_kill_switch(
    db: &PgPool,
    tenant_id: &str,
    engaged: bool,
    action: &str,
) -> Result<AutonomyState, SalesError> {
    upsert(db, tenant_id, None, Some(engaged), None, action).await
}

/// Replace the operator policy rules (exploration budgets, per-channel limits).
pub async fn set_rules(
    db: &PgPool,
    tenant_id: &str,
    rules: serde_json::Value,
    action: &str,
) -> Result<AutonomyState, SalesError> {
    upsert(db, tenant_id, None, None, Some(rules), action).await
}

/// Single upsert path so every mutation records the same bookkeeping.
async fn upsert(
    db: &PgPool,
    tenant_id: &str,
    mode: Option<AutonomyMode>,
    kill_switch: Option<bool>,
    rules: Option<serde_json::Value>,
    action: &str,
) -> Result<AutonomyState, SalesError> {
    let row: StateRow = sqlx::query_as(
        "INSERT INTO sales_autonomy_state \
             (tenant_id, mode, kill_switch, rules, last_action, last_action_at, updated_at) \
         VALUES ($1, COALESCE($2, 'disabled'), COALESCE($3, FALSE), COALESCE($4, '{}'::jsonb), \
                 $5, NOW(), NOW()) \
         ON CONFLICT (tenant_id) DO UPDATE SET \
             mode = COALESCE($2, sales_autonomy_state.mode), \
             kill_switch = COALESCE($3, sales_autonomy_state.kill_switch), \
             rules = COALESCE($4, sales_autonomy_state.rules), \
             last_action = $5, \
             last_action_at = NOW(), \
             updated_at = NOW() \
         RETURNING mode, kill_switch, rules, last_action, last_action_at",
    )
    .bind(tenant_id)
    .bind(mode.map(|m| m.as_str()))
    .bind(kill_switch)
    .bind(rules)
    .bind(action)
    .fetch_one(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    Ok(AutonomyState {
        tenant_id: tenant_id.to_string(),
        mode: AutonomyMode::parse(&row.mode),
        kill_switch: row.kill_switch,
        rules: row.rules,
        last_action: row.last_action,
        last_action_at: row.last_action_at,
    })
}

#[derive(sqlx::FromRow)]
struct StateRow {
    mode: String,
    kill_switch: bool,
    rules: serde_json::Value,
    last_action: Option<String>,
    last_action_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(mode: AutonomyMode, kill_switch: bool) -> AutonomyState {
        AutonomyState {
            tenant_id: "t".into(),
            mode,
            kill_switch,
            rules: serde_json::json!({}),
            last_action: None,
            last_action_at: None,
        }
    }

    #[test]
    fn missing_row_fails_closed_to_disabled() {
        let default = AutonomyState::default();
        assert_eq!(default.mode, AutonomyMode::Disabled);
        assert!(!default.permits_execution());
    }

    #[test]
    fn unknown_persisted_mode_fails_closed() {
        // A hand-edited row, or a mode written by a newer build, must never be
        // interpreted as more authority than the default.
        assert_eq!(
            AutonomyMode::parse("autonomous_full"),
            AutonomyMode::Disabled
        );
        assert_eq!(AutonomyMode::parse(""), AutonomyMode::Disabled);
        assert_eq!(AutonomyMode::parse("SHADOW"), AutonomyMode::Shadow);
    }

    #[test]
    fn kill_switch_blocks_execution_in_every_mode() {
        for mode in AutonomyMode::all() {
            assert!(
                !state(mode, true).permits_execution(),
                "kill switch must block execution in mode {mode}"
            );
        }
    }

    #[test]
    fn shadow_runs_the_brain_but_permits_no_execution() {
        let shadow = state(AutonomyMode::Shadow, false);
        assert!(shadow.mode.runs_brain(), "shadow must still run the brain");
        assert!(!shadow.permits_execution(), "shadow must not execute");
    }

    #[test]
    fn only_autonomous_guarded_executes_without_a_human() {
        for mode in AutonomyMode::all() {
            assert_eq!(
                mode.may_execute_autonomously(),
                mode == AutonomyMode::AutonomousGuarded,
                "only AutonomousGuarded may execute autonomously (mode {mode})"
            );
        }
    }

    #[test]
    fn disabled_mode_neither_thinks_nor_executes() {
        let disabled = state(AutonomyMode::Disabled, false);
        assert!(!disabled.mode.runs_brain());
        assert!(!disabled.permits_execution());
    }
}
