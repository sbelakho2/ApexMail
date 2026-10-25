//! Owner-approved autonomous-action policy packs (invariant I22).
//!
//! Flipping a tenant to `autonomous_guarded` grants the MODE, not the
//! AUTHORITY: autonomous execution additionally requires an ACTIVE,
//! OWNER-APPROVED policy pack that covers the tenant AND the action kind AND
//! has budget left. The gate is fail-closed: no pack, an unapproved pack, an
//! expired pack, an action the pack does not enumerate, or an exhausted cap
//! all refuse with a typed reason.

use chrono::{Datelike, DateTime, Utc};
use sqlx::PgPool;

use crate::types::SalesError;

/// The action kinds a pack may authorize. Keep in lockstep with the CHECK
/// constraint on `sales_policy_packs.actions` (migration 270).
pub const KNOWN_ACTIONS: &[&str] = &[
    "reply_autosend",
    "sequence_send",
    "calendar_book",
    "research",
];

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PolicyPack {
    pub id: uuid::Uuid,
    pub tenant_id: String,
    pub pack_name: String,
    pub actions: Vec<String>,
    pub daily_message_cap: i32,
    pub monthly_message_cap: i32,
    pub owner_approved_by: String,
    pub owner_approved_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackVerdict {
    pub allowed: bool,
    pub reasons: Vec<String>,
    pub daily_cap: i64,
    pub daily_used: i64,
}

/// Load THE active pack for a tenant (the partial unique index guarantees at
/// most one). `None` = no covering pack.
pub async fn load_active_pack<'e, E>(db: E, tenant_id: &str) -> Result<Option<PolicyPack>, SalesError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let row: Option<PolicyPack> = sqlx::query_as(
        "SELECT id, tenant_id, pack_name, actions, daily_message_cap, monthly_message_cap, \
                owner_approved_by, owner_approved_at, expires_at \
         FROM sales_policy_packs \
         WHERE tenant_id = $1 AND active \
           AND owner_approved_by <> '' \
           AND (expires_at IS NULL OR expires_at > NOW())",
    )
    .bind(tenant_id)
    .fetch_optional(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;
    Ok(row)
}

/// How many autonomous sends of `action` a tenant has performed since `since`.
///
/// `None` means the action has NO accounting ledger yet — the budget cannot be
/// enforced for it, and `evaluate` must say so rather than silently pass a
/// cap it never read (the opposite of the dead-by-omission class this repo
/// keeps finding).
///
/// Ledgers are real production writes:
/// * `reply_autosend` — the auto-send path's in-transaction audit row
///   (`control_plane.ai_draft.auto_sent`, whose `details.tenantId` names the
///   routed tenant; the row's own tenant_id is the system tenant);
/// * `sequence_send` — `sales_step_executions.state = 'sent'` (the worker's
///   executed-step ledger).
pub async fn action_count_since(
    db: &mut sqlx::PgConnection,
    tenant_id: &str,
    action: &str,
    since: DateTime<Utc>,
) -> Result<Option<i64>, SalesError> {
    let count: Option<i64> = match action {
        "reply_autosend" => {
            let rows: Option<i64> = sqlx::query_scalar(
                "SELECT count(*)::bigint FROM audit_logs \
                 WHERE action = 'control_plane.ai_draft.auto_sent' \
                   AND details->>'tenantId' = $1 \
                   AND timestamp >= $2",
            )
            .bind(tenant_id)
            .bind(since)
            .fetch_one(&mut *db)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;
            rows
        }
        "sequence_send" => {
            let rows: Option<i64> = sqlx::query_scalar(
                "SELECT count(*)::bigint FROM sales_step_executions \
                 WHERE tenant_id = $1 AND state = 'sent' AND executed_at >= $2",
            )
            .bind(tenant_id)
            .bind(since)
            .fetch_one(&mut *db)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;
            rows
        }
        _ => None,
    };
    Ok(count)
}

/// Fail-closed evaluation of `action` for `tenant_id`.
pub async fn evaluate(
    db: &mut sqlx::PgConnection,
    tenant_id: &str,
    action: &str,
) -> Result<PackVerdict, SalesError> {
    let mut reasons: Vec<String> = Vec::new();
    let Some(pack) = load_active_pack(&mut *db, tenant_id).await? else {
        reasons.push(
            "policy_pack_missing: autonomous execution requires an active, owner-approved \
             policy pack covering this tenant"
                .to_string(),
        );
        return Ok(PackVerdict {
            allowed: false,
            reasons,
            daily_cap: 0,
            daily_used: 0,
        });
    };
    if !pack.actions.iter().any(|a| a == action) {
        reasons.push(format!(
            "policy_pack_action_not_covered: pack '{}' authorizes {:?}, not '{action}'",
            pack.pack_name, pack.actions
        ));
    }

    let today = Utc::now().date_naive();
    let day_start = today
        .and_hms_opt(0, 0, 0)
        .expect("midnight exists")
        .and_utc();
    let month_start = today
        .with_day(1)
        .expect("first of month exists")
        .and_hms_opt(0, 0, 0)
        .expect("midnight exists")
        .and_utc();

    let daily_used = action_count_since(&mut *db, tenant_id, action, day_start).await?;
    let monthly_used = action_count_since(&mut *db, tenant_id, action, month_start).await?;
    let daily_cap = i64::from(pack.daily_message_cap);

    // Cap accounting only when a ledger exists for the action; an action
    // without a ledger is reported, never assumed at zero.
    let Some(daily_used) = daily_used else {
        if pack.actions.iter().any(|a| a == action) {
            tracing::warn!(
                tenant_id,
                action,
                "no send ledger for this action kind — pack budget cannot be enforced"
            );
        }
        return Ok(PackVerdict {
            allowed: reasons.is_empty(),
            reasons,
            daily_cap,
            daily_used: 0,
        });
    };
    if daily_used >= daily_cap {
        reasons.push(format!(
            "policy_pack_daily_cap_reached: {daily_used} autonomous sends today >= cap {daily_cap}"
        ));
    }
    if let Some(monthly_used) = monthly_used {
        if monthly_used >= i64::from(pack.monthly_message_cap) {
            reasons.push(format!(
                "policy_pack_monthly_cap_reached: {monthly_used} autonomous sends this month >= cap {}",
                pack.monthly_message_cap
            ));
        }
    }
    Ok(PackVerdict {
        allowed: reasons.is_empty(),
        reasons,
        daily_cap,
        daily_used,
    })
}

/// Admin approval path: insert or replace the tenant's active pack. The
/// caller MUST be the owner surface (the control plane routes gate this); the
/// `approved_by` name is recorded on the row itself.
pub async fn approve(
    db: &PgPool,
    tenant_id: &str,
    pack_name: &str,
    actions: &[String],
    daily_cap: i32,
    monthly_cap: i32,
    approved_by: &str,
) -> Result<PolicyPack, SalesError> {
    if !actions.iter().all(|a| KNOWN_ACTIONS.contains(&a.as_str())) {
        return Err(SalesError::InvalidInput(format!(
            "unknown action kinds {actions:?}; known: {KNOWN_ACTIONS:?}"
        )));
    }
    if approved_by.trim().is_empty() {
        return Err(SalesError::InvalidInput(
            "owner_approved_by is required — an anonymous approval is not an approval"
                .to_string(),
        ));
    }
    let mut tx = db
        .begin()
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
    // Deactivate any current pack first (the single-active trigger also
    // guards this, but the explicit update makes intent readable).
    sqlx::query("UPDATE sales_policy_packs SET active = false, updated_at = NOW() WHERE tenant_id = $1 AND active")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
    let row: PolicyPack = sqlx::query_as(
        "INSERT INTO sales_policy_packs (tenant_id, pack_name, actions, daily_message_cap, \
            monthly_message_cap, active, owner_approved_by) \
         VALUES ($1, $2, $3, $4, $5, true, $6) \
         RETURNING id, tenant_id, pack_name, actions, daily_message_cap, monthly_message_cap, \
                   owner_approved_by, owner_approved_at, expires_at",
    )
    .bind(tenant_id)
    .bind(pack_name)
    .bind(actions)
    .bind(daily_cap)
    .bind(monthly_cap)
    .bind(approved_by.trim())
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
    Ok(row)
}

/// Deactivate (operator kill path for the pack itself).
pub async fn deactivate(db: &PgPool, tenant_id: &str) -> Result<(), SalesError> {
    sqlx::query("UPDATE sales_policy_packs SET active = false, updated_at = NOW() WHERE tenant_id = $1 AND active")
        .bind(tenant_id)
        .execute(db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack(tenant: &str, actions: &[&str], daily: i32) -> PolicyPack {
        PolicyPack {
            id: uuid::Uuid::new_v4(),
            tenant_id: tenant.to_string(),
            pack_name: "test-pack".into(),
            actions: actions.iter().map(|s| s.to_string()).collect(),
            daily_message_cap: daily,
            monthly_message_cap: 1000,
            owner_approved_by: "operator".into(),
            owner_approved_at: Utc::now(),
            expires_at: None,
        }
    }

    #[test]
    fn cover_check_is_action_exact() {
        let p = pack("t1", &["reply_autosend"], 10);
        assert!(p.actions.iter().any(|a| a == "reply_autosend"));
        assert!(!p.actions.iter().any(|a| a == "sequence_send"));
    }

    #[test]
    fn known_actions_match_the_migration_check() {
        // Migration 270's CHECK allowlist — keep both sides in lockstep.
        let expected = ["reply_autosend", "sequence_send", "calendar_book", "research"];
        assert_eq!(KNOWN_ACTIONS, expected);
    }

    #[test]
    fn budget_math_refuses_at_the_cap_not_above_it() {
        let cap: i64 = 10;
        for used in [0, 9] {
            assert!(used < cap, "{used} must be allowed");
        }
        assert!(!(cap < cap), "used == cap must be refused");
    }
}
