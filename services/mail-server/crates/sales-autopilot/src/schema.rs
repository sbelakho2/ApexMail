//! Startup schema verification.
//!
//! Schema ownership is deterministic: every sales table is created by the
//! canonical migration chain (`services/mail-server/migrations`, applied by
//! the deploy-gate `migrator` binary). This module's job is to *verify* that
//! the database this process connected to is the schema this build expects,
//! and to refuse startup when it is not.
//!
//! It deliberately does not create or alter anything — no `CREATE TABLE IF
//! NOT EXISTS`, no `ALTER TABLE`. Runtime DDL previously made the effective
//! schema depend on service start order, which meant a deployment could serve
//! traffic against a schema no migration ever described.

use sqlx::PgPool;

use crate::types::SalesError;

/// Tables this service reads or writes. Missing any of them means the
/// canonical migration chain has not been applied.
pub const REQUIRED_TABLES: &[&str] = &[
    // Lead bridge (still read by the CP list and the reply handler).
    "sales_leads",
    "sales_unsubscribes",
    "sales_settings",
    // Tables that previously existed only through runtime DDL. They are
    // required here so this guard fails loudly if the bootstrap removal ever
    // outruns the migration again — that gap shipped once and broke
    // enrichment, calendar, inbox and conversion storage on a fresh database.
    "enriched_companies",
    "sales_calendar_events",
    "sales_inbox_messages",
    "sales_conversions",
    // Canonical account/contact model.
    "sales_accounts",
    "sales_contacts",
    "sales_contact_points",
    "sales_evidence",
    "sales_enrichment_facts",
    "sales_provider_stats",
    "sales_signals",
    "sales_scores",
    // Sequences and enrollments.
    "sales_sequences",
    "sales_sequence_versions",
    "sales_sequence_steps",
    "sales_enrollments",
    "sales_step_executions",
    // Work queue and decisions.
    "sales_actions",
    "sales_decisions",
    // Campaign execution (the canonical pair — NOT drip_campaigns).
    "sales_campaigns",
    "sales_campaign_recipients",
    // Sender reputation isolation.
    "sales_sender_identities",
    "sales_sender_health",
    // Replies, meetings, revenue.
    "sales_reply_classifications",
    "sales_meetings",
    "sales_opportunities",
    "sales_outcomes",
    "sales_experiments",
    "sales_experiment_arms",
    // Discovery.
    "sales_discovery_jobs",
    "sales_discovery_candidates",
    "sales_source_runs",
    // Legal gate.
    "sales_jurisdiction_policies",
    "sales_contact_policy_decisions",
    // Autonomy control.
    "sales_autonomy_state",
];

/// Columns the code depends on that were added by `ALTER TABLE` in later
/// migrations. Checked separately from [`REQUIRED_TABLES`] so a table that
/// exists in a pre-unification shape is reported precisely rather than
/// producing a runtime 42703 on the first send.
pub const REQUIRED_COLUMNS: &[(&str, &str)] = &[
    ("sales_campaigns", "last_error"),
    ("sales_campaign_recipients", "sent_at"),
    ("sales_campaign_recipients", "message_id"),
    ("sales_leads", "account_id"),
    ("sales_leads", "contact_id"),
    ("sales_leads", "snoozed_until"),
    ("sales_leads", "last_reply_at"),
    ("sales_settings", "scoring_weights"),
    ("sales_settings", "schedule"),
    ("sales_settings", "notifications"),
];

/// Tables that must NOT exist any more.
///
/// These were the control plane's second sales system. If one of them is
/// still present the deployment is running a half-applied migration, which
/// would let a stale code path write rows nothing consumes.
pub const RETIRED_TABLES: &[&str] = &[
    "drip_campaigns",
    "campaign_recipients",
    "sales_autopilot_state",
];

/// Verify the connected database matches this build's expectations.
///
/// Returns `Ok(())` only when every required relation exists and every retired
/// relation is gone. The message lists exactly what is wrong so an operator
/// can act without reading the source.
pub async fn verify(pool: &PgPool) -> Result<(), SalesError> {
    let mut problems: Vec<String> = Vec::new();

    // Missing required tables.
    let present: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname \
         FROM pg_catalog.pg_class c \
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') \
           AND c.relname = ANY($1)",
    )
    .bind(REQUIRED_TABLES)
    .fetch_all(pool)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    for required in REQUIRED_TABLES {
        if !present.iter().any(|name| name == required) {
            problems.push(format!("missing table `{required}`"));
        }
    }

    // Missing required columns (only checkable for tables that exist).
    for (table, column) in REQUIRED_COLUMNS {
        if !present.iter().any(|name| name == table) {
            continue;
        }
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS ( \
                 SELECT 1 FROM information_schema.columns \
                 WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2 \
             )",
        )
        .bind(table)
        .bind(column)
        .fetch_one(pool)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
        if !exists {
            problems.push(format!("missing column `{table}.{column}`"));
        }
    }

    // Retired tables still present.
    let still_there: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname \
         FROM pg_catalog.pg_class c \
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') \
           AND c.relname = ANY($1)",
    )
    .bind(RETIRED_TABLES)
    .fetch_all(pool)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    for retired in &still_there {
        problems.push(format!(
            "retired table `{retired}` still present — the sales unification migration \
             (200_sales_autopilot_v2_unification) is not fully applied"
        ));
    }

    if problems.is_empty() {
        return Ok(());
    }

    Err(SalesError::SchemaIncompatible(format!(
        "{} problem(s): {}. Apply the canonical migrations \
         (`cargo run -p migrator` with DATABASE_URL set) before starting this service.",
        problems.len(),
        problems.join("; ")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retired_tables_are_never_also_required() {
        for retired in RETIRED_TABLES {
            assert!(
                !REQUIRED_TABLES.contains(retired),
                "`{retired}` is both required and retired"
            );
        }
    }

    #[test]
    fn required_columns_reference_required_tables() {
        for (table, _) in REQUIRED_COLUMNS {
            assert!(
                REQUIRED_TABLES.contains(table),
                "`{table}` has required columns but is not a required table"
            );
        }
    }

    #[test]
    fn schema_error_is_a_service_unavailable_not_a_silent_success() {
        let err = SalesError::SchemaIncompatible("missing table `sales_actions`".into());
        assert!(err.to_string().contains("missing table"));
    }
}
