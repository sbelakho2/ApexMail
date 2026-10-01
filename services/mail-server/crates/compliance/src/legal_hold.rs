//! The single legal-hold authority for every deletion path (audit F4).
//!
//! `tenants.legal_hold` (migration 121) freezes a tenant's records as
//! evidence. Before this module, three jobs enforced the flag three
//! different ways — the retention sweep filtered `gdpr_exports` /
//! `dsr_verification_outbox` purges, `AuditLogger::archive` carried its own
//! inline exclusion, and `GdprAutomation::enforce_retention` plus the DSR
//! erasure path ignored the flag entirely (a held tenant's SAR exports and
//! consent history could be destroyed by the GDPR cron). Every deletion
//! path now resolves holds through [`active_holds`] / [`tenant_is_held`].
//!
//! Semantics (identical to the established `archive()` behavior):
//! * `Ok(Some(ids))` — holds were consulted; `ids` are the held tenants
//!   (possibly empty).
//! * `Ok(None)` — the deployment has no `tenants` table / `legal_hold`
//!   column (pre-migration-121 schemas): no exclusion is possible and
//!   callers keep their historical behavior.
//! * `Err(_)` — the lookup itself failed; callers must fail closed (never
//!   delete on an unknown hold state).

use sqlx::PgPool;

/// Held tenant ids from `tenants.legal_hold`. See the module docs for the
/// `Ok(None)` / `Err` contract.
pub async fn active_holds(db: &PgPool) -> Result<Option<Vec<String>>, String> {
    match sqlx::query_scalar::<_, String>("SELECT id FROM tenants WHERE legal_hold = true")
        .fetch_all(db)
        .await
    {
        Ok(ids) => Ok(Some(ids)),
        Err(e) if is_undefined_table(&e) => Ok(None),
        Err(e) if is_undefined_column(&e) => Ok(None),
        Err(e) => Err(format!("DB error (legal hold lookup): {e}")),
    }
}

/// Whether ONE tenant is under an active legal hold. The row-level form of
/// [`active_holds`] for per-tenant paths (DSR erasure). `Ok(None)` (no
/// tenants table) means "not held" — the deployment cannot express holds at
/// all; a genuine lookup error is propagated so the caller can fail closed.
pub async fn tenant_is_held(db: &PgPool, tenant_id: &str) -> Result<Option<bool>, String> {
    match sqlx::query_scalar::<_, bool>(
        "SELECT COALESCE(legal_hold, false) FROM tenants WHERE id = $1",
    )
    .bind(tenant_id)
    .fetch_optional(db)
    .await
    {
        Ok(held) => Ok(held),
        Err(e) if is_undefined_table(&e) => Ok(None),
        Err(e) if is_undefined_column(&e) => Ok(None),
        Err(e) => Err(format!("DB error (legal hold lookup): {e}")),
    }
}

/// The SQL fragment that excludes held tenants from a DELETE on
/// `tenant_column`. NULL-tenant rows are excluded too while any hold is
/// active — they cannot be attributed, so they might belong to a held
/// tenant (fall back to keep). Empty string when no hold is active.
///
/// The fragment references `$(N)` as the NEXT bind parameter; callers bind
/// the held ids at that position (see [`bind_held`]).
pub fn exclusion_sql(held: &Option<Vec<String>>, tenant_column: &str) -> String {
    let any_held = held.as_ref().is_some_and(|ids| !ids.is_empty());
    if !any_held {
        return String::new();
    }
    format!(" AND ({tenant_column} IS NOT NULL AND {tenant_column} <> ALL($2))")
}

/// Whether the caller must bind the held-ids array after its base binds.
pub fn binds_held(held: &Option<Vec<String>>) -> bool {
    held.as_ref().is_some_and(|ids| !ids.is_empty())
}

fn is_undefined_table(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("42P01"))
}

fn is_undefined_column(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("42703"))
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclusion_sql_is_empty_without_active_holds() {
        assert_eq!(exclusion_sql(&None, "tenant_id"), "");
        assert_eq!(exclusion_sql(&Some(vec![]), "tenant_id"), "");
    }

    #[test]
    fn exclusion_sql_keeps_unattributable_rows_and_excludes_held() {
        let held = Some(vec!["t-held".to_string()]);
        let sql = exclusion_sql(&held, "tenant_id");
        assert!(sql.contains("tenant_id IS NOT NULL"), "{sql}");
        assert!(sql.contains("tenant_id <> ALL($2)"), "{sql}");
        assert!(binds_held(&held));
    }

    #[test]
    fn binds_held_tracks_the_held_list() {
        assert!(!binds_held(&None));
        assert!(!binds_held(&Some(vec![])));
        assert!(binds_held(&Some(vec!["t1".to_string()])));
    }

    /// DB-backed: an explicit `legal_hold = true` tenant is reported by both
    /// lookups; an unknown tenant is not held. Requires the canonical test
    /// database (soft-skips without it).
    #[tokio::test]
    async fn hold_lookups_report_an_explicit_hold() {
        let Some(pool) = crate::test_support::canonical_pool("legal_hold", "legal_hold").await
        else {
            eprintln!("skipping: set TEST_DATABASE_URL");
            return;
        };
        let tenant = format!("t-hold-{}", std::process::id());
        sqlx::query("INSERT INTO tenants (id, name, legal_hold) VALUES ($1, 'Hold Probe', true)")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("insert held tenant");

        let held = active_holds(&pool).await.expect("active_holds");
        assert!(
            held.expect("tenants table exists")
                .iter()
                .any(|id| id == &tenant),
            "the explicitly held tenant must be reported"
        );
        assert_eq!(
            tenant_is_held(&pool, &tenant)
                .await
                .expect("tenant_is_held"),
            Some(true)
        );
        // An UNKNOWN tenant id has no row: `Ok(None)` — callers treat the
        // unresolvable case as not-held (an erasure for a nonexistent
        // tenant proceeds harmlessly), never as held.
        assert_eq!(
            tenant_is_held(&pool, "no-such-tenant")
                .await
                .expect("lookup"),
            None
        );

        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("cleanup");
    }
}
