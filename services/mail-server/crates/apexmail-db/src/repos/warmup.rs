//! ISP warmup CATALOG repository — advisory data only.
//! It is NOT an admission control.
//!
//! [`WarmupCatalogRepo`] is plain CRUD over `isp_warmup_templates`
//! (migration 042): one row per ISP holding example MX patterns and an
//! example daily-volume ramp. The rows are reference material for operators
//! and for a future provider-aware design; they are deliberately NOT read by
//! any send path in this snapshot, and no method here derives an admission
//! limit or resolves an MX host to a profile.
//!
//! # The live warmup control is per SOURCE IP, not per ISP
//!
//! Warmup admission is enforced by `worker-processors` on the dedicated
//! source IP (the reputation boundary), and only there:
//!
//! * the daily cap is
//!   `mail_common::warmup::WarmupSchedule::limit_for_day`, derived from
//!   `dedicated_ips.warmup_started_at`;
//! * the counter is the Redis key
//!   `apexmail:warmup:ip:{ip_address}:{utc_day}`, reserved atomically before
//!   the transport (`crates/worker-processors/src/email/processor.rs`).
//!
//! # Why an ISP-specific target cannot shape admission today
//!
//! A `min(canonical limit, ISP target)` rule needs the recipient's provider
//! (from MX) at or before admission time. No live path resolves it:
//!
//! * `SmtpTransport` hands the message to the relay MTA, which performs
//!   recipient MX resolution and does NOT report the provider back, so the
//!   receipt's `recipient_provider` is `None`
//!   (`crates/worker-processors/src/email/transport.rs`);
//! * `SesTransport` does not report a recipient provider either (same file);
//! * `DeliveryReceipt.recipient_provider` documents `None` as "NOT KNOWN on
//!   this path — never guessed"
//!   (`crates/worker-processors/src/email/types.rs`);
//! * the worker crate does not depend on this crate, and no MX resolver is
//!   reachable from its send path.
//!
//! Without an authoritative per-recipient provider at admission time the ISP
//! target cannot be computed, so it is not computed: this module intentionally
//! exposes storage only. Re-adding limit derivation or MX→profile resolution
//! here without first fixing provider resolution would recreate the inert
//! second model this decision removed (F87 / audit item 26).

use sqlx::PgPool;

use crate::types::IspWarmupTemplate;

/// Repository for the ADVISORY ISP warmup template catalog
/// (`isp_warmup_templates`). Catalog CRUD only — no admission logic.
pub struct WarmupCatalogRepo;

impl WarmupCatalogRepo {
    /// Create a new advisory ISP warmup template row.
    pub async fn create(
        pool: &PgPool,
        id: &str,
        isp_name: &str,
        mx_patterns: serde_json::Value,
        warmup_schedule: serde_json::Value,
        notes: Option<&str>,
    ) -> Result<IspWarmupTemplate, sqlx::Error> {
        sqlx::query_as::<_, IspWarmupTemplate>(
            "INSERT INTO isp_warmup_templates (id, isp_name, mx_patterns, warmup_schedule, notes, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, NOW(), NOW()) \
             RETURNING id, isp_name, mx_patterns, warmup_schedule, notes, created_at, updated_at",
        )
        .bind(id)
        .bind(isp_name)
        .bind(mx_patterns)
        .bind(warmup_schedule)
        .bind(notes)
        .fetch_one(pool)
        .await
    }

    /// Get an advisory template by ISP name.
    pub async fn get_by_isp(
        pool: &PgPool,
        isp_name: &str,
    ) -> Result<Option<IspWarmupTemplate>, sqlx::Error> {
        sqlx::query_as::<_, IspWarmupTemplate>(
            "SELECT id, isp_name, mx_patterns, warmup_schedule, notes, created_at, updated_at \
             FROM isp_warmup_templates WHERE isp_name = $1",
        )
        .bind(isp_name)
        .fetch_optional(pool)
        .await
    }

    /// Get an advisory template by ID.
    pub async fn get_by_id(
        pool: &PgPool,
        id: &str,
    ) -> Result<Option<IspWarmupTemplate>, sqlx::Error> {
        sqlx::query_as::<_, IspWarmupTemplate>(
            "SELECT id, isp_name, mx_patterns, warmup_schedule, notes, created_at, updated_at \
             FROM isp_warmup_templates WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// List all advisory templates.
    pub async fn list(pool: &PgPool) -> Result<Vec<IspWarmupTemplate>, sqlx::Error> {
        sqlx::query_as::<_, IspWarmupTemplate>(
            "SELECT id, isp_name, mx_patterns, warmup_schedule, notes, created_at, updated_at \
             FROM isp_warmup_templates ORDER BY isp_name",
        )
        .fetch_all(pool)
        .await
    }

    /// Update an advisory template's schedule/notes.
    pub async fn update(
        pool: &PgPool,
        id: &str,
        warmup_schedule: serde_json::Value,
        notes: Option<&str>,
    ) -> Result<Option<IspWarmupTemplate>, sqlx::Error> {
        sqlx::query_as::<_, IspWarmupTemplate>(
            "UPDATE isp_warmup_templates \
             SET warmup_schedule = $2, notes = $3, updated_at = NOW() \
             WHERE id = $1 \
             RETURNING id, isp_name, mx_patterns, warmup_schedule, notes, created_at, updated_at",
        )
        .bind(id)
        .bind(warmup_schedule)
        .bind(notes)
        .fetch_optional(pool)
        .await
    }

    /// Delete an advisory template.
    pub async fn delete(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM isp_warmup_templates WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    /// Collect every `.rs` file under `dir` (recursively).
    fn rust_sources_under(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut sources = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(current) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&current) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                    sources.push(path);
                }
            }
        }
        sources
    }

    #[test]
    fn test_warmup_catalog_repo_is_stateless_crud() {
        let _catalog = WarmupCatalogRepo;
    }

    #[test]
    fn test_warmup_template_mock_is_advisory_data() {
        let template = IspWarmupTemplate {
            id: "isp_gmail".into(),
            isp_name: "Gmail".into(),
            mx_patterns: serde_json::json!(["*.google.com", "*.googlemail.com"]),
            warmup_schedule: serde_json::json!([50, 100, 200, 400, 800]),
            notes: Some("Gmail warmup".into()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(template.isp_name, "Gmail");
    }

    /// The catalog module must SAY it is advisory and inert: a doc lock so a
    /// future edit cannot quietly turn it back into a control without
    /// revisiting the decision. Needles are assembled so this test's own
    /// source cannot satisfy them accidentally.
    #[test]
    fn catalog_documents_that_it_does_not_control_sending() {
        let source = include_str!("warmup.rs");
        for needle in [
            concat!("NOT an admission", " control"),
            concat!("deliberately NOT read", " by"),
            concat!("mail_common::warmup::WarmupSchedule", "::limit_for_day"),
            concat!("apexmail:warmup:ip:", "{ip_address}:{utc_day}"),
        ] {
            assert!(
                source.contains(needle),
                "the advisory catalog docs must state {needle:?} so operators \
                 cannot mistake these rows for an admission control"
            );
        }
    }

    /// The catalog exposes storage only: no limit derivation and no MX→ISP
    /// resolution may exist here while admission has no provider to key on.
    /// This is the delete-branch equivalent of the hostile-ISP-target cases:
    /// with no interpreter left, a catalog row containing 0, a negative
    /// value, or no matching profile cannot produce any cap at all, so the
    /// canonical `mail_common::warmup` limit remains the only one.
    #[test]
    fn catalog_exposes_no_limit_derivation_or_mx_resolution() {
        let source = include_str!("warmup.rs");
        for needle in [
            concat!("fn get", "_daily_limit"),
            concat!("fn find", "_by_mx_pattern"),
            concat!("fn matches", "_pattern"),
        ] {
            assert!(
                !source.contains(needle),
                "the advisory catalog must not compute an admission limit \
                 (found {needle:?}); the canonical per-IP cap is the only limit"
            );
        }
    }

    /// Grep-level assertion (precedented by the billing money-path gate):
    /// the removed ISP execution model is referenced by NO production path
    /// in the workspace. Identifiers are assembled at runtime so this test's
    /// own text cannot false-positive the scan.
    #[test]
    fn no_production_path_references_the_removed_execution_model() {
        let crates_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("apexmail-db sits under crates/");
        let removed = [
            ["Warmup", "ExecutionRepo"].concat(),
            ["IspWarmup", "Execution"].concat(),
            ["record", "_daily_actual"].concat(),
            ["instantiate", "_from_profile"].concat(),
            ["list", "_by_pool"].concat(),
            ["find", "_by_mx_pattern"].concat(),
            ["get", "_daily_limit"].concat(),
            ["Warmup", "ProfileRepo"].concat(),
        ];

        let mut scanned = 0usize;
        let mut violations: Vec<String> = Vec::new();
        for entry in std::fs::read_dir(crates_dir).expect("crates/ is readable") {
            let entry = entry.expect("crate dir entry");
            let src = entry.path().join("src");
            if !src.is_dir() {
                continue;
            }
            for path in rust_sources_under(&src) {
                scanned += 1;
                let Ok(source) = std::fs::read_to_string(&path) else {
                    continue;
                };
                for needle in &removed {
                    if source.contains(needle.as_str()) {
                        violations.push(format!("{}: {needle}", path.display()));
                    }
                }
            }
        }

        assert!(
            scanned > 100,
            "the source scan must actually read the workspace (scanned {scanned} files)"
        );
        assert!(
            violations.is_empty(),
            "the removed ISP execution model is still referenced by a production \
             path: {violations:?}"
        );
    }

    /// The SEND path specifically must not read the advisory catalog or the
    /// inert per-pool schedule table, and must not depend on this repository.
    /// Together with the canonical-cap single-entry-point test in
    /// `worker-processors`, this proves no catalog value (0, negative, huge,
    /// or absent) can widen the enforced cap.
    #[test]
    fn send_path_never_reads_the_isp_catalog() {
        let worker_src =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../worker-processors/src");
        let sources = rust_sources_under(&worker_src);
        assert!(
            !sources.is_empty(),
            "worker-processors sources must be readable at {}",
            worker_src.display()
        );

        let banned = [
            ["isp", "_warmup_templates"].concat(),
            ["isp", "_warmup_schedules"].concat(),
            ["mx", "_patterns"].concat(),
            ["Warmup", "CatalogRepo"].concat(),
            ["apexmail_db", "::repos::warmup"].concat(),
        ];
        let mut violations: Vec<String> = Vec::new();
        for path in sources {
            let Ok(source) = std::fs::read_to_string(&path) else {
                continue;
            };
            for needle in &banned {
                if source.contains(needle.as_str()) {
                    violations.push(format!("{}: {needle}", path.display()));
                }
            }
        }
        assert!(
            violations.is_empty(),
            "the send path must not read ISP warmup catalog data: {violations:?}"
        );
    }
}
