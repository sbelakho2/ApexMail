//! Control-plane route modules.
//!
//! All require admin authentication and are mounted under the system-tenant
//! admin router in `app.rs`. Modules without a direct nest in `app.rs` are
//! composed into a sibling router here (see `analytics`, `audit`, and
//! `dashboard`), so every module declared below is reachable at runtime.
//!
//! Historically several modules existed as files on disk but were never
//! declared here, making their features unreachable while the scope-guard
//! test still scanned (and passed on) the dead files. Those were either
//! mounted (see above) or deleted:
//! - `health.rs` — deleted: overlapped the live `system_health` router and
//!   depended on a background loop that was never spawned.
//! - `estonia_ou.rs` — deleted: VAT/KMD filings are served live by `vat`,
//!   `compliance_overview`, and `calendar`.
//! - `reports.rs` — deleted: depended on the never-declared crate-level
//!   `admin_report_scheduler` module; report export is served live by
//!   `analytics_export`.

pub mod ai_drafts;
pub mod analytics;
pub mod analytics_export;
pub mod audit;
pub mod audit_search;
pub mod autopilot;
pub mod calendar;
pub mod campaigns;
pub mod compliance_overview;
pub mod content;
pub mod crm_leads;
pub mod cross_tenant;
pub mod dashboard;
pub mod delivery_analytics;
pub mod domains;
pub mod features;
pub mod gdpr;
pub mod growth_analytics;
pub mod inbox;
pub mod insights;
pub mod leads_discovery;
pub mod operators;
pub mod predictive_analytics;
pub mod proxy;
pub mod revenue;
pub mod risk;
pub mod sales;
pub mod secrets;
pub mod sse;
pub mod support;
pub mod support_analytics;
pub mod system_health;
pub mod system_sender;
pub mod tenants;
pub mod vat;
pub mod warmup;

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    /// Extract the module names declared via `pub mod <name>;` in this file.
    ///
    /// The guard below deliberately checks DECLARED modules (the set the
    /// compiler actually builds and mounts), not "whatever .rs files happen
    /// to lie in this directory" — scanning the directory produced false
    /// assurance while unreachable modules sat on disk.
    fn declared_modules() -> Vec<String> {
        let source = include_str!("mod.rs");
        source
            .lines()
            .filter_map(|line| line.trim().strip_prefix("pub mod "))
            .map(|rest| rest.trim_end_matches(';').trim().to_string())
            .filter(|name| !name.is_empty())
            .collect()
    }

    /// The declaration guard over abstracted directory entries:
    /// (extension, file stem) pairs. Non-.rs entries and mod.rs itself are
    /// skipped; anything else missing from `declared` is reported.
    fn undeclared_files_of(
        entries: &[(Option<String>, String)],
        declared: &[String],
    ) -> Vec<String> {
        let mut undeclared_files = Vec::new();
        for (extension, name) in entries {
            if extension.as_deref() != Some("rs") {
                continue;
            }
            if name == "mod" {
                continue;
            }
            if !declared.contains(name) {
                undeclared_files.push(name.clone());
            }
        }
        undeclared_files
    }

    #[test]
    fn every_admin_route_file_is_declared() {
        let admin_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/routes/admin");
        let entries = fs::read_dir(&admin_dir).expect("failed to read admin route directory");

        let declared = declared_modules();
        let mut disk_entries: Vec<(Option<String>, String)> = Vec::new();
        for entry in entries {
            let entry = entry.expect("failed to read admin route entry");
            let path = entry.path();
            let extension = path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(str::to_string);
            let name = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or("<unknown>")
                .to_string();
            disk_entries.push((extension, name));
        }
        let undeclared_files = undeclared_files_of(&disk_entries, &declared);

        assert!(
            undeclared_files.is_empty(),
            "admin route files exist on disk but are not declared in mod.rs \
             (their features are unreachable): {:?}",
            undeclared_files,
        );
    }

    /// The scope-scan decision over abstracted (module, source) pairs:
    /// every module source must contain the wildcard-scope guard call.
    fn missing_scope_guards_of(module_sources: &[(String, String)]) -> Vec<String> {
        module_sources
            .iter()
            .filter(|(_, source)| !source.contains("require_scopes(&auth, &[\"*\"])"))
            .map(|(module, _)| module.clone())
            .collect()
    }

    #[test]
    fn admin_route_files_enforce_wildcard_scope() {
        let admin_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/routes/admin");

        let mut module_sources: Vec<(String, String)> = Vec::new();
        for module in declared_modules() {
            let path = admin_dir.join(format!("{module}.rs"));
            let contents =
                fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing source for {module}"));
            module_sources.push((module, contents));
        }
        let missing_scope_guards = missing_scope_guards_of(&module_sources);

        assert!(
            missing_scope_guards.is_empty(),
            "admin route files missing wildcard scope checks: {:?}",
            missing_scope_guards,
        );
    }

    #[test]
    fn declaration_and_scope_guards_flag_violations() {
        let declared = declared_modules();
        assert!(!declared.is_empty());

        // The abstracted declaration guard: non-.rs entries and mod.rs are
        // skipped; an undeclared .rs file is reported by stem.
        let entries = vec![
            (Some("rs".into()), "audit".into()),
            (Some("txt".into()), "notes".into()),
            (Some("rs".into()), "mod".into()),
            (Some("rs".into()), "totally_new_module".into()),
        ];
        let undeclared = undeclared_files_of(&entries, &declared);
        assert_eq!(undeclared, vec!["totally_new_module".to_string()]);

        // The scope-scan decision: a module source with the wildcard guard
        // passes; one without is flagged by name.
        let sources = vec![
            (
                "audit".to_string(),
                "require_scopes(&auth, &[\"*\"])?".to_string(),
            ),
            ("evil".to_string(), "fn x() {}".to_string()),
        ];
        assert_eq!(missing_scope_guards_of(&sources), vec!["evil".to_string()]);
    }
}
