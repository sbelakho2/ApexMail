//! Control-plane route modules.
//!
//! All require admin authentication.

pub mod analytics;
pub mod analytics_export;
pub mod audit;
pub mod autopilot;
pub mod operators;
pub mod calendar;
pub mod campaigns;
pub mod compliance_overview;
pub mod content;
pub mod crm_leads;
pub mod dashboard;
pub mod features;
pub mod gdpr;
pub mod inbox;
pub mod leads_discovery;
pub mod proxy;
pub mod revenue;
pub mod risk;
pub mod sales;
pub mod secrets;
pub mod support;
pub mod support_analytics;
pub mod system_health;
pub mod tenants;
pub mod vat;
pub mod warmup;

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn admin_route_files_enforce_wildcard_scope() {
        let admin_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/routes/admin");
        let entries = fs::read_dir(&admin_dir).expect("failed to read admin route directory");

        let mut missing_scope_guards = Vec::new();

        for entry in entries {
            let entry = entry.expect("failed to read admin route entry");
            let path = entry.path();

            if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                continue;
            }

            if path.file_name().and_then(|name| name.to_str()) == Some("mod.rs") {
                continue;
            }

            let contents =
                fs::read_to_string(&path).expect("failed to read admin route source file");
            if !contents.contains("require_scopes(&auth, &[\"*\"])") {
                missing_scope_guards.push(
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("<unknown>")
                        .to_string(),
                );
            }
        }

        assert!(
            missing_scope_guards.is_empty(),
            "admin route files missing wildcard scope checks: {:?}",
            missing_scope_guards,
        );
    }
}
