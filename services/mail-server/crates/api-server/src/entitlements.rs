//! Backend entitlement enforcement for customer handlers.
//!
//! Every gated handler calls one of:
//!
//! * [`require_feature`] — a boolean capability (`FeatureKey`);
//! * [`require_capacity`] — a numeric limit (`CapacityKey`), with `amount`
//!   the requested TOTAL (current usage + increment).
//!
//! Both resolve the tenant's [`EntitlementSnapshot`] from billing-service
//! (override-aware plan lookup + tenant feature-flag overrides) and map a
//! refusal to `403 Forbidden` (`ApiError::Forbidden`). A misclassified gate
//! — calling `require_feature` on a `ContractualOnly`/`NotYetImplemented`
//! field — maps to `500 Internal`: it is a server programming error, never
//! something a customer can trigger.
//!
//! UI/console surfaces may serialize [`EntitlementSnapshot::presentation`]
//! from the SAME snapshot (see `GET /v1/billing/entitlements`); the backend
//! remains authoritative.

use billing_entitlements::{CapacityKey, EntitlementError, EntitlementSnapshot, FeatureKey};

use crate::error::ApiError;
use crate::state::AppState;

/// Load the tenant's resolved entitlement snapshot.
///
/// `404` when the tenant does not exist. Database errors propagate (an
/// entitlement lookup must never silently grant).
pub async fn snapshot(state: &AppState, tenant_id: &str) -> Result<EntitlementSnapshot, ApiError> {
    billing_service::plans::get_entitlement_snapshot(&state.db, tenant_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("tenant not found".into()))
}

/// Load the snapshot and enforce a capability gate.
pub async fn require_feature(
    state: &AppState,
    tenant_id: &str,
    key: FeatureKey,
) -> Result<EntitlementSnapshot, ApiError> {
    let snapshot = snapshot(state, tenant_id).await?;
    gate_feature(&snapshot, key)?;
    Ok(snapshot)
}

/// Load the snapshot and enforce a capacity gate (`amount` = requested total).
pub async fn require_capacity(
    state: &AppState,
    tenant_id: &str,
    key: CapacityKey,
    amount: i64,
) -> Result<EntitlementSnapshot, ApiError> {
    let snapshot = snapshot(state, tenant_id).await?;
    gate_capacity(&snapshot, key, amount)?;
    Ok(snapshot)
}

/// Pure capability gate (unit-testable without a database).
pub fn gate_feature(snapshot: &EntitlementSnapshot, key: FeatureKey) -> Result<(), ApiError> {
    snapshot.require_feature(key).map_err(|error| {
        tracing::warn!(
            tenant_id = %snapshot.tenant_id(),
            plan = %snapshot.plan(),
            feature = key.as_str(),
            error = %error,
            "entitlement denied"
        );
        entitlement_to_api_error(error)
    })
}

/// Pure capacity gate (unit-testable without a database).
pub fn gate_capacity(
    snapshot: &EntitlementSnapshot,
    key: CapacityKey,
    amount: i64,
) -> Result<(), ApiError> {
    snapshot.require_capacity(key, amount).map_err(|error| {
        tracing::warn!(
            tenant_id = %snapshot.tenant_id(),
            plan = %snapshot.plan(),
            capacity = key.as_str(),
            amount,
            error = %error,
            "capacity denied"
        );
        entitlement_to_api_error(error)
    })
}

/// Customer-visible refusal is `403 Forbidden` for both a missing
/// capability and an exhausted capacity; a gate misconfiguration is `500`.
fn entitlement_to_api_error(error: EntitlementError) -> ApiError {
    let message = error.to_string();
    match error {
        EntitlementError::FeatureNotEntitled { .. } | EntitlementError::CapacityExceeded { .. } => {
            ApiError::Forbidden(message)
        }
        EntitlementError::NotRuntimeEnforced { .. } | EntitlementError::InvalidAmount { .. } => {
            ApiError::Internal(format!("entitlement gate misconfigured: {message}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan_features(overrides: serde_json::Value) -> serde_json::Value {
        let mut base = serde_json::json!({
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
            "ab_testing": false,
            "time_travel_debugging": false,
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
        });
        let (Some(base_map), Some(extra)) = (base.as_object_mut(), overrides.as_object()) else {
            unreachable!("object literals")
        };
        for (key, value) in extra {
            base_map.insert(key.clone(), value.clone());
        }
        base
    }

    fn snapshot(overrides: serde_json::Value) -> EntitlementSnapshot {
        EntitlementSnapshot::from_plan_features_json(
            "tenant-1",
            "growth",
            &plan_features(overrides),
        )
    }

    /// One test per gated capability: non-entitled → 403, entitled → Ok.
    #[test]
    fn every_runtime_feature_gate_refuses_a_non_entitled_tenant() {
        let denied = snapshot(serde_json::json!({"api_access": false}));
        let gated = [
            FeatureKey::DedicatedIp,
            FeatureKey::Sso,
            FeatureKey::ApiAccess,
            FeatureKey::Webhooks,
            FeatureKey::InboundEmail,
            FeatureKey::AdvancedAnalytics,
            FeatureKey::SendTimeOptimization,
            FeatureKey::DataExport,
            FeatureKey::CustomTemplates,
        ];
        for key in gated {
            let error =
                gate_feature(&denied, key).expect_err(&format!("{} must be refused", key.as_str()));
            assert!(
                matches!(error, ApiError::Forbidden(_)),
                "{} must map to 403, got {error:?}",
                key.as_str()
            );
        }
    }

    #[test]
    fn every_runtime_feature_gate_admits_an_entitled_tenant() {
        let granted = snapshot(serde_json::json!({
            "dedicated_ip": true,
            "sso_enabled": true,
            "api_access": true,
            "webhooks_enabled": true,
            "inbound_email": true,
            "advanced_analytics": true,
            "send_time_optimization": true,
            "data_export": true,
            "custom_templates": true
        }));
        for key in [
            FeatureKey::DedicatedIp,
            FeatureKey::Sso,
            FeatureKey::ApiAccess,
            FeatureKey::Webhooks,
            FeatureKey::InboundEmail,
            FeatureKey::AdvancedAnalytics,
            FeatureKey::SendTimeOptimization,
            FeatureKey::DataExport,
            FeatureKey::CustomTemplates,
        ] {
            assert!(
                gate_feature(&granted, key).is_ok(),
                "{} must be admitted",
                key.as_str()
            );
        }
    }

    /// `ContractualOnly`/`NotYetImplemented` fields must never be usable as
    /// runtime gates: that is a server bug, surfaced as 500.
    #[test]
    fn non_runtime_fields_are_never_gates() {
        let snap = snapshot(serde_json::json!({
            "sla_guarantee": true,
            "hipaa_compliance": true,
            "time_travel_debugging": true,
            "ab_testing": true,
            "white_label": true
        }));
        for key in [
            FeatureKey::SlaGuarantee,
            FeatureKey::HipaaCompliance,
            FeatureKey::TimeTravelDebugging,
            FeatureKey::AbTesting,
            FeatureKey::WhiteLabel,
        ] {
            let error = gate_feature(&snap, key)
                .expect_err(&format!("{} must not be a runtime gate", key.as_str()));
            assert!(
                matches!(error, ApiError::Internal(_)),
                "{} must map to 500 (misconfigured gate), got {error:?}",
                key.as_str()
            );
        }
    }

    /// Capacity boundary: limit-1 and limit pass, limit+1 is a 403.
    #[test]
    fn capacity_boundary_is_enforced() {
        let snap = snapshot(serde_json::json!({"max_team_members": 3, "max_sending_domains": 5}));

        assert!(gate_capacity(&snap, CapacityKey::TeamMembers, 2).is_ok());
        assert!(gate_capacity(&snap, CapacityKey::TeamMembers, 3).is_ok());
        let error =
            gate_capacity(&snap, CapacityKey::TeamMembers, 4).expect_err("limit+1 must be refused");

        match error {
            ApiError::Forbidden(message) => {
                assert!(message.contains("max_team_members"), "{message}");
                assert!(message.contains('3'), "{message}");
            }
            other => panic!("expected 403, got {other:?}"),
        }
    }

    #[test]
    fn unlimited_capacity_never_refuses() {
        let snap = snapshot(serde_json::json!({"max_sending_domains": -1}));
        assert!(gate_capacity(&snap, CapacityKey::SendingDomains, 1_000_000).is_ok());
    }

    #[test]
    fn unimplemented_capacity_maps_to_internal() {
        let snap = snapshot(serde_json::json!({"max_retention_days": 90}));
        assert!(matches!(
            gate_capacity(&snap, CapacityKey::RetentionDays, 1),
            Err(ApiError::Internal(_))
        ));
    }

    /// Release-gate parity in Rust: every field classified `RuntimeEnforced`
    /// must have its gate key referenced by a real api-server handler. A
    /// classification that claims enforcement without wiring fails here
    /// (the Python gate checks the same invariant at release time).
    #[test]
    fn every_runtime_enforced_field_is_wired_to_a_handler() {
        use billing_entitlements::{FeatureClass, Gate, PLAN_FEATURE_CLASSIFICATION};

        fn collect_rust_sources(dir: &std::path::Path, out: &mut Vec<String>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    collect_rust_sources(&path, out);
                } else if path.extension().is_some_and(|extension| extension == "rs")
                    && path
                        .file_name()
                        .is_some_and(|name| name != "entitlements.rs")
                {
                    if let Ok(text) = std::fs::read_to_string(&path) {
                        out.push(text);
                    }
                }
            }
        }

        let mut sources = Vec::new();
        collect_rust_sources(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src")
                .as_path(),
            &mut sources,
        );
        let wiring = sources.join("\n");

        for entry in PLAN_FEATURE_CLASSIFICATION {
            if entry.class != FeatureClass::RuntimeEnforced {
                continue;
            }
            let needle = match entry.gate {
                Gate::Feature(key) => format!("FeatureKey::{key:?}"),
                Gate::Capacity(key) => format!("CapacityKey::{key:?}"),
                Gate::None => panic!("`{}` is RuntimeEnforced but has no gate key", entry.field),
            };
            assert!(
                wiring.contains(&needle),
                "`{}` is classified RuntimeEnforced but no api-server handler references {needle}",
                entry.field
            );
        }
    }

    /// Resolution against the real schema: plan features grant/deny and a
    /// tenant feature-flag override flips a runtime-enforced gate. Skipped
    /// when TEST_DATABASE_URL is unset (same convention as other DB tests).
    #[tokio::test]
    async fn resolution_applies_plan_features_and_tenant_overrides() {
        use billing_service::plans::PlanSeed;
        use billing_service::types::PlanFeatures;

        let Some(pool) = crate::test_db::canonical_pool("entitlement_resolution").await else {
            return;
        };

        let plan_name = "entitlement-test-plan";
        // `tenants.id` is VARCHAR(26); a full UUID simple form is 32 chars before
        // the prefix, which the column rejects. Bound the suffix so the fixture
        // respects the same limit production ids do.
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let tenant_id = format!("ent{}", &suffix[..20]);
        let seed = PlanSeed {
            name: plan_name,
            display_name: "Entitlement Test",
            description: "test",
            price_monthly: 0,
            price_yearly: 0,
            email_limit: 1_000,
            api_call_limit: 1_000,
            sort_order: 999,
            features: PlanFeatures {
                webhooks_enabled: false,
                max_team_members: 2,
                ..PlanFeatures::default()
            },
        };
        billing_service::plans::upsert_plan(&pool, &seed)
            .await
            .expect("upsert test plan");

        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at) \
             VALUES ($1, 'Entitlement Test', $1, $2, 'active', '{}'::jsonb, '{}'::jsonb, NOW(), NOW())",
        )
        .bind(&tenant_id)
        .bind(plan_name)
        .execute(&pool)
        .await
        .expect("insert test tenant");

        let snap = billing_service::plans::get_entitlement_snapshot(&pool, &tenant_id)
            .await
            .expect("resolve snapshot")
            .expect("tenant exists");
        assert!(
            snap.require_feature(FeatureKey::Webhooks).is_err(),
            "plan does not include webhooks_enabled"
        );
        assert!(snap.require_capacity(CapacityKey::TeamMembers, 2).is_ok());
        assert!(snap.require_capacity(CapacityKey::TeamMembers, 3).is_err());

        // Tenant override grants the otherwise-denied capability.
        sqlx::query(
            "INSERT INTO feature_flag_overrides (id, flag_key, tenant_id, value, created_at) \
             VALUES (gen_random_uuid(), 'webhooks_enabled', $1, 'true'::jsonb, NOW()) \
             ON CONFLICT (tenant_id, flag_key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(&tenant_id)
        .execute(&pool)
        .await
        .expect("insert override");

        let snap = billing_service::plans::get_entitlement_snapshot(&pool, &tenant_id)
            .await
            .expect("resolve snapshot")
            .expect("tenant exists");
        assert!(
            snap.require_feature(FeatureKey::Webhooks).is_ok(),
            "tenant override must grant the runtime-enforced capability"
        );

        // Cleanup.
        let _ = sqlx::query("DELETE FROM feature_flag_overrides WHERE tenant_id = $1")
            .bind(&tenant_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(&tenant_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM plans WHERE name = $1")
            .bind(plan_name)
            .execute(&pool)
            .await;
    }
}
