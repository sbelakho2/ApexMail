//! Entitlement resolution and enforcement.
//!
//! [`EntitlementSnapshot`] is the tenant-scoped, already-resolved view of a
//! plan: capability grants and capacity limits. It is produced by
//! `billing-service` from the same override-aware plan lookup quota
//! enforcement uses, plus tenant `feature_flag_overrides` rows whose
//! `flag_key` names a [`FeatureKey`].
//!
//! # Authority
//!
//! The snapshot is the BACKEND authority: handlers call
//! [`EntitlementSnapshot::require_feature`] or
//! [`EntitlementSnapshot::require_capacity`] and refuse the request when the
//! check fails. UI/console surfaces may serialize
//! [`EntitlementSnapshot::presentation`] for display only — the same
//! snapshot, never a second source of truth.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::classify::{CapacityKey, FeatureClass, FeatureKey, PLAN_FEATURE_CLASSIFICATION};

/// Why a capability or capacity check failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EntitlementError {
    /// The plan does not grant the capability.
    #[error("plan `{plan}` does not include `{feature}`")]
    FeatureNotEntitled { feature: &'static str, plan: String },
    /// The requested total exceeds the plan's capacity. `limit == -1` never
    /// produces this error (unlimited).
    #[error("plan `{plan}` allows at most {limit} {capacity} (requested {requested})")]
    CapacityExceeded {
        capacity: &'static str,
        limit: i64,
        requested: i64,
        plan: String,
    },
    /// The field is classified `ContractualOnly` or `NotYetImplemented` and
    /// must not be used as a runtime access gate.
    #[error("`{field}` is {class} and cannot be used as a runtime entitlement gate")]
    NotRuntimeEnforced {
        field: &'static str,
        class: &'static str,
    },
    /// A negative amount is not a meaningful request.
    #[error("invalid amount {amount} for capacity `{capacity}`")]
    InvalidAmount { capacity: &'static str, amount: i64 },
}

/// A resolved capability/capacity grant for one tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitlementSnapshot {
    tenant_id: String,
    plan: String,
    /// Feature field name → granted. Only RuntimeEnforced keys can ever be
    /// `true`; absent keys are denied.
    granted: BTreeMap<String, bool>,
    /// Capacity field name → limit (-1 unlimited).
    capacities: BTreeMap<String, i64>,
    /// Tenant override keys that were applied (diagnostics/presentation).
    applied_overrides: Vec<String>,
}

impl EntitlementSnapshot {
    /// Build a snapshot from a serialized `PlanFeatures` JSON object.
    ///
    /// Missing booleans deny (fail closed); missing capacities are `0`
    /// (deny) — resolution never silently invents an entitlement.
    pub fn from_plan_features_json(
        tenant_id: impl Into<String>,
        plan: impl Into<String>,
        features: &serde_json::Value,
    ) -> Self {
        let mut granted = BTreeMap::new();
        let mut capacities = BTreeMap::new();

        for entry in PLAN_FEATURE_CLASSIFICATION {
            match entry.gate {
                crate::classify::Gate::Feature(key) => {
                    let value = features
                        .get(entry.field)
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false);
                    granted.insert(key.field_name().to_string(), value);
                }
                crate::classify::Gate::Capacity(key) => {
                    let value = features
                        .get(entry.field)
                        .and_then(serde_json::Value::as_i64)
                        .unwrap_or(0);
                    capacities.insert(key.field_name().to_string(), value);
                }
                crate::classify::Gate::None => {}
            }
        }

        Self {
            tenant_id: tenant_id.into(),
            plan: plan.into(),
            granted,
            capacities,
            applied_overrides: Vec::new(),
        }
    }

    /// Apply one tenant `feature_flag_overrides` row.
    ///
    /// Only JSON booleans whose `flag_key` is a [`FeatureKey`] field name
    /// are honoured, and only for [`FeatureClass::RuntimeEnforced`] fields —
    /// an override can never switch on an unimplemented or contractual
    /// capability. Returns `true` when the override was applied.
    pub fn apply_override(&mut self, flag_key: &str, value: &serde_json::Value) -> bool {
        let Some(key) = FeatureKey::from_field_name(flag_key) else {
            return false;
        };
        if key.class() != FeatureClass::RuntimeEnforced {
            tracing::warn!(
                flag_key,
                class = key.class().as_str(),
                "feature override targets a non-runtime-enforced field; ignored"
            );
            return false;
        }
        let Some(enabled) = value.as_bool() else {
            tracing::warn!(
                flag_key,
                "feature override is not a JSON boolean; failing closed to the plan value"
            );
            return false;
        };
        self.granted.insert(key.field_name().to_string(), enabled);
        self.applied_overrides.push(flag_key.to_string());
        true
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub fn plan(&self) -> &str {
        &self.plan
    }

    /// Whether a capability is granted. Non-runtime-enforced fields always
    /// report `false` (there is nothing to present as available).
    pub fn has_feature(&self, key: FeatureKey) -> bool {
        if key.class() != FeatureClass::RuntimeEnforced {
            return false;
        }
        self.granted.get(key.field_name()).copied().unwrap_or(false)
    }

    /// The plan's limit for a capacity (-1 = unlimited). Unclassified or
    /// non-runtime-enforced capacities report `0` (presentation only; the
    /// authoritative check is `require_capacity`).
    pub fn capacity(&self, key: CapacityKey) -> i64 {
        self.capacities.get(key.field_name()).copied().unwrap_or(0)
    }

    /// Authoritative access gate for a capability.
    ///
    /// Refuses (a) capabilities the plan does not include and (b) every
    /// field whose classification is not `RuntimeEnforced` — an
    /// implementation bug if it happens, which is why it is a distinct
    /// error.
    pub fn require_feature(&self, key: FeatureKey) -> Result<(), EntitlementError> {
        let class = key.class();
        if class != FeatureClass::RuntimeEnforced {
            return Err(EntitlementError::NotRuntimeEnforced {
                field: key.field_name(),
                class: class.as_str(),
            });
        }
        if self.has_feature(key) {
            Ok(())
        } else {
            Err(EntitlementError::FeatureNotEntitled {
                feature: key.field_name(),
                plan: self.plan.clone(),
            })
        }
    }

    /// Authoritative capacity gate. `amount` is the requested TOTAL (current
    /// usage plus the increment), so `limit - 1` and `limit` pass and
    /// `limit + 1` fails for a finite limit. `-1` is unlimited.
    pub fn require_capacity(&self, key: CapacityKey, amount: i64) -> Result<(), EntitlementError> {
        let class = key.class();
        if class != FeatureClass::RuntimeEnforced {
            return Err(EntitlementError::NotRuntimeEnforced {
                field: key.field_name(),
                class: class.as_str(),
            });
        }
        if amount < 0 {
            return Err(EntitlementError::InvalidAmount {
                capacity: key.field_name(),
                amount,
            });
        }
        let limit = self.capacity(key);
        if limit < 0 || amount <= limit {
            Ok(())
        } else {
            Err(EntitlementError::CapacityExceeded {
                capacity: key.field_name(),
                limit,
                requested: amount,
                plan: self.plan.clone(),
            })
        }
    }

    /// Serializable presentation view for UI/console surfaces. The backend
    /// remains authoritative: `granted` here is the same value
    /// `require_feature` enforces, and each row carries its classification
    /// so the console can render "not yet available" instead of an upsell.
    pub fn presentation(&self) -> EntitlementPresentation {
        let features = PLAN_FEATURE_CLASSIFICATION
            .iter()
            .filter_map(|entry| match entry.gate {
                crate::classify::Gate::Feature(key) => Some(FeaturePresentation {
                    key: key.field_name().to_string(),
                    class: entry.class.as_str().to_string(),
                    granted: self.has_feature(key),
                }),
                _ => None,
            })
            .collect();
        let capacities = PLAN_FEATURE_CLASSIFICATION
            .iter()
            .filter_map(|entry| match entry.gate {
                crate::classify::Gate::Capacity(key) => Some(CapacityPresentation {
                    key: key.field_name().to_string(),
                    class: entry.class.as_str().to_string(),
                    limit: self.capacity(key),
                }),
                _ => None,
            })
            .collect();
        EntitlementPresentation {
            tenant_id: self.tenant_id.clone(),
            plan: self.plan.clone(),
            features,
            capacities,
            applied_overrides: self.applied_overrides.clone(),
        }
    }
}

/// Presentation DTO (see [`EntitlementSnapshot::presentation`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitlementPresentation {
    pub tenant_id: String,
    pub plan: String,
    pub features: Vec<FeaturePresentation>,
    pub capacities: Vec<CapacityPresentation>,
    #[serde(default)]
    pub applied_overrides: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeaturePresentation {
    pub key: String,
    pub class: String,
    pub granted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityPresentation {
    pub key: String,
    pub class: String,
    /// -1 = unlimited.
    pub limit: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn features(overrides: serde_json::Value) -> serde_json::Value {
        let mut base = json!({
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
            "max_team_members": 1,
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
        EntitlementSnapshot::from_plan_features_json("tenant-1", "growth", &features(overrides))
    }

    #[test]
    fn denies_a_feature_the_plan_does_not_grant() {
        let snap = snapshot(json!({}));
        let error = snap
            .require_feature(FeatureKey::Webhooks)
            .expect_err("webhooks must be denied on a plan without the flag");
        assert!(matches!(
            error,
            EntitlementError::FeatureNotEntitled {
                feature: "webhooks_enabled",
                ..
            }
        ));
        assert!(!snap.has_feature(FeatureKey::Webhooks));
    }

    #[test]
    fn grants_a_feature_the_plan_includes() {
        let snap = snapshot(json!({"webhooks_enabled": true}));
        assert!(snap.require_feature(FeatureKey::Webhooks).is_ok());
        assert!(snap.has_feature(FeatureKey::Webhooks));
    }

    #[test]
    fn contractual_and_unimplemented_fields_are_never_runtime_gates() {
        let snap = snapshot(json!({
            "sla_guarantee": true,
            "hipaa_compliance": true,
            "time_travel_debugging": true,
            "ab_testing": true
        }));
        for key in [
            FeatureKey::SlaGuarantee,
            FeatureKey::HipaaCompliance,
            FeatureKey::TimeTravelDebugging,
            FeatureKey::AbTesting,
            FeatureKey::WhiteLabel,
        ] {
            let error = snap
                .require_feature(key)
                .expect_err("non-runtime fields must not be grantable");
            assert!(matches!(error, EntitlementError::NotRuntimeEnforced { .. }));
            assert!(!snap.has_feature(key));
        }
    }

    #[test]
    fn capacity_boundary_limit_minus_one_limit_limit_plus_one() {
        let snap = snapshot(json!({"max_team_members": 3}));
        assert!(
            snap.require_capacity(CapacityKey::TeamMembers, 2).is_ok(),
            "limit-1 must pass"
        );
        assert!(
            snap.require_capacity(CapacityKey::TeamMembers, 3).is_ok(),
            "limit must pass"
        );
        let error = snap
            .require_capacity(CapacityKey::TeamMembers, 4)
            .expect_err("limit+1 must fail");
        assert_eq!(
            error,
            EntitlementError::CapacityExceeded {
                capacity: "max_team_members",
                limit: 3,
                requested: 4,
                plan: "growth".into(),
            }
        );
    }

    #[test]
    fn unlimited_capacity_is_minus_one() {
        let snap = snapshot(json!({"max_team_members": -1, "max_sending_domains": -1}));
        assert!(snap
            .require_capacity(CapacityKey::TeamMembers, 1_000_000)
            .is_ok());
        assert!(snap
            .require_capacity(CapacityKey::SendingDomains, i32::MAX as i64)
            .is_ok());
    }

    #[test]
    fn unimplemented_capacity_is_refused() {
        let snap = snapshot(json!({"max_retention_days": 730, "max_subaccounts": 100}));
        for key in [CapacityKey::RetentionDays, CapacityKey::Subaccounts] {
            assert!(
                matches!(
                    snap.require_capacity(key, 1),
                    Err(EntitlementError::NotRuntimeEnforced { .. })
                ),
                "{} is not runtime-enforced",
                key.field_name()
            );
            // Presentation still exposes the raw advertised number.
            assert_eq!(
                snap.capacity(key),
                if key == CapacityKey::RetentionDays {
                    730
                } else {
                    100
                }
            );
        }
    }

    #[test]
    fn negative_amount_is_rejected() {
        let snap = snapshot(json!({"max_team_members": 3}));
        assert!(matches!(
            snap.require_capacity(CapacityKey::TeamMembers, -1),
            Err(EntitlementError::InvalidAmount { .. })
        ));
    }

    #[test]
    fn tenant_override_can_grant_and_revoke_runtime_features() {
        let mut snap = snapshot(json!({}));
        assert!(!snap.has_feature(FeatureKey::AdvancedAnalytics));

        // Grant via override.
        assert!(snap.apply_override("advanced_analytics", &json!(true)));
        assert!(snap.require_feature(FeatureKey::AdvancedAnalytics).is_ok());

        // Revoke via override.
        assert!(snap.apply_override("advanced_analytics", &json!(false)));
        assert!(snap.require_feature(FeatureKey::AdvancedAnalytics).is_err());

        // Non-boolean override fails closed (keeps the plan value).
        assert!(!snap.apply_override("advanced_analytics", &json!("true")));
        assert!(!snap.has_feature(FeatureKey::AdvancedAnalytics));

        // Unknown names never apply.
        assert!(!snap.apply_override("ai_chat", &json!(true)));
        // Non-runtime-enforced fields never apply, regardless of value.
        assert!(!snap.apply_override("time_travel_debugging", &json!(true)));
        assert!(!snap.apply_override("sla_guarantee", &json!(true)));
    }

    #[test]
    fn missing_fields_fail_closed() {
        let snap = EntitlementSnapshot::from_plan_features_json("t", "free", &json!({}));
        assert!(!snap.has_feature(FeatureKey::ApiAccess));
        assert_eq!(snap.capacity(CapacityKey::TeamMembers), 0);
        assert!(matches!(
            snap.require_capacity(CapacityKey::TeamMembers, 1),
            Err(EntitlementError::CapacityExceeded { limit: 0, .. })
        ));
    }

    #[test]
    fn presentation_matches_enforcement() {
        let snap = snapshot(json!({
            "webhooks_enabled": true,
            "max_team_members": 3
        }));
        let view = snap.presentation();
        assert_eq!(view.tenant_id, "tenant-1");
        assert_eq!(view.plan, "growth");

        let webhooks = view
            .features
            .iter()
            .find(|f| f.key == "webhooks_enabled")
            .expect("webhooks row");
        assert!(webhooks.granted);
        assert_eq!(webhooks.class, "RuntimeEnforced");

        let unimplemented = view
            .features
            .iter()
            .find(|f| f.key == "time_travel_debugging")
            .expect("ttd row");
        assert!(!unimplemented.granted);
        assert_eq!(unimplemented.class, "NotYetImplemented");

        let seats = view
            .capacities
            .iter()
            .find(|c| c.key == "max_team_members")
            .expect("team row");
        assert_eq!(seats.limit, 3);
        assert_eq!(seats.class, "RuntimeEnforced");

        // Round-trips over the wire for the console.
        let json = serde_json::to_value(&view).unwrap();
        let back: EntitlementPresentation = serde_json::from_value(json).unwrap();
        assert_eq!(back, view);
    }
}
