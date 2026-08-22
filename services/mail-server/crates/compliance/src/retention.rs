use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionMode {
    Immediate,
    Queued,
    Propagated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionDefinition {
    pub category_id: String,
    pub category_name: String,
    pub default_retention_days: u32,
    pub minimum_customer_selectable_days: u32,
    pub maximum_customer_selectable_days: u32,
    pub plan_specific_limit: Option<RetentionPlanLimits>,
    pub backup_retention_days: u32,
    pub deletion_processing_deadline_hours: u32,
    pub legal_retention_can_override: bool,
    pub deletion_mode: DeletionMode,
    pub export_available: bool,
    pub dedicated_tenant_behavior: DedicatedTenantRetention,
    pub byoc_behavior: BYOCRetention,
    pub zero_retention_allowed: bool,
    pub content_retention_separate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPlanLimits {
    pub free: u32,
    pub developer: u32,
    pub pro: u32,
    pub growth: u32,
    pub business: u32,
    pub enterprise: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DedicatedTenantRetention {
    MatchesPlan,
    Negotiated,
    CustomerControlled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BYOCRetention {
    CustomerResponsibility,
    AssistOnly,
    PlatformManaged,
}

#[derive(Debug, Clone)]
pub struct RetentionRegistry {
    categories: HashMap<String, RetentionDefinition>,
}

impl Default for RetentionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RetentionRegistry {
    pub fn new() -> Self {
        Self {
            categories: HashMap::new(),
        }
    }

    pub fn register(&mut self, def: RetentionDefinition) {
        self.categories.insert(def.category_id.clone(), def);
    }

    pub fn get(&self, id: &str) -> Option<&RetentionDefinition> {
        self.categories.get(id)
    }

    pub fn all(&self) -> Vec<&RetentionDefinition> {
        self.categories.values().collect()
    }

    pub fn validate_customer_selection(
        &self,
        category_id: &str,
        plan: &str,
        requested_days: u32,
    ) -> Result<(), String> {
        let def = self
            .categories
            .get(category_id)
            .ok_or_else(|| format!("Unknown retention category: {}", category_id))?;

        if requested_days < def.minimum_customer_selectable_days {
            return Err(format!(
                "Requested retention {} days below minimum {} for {}",
                requested_days, def.minimum_customer_selectable_days, def.category_name
            ));
        }

        if let Some(ref limits) = def.plan_specific_limit {
            let plan_limit = match plan {
                "free" => limits.free,
                "developer" => limits.developer,
                "pro" => limits.pro,
                "growth" => limits.growth,
                "business" => limits.business,
                "enterprise" => limits.enterprise,
                _ => limits.free,
            };

            if requested_days > plan_limit {
                return Err(format!(
                    "Requested retention {} days exceeds plan limit of {} for {}",
                    requested_days, plan_limit, def.category_name
                ));
            }
        }

        Ok(())
    }
}

pub fn seed_retention_registry() -> RetentionRegistry {
    let mut registry = RetentionRegistry::new();

    registry.register(RetentionDefinition {
        category_id: "RET-001".into(),
        category_name: "Message Body".into(),
        default_retention_days: 7,
        minimum_customer_selectable_days: 0,
        maximum_customer_selectable_days: 90,
        plan_specific_limit: Some(RetentionPlanLimits {
            free: 1,
            developer: 7,
            pro: 30,
            growth: 90,
            business: 90,
            enterprise: 365,
        }),
        backup_retention_days: 30,
        deletion_processing_deadline_hours: 24,
        legal_retention_can_override: true,
        deletion_mode: DeletionMode::Queued,
        export_available: false,
        dedicated_tenant_behavior: DedicatedTenantRetention::Negotiated,
        byoc_behavior: BYOCRetention::CustomerResponsibility,
        zero_retention_allowed: true,
        content_retention_separate: true,
    });

    registry.register(RetentionDefinition {
        category_id: "RET-002".into(),
        category_name: "Subject Line".into(),
        default_retention_days: 7,
        minimum_customer_selectable_days: 0,
        maximum_customer_selectable_days: 90,
        plan_specific_limit: Some(RetentionPlanLimits {
            free: 1,
            developer: 7,
            pro: 30,
            growth: 90,
            business: 90,
            enterprise: 365,
        }),
        backup_retention_days: 30,
        deletion_processing_deadline_hours: 24,
        legal_retention_can_override: true,
        deletion_mode: DeletionMode::Queued,
        export_available: true,
        dedicated_tenant_behavior: DedicatedTenantRetention::Negotiated,
        byoc_behavior: BYOCRetention::CustomerResponsibility,
        zero_retention_allowed: true,
        content_retention_separate: true,
    });

    registry.register(RetentionDefinition {
        category_id: "RET-003".into(),
        category_name: "Sender Address".into(),
        default_retention_days: 7,
        minimum_customer_selectable_days: 1,
        maximum_customer_selectable_days: 365,
        plan_specific_limit: Some(RetentionPlanLimits {
            free: 7,
            developer: 30,
            pro: 90,
            growth: 90,
            business: 180,
            enterprise: 365,
        }),
        backup_retention_days: 30,
        deletion_processing_deadline_hours: 24,
        legal_retention_can_override: true,
        deletion_mode: DeletionMode::Queued,
        export_available: true,
        dedicated_tenant_behavior: DedicatedTenantRetention::Negotiated,
        byoc_behavior: BYOCRetention::CustomerResponsibility,
        zero_retention_allowed: false,
        content_retention_separate: false,
    });

    registry.register(RetentionDefinition {
        category_id: "RET-004".into(),
        category_name: "Recipient Address".into(),
        default_retention_days: 30,
        minimum_customer_selectable_days: 1,
        maximum_customer_selectable_days: 365,
        plan_specific_limit: Some(RetentionPlanLimits {
            free: 7,
            developer: 30,
            pro: 90,
            growth: 90,
            business: 180,
            enterprise: 365,
        }),
        backup_retention_days: 30,
        deletion_processing_deadline_hours: 24,
        legal_retention_can_override: true,
        deletion_mode: DeletionMode::Queued,
        export_available: true,
        dedicated_tenant_behavior: DedicatedTenantRetention::Negotiated,
        byoc_behavior: BYOCRetention::CustomerResponsibility,
        zero_retention_allowed: false,
        content_retention_separate: false,
    });

    registry.register(RetentionDefinition {
        category_id: "RET-005".into(),
        category_name: "Headers".into(),
        default_retention_days: 7,
        minimum_customer_selectable_days: 0,
        maximum_customer_selectable_days: 90,
        plan_specific_limit: Some(RetentionPlanLimits {
            free: 1,
            developer: 7,
            pro: 30,
            growth: 90,
            business: 90,
            enterprise: 365,
        }),
        backup_retention_days: 30,
        deletion_processing_deadline_hours: 24,
        legal_retention_can_override: true,
        deletion_mode: DeletionMode::Queued,
        export_available: true,
        dedicated_tenant_behavior: DedicatedTenantRetention::Negotiated,
        byoc_behavior: BYOCRetention::CustomerResponsibility,
        zero_retention_allowed: true,
        content_retention_separate: true,
    });

    registry.register(RetentionDefinition {
        category_id: "RET-006".into(),
        category_name: "Attachments".into(),
        default_retention_days: 7,
        minimum_customer_selectable_days: 0,
        maximum_customer_selectable_days: 90,
        plan_specific_limit: Some(RetentionPlanLimits {
            free: 1,
            developer: 7,
            pro: 30,
            growth: 90,
            business: 90,
            enterprise: 365,
        }),
        backup_retention_days: 30,
        deletion_processing_deadline_hours: 24,
        legal_retention_can_override: true,
        deletion_mode: DeletionMode::Queued,
        export_available: false,
        dedicated_tenant_behavior: DedicatedTenantRetention::Negotiated,
        byoc_behavior: BYOCRetention::CustomerResponsibility,
        zero_retention_allowed: true,
        content_retention_separate: true,
    });

    registry.register(RetentionDefinition {
        category_id: "RET-007".into(),
        category_name: "Message Events".into(),
        default_retention_days: 30,
        minimum_customer_selectable_days: 1,
        maximum_customer_selectable_days: 365,
        plan_specific_limit: Some(RetentionPlanLimits {
            free: 7,
            developer: 30,
            pro: 90,
            growth: 90,
            business: 180,
            enterprise: 365,
        }),
        backup_retention_days: 30,
        deletion_processing_deadline_hours: 48,
        legal_retention_can_override: true,
        deletion_mode: DeletionMode::Propagated,
        export_available: true,
        dedicated_tenant_behavior: DedicatedTenantRetention::Negotiated,
        byoc_behavior: BYOCRetention::CustomerResponsibility,
        zero_retention_allowed: false,
        content_retention_separate: true,
    });

    registry.register(RetentionDefinition {
        category_id: "RET-008".into(),
        category_name: "SMTP Responses".into(),
        default_retention_days: 30,
        minimum_customer_selectable_days: 1,
        maximum_customer_selectable_days: 365,
        plan_specific_limit: Some(RetentionPlanLimits {
            free: 7,
            developer: 30,
            pro: 90,
            growth: 90,
            business: 180,
            enterprise: 365,
        }),
        backup_retention_days: 30,
        deletion_processing_deadline_hours: 48,
        legal_retention_can_override: true,
        deletion_mode: DeletionMode::Propagated,
        export_available: true,
        dedicated_tenant_behavior: DedicatedTenantRetention::Negotiated,
        byoc_behavior: BYOCRetention::CustomerResponsibility,
        zero_retention_allowed: false,
        content_retention_separate: false,
    });

    registry.register(RetentionDefinition {
        category_id: "RET-009".into(),
        category_name: "Opens".into(),
        default_retention_days: 30,
        minimum_customer_selectable_days: 0,
        maximum_customer_selectable_days: 365,
        plan_specific_limit: Some(RetentionPlanLimits {
            free: 7,
            developer: 30,
            pro: 90,
            growth: 90,
            business: 180,
            enterprise: 365,
        }),
        backup_retention_days: 30,
        deletion_processing_deadline_hours: 48,
        legal_retention_can_override: false,
        deletion_mode: DeletionMode::Propagated,
        export_available: true,
        dedicated_tenant_behavior: DedicatedTenantRetention::Negotiated,
        byoc_behavior: BYOCRetention::CustomerResponsibility,
        zero_retention_allowed: true,
        content_retention_separate: false,
    });

    registry.register(RetentionDefinition {
        category_id: "RET-010".into(),
        category_name: "Clicks".into(),
        default_retention_days: 30,
        minimum_customer_selectable_days: 0,
        maximum_customer_selectable_days: 365,
        plan_specific_limit: Some(RetentionPlanLimits {
            free: 7,
            developer: 30,
            pro: 90,
            growth: 90,
            business: 180,
            enterprise: 365,
        }),
        backup_retention_days: 30,
        deletion_processing_deadline_hours: 48,
        legal_retention_can_override: false,
        deletion_mode: DeletionMode::Propagated,
        export_available: true,
        dedicated_tenant_behavior: DedicatedTenantRetention::Negotiated,
        byoc_behavior: BYOCRetention::CustomerResponsibility,
        zero_retention_allowed: true,
        content_retention_separate: false,
    });

    registry.register(RetentionDefinition {
        category_id: "RET-011".into(),
        category_name: "Bounces".into(),
        default_retention_days: 90,
        minimum_customer_selectable_days: 7,
        maximum_customer_selectable_days: 365,
        plan_specific_limit: Some(RetentionPlanLimits {
            free: 30,
            developer: 90,
            pro: 90,
            growth: 180,
            business: 180,
            enterprise: 365,
        }),
        backup_retention_days: 30,
        deletion_processing_deadline_hours: 48,
        legal_retention_can_override: true,
        deletion_mode: DeletionMode::Propagated,
        export_available: true,
        dedicated_tenant_behavior: DedicatedTenantRetention::Negotiated,
        byoc_behavior: BYOCRetention::CustomerResponsibility,
        zero_retention_allowed: false,
        content_retention_separate: false,
    });

    registry.register(RetentionDefinition {
        category_id: "RET-012".into(),
        category_name: "Complaints".into(),
        default_retention_days: 90,
        minimum_customer_selectable_days: 7,
        maximum_customer_selectable_days: 365,
        plan_specific_limit: Some(RetentionPlanLimits {
            free: 30,
            developer: 90,
            pro: 90,
            growth: 180,
            business: 180,
            enterprise: 365,
        }),
        backup_retention_days: 30,
        deletion_processing_deadline_hours: 48,
        legal_retention_can_override: true,
        deletion_mode: DeletionMode::Propagated,
        export_available: true,
        dedicated_tenant_behavior: DedicatedTenantRetention::Negotiated,
        byoc_behavior: BYOCRetention::CustomerResponsibility,
        zero_retention_allowed: false,
        content_retention_separate: false,
    });

    registry.register(RetentionDefinition {
        category_id: "RET-013".into(),
        category_name: "Suppressions".into(),
        default_retention_days: 0,
        minimum_customer_selectable_days: 0,
        maximum_customer_selectable_days: 0,
        plan_specific_limit: None,
        backup_retention_days: 30,
        deletion_processing_deadline_hours: 0,
        legal_retention_can_override: false,
        deletion_mode: DeletionMode::Immediate,
        export_available: true,
        dedicated_tenant_behavior: DedicatedTenantRetention::MatchesPlan,
        byoc_behavior: BYOCRetention::CustomerResponsibility,
        zero_retention_allowed: true,
        content_retention_separate: false,
    });

    registry.register(RetentionDefinition {
        category_id: "RET-014".into(),
        category_name: "Webhook Request Bodies".into(),
        default_retention_days: 7,
        minimum_customer_selectable_days: 0,
        maximum_customer_selectable_days: 30,
        plan_specific_limit: Some(RetentionPlanLimits {
            free: 1,
            developer: 7,
            pro: 30,
            growth: 90,
            business: 90,
            enterprise: 365,
        }),
        backup_retention_days: 30,
        deletion_processing_deadline_hours: 24,
        legal_retention_can_override: true,
        deletion_mode: DeletionMode::Queued,
        export_available: false,
        dedicated_tenant_behavior: DedicatedTenantRetention::Negotiated,
        byoc_behavior: BYOCRetention::CustomerResponsibility,
        zero_retention_allowed: true,
        content_retention_separate: true,
    });

    registry.register(RetentionDefinition {
        category_id: "RET-015".into(),
        category_name: "Webhook Response Bodies".into(),
        default_retention_days: 7,
        minimum_customer_selectable_days: 0,
        maximum_customer_selectable_days: 30,
        plan_specific_limit: Some(RetentionPlanLimits {
            free: 1,
            developer: 7,
            pro: 30,
            growth: 90,
            business: 90,
            enterprise: 365,
        }),
        backup_retention_days: 30,
        deletion_processing_deadline_hours: 24,
        legal_retention_can_override: true,
        deletion_mode: DeletionMode::Queued,
        export_available: false,
        dedicated_tenant_behavior: DedicatedTenantRetention::Negotiated,
        byoc_behavior: BYOCRetention::CustomerResponsibility,
        zero_retention_allowed: true,
        content_retention_separate: true,
    });

    registry.register(RetentionDefinition {
        category_id: "RET-016".into(),
        category_name: "API Request Logs".into(),
        default_retention_days: 30,
        minimum_customer_selectable_days: 1,
        maximum_customer_selectable_days: 365,
        plan_specific_limit: Some(RetentionPlanLimits {
            free: 7,
            developer: 30,
            pro: 90,
            growth: 90,
            business: 180,
            enterprise: 365,
        }),
        backup_retention_days: 30,
        deletion_processing_deadline_hours: 48,
        legal_retention_can_override: true,
        deletion_mode: DeletionMode::Propagated,
        export_available: true,
        dedicated_tenant_behavior: DedicatedTenantRetention::Negotiated,
        byoc_behavior: BYOCRetention::CustomerResponsibility,
        zero_retention_allowed: false,
        content_retention_separate: false,
    });

    registry.register(RetentionDefinition {
        category_id: "RET-017".into(),
        category_name: "Audit Logs".into(),
        default_retention_days: 365,
        minimum_customer_selectable_days: 30,
        maximum_customer_selectable_days: 2555,
        plan_specific_limit: Some(RetentionPlanLimits {
            free: 0,
            developer: 0,
            pro: 0,
            growth: 365,
            business: 730,
            enterprise: 2555,
        }),
        backup_retention_days: 90,
        deletion_processing_deadline_hours: 72,
        legal_retention_can_override: true,
        deletion_mode: DeletionMode::Propagated,
        export_available: true,
        dedicated_tenant_behavior: DedicatedTenantRetention::Negotiated,
        byoc_behavior: BYOCRetention::CustomerResponsibility,
        zero_retention_allowed: false,
        content_retention_separate: false,
    });

    registry.register(RetentionDefinition {
        category_id: "RET-018".into(),
        category_name: "Billing Records".into(),
        default_retention_days: 2555,
        minimum_customer_selectable_days: 365,
        maximum_customer_selectable_days: 3650,
        plan_specific_limit: Some(RetentionPlanLimits {
            free: 2555,
            developer: 2555,
            pro: 2555,
            growth: 2555,
            business: 2555,
            enterprise: 3650,
        }),
        backup_retention_days: 90,
        deletion_processing_deadline_hours: 72,
        legal_retention_can_override: true,
        deletion_mode: DeletionMode::Propagated,
        export_available: true,
        dedicated_tenant_behavior: DedicatedTenantRetention::Negotiated,
        byoc_behavior: BYOCRetention::CustomerResponsibility,
        zero_retention_allowed: false,
        content_retention_separate: false,
    });

    registry.register(RetentionDefinition {
        category_id: "RET-019".into(),
        category_name: "Support Tickets".into(),
        default_retention_days: 365,
        minimum_customer_selectable_days: 30,
        maximum_customer_selectable_days: 2555,
        plan_specific_limit: Some(RetentionPlanLimits {
            free: 90,
            developer: 365,
            pro: 365,
            growth: 730,
            business: 730,
            enterprise: 2555,
        }),
        backup_retention_days: 90,
        deletion_processing_deadline_hours: 72,
        legal_retention_can_override: true,
        deletion_mode: DeletionMode::Propagated,
        export_available: true,
        dedicated_tenant_behavior: DedicatedTenantRetention::Negotiated,
        byoc_behavior: BYOCRetention::CustomerResponsibility,
        zero_retention_allowed: false,
        content_retention_separate: false,
    });

    registry.register(RetentionDefinition {
        category_id: "RET-020".into(),
        category_name: "Security Logs".into(),
        default_retention_days: 365,
        minimum_customer_selectable_days: 90,
        maximum_customer_selectable_days: 2555,
        plan_specific_limit: Some(RetentionPlanLimits {
            free: 0,
            developer: 0,
            pro: 0,
            growth: 365,
            business: 730,
            enterprise: 2555,
        }),
        backup_retention_days: 90,
        deletion_processing_deadline_hours: 72,
        legal_retention_can_override: true,
        deletion_mode: DeletionMode::Propagated,
        export_available: true,
        dedicated_tenant_behavior: DedicatedTenantRetention::Negotiated,
        byoc_behavior: BYOCRetention::CustomerResponsibility,
        zero_retention_allowed: false,
        content_retention_separate: false,
    });

    registry.register(RetentionDefinition {
        category_id: "RET-021".into(),
        category_name: "Backups".into(),
        default_retention_days: 30,
        minimum_customer_selectable_days: 7,
        maximum_customer_selectable_days: 90,
        plan_specific_limit: Some(RetentionPlanLimits {
            free: 7,
            developer: 30,
            pro: 30,
            growth: 30,
            business: 60,
            enterprise: 90,
        }),
        backup_retention_days: 0,
        deletion_processing_deadline_hours: 72,
        legal_retention_can_override: true,
        deletion_mode: DeletionMode::Propagated,
        export_available: false,
        dedicated_tenant_behavior: DedicatedTenantRetention::Negotiated,
        byoc_behavior: BYOCRetention::CustomerResponsibility,
        zero_retention_allowed: false,
        content_retention_separate: false,
    });

    registry.register(RetentionDefinition {
        category_id: "RET-022".into(),
        category_name: "Inbox-Placement Test Content".into(),
        default_retention_days: 7,
        minimum_customer_selectable_days: 0,
        maximum_customer_selectable_days: 30,
        plan_specific_limit: Some(RetentionPlanLimits {
            free: 0,
            developer: 0,
            pro: 30,
            growth: 30,
            business: 90,
            enterprise: 90,
        }),
        backup_retention_days: 30,
        deletion_processing_deadline_hours: 24,
        legal_retention_can_override: false,
        deletion_mode: DeletionMode::Queued,
        export_available: false,
        dedicated_tenant_behavior: DedicatedTenantRetention::Negotiated,
        byoc_behavior: BYOCRetention::CustomerResponsibility,
        zero_retention_allowed: true,
        content_retention_separate: true,
    });

    registry.register(RetentionDefinition {
        category_id: "RET-023".into(),
        category_name: "Inbound-Email Content".into(),
        default_retention_days: 7,
        minimum_customer_selectable_days: 0,
        maximum_customer_selectable_days: 90,
        plan_specific_limit: Some(RetentionPlanLimits {
            free: 0,
            developer: 7,
            pro: 30,
            growth: 90,
            business: 90,
            enterprise: 365,
        }),
        backup_retention_days: 30,
        deletion_processing_deadline_hours: 24,
        legal_retention_can_override: true,
        deletion_mode: DeletionMode::Queued,
        export_available: false,
        dedicated_tenant_behavior: DedicatedTenantRetention::Negotiated,
        byoc_behavior: BYOCRetention::CustomerResponsibility,
        zero_retention_allowed: true,
        content_retention_separate: true,
    });

    registry
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> RetentionRegistry {
        seed_retention_registry()
    }

    #[test]
    fn test_all_23_categories_exist() {
        let r = registry();
        assert_eq!(r.all().len(), 23, "Expected 23 retention categories");
    }

    #[test]
    fn test_all_have_unique_ids() {
        let r = registry();
        let mut ids: Vec<&str> = r.all().iter().map(|c| c.category_id.as_str()).collect();
        ids.sort();
        let mut deduped = ids.clone();
        deduped.dedup();
        assert_eq!(ids.len(), deduped.len(), "Duplicate category IDs found");
    }

    #[test]
    fn test_zero_retention_allowed_for_content_categories() {
        let r = registry();
        let content_categories = [
            "RET-001", "RET-005", "RET-006", "RET-014", "RET-015", "RET-022", "RET-023",
        ];
        for id in content_categories {
            let cat = r.get(id).unwrap_or_else(|| panic!("{} should exist", id));
            assert!(
                cat.zero_retention_allowed,
                "{} should allow zero retention",
                cat.category_name
            );
        }
    }

    #[test]
    fn test_content_retention_separate_from_events() {
        let r = registry();
        let body = r.get("RET-001").unwrap();
        assert!(body.content_retention_separate);

        let events = r.get("RET-007").unwrap();
        assert!(events.content_retention_separate);
        assert_ne!(
            body.default_retention_days, events.default_retention_days,
            "Content and event retention should differ"
        );
    }

    #[test]
    fn test_plan_limits_enforced() {
        let r = registry();
        assert!(
            r.validate_customer_selection("RET-001", "free", 7).is_err(),
            "Free plan should not allow 7-day message body retention"
        );
        assert!(
            r.validate_customer_selection("RET-001", "free", 1).is_ok(),
            "Free plan should allow 1-day message body retention"
        );
        assert!(
            r.validate_customer_selection("RET-001", "enterprise", 365)
                .is_ok(),
            "Enterprise should allow 365-day message body retention"
        );
        assert!(
            r.validate_customer_selection("RET-001", "enterprise", 400)
                .is_err(),
            "Enterprise should not allow 400-day message body retention"
        );
    }

    #[test]
    fn test_suppressions_indefinite_retention() {
        let r = registry();
        let supp = r.get("RET-013").unwrap();
        assert_eq!(
            supp.default_retention_days, 0,
            "Suppressions have indefinite retention (0 = never expire)"
        );
        assert!(
            supp.plan_specific_limit.is_none(),
            "Suppressions should not have plan limits"
        );
    }

    #[test]
    fn test_billing_minimum_retention() {
        let r = registry();
        let billing = r.get("RET-018").unwrap();
        assert!(
            billing.default_retention_days >= 2555,
            "Billing records must be retained at least 7 years"
        );
        assert!(
            billing.legal_retention_can_override,
            "Legal must be able to override billing retention"
        );
    }
}
