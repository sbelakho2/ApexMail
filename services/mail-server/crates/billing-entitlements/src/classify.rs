//! Closed capability/capacity model for plan entitlements.
//!
//! This module is the SINGLE authoritative classification of every
//! `PlanFeatures` field (defined in `billing-service/src/types.rs`). It is
//! deliberately data, not prose: `tools/check_feature_entitlements.py`
//! enumerates the struct fields at release time and fails unless each one
//! appears exactly once in [`PLAN_FEATURE_CLASSIFICATION`], so a new field
//! cannot ship without an explicit decision about whether it is enforced.
//!
//! # Classes
//!
//! * [`FeatureClass::RuntimeEnforced`] — the capability has a real handler
//!   gate. `FeatureKey::class()` for such a key is the only thing
//!   [`crate::EntitlementSnapshot::require_feature`] will grant.
//! * [`FeatureClass::ContractualOnly`] — a contract/deployment/support fact.
//!   It is deliberately NOT a runtime Boolean: `require_feature` refuses it
//!   so no handler can quietly treat e.g. `hipaa_compliance` as a gate.
//! * [`FeatureClass::NotYetImplemented`] — advertised in the pricing/type
//!   surface but with no runtime implementation. `require_feature` and
//!   `require_capacity` refuse it; presentation surfaces must render it as
//!   unavailable rather than as an upsell.

use serde::{Deserialize, Serialize};

/// How a priced capability or limit is (or is not) enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureClass {
    /// Enforced by real runtime code via `require_feature`/`require_capacity`.
    RuntimeEnforced,
    /// Contract, deployment, or support fact. Never used as an access gate.
    ContractualOnly,
    /// Priced/advertised but not implemented in the runtime.
    NotYetImplemented,
}

impl FeatureClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeEnforced => "RuntimeEnforced",
            Self::ContractualOnly => "ContractualOnly",
            Self::NotYetImplemented => "NotYetImplemented",
        }
    }
}

/// A priced *capability* (a boolean in `PlanFeatures`) that a handler can
/// gate with `EntitlementSnapshot::require_feature`.
///
/// The enum is CLOSED: adding a capability means adding a variant AND a
/// [`PLAN_FEATURE_CLASSIFICATION`] entry (the release gate enforces both).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureKey {
    /// `dedicated_ip` — dedicated sending IP allocation (eligibility-checked).
    DedicatedIp,
    /// `sso_enabled` — enterprise single sign-on.
    Sso,
    /// `audit_logs` — customer-facing audit log access.
    AuditLogs,
    /// `api_access` — API key minting / programmatic access.
    ApiAccess,
    /// `webhooks_enabled` — webhook endpoint creation.
    Webhooks,
    /// `inbound_email` — inbound mailbox provisioning / inbound event
    /// consumption.
    InboundEmail,
    /// `advanced_analytics` — advanced analytics endpoints (engagement,
    /// deliverability).
    AdvancedAnalytics,
    /// `send_time_optimization` — send-time recommendation endpoint.
    SendTimeOptimization,
    /// `ab_testing` — experiment creation.
    AbTesting,
    /// `time_travel_debugging` — historical message state replay/debugging.
    TimeTravelDebugging,
    /// `data_export` — analytics/contact data export.
    DataExport,
    /// `custom_tracking_domain` — custom open/click tracking domain setup.
    CustomTrackingDomain,
    /// `custom_templates` — template creation/customization.
    CustomTemplates,
    /// `template_approval_workflow` — maker/checker template publishing.
    TemplateApprovalWorkflow,
    /// `white_label` — removing ApexMail branding (renderer-central).
    WhiteLabel,
    /// `powered_by_footer` — the "powered by" footer switch (renderer-central).
    PoweredByFooter,
    /// `custom_retention` — editing message/event retention.
    CustomRetention,
    /// `subaccounts` — child workspaces with isolated quotas.
    Subaccounts,
    /// `byoip` — bring-your-own-IP (separate infrastructure flow).
    Byoip,
    /// `sla_guarantee` — contractual SLA.
    SlaGuarantee,
    /// `hipaa_compliance` — BAA eligibility review.
    HipaaCompliance,
    /// `soc2_compliance` — SOC 2 report availability.
    Soc2Compliance,
    /// `private_cloud` — dedicated deployment.
    PrivateCloud,
    /// `dedicated_csm` — dedicated customer success manager.
    DedicatedCsm,
    /// `priority_onboarding` — white-glove onboarding.
    PriorityOnboarding,
}

impl FeatureKey {
    /// Every capability key, so tests and presentation surfaces can iterate
    /// the closed enum without a wildcard match.
    pub const ALL: &'static [FeatureKey] = &[
        Self::DedicatedIp,
        Self::Sso,
        Self::AuditLogs,
        Self::ApiAccess,
        Self::Webhooks,
        Self::InboundEmail,
        Self::AdvancedAnalytics,
        Self::SendTimeOptimization,
        Self::AbTesting,
        Self::TimeTravelDebugging,
        Self::DataExport,
        Self::CustomTrackingDomain,
        Self::CustomTemplates,
        Self::TemplateApprovalWorkflow,
        Self::WhiteLabel,
        Self::PoweredByFooter,
        Self::CustomRetention,
        Self::Subaccounts,
        Self::Byoip,
        Self::SlaGuarantee,
        Self::HipaaCompliance,
        Self::Soc2Compliance,
        Self::PrivateCloud,
        Self::DedicatedCsm,
        Self::PriorityOnboarding,
    ];

    /// Serde/JSON field name in `PlanFeatures` (snake_case).
    pub const fn field_name(self) -> &'static str {
        match self {
            Self::DedicatedIp => "dedicated_ip",
            Self::Sso => "sso_enabled",
            Self::AuditLogs => "audit_logs",
            Self::ApiAccess => "api_access",
            Self::Webhooks => "webhooks_enabled",
            Self::InboundEmail => "inbound_email",
            Self::AdvancedAnalytics => "advanced_analytics",
            Self::SendTimeOptimization => "send_time_optimization",
            Self::AbTesting => "ab_testing",
            Self::TimeTravelDebugging => "time_travel_debugging",
            Self::DataExport => "data_export",
            Self::CustomTrackingDomain => "custom_tracking_domain",
            Self::CustomTemplates => "custom_templates",
            Self::TemplateApprovalWorkflow => "template_approval_workflow",
            Self::WhiteLabel => "white_label",
            Self::PoweredByFooter => "powered_by_footer",
            Self::CustomRetention => "custom_retention",
            Self::Subaccounts => "subaccounts",
            Self::Byoip => "byoip",
            Self::SlaGuarantee => "sla_guarantee",
            Self::HipaaCompliance => "hipaa_compliance",
            Self::Soc2Compliance => "soc2_compliance",
            Self::PrivateCloud => "private_cloud",
            Self::DedicatedCsm => "dedicated_csm",
            Self::PriorityOnboarding => "priority_onboarding",
        }
    }

    /// Stable machine name (same as the `PlanFeatures` field name).
    pub const fn as_str(self) -> &'static str {
        self.field_name()
    }

    /// Parse a canonical feature key (used for tenant feature-flag
    /// overrides, whose `flag_key` column is the snake_case field name).
    pub fn from_field_name(field: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|key| key.field_name() == field)
    }

    /// The classification of the `PlanFeatures` field that backs this key.
    pub fn class(self) -> FeatureClass {
        feature_classification(self).class
    }
}

/// A priced *capacity* (a numeric limit in `PlanFeatures`) that a handler can
/// gate with `EntitlementSnapshot::require_capacity`. `-1` means unlimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityKey {
    /// `dedicated_ip_count` — included dedicated IPs.
    DedicatedIps,
    /// `max_sending_domains` — sending domains per tenant.
    SendingDomains,
    /// `max_retention_days` — retention ceiling (data/event age).
    RetentionDays,
    /// `max_team_members` — seats, including invited-but-unactivated users.
    TeamMembers,
    /// `max_subaccounts` — child workspaces.
    Subaccounts,
}

impl CapacityKey {
    pub const ALL: &'static [CapacityKey] = &[
        Self::DedicatedIps,
        Self::SendingDomains,
        Self::RetentionDays,
        Self::TeamMembers,
        Self::Subaccounts,
    ];

    pub const fn field_name(self) -> &'static str {
        match self {
            Self::DedicatedIps => "dedicated_ip_count",
            Self::SendingDomains => "max_sending_domains",
            Self::RetentionDays => "max_retention_days",
            Self::TeamMembers => "max_team_members",
            Self::Subaccounts => "max_subaccounts",
        }
    }

    pub const fn as_str(self) -> &'static str {
        self.field_name()
    }

    /// The classification of the `PlanFeatures` field that backs this key.
    pub fn class(self) -> FeatureClass {
        capacity_classification(self).class
    }
}

/// Which gate (if any) the `PlanFeatures` field maps to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// Boolean capability gated by `require_feature`.
    Feature(FeatureKey),
    /// Numeric limit gated by `require_capacity`.
    Capacity(CapacityKey),
    /// No key: contract/presentation fact, or unimplemented without a key.
    None,
}

/// One row of the release-audited classification table.
#[derive(Debug, Clone, Copy)]
pub struct FieldClassification {
    /// `PlanFeatures` field name (serde/JSON key).
    pub field: &'static str,
    pub class: FeatureClass,
    pub gate: Gate,
    /// Why this class, in one sentence. Checked non-empty by the release
    /// gate and by unit tests.
    pub rationale: &'static str,
}

/// Every `PlanFeatures` field, classified exactly once.
///
/// The ordering mirrors `PlanFeatures` in `billing-service/src/types.rs`.
/// Before editing: change the struct field, the enum variant, the
/// classification entry, and the handler gate together. The release gate
/// (`tools/check_feature_entitlements.py`) fails otherwise.
pub const PLAN_FEATURE_CLASSIFICATION: &[FieldClassification] = &[
    // ── Infrastructure ─────────────────────────────────────────────
    // RuntimeEnforced — `dedicated_ips::allocate_ip` requires
    // `FeatureKey::DedicatedIp` before the provider is called.
    FieldClassification {
        field: "dedicated_ip",
        class: FeatureClass::RuntimeEnforced,
        gate: Gate::Feature(FeatureKey::DedicatedIp),
        rationale: "Dedicated IP allocation is a real handler and is gated per tenant; eligibility review remains a separate operational step.",
    },
    // ContractualOnly — this number drives INVOICING (IPs within the count
    // are included; extras are billed as pending_charge), never a denial
    // gate. `require_capacity(CapacityKey::DedicatedIps, _)` refuses it.
    FieldClassification {
        field: "dedicated_ip_count",
        class: FeatureClass::ContractualOnly,
        gate: Gate::Capacity(CapacityKey::DedicatedIps),
        rationale: "Included-IP count is a billing term: extra IPs are charged, not refused, so it must not be used as an access gate.",
    },
    // RuntimeEnforced — `domains::create_domain` gates domain creation
    // with `require_capacity(CapacityKey::SendingDomains, count + 1)`.
    FieldClassification {
        field: "max_sending_domains",
        class: FeatureClass::RuntimeEnforced,
        gate: Gate::Capacity(CapacityKey::SendingDomains),
        rationale: "Sending domains are created through a real handler and the existing count check is now an entitlement capacity gate.",
    },

    // ── Auth & Security ────────────────────────────────────────────
    // RuntimeEnforced — the SSO-enforced login path requires
    // `FeatureKey::Sso` before honouring `ent_sso_configurations`.
    FieldClassification {
        field: "sso_enabled",
        class: FeatureClass::RuntimeEnforced,
        gate: Gate::Feature(FeatureKey::Sso),
        rationale: "Enterprise SSO is consumed at login; a tenant that enforces SSO without the entitlement is refused instead of silently receiving it.",
    },
    // NotYetImplemented — audit rows are written in api-server, but no
    // customer-facing audit read/export handler exists (the `/audit`
    // surface is operator-only). Removed from the paid plan seeds.
    FieldClassification {
        field: "audit_logs",
        class: FeatureClass::NotYetImplemented,
        gate: Gate::Feature(FeatureKey::AuditLogs),
        rationale: "No customer audit-log read surface exists in api-server; selling the flag would be pricing metadata only.",
    },

    // ── API & Integrations ─────────────────────────────────────────
    // RuntimeEnforced — API key minting requires `FeatureKey::ApiAccess`.
    FieldClassification {
        field: "api_access",
        class: FeatureClass::RuntimeEnforced,
        gate: Gate::Feature(FeatureKey::ApiAccess),
        rationale: "Programmatic access begins at API key creation, which now requires the entitlement.",
    },
    // RuntimeEnforced — `webhooks::create_webhook` requires
    // `FeatureKey::Webhooks`.
    FieldClassification {
        field: "webhooks_enabled",
        class: FeatureClass::RuntimeEnforced,
        gate: Gate::Feature(FeatureKey::Webhooks),
        rationale: "Webhook endpoints are customer-created rows; creation requires the entitlement.",
    },
    // RuntimeEnforced — inbound event consumption requires
    // `FeatureKey::InboundEmail` (webhook subscription to `inbound`
    // events). Raw SMTP acceptance is deliberately never gated.
    FieldClassification {
        field: "inbound_email",
        class: FeatureClass::RuntimeEnforced,
        gate: Gate::Feature(FeatureKey::InboundEmail),
        rationale: "Inbound consumption is gated where api-server can see it (inbound event subscriptions); raw MX acceptance must not be gated.",
    },

    // ── Analytics ──────────────────────────────────────────────────
    // RuntimeEnforced — `analytics::engagement`/`deliverability` require
    // `FeatureKey::AdvancedAnalytics`.
    FieldClassification {
        field: "advanced_analytics",
        class: FeatureClass::RuntimeEnforced,
        gate: Gate::Feature(FeatureKey::AdvancedAnalytics),
        rationale: "Advanced endpoints are separate handlers and are now gated; the basic dashboard/volume endpoints stay available.",
    },
    // RuntimeEnforced — `ai_insights::send_time_optimization` requires
    // `FeatureKey::SendTimeOptimization`.
    FieldClassification {
        field: "send_time_optimization",
        class: FeatureClass::RuntimeEnforced,
        gate: Gate::Feature(FeatureKey::SendTimeOptimization),
        rationale: "The recommendation endpoint is the feature and now requires the entitlement.",
    },
    // NotYetImplemented — no experiment-creation handler exists; the flag
    // was removed from the paid seeds.
    FieldClassification {
        field: "ab_testing",
        class: FeatureClass::NotYetImplemented,
        gate: Gate::Feature(FeatureKey::AbTesting),
        rationale: "No experiment creation surface exists in api-server, so there is nothing to gate; not sold until implemented.",
    },
    // NotYetImplemented — no historical state replay implementation; the
    // field is removed from the paid seeds rather than sold as metadata.
    FieldClassification {
        field: "time_travel_debugging",
        class: FeatureClass::NotYetImplemented,
        gate: Gate::Feature(FeatureKey::TimeTravelDebugging),
        rationale: "The audit found this advertised without any runtime implementation; it is no longer priced.",
    },
    // RuntimeEnforced — `analytics::export`, `export_pdf`,
    // `download_export` and the contacts CSV form require
    // `FeatureKey::DataExport`.
    FieldClassification {
        field: "data_export",
        class: FeatureClass::RuntimeEnforced,
        gate: Gate::Feature(FeatureKey::DataExport),
        rationale: "Export handlers create jobs/artifacts and now require the entitlement.",
    },

    // ── Customization ──────────────────────────────────────────────
    // NotYetImplemented — no tracking-domain setup handler exists in
    // api-server; removed from the paid seeds.
    FieldClassification {
        field: "custom_tracking_domain",
        class: FeatureClass::NotYetImplemented,
        gate: Gate::Feature(FeatureKey::CustomTrackingDomain),
        rationale: "Domains are created without a tracking-domain surface, so the flag cannot be enforced and is not sold.",
    },
    // RuntimeEnforced — template create/update (JSON and form) require
    // `FeatureKey::CustomTemplates`.
    FieldClassification {
        field: "custom_templates",
        class: FeatureClass::RuntimeEnforced,
        gate: Gate::Feature(FeatureKey::CustomTemplates),
        rationale: "Template write handlers are the customization surface and now require the entitlement.",
    },
    // NotYetImplemented — no approval-workflow state exists on templates;
    // removed from the paid seeds.
    FieldClassification {
        field: "template_approval_workflow",
        class: FeatureClass::NotYetImplemented,
        gate: Gate::Feature(FeatureKey::TemplateApprovalWorkflow),
        rationale: "No maker/checker publishing path exists; not sold until implemented.",
    },
    // ContractualOnly — branding is applied by the central renderer and
    // enterprise agreement, never a per-request API gate.
    FieldClassification {
        field: "white_label",
        class: FeatureClass::ContractualOnly,
        gate: Gate::Feature(FeatureKey::WhiteLabel),
        rationale: "White-label branding is a renderer/deployment concern delivered by contract; handlers must not branch on it.",
    },
    // ContractualOnly — the footer is controlled by the central renderer;
    // the database default (`true`) is presentational only.
    FieldClassification {
        field: "powered_by_footer",
        class: FeatureClass::ContractualOnly,
        gate: Gate::Feature(FeatureKey::PoweredByFooter),
        rationale: "Footer branding is a renderer presentation switch, not an access gate.",
    },

    // ── Retention ──────────────────────────────────────────────────
    // NotYetImplemented — there is no retention-editing handler; removed
    // from the paid seeds.
    FieldClassification {
        field: "custom_retention",
        class: FeatureClass::NotYetImplemented,
        gate: Gate::Feature(FeatureKey::CustomRetention),
        rationale: "No customer retention-editing surface exists; retention is operator-set until an editing handler lands.",
    },
    // NotYetImplemented — the ceiling is displayed but no editing handler
    // validates against it yet.
    FieldClassification {
        field: "max_retention_days",
        class: FeatureClass::NotYetImplemented,
        gate: Gate::Capacity(CapacityKey::RetentionDays),
        rationale: "Advertised retention ceiling without a validated editing surface; must not be treated as enforced.",
    },

    // ── Team ───────────────────────────────────────────────────────
    // RuntimeEnforced — team invitations check
    // `require_capacity(CapacityKey::TeamMembers, seats + 1)` inside the
    // invitation transaction.
    FieldClassification {
        field: "max_team_members",
        class: FeatureClass::RuntimeEnforced,
        gate: Gate::Capacity(CapacityKey::TeamMembers),
        rationale: "Seats are consumed by a real invitation handler; the check runs transactionally with the insert.",
    },
    // NotYetImplemented — no subaccount resource exists in the runtime;
    // removed from the paid seeds.
    FieldClassification {
        field: "subaccounts",
        class: FeatureClass::NotYetImplemented,
        gate: Gate::Feature(FeatureKey::Subaccounts),
        rationale: "No subaccount creation surface exists; not sold until implemented.",
    },
    // NotYetImplemented — no subaccount creation surface to enforce the
    // limit on; removed from the paid seeds.
    FieldClassification {
        field: "max_subaccounts",
        class: FeatureClass::NotYetImplemented,
        gate: Gate::Capacity(CapacityKey::Subaccounts),
        rationale: "Capacity for a resource that cannot yet be created; not sold until implemented.",
    },

    // ── Support ────────────────────────────────────────────────────
    // ContractualOnly — describes the human support channel; see
    // `docs/enterprise/support.md`. Not an access gate.
    FieldClassification {
        field: "support_level",
        class: FeatureClass::ContractualOnly,
        gate: Gate::None,
        rationale: "Support policy is contractual and process-delivered; never checked as a runtime Boolean.",
    },
    // ContractualOnly — a named CSM is a staffing commitment, not a gate.
    FieldClassification {
        field: "dedicated_csm",
        class: FeatureClass::ContractualOnly,
        gate: Gate::Feature(FeatureKey::DedicatedCsm),
        rationale: "Delivered by the support org per contract; the flag is advisory.",
    },
    // ContractualOnly — onboarding is a scheduled process, not a gate.
    FieldClassification {
        field: "priority_onboarding",
        class: FeatureClass::ContractualOnly,
        gate: Gate::Feature(FeatureKey::PriorityOnboarding),
        rationale: "Onboarding priority is a process commitment; no handler may branch on it.",
    },

    // ── Enterprise ─────────────────────────────────────────────────
    // ContractualOnly — BYOIP is a separate reviewed infrastructure flow.
    FieldClassification {
        field: "byoip",
        class: FeatureClass::ContractualOnly,
        gate: Gate::Feature(FeatureKey::Byoip),
        rationale: "Bring-your-own-IP is provisioned by a separate operational flow with legal/network review, not an API Boolean.",
    },
    // ContractualOnly — an SLA exists only inside a signed contract.
    FieldClassification {
        field: "sla_guarantee",
        class: FeatureClass::ContractualOnly,
        gate: Gate::Feature(FeatureKey::SlaGuarantee),
        rationale: "SLA commitments are contractual; the Boolean must never be read as runtime availability.",
    },
    // ContractualOnly — the credit percentage is a contract term.
    FieldClassification {
        field: "sla_credit_percentage",
        class: FeatureClass::ContractualOnly,
        gate: Gate::None,
        rationale: "SLA credits are computed from the signed contract, not the plan JSON.",
    },
    // ContractualOnly — BAA eligibility requires review; the Boolean never
    // implies HIPAA certification.
    FieldClassification {
        field: "hipaa_compliance",
        class: FeatureClass::ContractualOnly,
        gate: Gate::Feature(FeatureKey::HipaaCompliance),
        rationale: "BAA availability is reviewed per customer; never treat the flag as compliance certification.",
    },
    // ContractualOnly — the SOC 2 report is shared under NDA; the Boolean
    // never implies certification.
    FieldClassification {
        field: "soc2_compliance",
        class: FeatureClass::ContractualOnly,
        gate: Gate::Feature(FeatureKey::Soc2Compliance),
        rationale: "SOC 2 availability is an audit/report fact; never treat the flag as certification.",
    },
    // ContractualOnly — private cloud is a deployment fact.
    FieldClassification {
        field: "private_cloud",
        class: FeatureClass::ContractualOnly,
        gate: Gate::Feature(FeatureKey::PrivateCloud),
        rationale: "Dedicated infrastructure is chosen at deployment time, not granted by a request-path check.",
    },
];

/// The unique classification row for a `PlanFeatures` field name.
pub fn classification_for_field(field: &str) -> Option<&'static FieldClassification> {
    PLAN_FEATURE_CLASSIFICATION
        .iter()
        .find(|entry| entry.field == field)
}

/// The classification row backing a capability key.
pub fn feature_classification(key: FeatureKey) -> &'static FieldClassification {
    // Invariant: every variant has exactly one entry (unit-tested).
    classification_for_field(key.field_name())
        .expect("every FeatureKey has a PlanFeatures classification entry")
}

/// The classification row backing a capacity key.
pub fn capacity_classification(key: CapacityKey) -> &'static FieldClassification {
    classification_for_field(key.field_name())
        .expect("every CapacityKey has a PlanFeatures classification entry")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_field_is_classified_exactly_once() {
        let mut seen = std::collections::BTreeSet::new();
        for entry in PLAN_FEATURE_CLASSIFICATION {
            assert!(
                seen.insert(entry.field),
                "duplicate classification for {}",
                entry.field
            );
            assert!(
                !entry.rationale.trim().is_empty(),
                "{} must state why it is classified {}",
                entry.field,
                entry.class.as_str()
            );
        }
    }

    #[test]
    fn feature_keys_map_to_feature_gates() {
        for key in FeatureKey::ALL {
            let entry = feature_classification(*key);
            assert_eq!(
                entry.gate,
                Gate::Feature(*key),
                "{} must map to its feature gate",
                key.field_name()
            );
        }
    }

    #[test]
    fn capacity_keys_map_to_capacity_gates() {
        for key in CapacityKey::ALL {
            let entry = capacity_classification(*key);
            assert_eq!(
                entry.gate,
                Gate::Capacity(*key),
                "{} must map to its capacity gate",
                key.field_name()
            );
        }
    }

    #[test]
    fn classes_are_one_of_the_three_release_classes() {
        for entry in PLAN_FEATURE_CLASSIFICATION {
            assert!(matches!(
                entry.class,
                FeatureClass::RuntimeEnforced
                    | FeatureClass::ContractualOnly
                    | FeatureClass::NotYetImplemented
            ));
        }
    }

    #[test]
    fn field_name_round_trips_through_from_field_name() {
        for key in FeatureKey::ALL {
            assert_eq!(FeatureKey::from_field_name(key.field_name()), Some(*key));
        }
        assert_eq!(FeatureKey::from_field_name("not_a_field"), None);
    }
}
