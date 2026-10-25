//! The per-tenant outbound delivery routing mode (`tenants.settings.routingMode`).
//!
//! The mode is a tenant FACT stored in the tenant settings JSON, the same
//! object `billingCurrency` lives in (`api-server::routes::billing`
//! `resolve_tenant_billing_currency` reads it the same way). The typed reader
//! is shared by the API surface that writes it and the worker that must
//! ENFORCE it on the send path, so the two can never disagree about what a
//! stored value means.
//!
//! * [`RoutingMode::Global`], the default when the key is absent. The send
//!   path keeps its historical behaviour: a selected dedicated IP rides
//!   ApexMail's own relay MTA, everything else rides the shared pool.
//! * [`RoutingMode::EuOnly`], EU-only routing. Every send MUST leave through
//!   ApexMail's OWN relay MTA; the shared third-party transport (AWS SES) is
//!   forbidden. When no own-MTA route is available the worker HOLDS the
//!   message with a named reason, it never fails over to the third-party
//!   transport (the plan's headline invariant: "EU-only mail fails closed").
//!
//! # Fail-closed resolution
//!
//! [`RoutingMode::from_settings_json`] resolves the stored value honestly:
//!
//! * key ABSENT (or explicit JSON `null`) → [`RoutingMode::Global`], the
//!   documented default that preserves every existing tenant's routing;
//! * a recognized value (`global`, `eu_only`, case-insensitive after trim) →
//!   that mode;
//! * ANY OTHER value (a typo, casing drift, a non-string) →
//!   [`RoutingMode::EuOnly`]. The only safe reading of a corrupted mode that
//!   *might* mean EU-only is the strict one: routing a residency-bound
//!   message through a transport the customer meant to exclude is
//!   unrecallable, while a held message is visible, inspectable and
//!   releasable. [`RoutingMode::resolve_value`] reports the unrecognized raw
//!   value so callers can log loudly instead of misreading it silently.
//!
//! # The self-serve add-on flag (`settings.addons.euOnlyRouting`)
//!
//! EU-only routing is included on Enterprise Cloud (and the Compliance
//! contract line) and sold as a monthly add-on on self-serve Pro and above
//! (`platform-catalog::addon_by_name("eu_only_routing")`, €149/$165). There
//! is no generic add-on table in the billing runtime (the dedicated-IP
//! add-on lives as `dedicated_ips.billing_status`), so the purchased
//! self-serve add-on is recorded as a boolean in the same settings object:
//!
//! ```json
//! { "addons": { "euOnlyRouting": true }, "routingMode": "eu_only" }
//! ```
//!
//! The billing flow that records a purchase sets
//! `settings.addons.euOnlyRouting = true` (and clears it on cancel); the
//! activation gate in the API accepts either the plan entitlement
//! (`eu_only_routing` on the plan's features) or this flag.
//! [`eu_only_addon_enabled`] is strict: only a JSON `true` counts.

use serde::{Deserialize, Serialize};

/// The tenant's outbound routing mode (see the module docs).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingMode {
    /// Default: dedicated-IP sends ride our relay MTA, everything else the
    /// shared pool (AWS SES in managed deployments).
    #[default]
    Global,
    /// EU-only: own-MTA transport only. No third-party transport may carry
    /// the message; an unavailable own-MTA route HOLDS it.
    EuOnly,
}

/// The settings key holding the mode (`tenants.settings.routingMode`).
pub const ROUTING_MODE_SETTINGS_KEY: &str = "routingMode";

/// The settings key holding the self-serve add-on flag
/// (`tenants.settings.addons.euOnlyRouting`).
pub const EU_ONLY_ADDON_SETTINGS_KEY: &str = "euOnlyRouting";

/// The parent object for add-on flags (`tenants.settings.addons`).
pub const ADDONS_SETTINGS_KEY: &str = "addons";

impl RoutingMode {
    /// Every mode, so validation surfaces can enumerate without a wildcard.
    pub const ALL: &'static [RoutingMode] = &[Self::Global, Self::EuOnly];

    /// Stable wire/settings value (`global` | `eu_only`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::EuOnly => "eu_only",
        }
    }

    /// Parse a canonical value (trimmed, ASCII-case-insensitive). `None` for
    /// anything unrecognized, callers decide how to fail (the send path
    /// fails closed; the API rejects with 400).
    pub fn parse(raw: &str) -> Option<Self> {
        let normalized = raw.trim().to_ascii_lowercase();
        Self::ALL
            .iter()
            .copied()
            .find(|mode| mode.as_str() == normalized)
    }

    /// True for [`RoutingMode::EuOnly`].
    pub const fn is_eu_only(self) -> bool {
        matches!(self, Self::EuOnly)
    }

    /// Resolve one stored JSON value with provenance, so a caller can log an
    /// unrecognized value while still failing closed.
    pub fn resolve_value(value: Option<&serde_json::Value>) -> ResolvedRoutingMode {
        match value {
            // Absent or explicit null: the documented default.
            None | Some(serde_json::Value::Null) => ResolvedRoutingMode {
                mode: Self::Global,
                unrecognized: None,
            },
            Some(serde_json::Value::String(raw)) => match Self::parse(raw) {
                Some(mode) => ResolvedRoutingMode {
                    mode,
                    unrecognized: None,
                },
                None => ResolvedRoutingMode {
                    mode: Self::EuOnly,
                    unrecognized: Some(raw.clone()),
                },
            },
            // A non-string value is not a mode: fail closed to the strict
            // mode and report what was stored.
            Some(other) => ResolvedRoutingMode {
                mode: Self::EuOnly,
                unrecognized: Some(other.to_string()),
            },
        }
    }

    /// Resolve the mode from a tenant settings object (see module docs).
    pub fn from_settings_json(settings: &serde_json::Value) -> Self {
        Self::resolve_value(settings.get(ROUTING_MODE_SETTINGS_KEY)).mode
    }
}

/// The result of resolving a stored mode value (see
/// [`RoutingMode::resolve_value`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRoutingMode {
    /// The mode to act on (fail closed).
    pub mode: RoutingMode,
    /// The raw stored value when it was not a recognized mode (or was not a
    /// string at all), present so the caller can log/hold with the exact
    /// offending value.
    pub unrecognized: Option<String>,
}

/// Whether the purchased self-serve EU-only add-on is recorded in the tenant
/// settings. Strict: only a JSON `true` counts (a string `"true"`, a number,
/// or an absent key all deny, the gate must not be spoofable by a loosely
/// typed value).
pub fn eu_only_addon_enabled(settings: &serde_json::Value) -> bool {
    settings
        .get(ADDONS_SETTINGS_KEY)
        .and_then(|addons| addons.get(EU_ONLY_ADDON_SETTINGS_KEY))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn absent_and_null_settings_default_to_global() {
        assert_eq!(
            RoutingMode::from_settings_json(&json!({})),
            RoutingMode::Global
        );
        assert_eq!(
            RoutingMode::from_settings_json(&json!({"routingMode": null})),
            RoutingMode::Global
        );
        assert_eq!(RoutingMode::default(), RoutingMode::Global);
        assert!(!RoutingMode::Global.is_eu_only());
    }

    #[test]
    fn recognized_values_round_trip() {
        for mode in RoutingMode::ALL {
            assert_eq!(RoutingMode::parse(mode.as_str()), Some(*mode));
            let settings = json!({ "routingMode": mode.as_str() });
            assert_eq!(RoutingMode::from_settings_json(&settings), *mode);
        }
        // Trimmed + case-insensitive on read; the canonical form is written.
        assert_eq!(RoutingMode::parse(" EU_ONLY "), Some(RoutingMode::EuOnly));
        assert_eq!(
            RoutingMode::from_settings_json(&json!({"routingMode": "Global"})),
            RoutingMode::Global
        );
        assert_eq!(RoutingMode::EuOnly.as_str(), "eu_only");
        assert!(RoutingMode::EuOnly.is_eu_only());
        assert_eq!(RoutingMode::parse(""), None);
        assert_eq!(RoutingMode::parse("eu-only"), None);
    }

    /// A corrupted value must fail CLOSED: the only safe reading of a mode
    /// that might mean EU-only is the strict one, and the resolver reports
    /// the offending raw value for the hold/log.
    #[test]
    fn unrecognized_values_fail_closed_to_eu_only_with_the_raw_value() {
        let resolved = RoutingMode::resolve_value(Some(&json!("eu-only")));
        assert_eq!(resolved.mode, RoutingMode::EuOnly);
        assert_eq!(resolved.unrecognized.as_deref(), Some("eu-only"));

        for corrupt in [
            json!(true),
            json!(3),
            json!(["eu_only"]),
            json!({"mode": "eu_only"}),
        ] {
            let settings = json!({ "routingMode": corrupt.clone() });
            let resolved = RoutingMode::resolve_value(settings.get(ROUTING_MODE_SETTINGS_KEY));
            assert_eq!(
                resolved.mode,
                RoutingMode::EuOnly,
                "non-string {corrupt} must fail closed"
            );
            assert!(resolved.unrecognized.is_some(), "{corrupt}");
        }

        // The absent/null cases stay Global (carve-out above).
        assert_eq!(RoutingMode::resolve_value(None).unrecognized, None);
        assert_eq!(
            RoutingMode::resolve_value(Some(&serde_json::Value::Null)).unrecognized,
            None
        );
    }

    #[test]
    fn addon_flag_is_strict_boolean() {
        assert!(eu_only_addon_enabled(&json!({
            "addons": { "euOnlyRouting": true }
        })));
        assert!(!eu_only_addon_enabled(&json!({})));
        assert!(!eu_only_addon_enabled(&json!({"addons": {}})));
        assert!(!eu_only_addon_enabled(
            &json!({"addons": { "euOnlyRouting": false }})
        ));
        // Loose shapes must not open the gate.
        assert!(!eu_only_addon_enabled(
            &json!({"addons": { "euOnlyRouting": "true" }})
        ));
        assert!(!eu_only_addon_enabled(&json!({"addons": "euOnlyRouting"})));
        assert!(!eu_only_addon_enabled(
            &json!({"addons": { "euOnlyRouting": 1 }})
        ));
    }

    #[test]
    fn settings_keys_are_the_documented_shape() {
        assert_eq!(ROUTING_MODE_SETTINGS_KEY, "routingMode");
        assert_eq!(EU_ONLY_ADDON_SETTINGS_KEY, "euOnlyRouting");
        // The combined shape the billing flow writes on purchase.
        let purchased = json!({
            "addons": { "euOnlyRouting": true },
            "routingMode": "eu_only"
        });
        assert!(eu_only_addon_enabled(&purchased));
        assert_eq!(
            RoutingMode::from_settings_json(&purchased),
            RoutingMode::EuOnly
        );
    }
}
