//! The provider registry: ONE configured payment provider, resolved fail
//! closed (external audit, P0-A, step 3).
//!
//! `PAYMENTS_PROVIDER` selects the adapter. The default and, this round,
//! the ONLY supported value is `mollie`; an unknown value is a typed
//! configuration error, never a silent fallback to a different processor
//! (money must never move through a provider the operator did not name).
//! Provider CONSTRUCTION is validated after the kind check: a selected
//! provider whose credentials are missing still fails closed, visibly.

use std::sync::Arc;

use super::mollie_provider::MollieProvider;
use super::PaymentProvider;

/// The environment variable that selects the payment provider.
pub const PROVIDER_ENV_VAR: &str = "PAYMENTS_PROVIDER";

/// The adapters this build can construct. Extending the list (steps 11-18
/// of the mandated order) is a code change, never a runtime guess.
pub const SUPPORTED_PROVIDERS: &[&str] = &["mollie"];

/// The configured provider kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    Mollie,
}

impl ProviderKind {
    /// The adapter name this kind resolves to.
    pub fn name(self) -> &'static str {
        match self {
            ProviderKind::Mollie => "mollie",
        }
    }
}

/// Typed registry failures. Both variants are deployment/configuration
/// problems the operator must fix; neither is retried by callers.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// `PAYMENTS_PROVIDER` names a provider this build cannot construct.
    /// Fail closed: no fallback provider is ever silently selected.
    #[error(
        "PAYMENTS_PROVIDER={value:?} is not a supported payment provider \
         (supported: {supported:?}); refusing to fall back"
    )]
    UnknownProvider {
        value: String,
        supported: &'static [&'static str],
    },
    /// The selected provider is configured but its credentials/setup are
    /// incomplete; the underlying message names what is missing.
    #[error("payment provider setup failed: {0}")]
    ProviderSetup(String),
}

/// Resolve a raw configuration value to a provider kind. Empty (unset or
/// blank) resolves to the default provider; matching is ASCII
/// case-insensitive so operator configuration stays forgiving, but nothing
/// unknown is ever accepted.
pub fn provider_kind_from_value(raw: &str) -> Result<ProviderKind, RegistryError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("mollie") {
        return Ok(ProviderKind::Mollie);
    }
    Err(RegistryError::UnknownProvider {
        value: trimmed.to_string(),
        supported: SUPPORTED_PROVIDERS,
    })
}

/// The configured provider kind from the environment (default when unset).
pub fn kind_from_env() -> Result<ProviderKind, RegistryError> {
    let raw = std::env::var(PROVIDER_ENV_VAR).unwrap_or_default();
    provider_kind_from_value(&raw)
}

/// The configured provider, constructed and ready. The one entry point
/// domain modules use; they never name an adapter type.
pub fn from_env() -> Result<Arc<dyn PaymentProvider>, RegistryError> {
    from_value(&std::env::var(PROVIDER_ENV_VAR).unwrap_or_default())
}

/// Resolve the provider from a raw configuration VALUE: the exact path
/// [`from_env`] takes, pure with respect to the environment (tests drive
/// the fail-closed contract through here without mutating process env).
pub fn from_value(raw: &str) -> Result<Arc<dyn PaymentProvider>, RegistryError> {
    match provider_kind_from_value(raw)? {
        ProviderKind::Mollie => MollieProvider::from_env()
            .map(|provider| Arc::new(provider) as Arc<dyn PaymentProvider>)
            .map_err(|error| RegistryError::ProviderSetup(error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_provider_is_the_only_supported_provider() {
        assert_eq!(SUPPORTED_PROVIDERS, ["mollie"].as_slice());
        assert_eq!(provider_kind_from_value("").unwrap(), ProviderKind::Mollie);
        assert_eq!(
            provider_kind_from_value("   ").unwrap(),
            ProviderKind::Mollie
        );
        assert_eq!(
            provider_kind_from_value("mollie").unwrap(),
            ProviderKind::Mollie
        );
        // Case-insensitive: operator configuration stays forgiving, the
        // resolved name is still the canonical lowercase adapter name.
        assert_eq!(
            provider_kind_from_value("MOLLIE").unwrap(),
            ProviderKind::Mollie
        );
        assert_eq!(ProviderKind::Mollie.name(), "mollie");
    }

    #[test]
    fn unknown_providers_fail_closed_with_a_typed_error() {
        // Stripe is FORBIDDEN this round (steps 11-18 are owner-gated);
        // naming it here is exactly the fail-closed case. Surrounding
        // whitespace is trimmed before matching (the forgiving arm asserted
        // above), so these values are genuinely unknown processors.
        for value in ["stripe", "adyen", "paypal", "m ollie", "0", "null"] {
            let error = provider_kind_from_value(value).expect_err("must fail closed");
            match &error {
                RegistryError::UnknownProvider {
                    value: rejected,
                    supported,
                } => {
                    assert_eq!(rejected, value.trim());
                    assert_eq!(supported, &SUPPORTED_PROVIDERS);
                }
                _ => panic!("expected UnknownProvider, got a provider handle"),
            }
            assert!(error.to_string().contains("refusing to fall back"));
        }
    }

    /// The registry resolves through the SAME value path from_env uses, so
    /// the fail-closed contract is provable without mutating process env
    /// (this binary's other suites race env vars; a pure oracle is
    /// deterministic by construction).
    #[test]
    fn from_value_rejects_an_unknown_provider_before_anything_is_constructed() {
        // The kind check fails closed BEFORE provider construction, so no
        // provider credential is even consulted.
        match from_value("stripe") {
            Err(RegistryError::UnknownProvider { value, .. }) => assert_eq!(value, "stripe"),
            _ => panic!("expected UnknownProvider, got a provider handle"),
        }
    }

    #[test]
    fn from_value_default_resolves_or_reports_setup_visibly() {
        // Unset/blank/mollie all select the default adapter, which is then
        // CONSTRUCTED: either it resolves (credentials present) or it
        // reports a typed setup failure naming what is missing. Both arms
        // are fail-closed; a third outcome (a different provider, a
        // panic) is impossible by construction. This test never mutates
        // the credential environment: it asserts on the world it finds.
        for value in ["", "   ", "mollie", "MOLLIE"] {
            let provider = from_value(value);
            match provider {
                Ok(provider) => assert_eq!(provider.provider_name(), "mollie"),
                Err(RegistryError::ProviderSetup(message)) => {
                    assert!(
                        message.contains("Mollie"),
                        "names the missing setup: {message}"
                    )
                }
                Err(other) => panic!("unexpected registry error for {value:?}: {other:?}"),
            }
        }
    }
}
