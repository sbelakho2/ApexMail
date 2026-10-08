//! Transitional gate for capabilities whose runtime implementation has
//! landed but whose `billing-entitlements/src/classify.rs` entry still says
//! `NotYetImplemented`.
//!
//! `EntitlementSnapshot::require_feature` deliberately refuses every
//! non-`RuntimeEnforced` field (`NotRuntimeEnforced`), and `apply_override`
//! ignores tenant flag overrides for such fields. That is the correct
//! fail-closed behaviour for a capability that has NO implementation — but
//! for a capability that is now implemented and only waiting for the
//! classification flip (owned by the capabilities wave-1 agent), blindly
//! calling `require_feature` would turn every request into a 500
//! "gate misconfigured" instead of an honest customer refusal.
//!
//! [`require_feature_with_fixture`] therefore:
//!
//! 1. runs the canonical gate first — once `classify.rs` is flipped to
//!    `RuntimeEnforced` (wave-1, on this agent's reported diff), the plan
//!    Boolean / tenant override path is the ONE authority;
//! 2. while the field is still `NotYetImplemented`/`ContractualOnly`, reads
//!    the effective plan's RAW Boolean for the field (the same
//!    override-aware plan lookup entitlement resolution uses). Production
//!    seeds keep these flags false until the flip, so the surface stays
//!    refused with the SAME named reason a non-entitled plan gets
//!    (`plan \`X\` does not include \`field\``); tests seed the fixture plan
//!    with the flag true to exercise the implemented happy path today.
//!
//! REMOVE the pre-flip branch once `classify.rs` carries the
//! `RuntimeEnforced` flip for the capability.

use billing_entitlements::{EntitlementError, EntitlementSnapshot, FeatureKey};

use crate::error::ApiError;
use crate::state::AppState;

/// Enforce a capability gate with the pre-classification-flip fixture seam
/// (see the module docs). Returns the resolved snapshot on success.
pub(crate) async fn require_feature_with_fixture(
    state: &AppState,
    tenant_id: &str,
    key: FeatureKey,
) -> Result<EntitlementSnapshot, ApiError> {
    let snapshot = crate::entitlements::snapshot(state, tenant_id).await?;
    match snapshot.require_feature(key) {
        Ok(()) => Ok(snapshot),
        // Not entitled — the runtime-enforced refusal, and the shape the
        // pre-flip branch below mirrors exactly.
        Err(error @ EntitlementError::FeatureNotEntitled { .. }) => {
            Err(ApiError::Forbidden(error.to_string()))
        }
        Err(EntitlementError::NotRuntimeEnforced { .. }) => {
            if raw_plan_flag_granted(state, tenant_id, key).await? {
                // Fixture/seed granted the raw flag: the implementation has
                // landed and the plan carries the capability. Wave-1's
                // classify flip makes this branch unreachable.
                Ok(snapshot)
            } else {
                Err(ApiError::Forbidden(format!(
                    "plan `{}` does not include `{}`",
                    snapshot.plan(),
                    key.field_name()
                )))
            }
        }
        // A feature gate can never produce these (capacity-only).
        Err(
            error @ (EntitlementError::InvalidAmount { .. }
            | EntitlementError::CapacityExceeded { .. }),
        ) => Err(ApiError::Internal(format!(
            "entitlement gate misconfigured: {error}"
        ))),
    }
}

/// The effective plan's RAW Boolean for one feature field (override-aware,
/// mirroring `billing_service::plans::get_plan_for_tenant`). `false` when
/// the tenant or plan row is missing — fail closed.
async fn raw_plan_flag_granted(
    state: &AppState,
    tenant_id: &str,
    key: FeatureKey,
) -> Result<bool, ApiError> {
    let plan = billing_service::plans::get_plan_for_tenant(&state.db, tenant_id).await?;
    Ok(plan
        .and_then(|plan| serde_json::to_value(&plan.features).ok())
        .and_then(|features| {
            features
                .get(key.field_name())
                .and_then(serde_json::Value::as_bool)
        })
        .unwrap_or(false))
}
