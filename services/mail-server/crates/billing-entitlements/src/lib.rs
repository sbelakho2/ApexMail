//! Runtime feature entitlements shared by billing, api-server and UI
//! presentation.
//!
//! The crate is deliberately tiny and dependency-light: it holds the closed
//! [`FeatureKey`]/[`CapacityKey`] model, the per-`PlanFeatures`-field
//! [`FeatureClass`]ification audited by `tools/check_feature_entitlements.py`,
//! and the tenant-scoped [`EntitlementSnapshot`] that every customer handler
//! gates on.
//!
//! ```text
//! plans.features (JSONB) ──┐
//! plan_overrides           ├─► EntitlementSnapshot ──► require_feature()
//! feature_flag_overrides ──┘                     └──► require_capacity()
//!                                                     │
//!                                      presentation() ─┴─► UI/console (display only)
//! ```

pub mod classify;
pub mod snapshot;

pub use classify::{
    capacity_classification, classification_for_field, feature_classification, CapacityKey,
    FeatureClass, FeatureKey, FieldClassification, Gate, PLAN_FEATURE_CLASSIFICATION,
};
pub use snapshot::{
    CapacityPresentation, EntitlementError, EntitlementPresentation, EntitlementSnapshot,
    FeaturePresentation,
};
