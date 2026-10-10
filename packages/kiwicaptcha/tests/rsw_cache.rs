//! The validated-pair memo counting test — a dedicated test binary on
//! purpose: the counting seam (`kiwicaptcha::rsw::validation_call_count`)
//! is PROCESS-global, and the main lib test binary runs rsw issuance
//! tests in parallel threads that each validate the fixture pair,
//! polluting any exact-count window. In this binary the counting test
//! is the only test, so the counts are exact: every `validated` call
//! of a memoized pair advances the counter once (the cache-hit probe)
//! and never re-runs the expensive primality work.

use std::sync::Arc;

use kiwicaptcha::rsw::{self, fixtures};

#[test]
fn the_second_validation_of_a_pair_is_served_from_the_memo() {
    let before = rsw::validation_call_count();
    let first = rsw::RswTrapdoor::validated(fixtures::MODULUS_N_B64, fixtures::LAMBDA_B64)
        .expect("the fixture pair validates");
    let second = rsw::RswTrapdoor::validated(fixtures::MODULUS_N_B64, fixtures::LAMBDA_B64)
        .expect("the memo serves the same pair");
    assert!(
        Arc::ptr_eq(&first, &second),
        "the same pair must reuse the cached trapdoor allocation"
    );
    assert_eq!(
        rsw::validation_call_count() - before,
        2,
        "every call probes the memo exactly once (hit or miss)"
    );
    let third = rsw::RswTrapdoor::validated(fixtures::MODULUS_N_B64, fixtures::LAMBDA_B64)
        .expect("the memo keeps serving the pair");
    assert!(Arc::ptr_eq(&first, &third));
    assert_eq!(rsw::validation_call_count() - before, 3);
}
