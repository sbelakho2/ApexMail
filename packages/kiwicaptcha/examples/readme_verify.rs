//! Compile-tested mirror of the root README's "Verify the solution"
//! example (audit round 15): the README snippet must never drift from the
//! real API — this example is built by every `cargo test` / `cargo build
//! --examples`, so a struct-field or enum-variant change breaks CI instead
//! of breaking new consumers who copied the docs.
//!
//! The code below mirrors the documentation example VERBATIM (modulo the
//! `?` operators, which need a real error context); it is intentionally
//! not executed — issuance and storage are application concerns.

use std::collections::{HashMap, HashSet};

use kiwicaptcha::{verify_solution, ChallengeRecord, SolutionToken, VerifyContext, VerifyOutcome};

#[allow(dead_code)]
fn verify_example(
    mut record: ChallengeRecord,
    solution: SolutionToken,
    secret_key: &str,
    client_ip: &str,
    now_unix: u64,
    now_ns: u64,
) -> Result<String, kiwicaptcha::VerifyError> {
    let secrets_by_kid: HashMap<u32, String> = HashMap::new(); // kid -> master secret (audit #91)
    let revoked_kids: HashSet<u32> = HashSet::new(); // compromise-revoked kids (audit #117)

    let mut ctx = VerifyContext {
        record: &mut record,
        secret_key, // must match issuance; >= 16 bytes
        secrets_by_kid: Some(&secrets_by_kid),
        revoked_kids: Some(&revoked_kids),
        counter: solution.counter,
        duration_ms: solution.duration_ms, // client-reported — telemetry only
        now_unix,                          // TTL check (seconds)
        now_ns,                            // receipt time in EPOCH MICROSECONDS
        // (server-side elapsed-duration check)
        min_duration_ms: 0, // floor is max(ctx, record.min_duration_ms);
        // 0 = use only the record's floor
        expected_scope: Some("login"),    // reject cross-scope replay
        expected_region: None,            // Some("eu") for region-bound deployments
        expected_issuer: None,            // Some("auth-gateway") to pin the issuer (audit #67)
        expected_policy_version: Some(1), // the CURRENT security-policy epoch — a record
        // issued under a revoked policy dies immediately
        client_ip: Some(client_ip), // IP binding: None + a bound record => MissingClientIp;
        //                                        only BindingMode::None records verify without an IP
        telemetry: Some(&solution.telemetry), // supplementary behavioral signal
        enforce_telemetry: true,              // reject on hard bot signals
        accept_legacy_v1: false,              // v2 is the only issued format — reject legacy
        max_attempts: 10,                     // per-nonce attempt cap (0 = unlimited)
    };

    match verify_solution(&mut ctx) {
        VerifyOutcome::Valid { nonce, .. } => {
            // Consume the challenge atomically for strict single-use under
            // concurrency (e.g. the RedisChallengeStore Lua transition),
            // then allow login. `nonce` is the consumed challenge's
            // canonical id (jti); `request_binding` is the application
            // transaction binding to correlate with the final POST.
            Ok(nonce)
        }
        VerifyOutcome::Invalid(reason) => Err(reason),
    }
}

fn main() {
    // Compile-check only: the verified example lives in
    // `verify_example` above (README §3 mirrors it).
    println!("kiwicaptacha readme example: compile check OK");
}
