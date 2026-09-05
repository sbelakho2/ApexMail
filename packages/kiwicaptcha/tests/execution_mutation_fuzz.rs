//! The execution-parser mutation corpus: the no-panic and
//! deterministic-outcome invariants of the ExecutionChallengeV1 decode
//! and verify paths under attacker-controlled mutation.
//!
//! For every execution version 1..=MAX_EXECUTION_VERSION the corpus
//! builds a valid program and its executed trace through the fixture
//! machinery (`generate` + `decode` + `fixtures::executed_trace_for`,
//! the browser-equivalent synthesizer of the `test-fixtures` module),
//! then mutates, per case independently: the program base64 text, the
//! decoded blob bytes, the header (scope length, action length, the
//! execution-version byte, the op count), every opcode, every
//! variable-length operand length and content, the observe destination
//! and height, the sibling-index value, the trace entry ordering, a
//! missing or duplicated trace entry, appended trace garbage, the
//! trace base64, the presented digest, and the record's
//! execution_commitment and execution version.
//!
//! Every case must finish without a panic (each decode/verify call runs
//! under `catch_unwind`) and settle on a deterministic verdict:
//! malformed or execution-mismatch whenever the mutation touched the
//! corpus, and valid only when the mutation left the corpus untouched
//! (the mutate-then-restore points inside the observe and sibling-index
//! sweeps). A mutation that changes program bytes without changing the
//! simulated trace is caught by the digest binding: the expected digest
//! of the mutated program must differ from the digest of the original.
//!
//! The record-level corpus rides the canonical record register (1..=
//! MAX_EXECUTION_VERSION, the set `validate_record` accepts — the exact
//! set of the PHP record/verifier gate); the fixture-level corpus spans
//! the full execution-version range. The last section pins the
//! cross-language differential corpus shared with the PHP suite: the
//! classifications of 19 adversarial program/trace cases must match
//! `ExecutionDifferentialCorpusTest` case for case.

use std::panic::{catch_unwind, AssertUnwindSafe};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use kiwicaptcha::challenge::{
    issue_challenge_with_execution, ChallengeConfig, ChallengeRecord, PoWAlgorithm,
};
use kiwicaptcha::execution;
use kiwicaptcha::token::SolutionToken;
use kiwicaptcha::verify::{
    validate_record, verify_solution, VerifyContext, VerifyError, VerifyOutcome,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const KEY: &str = "0123456789abcdef0123456789abcdef";
const NONCE: &str = "xAfSYcl6VyvtYZcQUhvXxin2pojnG5TmZoHg7K6NG3s=";
const SCOPE: &str = "login";
const ACTION: &str = "login-action";
const IP: &str = "198.51.100.7";
const NOW_UNIX: u64 = 1_700_000_000;
const NOW_NS: u64 = 1_700_000_000_000_000;

/// The outcome of one decode/verify probe on a (program, trace) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Malformed,
    ExecutionMismatch,
    Valid,
}

/// The decode/verify verdict, the mirror of the PHP corpus verdict:
/// malformed when the program does not parse, execution-mismatch when
/// the trace is not a valid execution of the parsed program, valid
/// otherwise.
fn classify(program_b64: &str, trace: &str) -> Verdict {
    if execution::decode(program_b64).is_none() {
        return Verdict::Malformed;
    }
    match execution::verify_executed_trace(program_b64, NONCE, trace) {
        Some(_) => Verdict::Valid,
        None => Verdict::ExecutionMismatch,
    }
}

/// Runs the closure under `catch_unwind`: a panic anywhere in a parse
/// or verify path is a test failure, never a case outcome.
fn guarded<T>(what: &str, f: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| panic!("panic while exercising {what}"))
}

fn config() -> ChallengeConfig {
    ChallengeConfig {
        secret_key: KEY.to_string(),
        kid: 1,
        execution_key: Some(KEY.to_string()),
        rsw_modulus_n: None,
        rsw_lambda: None,
        rsw_t: kiwicaptcha::challenge::DEFAULT_RSW_T,
        algorithm: PoWAlgorithm::Sha256,
        m_kib: 0,
        t: 1,
        p: 1,
        target_bits: 8,
        argon2_target_bits: 8,
        ttl_secs: 120,
        min_duration_ms: Some(0),
        auto_tune: false,
        auto_tune_min_bits: 8,
        auto_tune_max_bits: 20,
        binding_mode: kiwicaptcha::challenge::BindingMode::Bound,
        region: None,
        issuer: None,
        policy_version: 1,
    }
}

/// The fixed offsets of a generated blob's header fields.
#[derive(Clone, Copy)]
struct HeaderOffsets {
    scope_len_at: usize,
    action_len_at: usize,
    version_at: usize,
    op_count_at: usize,
    op0_at: usize,
}

fn header_offsets(blob: &[u8]) -> HeaderOffsets {
    assert_eq!(blob[0], 1, "the generated blob opens with format version 1");
    let scope_len = blob[1] as usize;
    let action_len_at = 2 + scope_len;
    let action_len = blob[action_len_at] as usize;
    let version_at = action_len_at + 1 + action_len;
    HeaderOffsets {
        scope_len_at: 1,
        action_len_at,
        version_at,
        op_count_at: version_at + 1,
        op0_at: version_at + 2,
    }
}

/// One per-version seed corpus: the generated program, its decoded
/// structure, its executed trace and digest, all deterministic per the
/// fixed key and nonce.
struct Seed {
    program_b64: String,
    blob: Vec<u8>,
    trace: String,
    digest: String,
    offsets: HeaderOffsets,
}

fn build_seed(version: u8) -> Seed {
    let program_b64 = execution::generate(KEY.as_bytes(), NONCE, SCOPE, ACTION, version)
        .expect("the seeded version must generate");
    let decoded = execution::decode(&program_b64).expect("the seeded program must parse");
    assert_eq!(
        decoded.op_version, version,
        "the seed stays on its declared version"
    );
    let trace = execution::fixtures::executed_trace_for(&decoded);
    assert!(
        execution::verify_executed_trace(&program_b64, NONCE, &trace).is_some(),
        "the executed trace of the seed must verify"
    );
    let digest = execution::expected_digest_over_trace(&program_b64, NONCE, &trace)
        .expect("the seed must digest");
    let blob = B64
        .decode(&program_b64)
        .expect("the seed base64 is canonical");
    let offsets = header_offsets(&blob);
    Seed {
        program_b64,
        blob,
        trace,
        digest,
        offsets,
    }
}

/// The decoded program must reject a mutated blob deterministically:
/// two decodes of the same blob agree, and neither panics.
fn decode_twice(what: &str, mutated: &str) -> Option<kiwicaptcha::execution::Program> {
    let a = guarded(&format!("{what} decode"), || execution::decode(mutated));
    let b = guarded(&format!("{what} re-decode"), || execution::decode(mutated));
    assert_eq!(a, b, "the decode verdict of {what} must be deterministic");
    a
}

/// The digest of the mutated program over the original trace must never
/// equal the original digest (the digest key is the program blob
/// itself, so any byte change rebinds the evidence).
fn assert_digest_rebound(what: &str, mutated_b64: &str, seed: &Seed) {
    if let Some(d) = execution::expected_digest_over_trace(mutated_b64, NONCE, &seed.trace) {
        assert_ne!(
            d, seed.digest,
            "{what} must rebind the digest (program bytes changed)"
        );
    }
}

fn reencode(blob: &[u8]) -> String {
    B64.encode(blob)
}

#[test]
fn program_mutations_never_panic_and_reject_deterministically() {
    let mut rng = StdRng::seed_from_u64(0x5EED_E2EC_0101);
    let mut cases = 0usize;
    for version in 1..=execution::MAX_EXECUTION_VERSION {
        let seed = build_seed(version);
        let b64 = &seed.program_b64;
        let what = |label: String| format!("v{version} {label}");

        // The unmutated control case: the seed parses, verifies and
        // digests, the mutate-then-restore baseline of every class.
        assert_eq!(
            classify(b64, &seed.trace),
            Verdict::Valid,
            "the seed corpus is valid"
        );
        assert_eq!(
            execution::expected_digest_over_trace(b64, NONCE, &seed.trace).as_deref(),
            Some(seed.digest.as_str())
        );
        cases += 1;

        // Base64-text flips: each flip must keep the decode verdict
        // deterministic; a parseable mutation must rebind the digest.
        let mut flipped = b64.clone();
        for _ in 0..24 {
            let at = rng.gen_range(0..flipped.len());
            let old = flipped.as_bytes()[at];
            let mut fresh = old;
            while fresh == old {
                fresh = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                    [rng.gen_range(0..64)];
            }
            flipped.replace_range(at..at + 1, (fresh as char).to_string().as_str());
            let label = what("base64 text flip".into());
            let decoded = decode_twice(&label, &flipped);
            if decoded.is_some() {
                assert_digest_rebound(&label, &flipped, &seed);
            }
            cases += 1;
        }

        // Blob-byte flips across the whole decoded program.
        for _ in 0..96 {
            let mut blob = seed.blob.clone();
            let at = rng.gen_range(0..blob.len());
            blob[at] = blob[at].wrapping_add(1);
            let mutated = reencode(&blob);
            let label = what("blob byte flip".into());
            let decoded = decode_twice(&label, &mutated);
            if decoded.is_some() {
                let verdict = guarded(&label, || classify(&mutated, &seed.trace));
                if verdict == Verdict::Valid {
                    assert_digest_rebound(&label, &mutated, &seed);
                }
            }
            cases += 1;
        }

        // Header scope/action length bytes: a zero or over-max length
        // is outside the grammar, deterministically malformed.
        let o = seed.offsets;
        for (at, value) in [
            (o.scope_len_at, 0u8),
            (o.scope_len_at, 129),
            (o.scope_len_at, 255),
            (o.action_len_at, 0),
            (o.action_len_at, 33),
            (o.action_len_at, 255),
        ] {
            let mut blob = seed.blob.clone();
            blob[at] = value;
            let mutated = reencode(&blob);
            let label = what(format!("header length byte at {at} set to {value}"));
            assert_eq!(
                decode_twice(&label, &mutated),
                None,
                "{label} must be malformed"
            );
            cases += 1;
        }

        // The execution-version byte: out-of-range values are refused,
        // and a downward rewrite crosses the opcode fence of the newer
        // grammar (an old interpreter rejects the newer opcodes).
        for value in [0u8, 9, 255] {
            let mut blob = seed.blob.clone();
            blob[o.version_at] = value;
            let mutated = reencode(&blob);
            let label = what(format!("execution version byte set to {value}"));
            assert_eq!(
                decode_twice(&label, &mutated),
                None,
                "{label} must be malformed"
            );
            cases += 1;
        }
        if version > 1 {
            let mut blob = seed.blob.clone();
            blob[o.version_at] = version - 1;
            let mutated = reencode(&blob);
            let label = what(format!("execution version downgraded to {}", version - 1));
            assert_eq!(
                decode_twice(&label, &mutated),
                None,
                "{label} must hit the decode fence (newer opcodes present)"
            );
            cases += 1;
        }
        {
            let mut blob = seed.blob.clone();
            let upward = (version % execution::MAX_EXECUTION_VERSION) + 1;
            blob[o.version_at] = upward;
            let mutated = reencode(&blob);
            let label = what(format!("execution version raised to {upward}"));
            let decoded = decode_twice(&label, &mutated);
            if decoded.is_some() {
                assert_digest_rebound(&label, &mutated, &seed);
            }
            cases += 1;
        }

        // The op-count byte: any count other than the stamped one is
        // malformed (out of the 8..24 bounds or off the exact EOF).
        for value in [0u8, 7, 8, 24, 25, 255] {
            if value == seed.blob[o.op_count_at] {
                continue;
            }
            let mut blob = seed.blob.clone();
            blob[o.op_count_at] = value;
            let mutated = reencode(&blob);
            let label = what(format!("op count set to {value}"));
            assert_eq!(
                decode_twice(&label, &mutated),
                None,
                "{label} must be malformed"
            );
            cases += 1;
        }

        // Every opcode, one mutation per op: the rewritten opcode byte
        // either breaks the operand shapes (malformed) or changes the
        // trace name of its op (execution mismatch against the seed
        // trace), never a valid outcome.
        let mut op_at = o.op0_at;
        for (index, op) in execution::decode(b64)
            .expect("re-decode for op scan")
            .ops
            .iter()
            .enumerate()
        {
            assert_eq!(seed.blob[op_at], op.opcode, "op scan stays aligned");
            let content_at = op_at + 1;
            let bound = match version {
                1 => 33,
                2 => 34,
                3 => 35,
                _ => execution::OP_COUNT,
            };
            let next_opcode = (op.opcode + 1) % bound;
            if next_opcode != op.opcode {
                let mut blob = seed.blob.clone();
                blob[content_at - 1] = next_opcode;
                let mutated = reencode(&blob);
                let label = what(format!("opcode of op {index} rewritten to {next_opcode}"));
                let decoded = decode_twice(&label, &mutated);
                if decoded.is_some() {
                    assert_eq!(
                        guarded(&label, || classify(&mutated, &seed.trace)),
                        Verdict::ExecutionMismatch,
                        "{label} must change the trace name of its op"
                    );
                }
                cases += 1;
            }
            op_at += 1 + op_content_len(&seed.blob, op.opcode, content_at);
        }
        assert_eq!(op_at, seed.blob.len(), "the op scan ends at exact EOF");

        // Every variable-length operand: a length byte of 0 or 255 is
        // outside every operand bound (malformed), and every content
        // byte flip either changes the trace (execution mismatch) or
        // rebinds the digest.
        let mut op_at = o.op0_at;
        for op in execution::decode(b64)
            .expect("re-decode for operand scan")
            .ops
            .iter()
        {
            let content_at = op_at + 1;
            for (len_at, content_off, len) in var_operand_spans(&seed.blob, op.opcode, content_at) {
                for bad_len in [0u8, 255] {
                    let mut blob = seed.blob.clone();
                    blob[len_at] = bad_len;
                    let mutated = reencode(&blob);
                    let label = what(format!(
                        "operand length of op {} set to {bad_len}",
                        op.opcode
                    ));
                    assert_eq!(
                        decode_twice(&label, &mutated),
                        None,
                        "{label} must be malformed"
                    );
                    cases += 1;
                }
                for off in 0..len {
                    let mut blob = seed.blob.clone();
                    let at = content_off + off;
                    blob[at] ^= 1;
                    let mutated = reencode(&blob);
                    let label = what(format!("operand content byte of op {} at {at}", op.opcode));
                    let decoded = decode_twice(&label, &mutated);
                    if decoded.is_some() {
                        let verdict = guarded(&label, || classify(&mutated, &seed.trace));
                        if verdict == Verdict::Valid {
                            assert_digest_rebound(&label, &mutated, &seed);
                        }
                    }
                    cases += 1;
                }
            }
            op_at += 1 + op_content_len(&seed.blob, op.opcode, op_at + 1);
        }
        assert_eq!(op_at, seed.blob.len(), "the operand scan ends at exact EOF");
    }
    eprintln!(
        "program mutation corpus: {cases} cases across {} versions, all deterministic",
        execution::MAX_EXECUTION_VERSION
    );
    assert!(
        cases > 500,
        "the program mutation corpus must stay substantial"
    );
}

/// The byte length of one op record's content, read from the blob with
/// the parser's exact layout (the generator's emission order).
fn op_content_len(blob: &[u8], opcode: u8, content_at: usize) -> usize {
    let byte = |rel: usize| -> usize { blob.get(content_at + rel).copied().unwrap_or(0) as usize };
    match opcode {
        0..=7 => 8,
        8 | 10 | 11 => 1,
        9 => 2,
        12 => 1 + byte(0),
        13 | 14 => 1 + byte(0) + 1,
        15 => 1 + byte(0) + 2,
        16 | 17 | 35 => 2 + byte(1),
        18 | 25 | 26 | 27 | 32 => 0,
        19 | 22 | 23 | 24 | 28 | 29 | 31 | 34 | 36 => 1 + byte(0),
        20 => 1,
        21 => {
            let key_len = byte(0);
            1 + key_len + 1 + byte(1 + key_len)
        }
        30 => 2,
        33 => 1 + byte(0) + 1,
        37 => 2,
        38 | 39 => 2 + byte(0),
        40 | 41 => 1,
        42 => 0,
        43 => 1 + byte(0) + 1,
        44 => 3,
        _ => 0,
    }
}

/// The (length byte, content start, length) spans of every
/// variable-length operand of an op, in read order.
fn var_operand_spans(blob: &[u8], opcode: u8, content_at: usize) -> Vec<(usize, usize, usize)> {
    let byte = |rel: usize| -> usize { blob.get(content_at + rel).copied().unwrap_or(0) as usize };
    let span = |len_rel: usize| -> (usize, usize, usize) {
        let len = byte(len_rel);
        (content_at + len_rel, content_at + len_rel + 1, len)
    };
    match opcode {
        12 | 13 | 14 | 15 | 19 | 22 | 23 | 24 | 28 | 29 | 31 | 34 | 36 => vec![span(0)],
        16 | 17 | 35 => vec![span(1)],
        21 => {
            let key = span(0);
            vec![key, span(1 + key.2)]
        }
        33 => vec![span(0)],
        38 | 39 => vec![span(0)],
        43 => vec![span(0)],
        _ => Vec::new(),
    }
}

/// The entries of a trace, split on the ';' separator. Every entry is
/// an `opname(...)` record that never contains the separator, so the
/// split is exact for the mutation classes below.
fn trace_entries(trace: &str) -> Vec<String> {
    trace.split(';').map(str::to_string).collect()
}

fn join_entries(entries: &[String]) -> String {
    entries.join(";")
}

#[test]
fn trace_mutations_never_panic_and_reject_deterministically() {
    let mut cases = 0usize;
    for version in 1..=execution::MAX_EXECUTION_VERSION {
        let seed = build_seed(version);
        let entries = trace_entries(&seed.trace);
        let what = |label: String| format!("v{version} {label}");

        // Entry-order mutations: adjacent swaps, a missing entry and a
        // duplicated entry must each break the anchored walk, except a
        // swap of two byte-identical entries (the trace is unchanged).
        let mut swapped = entries.clone();
        let (k, other) = (1usize, 2usize);
        if swapped[k] == swapped[other] {
            swapped.swap(0, 1);
        } else {
            swapped.swap(k, other);
        }
        if swapped == entries {
            // The chosen pair was byte-identical; a true swap of the
            // first differing adjacent pair follows.
            let mut i = 0;
            while i + 1 < entries.len() && entries[i] == entries[i + 1] {
                i += 1;
            }
            assert!(i + 1 < entries.len(), "the seed trace has distinct entries");
            let mut swapped2 = entries.clone();
            swapped2.swap(i, i + 1);
            let label = what("adjacent entry swap".into());
            assert_eq!(
                guarded(&label, || execution::verify_executed_trace(
                    &seed.program_b64,
                    NONCE,
                    &join_entries(&swapped2)
                )),
                None,
                "{label} must break the anchored walk"
            );
            cases += 1;
        } else {
            let label = what("adjacent entry swap".into());
            assert_eq!(
                guarded(&label, || execution::verify_executed_trace(
                    &seed.program_b64,
                    NONCE,
                    &join_entries(&swapped)
                )),
                None,
                "{label} must break the anchored walk"
            );
            cases += 1;
        }

        let missing: Vec<String> = entries
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != entries.len() / 2)
            .map(|(_, e)| e.clone())
            .collect();
        let label = what("missing middle trace entry".into());
        assert_eq!(
            guarded(&label, || execution::verify_executed_trace(
                &seed.program_b64,
                NONCE,
                &join_entries(&missing)
            )),
            None,
            "{label} must break the anchored walk"
        );
        cases += 1;

        let mid = entries.len() / 2;
        let mut duplicated = entries.clone();
        duplicated.insert(mid, entries[mid].clone());
        let label = what("duplicated trace entry".into());
        assert_eq!(
            guarded(&label, || execution::verify_executed_trace(
                &seed.program_b64,
                NONCE,
                &join_entries(&duplicated)
            )),
            None,
            "{label} must break the anchored walk"
        );
        cases += 1;

        for suffix in ["garbage", ";add(1)", ";obs(1,1)"] {
            let forged = format!("{}{suffix}", seed.trace);
            let label = what("appended trace garbage".into());
            assert_eq!(
                guarded(&label, || execution::verify_executed_trace(
                    &seed.program_b64,
                    NONCE,
                    &forged
                )),
                None,
                "{label} must fail the exact-EOF walk"
            );
            cases += 1;
        }

        // The observe entry sweep: the destination index and the
        // observed height are replayed into the u8 state, so only the
        // exact (destination, height) pair of the seed trace verifies.
        let obs = seed.trace.match_indices("obs(").next().map(|(at, _)| {
            let end = seed.trace[at..].find(')').expect("obs entry closes") + at;
            seed.trace[at..=end].to_string()
        });
        if let Some(entry) = obs {
            let dst: i64 = entry
                .trim_start_matches("obs(")
                .split(',')
                .next()
                .expect("dst")
                .parse()
                .expect("dst is numeric");
            let height: i64 = entry
                .split(',')
                .nth(1)
                .expect("height part")
                .trim_end_matches(')')
                .parse()
                .expect("height is numeric");
            for d in 0..=255i64 {
                let forged = seed.trace.replace(&entry, &format!("obs({d},{height})"));
                let expected = if d == dst {
                    Verdict::Valid
                } else {
                    Verdict::ExecutionMismatch
                };
                let label = what(format!("observe destination {d}"));
                assert_eq!(
                    guarded(&label, || classify(&seed.program_b64, &forged)),
                    expected,
                    "{label}: only the seed destination verifies"
                );
                cases += 1;
            }
            for h in [0i64, 255, 256] {
                let forged = seed.trace.replace(&entry, &format!("obs({dst},{h})"));
                let label = what(format!("observe height {h}"));
                if h == height {
                    assert_eq!(
                        guarded(&label, || classify(&seed.program_b64, &forged)),
                        Verdict::Valid,
                        "{label}: the seed height restores the corpus"
                    );
                } else {
                    assert_eq!(
                        guarded(&label, || classify(&seed.program_b64, &forged)),
                        Verdict::ExecutionMismatch,
                        "{label}: a rewritten height breaks the write-through replay"
                    );
                }
                cases += 1;
            }
        }

        // The sibling-index sweep: the verifier derives the exact value
        // from the append order, so only the seed value verifies.
        let dsib = seed.trace.match_indices("dsib(").next().map(|(at, _)| {
            let end = seed.trace[at..].find(')').expect("dsib entry closes") + at;
            seed.trace[at..=end].to_string()
        });
        if let Some(entry) = dsib {
            let value: i64 = entry
                .trim_start_matches("dsib(")
                .trim_end_matches(')')
                .parse()
                .expect("dsib value is numeric");
            for v in 0..=5i64 {
                let forged = seed.trace.replace(&entry, &format!("dsib({v})"));
                let expected = if v == value {
                    Verdict::Valid
                } else {
                    Verdict::ExecutionMismatch
                };
                let label = what(format!("sibling index {v}"));
                assert_eq!(
                    guarded(&label, || classify(&seed.program_b64, &forged)),
                    expected,
                    "{label}: only the append-rank value verifies"
                );
                cases += 1;
            }
        }
    }
    eprintln!("trace mutation corpus: {cases} cases, all deterministic");
    assert_eq!(
        cases, 1084,
        "the deterministic trace corpus totals: v1 6, v2 265, v3 271, v4 271, v5 271"
    );
}

/// One armed record probe for the record-level mutation classes. The
/// record register accepts execution versions 1..=MAX_EXECUTION_VERSION
/// (the exact set of the PHP record/verifier gate), so the full-path
/// corpus rides the whole register; the fixture-level corpus above spans
/// the same 1..=MAX range.
struct ArmedProbe {
    record: ChallengeRecord,
    trace_b64: String,
    digest: String,
    counter: u64,
}

fn solve_counter(prefix: &str, salt: &str, target_bits: u32) -> u64 {
    use sha2::{Digest, Sha256};
    let salt_bytes = B64.decode(salt).unwrap();
    for counter in 0..1_000_000u64 {
        let mut input = Vec::new();
        input.extend_from_slice(prefix.as_bytes());
        input.extend_from_slice(counter.to_string().as_bytes());
        input.extend_from_slice(&salt_bytes);
        let hash = Sha256::digest(&input);
        let zeros = hash.iter().take_while(|b| **b == 0).count() * 8 + {
            let first = hash.iter().find(|b| **b != 0);
            match first {
                None => 0,
                Some(b) => {
                    let mut n = 0;
                    let mut v = *b;
                    while v & 0x80 == 0 {
                        n += 1;
                        v <<= 1;
                    }
                    n
                }
            }
        };
        if zeros >= target_bits as usize {
            return counter;
        }
    }
    panic!("no winning counter found");
}

fn issue_probe(version: u8) -> ArmedProbe {
    let issued = issue_challenge_with_execution(
        &config(),
        SCOPE,
        IP,
        NOW_UNIX,
        NOW_NS,
        0,
        None,
        true,
        Some(ACTION),
        Some(version),
        false,
    )
    .expect("armed issuance");
    let record = issued.record;
    let program_b64 = issued
        .challenge
        .execution_program
        .expect("armed challenges carry the program")
        .clone();
    let decoded = execution::decode(&program_b64).expect("the issued program parses");
    assert_eq!(decoded.op_version, version);
    let trace = execution::fixtures::executed_trace_for(&decoded);
    assert!(execution::verify_executed_trace(&program_b64, &record.nonce, &trace).is_some());
    let digest = execution::expected_digest_over_trace(&program_b64, &record.nonce, &trace)
        .expect("the armed probe digests");
    let trace_b64: String = B64
        .encode(trace.as_bytes())
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string();
    let counter = solve_counter(&record.prefix, &record.salt, 8);
    ArmedProbe {
        record,
        trace_b64,
        digest,
        counter,
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_probe(
    probe: &ArmedProbe,
    record: &mut ChallengeRecord,
    digest: Option<&str>,
    trace_b64: Option<&str>,
) -> VerifyOutcome {
    let mut ctx = VerifyContext {
        record,
        secret_key: KEY,
        secrets_by_kid: None,
        revoked_kids: None,
        counter: probe.counter,
        duration_ms: 5000,
        now_unix: Some(&mut || NOW_UNIX + 1),
        now_ns: NOW_NS + 5_000_000,
        min_duration_ms: 0,
        expected_scope: Some(SCOPE),
        expected_request_binding: kiwicaptcha::verify::RequestBindingExpectation::Unenforced,
        expected_region: None,
        expected_issuer: None,
        expected_policy_version: None,
        client_ip: Some(IP),
        execution_digest: digest,
        execution_trace: trace_b64,
        telemetry: None,
        enforce_telemetry: false,
        accept_legacy_v1: false,
        rsw_proof: None,
        rsw_modulus_n: None,
        rsw_lambda: None,
        max_attempts: 0,
    };
    verify_solution(&mut ctx)
}

fn assert_invalid(what: &str, outcome: VerifyOutcome) {
    assert!(
        matches!(outcome, VerifyOutcome::Invalid(_)),
        "{what} must be deterministic invalid"
    );
}

#[test]
fn record_evidence_mutations_never_panic_and_reject_deterministically() {
    let mut cases = 0usize;
    for version in 1..=execution::MAX_EXECUTION_VERSION {
        let probe = issue_probe(version);
        let what = |label: String| format!("v{version} {label}");

        // The unmutated control: the armed record with the executed
        // trace and its digest verifies end to end.
        let mut control = probe.record.clone();
        let outcome = guarded("control verify", || {
            verify_probe(
                &probe,
                &mut control,
                Some(&probe.digest),
                Some(&probe.trace_b64),
            )
        });
        assert!(
            matches!(outcome, VerifyOutcome::Valid { .. }),
            "the armed control corpus must verify"
        );
        cases += 1;

        // The trace base64 mutations: a corrupt or non-canonical
        // base64url body never decodes to the seed trace.
        let mut chars: Vec<char> = probe.trace_b64.chars().collect();
        for at in [0usize, probe.trace_b64.len() / 2, probe.trace_b64.len() - 1] {
            let old = chars[at];
            let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            let mut k = cases % 64;
            while alphabet[k] == old as u8 {
                k = (k + 1) % 64;
            }
            let fresh = alphabet[k] as char;
            let original = chars[at];
            chars[at] = fresh;
            let mutated: String = chars.iter().collect();
            chars[at] = original;
            let label = what(format!("trace base64 char at {at}"));
            let mut record = probe.record.clone();
            let outcome = guarded(&label, || {
                verify_probe(&probe, &mut record, Some(&probe.digest), Some(&mutated))
            });
            assert_invalid(&label, outcome);
            cases += 1;
        }
        {
            let truncated = &probe.trace_b64[..probe.trace_b64.len() - 2];
            let label = what("truncated trace base64".into());
            let mut record = probe.record.clone();
            let outcome = guarded(&label, || {
                verify_probe(&probe, &mut record, Some(&probe.digest), Some(truncated))
            });
            assert_invalid(&label, outcome);
            cases += 1;
        }

        // The digest mutations: length, hex alphabet and value are all
        // rejected by the constant-time comparison.
        let digest_last = probe.digest.as_bytes()[63];
        let digest_last_flipped = if digest_last == b'0' { '1' } else { '0' };
        let digest_last_mutated = format!("{}{}", &probe.digest[..63], digest_last_flipped);
        for digest in [
            "".to_string(),
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
            "0".repeat(64),
            digest_last_mutated,
        ] {
            let label = what(format!(
                "digest variant {:?}",
                &digest[..4.min(digest.len())]
            ));
            let mut record = probe.record.clone();
            let outcome = guarded(&label, || {
                verify_probe(&probe, &mut record, Some(&digest), Some(&probe.trace_b64))
            });
            assert_invalid(&label, outcome);
            cases += 1;
        }

        // Missing evidence: an armed record demands both the digest and
        // the trace.
        let mut record = probe.record.clone();
        let outcome = guarded("missing digest and trace", || {
            verify_probe(&probe, &mut record, None, None)
        });
        assert_invalid("missing digest and trace", outcome);
        cases += 1;
        let mut record = probe.record.clone();
        let outcome = guarded("missing trace", || {
            verify_probe(&probe, &mut record, Some(&probe.digest), None)
        });
        assert_invalid("missing trace", outcome);
        cases += 1;

        // The record execution_commitment mutations: a substituted,
        // truncated or non-hex commitment fails the authenticated
        // commitment equivalence before any execution work.
        let mut base = serde_json::to_value(&probe.record).expect("record serializes");
        let original_commitment = base["execution_commitment"].as_str().unwrap().to_string();
        let commitment_last = original_commitment.as_bytes()[63];
        let commitment_last_flipped = if commitment_last == b'1' { '2' } else { '1' };
        let commitment_last_mutated =
            format!("{}{}", &original_commitment[..63], commitment_last_flipped);
        for commitment in [
            commitment_last_mutated,
            "0".repeat(64),
            "f".repeat(63),
            "g".repeat(64),
            "A".repeat(64),
        ] {
            base["execution_commitment"] = serde_json::Value::String(commitment.clone());
            let record: ChallengeRecord =
                serde_json::from_value(base.clone()).expect("the mutated record still parses");
            let label = what(format!("commitment variant {}", commitment.len()));
            assert_eq!(
                guarded(&label, || validate_record(&record)),
                Err(VerifyError::MalformedRecord),
                "{label} must fail the commitment equivalence"
            );
            let mut record = record;
            let outcome = guarded(&label, || {
                verify_probe(
                    &probe,
                    &mut record,
                    Some(&probe.digest),
                    Some(&probe.trace_b64),
                )
            });
            assert_invalid(&label, outcome);
            cases += 1;
        }
        base["execution_commitment"] = serde_json::Value::String(original_commitment);

        // The record execution-version mutations: values outside the
        // canonical register (1..=MAX_EXECUTION_VERSION) are malformed,
        // and a value inside the register but different from the signed
        // one breaks the signature binding.
        for version_value in [0u8, 1, 2, 3, 4, 9] {
            if version_value == version {
                continue;
            }
            let mut record = probe.record.clone();
            record.execution_version = Some(version_value);
            let label = what(format!("record execution version {version_value}"));
            let validated = guarded(&label, || validate_record(&record));
            if !(1..=execution::MAX_EXECUTION_VERSION).contains(&version_value) {
                assert_eq!(
                    validated,
                    Err(VerifyError::MalformedRecord),
                    "{label} must fail the record gate"
                );
            } else {
                assert_eq!(
                    validated,
                    Ok(()),
                    "{label} rides the canonical register and must pass the record gate"
                );
            }
            let outcome = guarded(&label, || {
                verify_probe(
                    &probe,
                    &mut record,
                    Some(&probe.digest),
                    Some(&probe.trace_b64),
                )
            });
            assert_invalid(&label, outcome);
            cases += 1;
        }
        let mut record = probe.record.clone();
        record.execution_version = None;
        let label = what("record execution version stripped".into());
        assert_eq!(
            guarded(&label, || validate_record(&record)),
            Err(VerifyError::MalformedRecord),
            "{label}: a stripped version breaks the armed triplet"
        );
        let outcome = guarded(&label, || {
            verify_probe(
                &probe,
                &mut record,
                Some(&probe.digest),
                Some(&probe.trace_b64),
            )
        });
        assert_invalid(&label, outcome);
        cases += 1;
    }
    eprintln!("record evidence mutation corpus: {cases} cases, all deterministic");
    assert!(cases > 40, "the record corpus must stay substantial");
}

/// The record execution-version register parity sweep: the record gate
/// accepts exactly 1..=MAX_EXECUTION_VERSION, the exact set of the PHP
/// record/verifier gate (the same 0..=9 sweep runs in the PHP suite's
/// `ProtocolV4Test::testExecutionVersionRegisterGateSweepMatchesTheRustSuite`
/// and must land on the same verdicts case for case).
#[test]
fn record_execution_version_register_matches_the_php_gate_sweep() {
    let register = |v: u8| (1..=execution::MAX_EXECUTION_VERSION).contains(&v);

    // A record armed at the current maximum issues and verifies end to
    // end: the widened register accepts the full canonical set.
    let max_probe = issue_probe(execution::MAX_EXECUTION_VERSION);
    let label = format!(
        "record armed at the register maximum {}",
        execution::MAX_EXECUTION_VERSION
    );
    assert_eq!(
        guarded(&label, || validate_record(&max_probe.record)),
        Ok(()),
        "{label} must pass the record gate"
    );
    let mut max_control = max_probe.record.clone();
    let outcome = guarded(&label, || {
        verify_probe(
            &max_probe,
            &mut max_control,
            Some(&max_probe.digest),
            Some(&max_probe.trace_b64),
        )
    });
    assert!(
        matches!(outcome, VerifyOutcome::Valid { .. }),
        "{label} must verify end to end"
    );

    // The full 0..=9 sweep on one signed-at-1 armed record: rows inside
    // the register pass the record gate (and, when they differ from the
    // signed version, fail the signature binding instead), rows outside
    // it are MalformedRecord before any signature work.
    let probe = issue_probe(1);
    for value in 0..=9u8 {
        let mut record = probe.record.clone();
        record.execution_version = Some(value);
        let label = format!("record execution version register row {value}");
        let validated = guarded(&label, || validate_record(&record));
        if register(value) {
            assert_eq!(
                validated,
                Ok(()),
                "{label} rides the canonical register and must pass the record gate"
            );
        } else {
            assert_eq!(
                validated,
                Err(VerifyError::MalformedRecord),
                "{label} is outside the canonical register and must fail the record gate"
            );
        }
        let outcome = guarded(&label, || {
            verify_probe(
                &probe,
                &mut record,
                Some(&probe.digest),
                Some(&probe.trace_b64),
            )
        });
        let matches_sweep_expectation = match (&outcome, value) {
            (VerifyOutcome::Valid { .. }, 1) => true,
            (VerifyOutcome::Invalid(VerifyError::BadSignature), v) if register(v) => true,
            (VerifyOutcome::Invalid(VerifyError::MalformedRecord), v) if !register(v) => true,
            _ => false,
        };
        assert!(
            matches_sweep_expectation,
            "{label}: the full-path verdict {outcome:?} must mirror the PHP gate sweep"
        );
    }
    eprintln!(
        "record execution version register sweep: 0..=9 verdicts mirror the PHP gate (register 1..={})",
        execution::MAX_EXECUTION_VERSION
    );
}

/// The differential corpus shared with the PHP suite. Each case pins a
/// program blob, a trace and the expected decode/verify classification
/// (malformed, execution_mismatch or valid). The same 19 entries live
/// in `ExecutionDifferentialCorpusTest`; both suites must land on the
/// same verdict for every case.
struct CorpusCase {
    name: &'static str,
    version: u8,
    program: &'static str,
    trace: &'static str,
    expected: &'static str,
}

const CORPUS: [CorpusCase; 19] = [
    CorpusCase {
        name: "v1-valid",
        version: 1,
        program: "AQVsb2dpbgxsb2dpbi1hY3Rpb24BFhA4D3JWcHNlVHl2TVR4TG1zKxcJVXJYczFGMllaEh8PclZwc2VUeXZNVHhMbXMrHA9yVnBzZVR5dk1UeExtcysdD3JWcHNlVHl2TVR4TG1zKyAXCzJBcUxDOXNKQjR2BZbLHEPX1bDYB/KirhATuo0oGxILsBkQUA8xV2JFc3cvWGFsSkdSUlAJt5MaEOAQZFNIazI0RkFsM1diODVDMxQkFgVySmkjWQdwo5mMcPosjwLkcZPOX9oyWQ==",
        trace: "dcreate(clZwc2VUeXZNVHhMbXMr);cadd(VXJYczFGMlla);dappend(1);evreal(kiwi-ev:div);qreal(div|id=rVpseTyvMTxLms+);geom(0,10);sreal(bf797060cfda59d260e4f9be8bfb48c4281ac76ab4fcf982e42529ec7bfe5a76);cadd(MkFxTEM5c0pCNHY=);or(3621764315);shr(15901358);dserialize(aWQ9clZwc2VUeXZNVHhMbXMr);dappend(1);u8rot(0);dparent(1);dcreate(MVdiRXN3L1hhbEpHUlJQ);u8w(0);ddispatch(1);dcreate(ZFNIazI0RkFsM1diODVDMw==);dget();dgetd();shr(57671);mul(3922108062)",
        expected: "valid",
    },
    CorpusCase {
        name: "v2-valid",
        version: 2,
        program: "AQVsb2dpbgxsb2dpbi1hY3Rpb24CEhCNDFFpRjBZNTJyeGlsLxcJVHpOaWpvNHppEgjXIQxRaUYwWTUycnhpbC8YChgJDHIfDFFpRjBZNTJyeGlsLxwMUWlGMFk1MnJ4aWwvFHUZFgg/Y1l2KUZwWgjBAHQ4GXzGbcEkCxYEK3K7YCU/jIESBS5wXzlYoYg7",
        trace: "dcreate(UWlGMFk1MnJ4aWwv);cadd(VHpOaWpvNHpp);dappend(1);u8c(0);obs(24,10);u8r(10);u8w(124);evreal(kiwi-ev:div);qreal(div|id=QiF0Y52rxil/);dget();dparent(1);dgetd();u8c(0);add(983947936);u8rot(0);and(556959744);dappend(1);or(2129780539)",
        expected: "valid",
    },
    CorpusCase {
        name: "v3-valid",
        version: 3,
        program: "AQVsb2dpbgxsb2dpbi1hY3Rpb24DFBDBDnVPWlRTamU1a2ltTk9vFwU4QWF1TBIQkQ9YeWJUOTdpQXI4bWEvN3AVDHh6MnJmcWNqZzFqcgNXcyUSCNIhDnVPWlRTamU1a2ltTk9vIAogCebGHQ51T1pUU2plNWtpbU5PbyIPWHliVDk3aUFyOG1hLzdwIBwOdU9aVFNqZTVraW1OT28YCFRuRHZOUG9sFQZ4bWg3Nm4XKVghWD44OXY9K1s1bH0wUjtOX1AkQl8AZCz2ep3N8tYJAYwTC1Q3R0h3dEcxYUV0EVMRM1k+UyJVXWgkPDFaWDdbe0s=",
        trace: "dcreate(dU9aVFNqZTVraW1OT28=);cadd(OEFhdUw=);dappend(1);dcreate(WHliVDk3aUFyOG1hLzdw);dset(eHoycmZxY2pnMWpy);dappend(1);u8c(0);obs(32,10);u8r(10);u8w(208);geom(0,10);dsib(2);sreal(dcaf3e3e55c8ac4d0c5d0efa52c20026312f19884fef74774f9124b6ab0dd18f);qreal(none);ccont(0);dset(eG1oNzZu);add(33220944);u8w(92);dqsel(0);dattr(dGl0bGU=)",
        expected: "valid",
    },
    CorpusCase {
        name: "v4-valid",
        version: 4,
        program: "AQVsb2dpbgxsb2dpbi1hY3Rpb24EExCjDWxzM0JqblJlVG92Rk4VBHh6b2EcR0EvalpQVmZWSi9DZUsoYVlvPUIzJnNbaUBZYhIQuQdXTXZ2SXZXEfUDPHdLEiPWDGhKMTlmOGtDeW9keCN8B2JHT0NtU1IIYCENbHMzQmpuUmVUb3ZGThMKEwlW3B8NbHMzQmpuUmVUb3ZGTiIHV012dkl2VyQHYkdPQ21TUh8NbHMzQmpuUmVUb3ZGTiAgAHgKyiaEMcDn",
        trace: "dcreate(bHMzQmpuUmVUb3ZGTg==);dset(eHpvYQ==);dappend(1);dcreate(V012dkl2Vw==);dattr(ZGF0YS1raXdp);dappend(1);dchild(aEoxOWY4a0N5b2R4);dchild(YkdPQ21TUg==);u8c(0);obs(19,10);u8r(10);u8w(230);evreal(kiwi-ev:span);dsib(2);ddepth(2);evreal(kiwi-ev:span);sreal(cd9e8bb6200d6f874d25e6c520fcf5355622e04f4fb2f9140f48775369a8decb);sreal(cd9e8bb6200d6f874d25e6c520fcf5355622e04f4fb2f9140f48775369a8decb);add(4231826189)",
        expected: "valid",
    },
    CorpusCase {
        name: "v5-valid",
        version: 5,
        program: "AQVsb2dpbgxsb2dpbi1hY3Rpb24FGBCuB1JVL0ZoMlEVA3h5ZRhbcHReK0AkOTwwKmRPdFkvaE4jTld6WVcSEDIHWkdpZEZ5UxEIED5kPzI2QkFwYGpCUXkqVkESI7kFSWxlZlojLgVHeUV3aQjHIQdSVS9GaDJRAAoACW4GHwdSVS9GaDJRIgdaR2lkRnlTJAVHeUV3aSYEeHorTxQnB1pHaWRGeVMOCg4qKxoiMGhZRTBFSCMoJS9qdVQ0T1Aie2FjPllULAwgIB4YAAQwO2IhdS8Ddg==",
        trace: "dcreate(UlUvRmgyUQ==);dset(eHll);dappend(1);dcreate(WkdpZEZ5Uw==);dattr(dGl0bGU=);dappend(1);dchild(SWxlZlo=);dchild(R3lFd2k=);u8c(0);obs(0,10);u8r(10);u8w(10);evreal(kiwi-ev:span);dsib(2);ddepth(2);dclone(1);drepar(2);u8r(2);durlc(e76cac2dfcc313d58bb0f731c433badf0651978a1769007ff3c1ab62cf59fee7);dmutate(26);sreal(9b5d5921b44c155a1158e759306b670558b30865e11e604bbd721f255c3e6c0c);sreal(9b5d5921b44c155a1158e759306b670558b30865e11e604bbd721f255c3e6c0c);point(div);and(808124960)",
        expected: "valid",
    },
    CorpusCase {
        name: "v5-fragment-append",
        version: 5,
        program: "AQVsb2dpbgxsb2dpbi1hY3Rpb24FCBAABEFBQUERAAFaEhAABEJCQkISCAAKACUAAA==",
        trace: "dcreate(QUFBQQ==);dattr(ZGF0YS1raXdp);dappend(1);dcreate(QkJCQg==);dappend(1);u8c(0);u8r(0);dfrag(1)",
        expected: "valid",
    },
    CorpusCase {
        name: "v5-urlc-forged",
        version: 5,
        program: "AQVsb2dpbgxsb2dpbi1hY3Rpb24FGBCuB1JVL0ZoMlEVA3h5ZRhbcHReK0AkOTwwKmRPdFkvaE4jTld6WVcSEDIHWkdpZEZ5UxEIED5kPzI2QkFwYGpCUXkqVkESI7kFSWxlZlojLgVHeUV3aQjHIQdSVS9GaDJRAAoACW4GHwdSVS9GaDJRIgdaR2lkRnlTJAVHeUV3aSYEeHorTxQnB1pHaWRGeVMOCg4qKxoiMGhZRTBFSCMoJS9qdVQ0T1Aie2FjPllULAwgIB4YAAQwO2IhdS8Ddg==",
        trace: "dcreate(UlUvRmgyUQ==);dset(eHll);dappend(1);dcreate(WkdpZEZ5Uw==);dattr(dGl0bGU=);dappend(1);dchild(SWxlZlo=);dchild(R3lFd2k=);u8c(0);obs(0,10);u8r(10);u8w(10);evreal(kiwi-ev:span);dsib(2);ddepth(2);dclone(1);drepar(2);u8r(2);durlc(000000000000000000000000000000000000000000000000000000000000000g);dmutate(26);sreal(9b5d5921b44c155a1158e759306b670558b30865e11e604bbd721f255c3e6c0c);sreal(9b5d5921b44c155a1158e759306b670558b30865e11e604bbd721f255c3e6c0c);point(div);and(808124960)",
        expected: "execution_mismatch",
    },
    CorpusCase {
        name: "op-count-too-large",
        version: 1,
        program: "AQVsb2dpbgxsb2dpbi1hY3Rpb24B/xA4D3JWcHNlVHl2TVR4TG1zKxcJVXJYczFGMllaEh8PclZwc2VUeXZNVHhMbXMrHA9yVnBzZVR5dk1UeExtcysdD3JWcHNlVHl2TVR4TG1zKyAXCzJBcUxDOXNKQjR2BZbLHEPX1bDYB/KirhATuo0oGxILsBkQUA8xV2JFc3cvWGFsSkdSUlAJt5MaEOAQZFNIazI0RkFsM1diODVDMxQkFgVySmkjWQdwo5mMcPosjwLkcZPOX9oyWQ==",
        trace: "dcreate(clZwc2VUeXZNVHhMbXMr);cadd(VXJYczFGMlla);dappend(1);evreal(kiwi-ev:div);qreal(div|id=rVpseTyvMTxLms+);geom(0,10);sreal(bf797060cfda59d260e4f9be8bfb48c4281ac76ab4fcf982e42529ec7bfe5a76);cadd(MkFxTEM5c0pCNHY=);or(3621764315);shr(15901358);dserialize(aWQ9clZwc2VUeXZNVHhMbXMr);dappend(1);u8rot(0);dparent(1);dcreate(MVdiRXN3L1hhbEpHUlJQ);u8w(0);ddispatch(1);dcreate(ZFNIazI0RkFsM1diODVDMw==);dget();dgetd();shr(57671);mul(3922108062)",
        expected: "malformed",
    },
    CorpusCase {
        name: "trailing-bytes",
        version: 1,
        program: "AQVsb2dpbgxsb2dpbi1hY3Rpb24BFhA4D3JWcHNlVHl2TVR4TG1zKxcJVXJYczFGMllaEh8PclZwc2VUeXZNVHhMbXMrHA9yVnBzZVR5dk1UeExtcysdD3JWcHNlVHl2TVR4TG1zKyAXCzJBcUxDOXNKQjR2BZbLHEPX1bDYB/KirhATuo0oGxILsBkQUA8xV2JFc3cvWGFsSkdSUlAJt5MaEOAQZFNIazI0RkFsM1diODVDMxQkFgVySmkjWQdwo5mMcPosjwLkcZPOX9oyWQA=",
        trace: "dcreate(clZwc2VUeXZNVHhMbXMr);cadd(VXJYczFGMlla);dappend(1);evreal(kiwi-ev:div);qreal(div|id=rVpseTyvMTxLms+);geom(0,10);sreal(bf797060cfda59d260e4f9be8bfb48c4281ac76ab4fcf982e42529ec7bfe5a76);cadd(MkFxTEM5c0pCNHY=);or(3621764315);shr(15901358);dserialize(aWQ9clZwc2VUeXZNVHhMbXMr);dappend(1);u8rot(0);dparent(1);dcreate(MVdiRXN3L1hhbEpHUlJQ);u8w(0);ddispatch(1);dcreate(ZFNIazI0RkFsM1diODVDMw==);dget();dgetd();shr(57671);mul(3922108062)",
        expected: "malformed",
    },
    CorpusCase {
        name: "bad-op-version",
        version: 2,
        program: "AQVsb2dpbgxsb2dpbi1hY3Rpb24JEhCNDFFpRjBZNTJyeGlsLxcJVHpOaWpvNHppEgjXIQxRaUYwWTUycnhpbC8YChgJDHIfDFFpRjBZNTJyeGlsLxwMUWlGMFk1MnJ4aWwvFHUZFgg/Y1l2KUZwWgjBAHQ4GXzGbcEkCxYEK3K7YCU/jIESBS5wXzlYoYg7",
        trace: "dcreate(UWlGMFk1MnJ4aWwv);cadd(VHpOaWpvNHpp);dappend(1);u8c(0);obs(24,10);u8r(10);u8w(124);evreal(kiwi-ev:div);qreal(div|id=QiF0Y52rxil/);dget();dparent(1);dgetd();u8c(0);add(983947936);u8rot(0);and(556959744);dappend(1);or(2129780539)",
        expected: "malformed",
    },
    CorpusCase {
        name: "bad-op-version-down",
        version: 4,
        program: "AQVsb2dpbgxsb2dpbi1hY3Rpb24DExCjDWxzM0JqblJlVG92Rk4VBHh6b2EcR0EvalpQVmZWSi9DZUsoYVlvPUIzJnNbaUBZYhIQuQdXTXZ2SXZXEfUDPHdLEiPWDGhKMTlmOGtDeW9keCN8B2JHT0NtU1IIYCENbHMzQmpuUmVUb3ZGThMKEwlW3B8NbHMzQmpuUmVUb3ZGTiIHV012dkl2VyQHYkdPQ21TUh8NbHMzQmpuUmVUb3ZGTiAgAHgKyiaEMcDn",
        trace: "dcreate(bHMzQmpuUmVUb3ZGTg==);dset(eHpvYQ==);dappend(1);dcreate(V012dkl2Vw==);dattr(ZGF0YS1raXdp);dappend(1);dchild(aEoxOWY4a0N5b2R4);dchild(YkdPQ21TUg==);u8c(0);obs(19,10);u8r(10);u8w(230);evreal(kiwi-ev:span);dsib(2);ddepth(2);evreal(kiwi-ev:span);sreal(cd9e8bb6200d6f874d25e6c520fcf5355622e04f4fb2f9140f48775369a8decb);sreal(cd9e8bb6200d6f874d25e6c520fcf5355622e04f4fb2f9140f48775369a8decb);add(4231826189)",
        expected: "malformed",
    },
    CorpusCase {
        name: "overlong-operand",
        version: 1,
        program: "AQVsb2dpbgxsb2dpbi1hY3Rpb24BCBISEhISEhIMEQ==",
        trace: "dcreate(clZwc2VUeXZNVHhMbXMr);cadd(VXJYczFGMlla);dappend(1);evreal(kiwi-ev:div);qreal(div|id=rVpseTyvMTxLms+);geom(0,10);sreal(bf797060cfda59d260e4f9be8bfb48c4281ac76ab4fcf982e42529ec7bfe5a76);cadd(MkFxTEM5c0pCNHY=);or(3621764315);shr(15901358);dserialize(aWQ9clZwc2VUeXZNVHhMbXMr);dappend(1);u8rot(0);dparent(1);dcreate(MVdiRXN3L1hhbEpHUlJQ);u8w(0);ddispatch(1);dcreate(ZFNIazI0RkFsM1diODVDMw==);dget();dgetd();shr(57671);mul(3922108062)",
        expected: "malformed",
    },
    CorpusCase {
        name: "sibling-index-forged",
        version: 3,
        program: "AQVsb2dpbgxsb2dpbi1hY3Rpb24DFBDBDnVPWlRTamU1a2ltTk9vFwU4QWF1TBIQkQ9YeWJUOTdpQXI4bWEvN3AVDHh6MnJmcWNqZzFqcgNXcyUSCNIhDnVPWlRTamU1a2ltTk9vIAogCebGHQ51T1pUU2plNWtpbU5PbyIPWHliVDk3aUFyOG1hLzdwIBwOdU9aVFNqZTVraW1OT28YCFRuRHZOUG9sFQZ4bWg3Nm4XKVghWD44OXY9K1s1bH0wUjtOX1AkQl8AZCz2ep3N8tYJAYwTC1Q3R0h3dEcxYUV0EVMRM1k+UyJVXWgkPDFaWDdbe0s=",
        trace: "dcreate(dU9aVFNqZTVraW1OT28=);cadd(OEFhdUw=);dappend(1);dcreate(WHliVDk3aUFyOG1hLzdw);dset(eHoycmZxY2pnMWpy);dappend(1);u8c(0);obs(32,10);u8r(10);u8w(208);geom(0,10);dsib(3);sreal(dcaf3e3e55c8ac4d0c5d0efa52c20026312f19884fef74774f9124b6ab0dd18f);qreal(none);ccont(0);dset(eG1oNzZu);add(33220944);u8w(92);dqsel(0);dattr(dGl0bGU=)",
        expected: "execution_mismatch",
    },
    CorpusCase {
        name: "observe-out-of-bounds",
        version: 2,
        program: "AQVsb2dpbgxsb2dpbi1hY3Rpb24CEhCNDFFpRjBZNTJyeGlsLxcJVHpOaWpvNHppEgjXIQxRaUYwWTUycnhpbC8YChgJDHIfDFFpRjBZNTJyeGlsLxwMUWlGMFk1MnJ4aWwvFHUZFgg/Y1l2KUZwWgjBAHQ4GXzGbcEkCxYEK3K7YCU/jIESBS5wXzlYoYg7",
        trace: "dcreate(UWlGMFk1MnJ4aWwv);cadd(VHpOaWpvNHpp);dappend(1);u8c(0);obs(24,256);u8r(10);u8w(124);evreal(kiwi-ev:div);qreal(div|id=QiF0Y52rxil/);dget();dparent(1);dgetd();u8c(0);add(983947936);u8rot(0);and(556959744);dappend(1);or(2129780539)",
        expected: "execution_mismatch",
    },
    CorpusCase {
        name: "observe-out-of-bounds-dst",
        version: 2,
        program: "AQVsb2dpbgxsb2dpbi1hY3Rpb24CEhCNDFFpRjBZNTJyeGlsLxcJVHpOaWpvNHppEgjXIQxRaUYwWTUycnhpbC8YChgJDHIfDFFpRjBZNTJyeGlsLxwMUWlGMFk1MnJ4aWwvFHUZFgg/Y1l2KUZwWgjBAHQ4GXzGbcEkCxYEK3K7YCU/jIESBS5wXzlYoYg7",
        trace: "dcreate(UWlGMFk1MnJ4aWwv);cadd(VHpOaWpvNHpp);dappend(1);u8c(0);obs(99,10);u8r(10);u8w(124);evreal(kiwi-ev:div);qreal(div|id=QiF0Y52rxil/);dget();dparent(1);dgetd();u8c(0);add(983947936);u8rot(0);and(556959744);dappend(1);or(2129780539)",
        expected: "execution_mismatch",
    },
    CorpusCase {
        name: "duplicate-entry",
        version: 1,
        program: "AQVsb2dpbgxsb2dpbi1hY3Rpb24BFhA4D3JWcHNlVHl2TVR4TG1zKxcJVXJYczFGMllaEh8PclZwc2VUeXZNVHhMbXMrHA9yVnBzZVR5dk1UeExtcysdD3JWcHNlVHl2TVR4TG1zKyAXCzJBcUxDOXNKQjR2BZbLHEPX1bDYB/KirhATuo0oGxILsBkQUA8xV2JFc3cvWGFsSkdSUlAJt5MaEOAQZFNIazI0RkFsM1diODVDMxQkFgVySmkjWQdwo5mMcPosjwLkcZPOX9oyWQ==",
        trace: "dcreate(clZwc2VUeXZNVHhMbXMr);cadd(VXJYczFGMlla);dappend(1);dappend(1);evreal(kiwi-ev:div);qreal(div|id=rVpseTyvMTxLms+);geom(0,10);sreal(bf797060cfda59d260e4f9be8bfb48c4281ac76ab4fcf982e42529ec7bfe5a76);cadd(MkFxTEM5c0pCNHY=);or(3621764315);shr(15901358);dserialize(aWQ9clZwc2VUeXZNVHhMbXMr);dappend(1);dappend(1);u8rot(0);dparent(1);dcreate(MVdiRXN3L1hhbEpHUlJQ);u8w(0);ddispatch(1);dcreate(ZFNIazI0RkFsM1diODVDMw==);dget();dgetd();shr(57671);mul(3922108062)",
        expected: "execution_mismatch",
    },
    CorpusCase {
        name: "missing-entry",
        version: 2,
        program: "AQVsb2dpbgxsb2dpbi1hY3Rpb24CEhCNDFFpRjBZNTJyeGlsLxcJVHpOaWpvNHppEgjXIQxRaUYwWTUycnhpbC8YChgJDHIfDFFpRjBZNTJyeGlsLxwMUWlGMFk1MnJ4aWwvFHUZFgg/Y1l2KUZwWgjBAHQ4GXzGbcEkCxYEK3K7YCU/jIESBS5wXzlYoYg7",
        trace: "dcreate(UWlGMFk1MnJ4aWwv);cadd(VHpOaWpvNHpp);dappend(1);u8c(0);u8r(10);u8w(124);evreal(kiwi-ev:div);qreal(div|id=QiF0Y52rxil/);dget();dparent(1);dgetd();u8c(0);add(983947936);u8rot(0);and(556959744);dappend(1);or(2129780539)",
        expected: "execution_mismatch",
    },
    CorpusCase {
        name: "appended-garbage",
        version: 4,
        program: "AQVsb2dpbgxsb2dpbi1hY3Rpb24EExCjDWxzM0JqblJlVG92Rk4VBHh6b2EcR0EvalpQVmZWSi9DZUsoYVlvPUIzJnNbaUBZYhIQuQdXTXZ2SXZXEfUDPHdLEiPWDGhKMTlmOGtDeW9keCN8B2JHT0NtU1IIYCENbHMzQmpuUmVUb3ZGThMKEwlW3B8NbHMzQmpuUmVUb3ZGTiIHV012dkl2VyQHYkdPQ21TUh8NbHMzQmpuUmVUb3ZGTiAgAHgKyiaEMcDn",
        trace: "dcreate(bHMzQmpuUmVUb3ZGTg==);dset(eHpvYQ==);dappend(1);dcreate(V012dkl2Vw==);dattr(ZGF0YS1raXdp);dappend(1);dchild(aEoxOWY4a0N5b2R4);dchild(YkdPQ21TUg==);u8c(0);obs(19,10);u8r(10);u8w(230);evreal(kiwi-ev:span);dsib(2);ddepth(2);evreal(kiwi-ev:span);sreal(cd9e8bb6200d6f874d25e6c520fcf5355622e04f4fb2f9140f48775369a8decb);sreal(cd9e8bb6200d6f874d25e6c520fcf5355622e04f4fb2f9140f48775369a8decb);add(4231826189);add(0)",
        expected: "execution_mismatch",
    },
    CorpusCase {
        name: "appended-garbage-raw",
        version: 4,
        program: "AQVsb2dpbgxsb2dpbi1hY3Rpb24EExCjDWxzM0JqblJlVG92Rk4VBHh6b2EcR0EvalpQVmZWSi9DZUsoYVlvPUIzJnNbaUBZYhIQuQdXTXZ2SXZXEfUDPHdLEiPWDGhKMTlmOGtDeW9keCN8B2JHT0NtU1IIYCENbHMzQmpuUmVUb3ZGThMKEwlW3B8NbHMzQmpuUmVUb3ZGTiIHV012dkl2VyQHYkdPQ21TUh8NbHMzQmpuUmVUb3ZGTiAgAHgKyiaEMcDn",
        trace: "dcreate(bHMzQmpuUmVUb3ZGTg==);dset(eHpvYQ==);dappend(1);dcreate(V012dkl2Vw==);dattr(ZGF0YS1raXdp);dappend(1);dchild(aEoxOWY4a0N5b2R4);dchild(YkdPQ21TUg==);u8c(0);obs(19,10);u8r(10);u8w(230);evreal(kiwi-ev:span);dsib(2);ddepth(2);evreal(kiwi-ev:span);sreal(cd9e8bb6200d6f874d25e6c520fcf5355622e04f4fb2f9140f48775369a8decb);sreal(cd9e8bb6200d6f874d25e6c520fcf5355622e04f4fb2f9140f48775369a8decb);add(4231826189)garbage",
        expected: "execution_mismatch",
    },
];

#[test]
fn differential_corpus_verdicts_match_the_php_suite() {
    // The manifest ceiling check mirrors the PHP test: every corpus
    // case stays inside the declared execution-version register.
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("../../../protocol/execution-v1.json"))
            .expect("the manifest must parse");
    let max_version = manifest["max_execution_version"].as_u64().unwrap() as u8;

    let mut valid_digests = 0usize;
    for case in CORPUS {
        assert!(
            (1..=max_version).contains(&case.version),
            "case {} sits inside the manifest version register",
            case.name
        );
        let verdict = guarded(case.name, || classify(case.program, case.trace));
        let expected = match case.expected {
            "malformed" => Verdict::Malformed,
            "execution_mismatch" => Verdict::ExecutionMismatch,
            "valid" => Verdict::Valid,
            other => panic!("unknown expected classification {other}"),
        };
        assert_eq!(
            verdict, expected,
            "case {}: the Rust verdict must match the shared corpus expectation",
            case.name
        );
        if verdict == Verdict::Valid {
            let digest_a = execution::expected_digest_over_trace(case.program, NONCE, case.trace)
                .expect("a valid trace must digest");
            let digest_b = execution::expected_digest_over_trace(case.program, NONCE, case.trace)
                .expect("a valid trace must digest deterministically");
            assert_eq!(
                digest_a, digest_b,
                "case {}: the digest is deterministic",
                case.name
            );
            assert_eq!(
                digest_a.len(),
                64,
                "case {}: the digest is 64 hex",
                case.name
            );
            assert!(
                digest_a.bytes().all(|b| b.is_ascii_hexdigit()),
                "case {}: the digest is hex",
                case.name
            );
            let decoded = execution::decode(case.program).expect("a valid case parses");
            assert_eq!(
                decoded.op_version, case.version,
                "case {}: the decoded program declares its case version",
                case.name
            );
            valid_digests += 1;
        }
    }
    assert_eq!(
        valid_digests, 6,
        "the corpus pins one valid case per version plus the version-5 fragment append"
    );
}

#[test]
fn token_round_trip_with_mutated_execution_evidence_never_panics() {
    // The token surface of the same corpus: a solution token carrying a
    // mutated execution digest or trace segment must decode without a
    // panic, and the decode outcome must be deterministic. The digest
    // and trace shapes the driver submits ride the fifth segment
    // (`digest` or `digest:trace`).
    let mut rng = StdRng::seed_from_u64(0x5EED_E2EC_0102);
    let base = SolutionToken {
        nonce: NONCE.to_string(),
        counter: 1,
        duration_ms: 5000,
        telemetry: serde_json::json!({"v": 2}),
        execution_digest: Some("a".repeat(64)),
        execution_trace: Some("dcreate(AAAA)".to_string()),
        rsw_proof: None,
    };
    for variant in 0..64u8 {
        let mut token = base.clone();
        if variant % 2 == 0 {
            token.execution_digest = Some(format!("{:02x}", variant).repeat(32));
        } else {
            let at = (variant % 16) as usize;
            let mut trace = token.execution_trace.clone().unwrap().into_bytes();
            let len = trace.len();
            if len > 0 {
                trace[at % len] ^= 0x5A;
                token.execution_trace = Some(String::from_utf8_lossy(&trace).into_owned());
            }
        }
        let encoded = token.encode();
        let label = format!("token variant {variant}");
        let decoded = guarded(&label, || SolutionToken::decode(&encoded));
        let again = guarded(&label, || SolutionToken::decode(&encoded));
        assert_eq!(
            decoded.is_ok(),
            again.is_ok(),
            "{label}: the token decode outcome is deterministic"
        );
        let _ = rng.gen::<u8>();
    }
}
