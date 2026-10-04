//! Fuzz tests for validation functions in apexmail-lib.
//!
//! SM12 F12: the RNG is seeded from `FUZZ_SEED` (printed once per process —
//! see `fuzz_tests::fuzz_rng`) so failures reproduce, and every loop now
//! carries an OUTPUT ORACLE. The audit caught the old loops discarding the
//! verdict (`let _ = is_valid_email(&input);`) — a validator that returned
//! constant `true` or constant `false` would have passed all 10,000
//! iterations. Constant validators now fail immediately:
//!
//! * `fuzz_email_accepts_wellformed` — a constant-false validator fails;
//! * `fuzz_email_rejects_malformed` — a constant-true validator fails;
//! * `fuzz_uuid_validation_oracle` / `fuzz_sanitize_round_trip` — the same
//!   principle for the UUID and sanitization surfaces.

use apexmail_lib::validation::{
    has_null_bytes, is_valid_domain, is_valid_email, is_valid_uuid, sanitize_string,
};
use fuzz_tests::*;
use rand::Rng;

#[test]
fn fuzz_email_validation_never_panics() {
    // 10,000 random ASCII strings — is_valid_email must never panic AND
    // must agree with a cheap shape referee on the obvious cases.
    let mut rng = fuzz_tests::fuzz_rng();
    for _ in 0..10_000 {
        let input = random_ascii(rng.random::<u32>() as usize % 256);
        let verdict = is_valid_email(&input);
        // Oracle: a string without any '@' can never be valid.
        if !input.contains('@') {
            assert!(!verdict, "validator accepted an @-less string: {input:?}");
        }
        // Oracle: a string containing a raw control char can never be valid.
        if input.chars().any(|c| c.is_control()) {
            assert!(
                !verdict,
                "validator accepted a control-char string: {input:?}"
            );
        }
    }
    // Fixed edge inputs with asserted verdicts (previously discarded).
    assert!(!is_valid_email(""), "empty must be invalid");
    assert!(!is_valid_email("@"), "bare @ must be invalid");
    assert!(!is_valid_email("a"), "bare local must be invalid");
}

#[test]
fn fuzz_email_accepts_wellformed() {
    // Oracle against a constant-FALSE validator: structurally well-formed
    // addresses constructed from random parts MUST be accepted. The TLD is
    // letters-only per the validator's `[a-zA-Z]{2,}` rule.
    let mut rng = fuzz_tests::fuzz_rng();
    for _ in 0..2_000 {
        let local_len = rng.random_range(1..=20);
        let domain_len = rng.random_range(1..=15);
        let tld_len = rng.random_range(2..=6);
        let tld: String = (0..tld_len)
            .map(|_| (b'a' + rng.random_range(0..26)) as char)
            .collect();
        let email = format!(
            "{}@{}.{}",
            random_string(local_len),
            random_string(domain_len),
            tld
        );
        assert!(
            is_valid_email(&email),
            "constant-false regression: well-formed {email:?} was rejected"
        );
    }
}

#[test]
fn fuzz_email_rejects_malformed() {
    // Oracle against a constant-TRUE validator: malformed shapes MUST be
    // rejected, at volume, from randomized malformations.
    let mut rng = fuzz_tests::fuzz_rng();
    for _ in 0..2_000 {
        let local = random_string(rng.random_range(1..=20));
        let domain = random_string(rng.random_range(1..=15));
        let malformation = rng.random_range(0..4);
        let bad = match malformation {
            0 => format!("{local}{domain}"),        // no @
            1 => format!("{local}@{domain}@x.com"), // two @
            2 => format!("@{domain}.com"),          // empty local
            _ => format!("{local}@{domain}"),       // no dot in domain
        };
        assert!(
            !is_valid_email(&bad),
            "constant-true regression: malformed {bad:?} was accepted"
        );
    }
}

#[test]
fn fuzz_domain_validation_never_panics() {
    let mut rng = fuzz_tests::fuzz_rng();
    for _ in 0..10_000 {
        let input = random_ascii(rng.random::<u32>() as usize % 256);
        let verdict = is_valid_domain(&input);
        // Oracle: a label with no dot has no TLD — never a valid domain…
        // …EXCEPT the documented domain-literal form: production routes a
        // leading `[` to DOMAIN_LITERAL_RE
        // (`^\[[^\]\s\x00-\x1f\x7f-\x9f]+\]$`,
        // apexmail-lib/src/validation.rs), which accepts printable bracketed
        // literals regardless of dots — the very contract the email side
        // relies on for `user@[192.168.1.1]`. Random ASCII hits that shape
        // (`"[...]"` with no dot), so the oracle must not fire there.
        let is_domain_literal = input.starts_with('[');
        if !input.contains('.') && !is_domain_literal {
            assert!(!verdict, "validator accepted a TLD-less domain: {input:?}");
        }
        // Control characters inside domain literals are rejected since the
        // SM4 escalation repair — pinned by
        // apexmail-lib's `test_domain_literal_rejects_control_characters_and_whitespace`
        // (the generator below cannot produce control chars, so the oracle
        // does not re-assert that direction here).
    }
    assert!(!is_valid_domain(""), "empty must be invalid");
    assert!(!is_valid_domain(".."), "dot-dot must be invalid");
    assert!(is_valid_domain("example.co"), "plain domain must be valid");
    // Pin the documented literal contract explicitly so it is a decision,
    // not an accident the fuzzer trips over.
    assert!(
        is_valid_domain("[192.168.1.1]"),
        "an IP domain literal must be valid (email side accepts user@[192.168.1.1])"
    );
    assert!(!is_valid_domain("[]"), "an empty literal must be invalid");
    assert!(
        !is_valid_domain("[a]b]"),
        "a literal with an embedded ']' must be invalid"
    );
}

#[test]
fn fuzz_uuid_validation_oracle() {
    let mut rng = fuzz_tests::fuzz_rng();
    for _ in 0..10_000 {
        let input = random_ascii(rng.random::<u32>() as usize % 64);
        let verdict = is_valid_uuid(&input);
        // Oracle: the canonical form is exactly 36 chars — nothing else is
        // valid.
        if input.len() != 36 {
            assert!(!verdict, "validator accepted a non-36-char UUID: {input:?}");
        }
    }
    let mut rng = fuzz_tests::fuzz_rng();
    const HEX: &[u8] = b"0123456789abcdef";
    for _ in 0..2_000 {
        // A canonically-shaped random UUID (real hex digits) must be
        // accepted.
        let hex: String = (0..32)
            .map(|_| HEX[rng.random_range(0..HEX.len())] as char)
            .collect();
        let uuid = format!(
            "{}-{}-{}-{}-{}",
            &hex[0..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..32]
        );
        assert!(
            is_valid_uuid(&uuid),
            "canonical random UUID {uuid} was rejected"
        );
    }
    assert!(!is_valid_uuid(""), "empty must be invalid");
}

#[test]
fn fuzz_sanitize_round_trip() {
    // Sanitize must ALWAYS produce NUL-free output and must NEVER alter
    // NUL-free input — a sanitizer that mutated clean input or left NULs
    // in place fails here (the old loop discarded its output entirely).
    let mut rng = fuzz_tests::fuzz_rng();
    for _ in 0..5_000 {
        let len = rng.random_range(0..200);
        let with_maybe_null = {
            let mut s = random_ascii(len);
            if rng.random_bool(0.5) {
                let pos = rng.random_range(0..=s.len());
                s.insert(pos, '\0');
            }
            s
        };
        let sanitized = sanitize_string(&with_maybe_null);
        assert!(
            !has_null_bytes(&sanitized),
            "sanitizer left a NUL in: {with_maybe_null:?} -> {sanitized:?}"
        );
        if !with_maybe_null.contains('\0') && !with_maybe_null.contains("\\u0000") {
            assert_eq!(sanitized, with_maybe_null, "sanitizer mutated clean input");
        }
    }
}

#[test]
fn fuzz_null_byte_detection() {
    // Strings with embedded \0 must always be detected.
    let mut rng = fuzz_tests::fuzz_rng();
    for _ in 0..1_000 {
        let prefix = random_string(rng.random::<u32>() as usize % 50);
        let suffix = random_string(rng.random::<u32>() as usize % 50);
        let with_null = format!("{prefix}\0{suffix}");
        assert!(
            has_null_bytes(&with_null),
            "Failed to detect null byte in: {:?}",
            with_null
        );
    }
    // Strings without null bytes should not be detected (probabilistic check).
    for _ in 0..1_000 {
        let clean = random_string(rng.random::<u32>() as usize % 100);
        // random_string only produces alphanumeric, so no null bytes.
        assert!(
            !has_null_bytes(&clean),
            "False positive null byte detection in: {:?}",
            clean
        );
    }
}

#[test]
fn fuzz_email_with_unicode() {
    // 1,000 Unicode emails — must never panic, and (RFC 6531 EAI being
    // supported) a Unicode address built purely from alphanumeric parts
    // must be ACCEPTED.
    let mut rng = fuzz_tests::fuzz_rng();
    for _ in 0..1_000 {
        let local = random_unicode(rng.random::<u32>() as usize % 30 + 1);
        let domain = random_unicode(rng.random::<u32>() as usize % 20 + 1);
        let email = format!("{local}@{domain}.com");
        let verdict = is_valid_email(&email);
        // Oracle: '@' or whitespace anywhere in the parts must reject —
        // the split or the domain regex cannot survive them.
        if local.contains('@') || domain.contains('@') {
            assert!(!verdict, "embedded @ must invalidate: {email:?}");
        } else if local.chars().any(char::is_whitespace) || domain.chars().any(char::is_whitespace)
        {
            assert!(!verdict, "whitespace must invalidate: {email:?}");
        } else if local.chars().all(char::is_alphanumeric)
            && domain.chars().all(char::is_alphanumeric)
            // Byte-length referee: the documented RFC caps (local ≤ 64
            // octets, total ≤ 254) are the only other rules alphanumeric
            // parts can trip — EAI characters are 2-4 UTF-8 bytes each.
            && local.len() <= 64
            && email.len() <= 254
        {
            // Accept oracle: alphanumeric parts within the byte caps
            // violate none of the validator's rules (ASCII or RFC 6531
            // EAI alike).
            assert!(
                verdict,
                "EAI address {email:?} with clean alphanumeric parts was rejected"
            );
        }
    }
}

#[test]
fn fuzz_very_long_inputs() {
    // Inputs up to 1 MB — must not panic or hang, and the 254-char RFC
    // 5321 cap must reject every oversized address.
    let sizes = [1_000, 10_000, 100_000, 500_000, 1_000_000];
    for &size in &sizes {
        let long_input = random_ascii(size);
        assert!(
            !is_valid_email(&long_input),
            "a {size}-char address must exceed the 254 cap"
        );
        assert!(
            !is_valid_domain(&long_input),
            "oversized domain must be invalid"
        );
        assert!(
            !is_valid_uuid(&long_input),
            "oversized UUID must be invalid"
        );
        assert!(!has_null_bytes(&long_input));
    }
}
