//! Fuzz tests for validation functions in apexmail-lib.

use fuzz_tests::*;
use apexmail_lib::validation::{is_valid_email, is_valid_domain, is_valid_uuid, has_null_bytes};

#[test]
fn fuzz_email_validation_never_panics() {
    // 10,000 random strings — is_valid_email must never panic.
    for _ in 0..10_000 {
        let input = random_ascii(rand::random::<usize>() % 256);
        let _ = is_valid_email(&input);
    }
    // Also test with empty and very short
    let _ = is_valid_email("");
    let _ = is_valid_email("@");
    let _ = is_valid_email("a");
}

#[test]
fn fuzz_domain_validation_never_panics() {
    for _ in 0..10_000 {
        let input = random_ascii(rand::random::<usize>() % 256);
        let _ = is_valid_domain(&input);
    }
    let _ = is_valid_domain("");
    let _ = is_valid_domain(".");
    let _ = is_valid_domain("..");
}

#[test]
fn fuzz_uuid_validation_never_panics() {
    for _ in 0..10_000 {
        let input = random_ascii(rand::random::<usize>() % 64);
        let _ = is_valid_uuid(&input);
    }
    let _ = is_valid_uuid("");
    let _ = is_valid_uuid("00000000-0000-0000-0000-000000000000");
}

#[test]
fn fuzz_null_byte_detection() {
    // Strings with embedded \0 must always be detected.
    for _ in 0..1_000 {
        let prefix = random_string(rand::random::<usize>() % 50);
        let suffix = random_string(rand::random::<usize>() % 50);
        let with_null = format!("{prefix}\0{suffix}");
        assert!(
            has_null_bytes(&with_null),
            "Failed to detect null byte in: {:?}",
            with_null
        );
    }
    // Strings without null bytes should not be detected (probabilistic check).
    for _ in 0..1_000 {
        let clean = random_string(rand::random::<usize>() % 100);
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
    // 1,000 Unicode emails — must never panic.
    for _ in 0..1_000 {
        let local = random_unicode(rand::random::<usize>() % 30 + 1);
        let domain = random_unicode(rand::random::<usize>() % 20 + 1);
        let email = format!("{local}@{domain}.com");
        let _ = is_valid_email(&email);
    }
}

#[test]
fn fuzz_very_long_inputs() {
    // Inputs up to 1 MB — must not panic or hang.
    let sizes = [1_000, 10_000, 100_000, 500_000, 1_000_000];
    for &size in &sizes {
        let long_input = random_ascii(size);
        let _ = is_valid_email(&long_input);
        let _ = is_valid_domain(&long_input);
        let _ = is_valid_uuid(&long_input);
        let _ = has_null_bytes(&long_input);
    }
}
