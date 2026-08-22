//! Benchmarks for WAF engine performance — critical hot path.
//!
//! Measures throughput for://! - Clean requests (fast path)
//! - SQLi payloads
//! - XSS payloads
//! - Path traversal
//! - Command injection
//! - Full inspection pipeline

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use waf_engine::{
    config::WafConfig,
    engine::{HttpRequest, WafEngine},
};

fn make_engine() -> WafEngine {
    WafEngine::new(WafConfig::default())
}

fn make_clean_request<'a>(path: &'a str, body: Option<&'a str>) -> HttpRequest<'a> {
    HttpRequest {
        client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        method: "GET",
        path,
        query_string: None,
        headers: &[],
        body,
    }
}

// ---------------------------------------------------------------------------
// Clean request benchmarks (fast path)
// ---------------------------------------------------------------------------

fn bench_clean_request(c: &mut Criterion) {
    let engine = make_engine();

    let mut group = c.benchmark_group("waf_clean_requests");
    group.throughput(Throughput::Elements(1));

    // Simple GET
    group.bench_function("simple_get", |b| {
        let req = make_clean_request("/api/v1/users", None);
        b.iter(|| engine.inspect(black_box(&req)))
    });

    // GET with query string
    group.bench_function("get_with_query", |b| {
        let req = HttpRequest {
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            method: "GET",
            path: "/search",
            query_string: Some("q=hello+world&page=1&limit=20"),
            headers: &[],
            body: None,
        };
        b.iter(|| engine.inspect(black_box(&req)))
    });

    // POST with JSON body
    group.bench_function("post_json_small", |b| {
        let body = r#"{"name":"John","email":"john@example.com"}"#;
        let req = HttpRequest {
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            method: "POST",
            path: "/api/v1/users",
            query_string: None,
            headers: &[("content-type".into(), "application/json".into())],
            body: Some(body),
        };
        b.iter(|| engine.inspect(black_box(&req)))
    });

    // POST with larger JSON body
    group.bench_function("post_json_1kb", |b| {
        let body = format!(r#"{{"data":"{}"}}"#, "x".repeat(1000));
        let req = HttpRequest {
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            method: "POST",
            path: "/api/v1/data",
            query_string: None,
            headers: &[("content-type".into(), "application/json".into())],
            body: Some(&body),
        };
        b.iter(|| engine.inspect(black_box(&req)))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// SQLi detection benchmarks
// ---------------------------------------------------------------------------

fn bench_sqli_detection(c: &mut Criterion) {
    let engine = make_engine();

    let mut group = c.benchmark_group("waf_sqli");
    group.throughput(Throughput::Elements(1));

    let sqli_payloads = [
        ("classic_union", "' UNION SELECT * FROM users --"),
        ("boolean_blind", "' OR 1=1 --"),
        ("time_blind", "'; WAITFOR DELAY '0:0:5' --"),
        ("stacked", "'; DROP TABLE users; --"),
        ("comment_bypass", "/*!50000UNION*/SELECT"),
        ("hex_encoded", "0x27206f722031"),
        ("nested", "' OR/**/1=1/**/ --"),
    ];

    for (name, payload) in sqli_payloads {
        group.bench_with_input(BenchmarkId::new("query", name), &payload, |b, payload| {
            let req = HttpRequest {
                client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                method: "GET",
                path: "/search",
                query_string: Some(payload),
                headers: &[],
                body: None,
            };
            b.iter(|| engine.inspect(black_box(&req)))
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// XSS detection benchmarks
// ---------------------------------------------------------------------------

fn bench_xss_detection(c: &mut Criterion) {
    let engine = make_engine();

    let mut group = c.benchmark_group("waf_xss");
    group.throughput(Throughput::Elements(1));

    let xss_payloads = [
        ("script_tag", "<script>alert(1)</script>"),
        ("img_onerror", "<img src=x onerror=alert(1)>"),
        ("svg_onload", "<svg onload=alert(1)>"),
        ("event_handler", "<body onload=alert(1)>"),
        ("javascript_uri", "javascript:alert(1)"),
        ("data_uri", "data:text/html,<script>alert(1)</script>"),
        ("encoded", "%3Cscript%3Ealert(1)%3C/script%3E"),
    ];

    for (name, payload) in xss_payloads {
        group.bench_with_input(BenchmarkId::new("body", name), &payload, |b, payload| {
            let req = HttpRequest {
                client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                method: "POST",
                path: "/comment",
                query_string: None,
                headers: &[("content-type".into(), "text/plain".into())],
                body: Some(payload),
            };
            b.iter(|| engine.inspect(black_box(&req)))
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Path traversal benchmarks
// ---------------------------------------------------------------------------

fn bench_path_traversal(c: &mut Criterion) {
    let engine = make_engine();

    let mut group = c.benchmark_group("waf_path_traversal");
    group.throughput(Throughput::Elements(1));

    let traversal_payloads = [
        ("basic", "../../../etc/passwd"),
        ("encoded", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd"),
        ("double_encoded", "%252e%252e%252f"),
        ("null_byte", "../../../etc/passwd%00.jpg"),
        ("windows", "..\\..\\..\\windows\\system32\\config\\sam"),
    ];

    for (name, payload) in traversal_payloads {
        group.bench_with_input(BenchmarkId::new("path", name), &payload, |b, payload| {
            let req = HttpRequest {
                client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                method: "GET",
                path: payload,
                query_string: None,
                headers: &[],
                body: None,
            };
            b.iter(|| engine.inspect(black_box(&req)))
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Command injection benchmarks
// ---------------------------------------------------------------------------

fn bench_command_injection(c: &mut Criterion) {
    let engine = make_engine();

    let mut group = c.benchmark_group("waf_cmdi");
    group.throughput(Throughput::Elements(1));

    let cmdi_payloads = [
        ("pipe", "| cat /etc/passwd"),
        ("semicolon", "; cat /etc/passwd"),
        ("backtick", "`cat /etc/passwd`"),
        ("dollar_paren", "$(cat /etc/passwd)"),
        ("newline", "\ncat /etc/passwd"),
        ("and", "&& cat /etc/passwd"),
    ];

    for (name, payload) in cmdi_payloads {
        group.bench_with_input(BenchmarkId::new("query", name), &payload, |b, payload| {
            let req = HttpRequest {
                client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                method: "GET",
                path: "/ping",
                query_string: Some(&format!("host={}", payload)),
                headers: &[],
                body: None,
            };
            b.iter(|| engine.inspect(black_box(&req)))
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Request size scaling benchmarks
// ---------------------------------------------------------------------------

fn bench_request_size_scaling(c: &mut Criterion) {
    let engine = make_engine();

    let mut group = c.benchmark_group("waf_size_scaling");

    let sizes = [100, 1_000, 10_000, 50_000];

    for size in sizes {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("body_bytes", size), &size, |b, &size| {
            let body = "x".repeat(size);
            let req = HttpRequest {
                client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                method: "POST",
                path: "/upload",
                query_string: None,
                headers: &[("content-type".into(), "text/plain".into())],
                body: Some(&body),
            };
            b.iter(|| engine.inspect(black_box(&req)))
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Header inspection benchmarks
// ---------------------------------------------------------------------------

fn bench_header_inspection(c: &mut Criterion) {
    let engine = make_engine();

    let mut group = c.benchmark_group("waf_headers");
    group.throughput(Throughput::Elements(1));

    // Varying number of headers
    for num_headers in [5, 10, 20, 50] {
        let headers: Vec<(String, String)> = (0..num_headers)
            .map(|i| (format!("x-custom-{}", i), format!("value-{}", i)))
            .collect();

        group.bench_with_input(
            BenchmarkId::new("count", num_headers),
            &headers,
            |b, headers| {
                let req = HttpRequest {
                    client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    method: "GET",
                    path: "/api",
                    query_string: None,
                    headers,
                    body: None,
                };
                b.iter(|| engine.inspect(black_box(&req)))
            },
        );
    }

    // Malicious headers
    group.bench_function("xss_in_header", |b| {
        let headers = vec![
            ("x-forwarded-for".into(), "192.168.1.1".into()),
            ("user-agent".into(), "<script>alert(1)</script>".into()),
        ];
        let req = HttpRequest {
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            method: "GET",
            path: "/",
            query_string: None,
            headers: &headers,
            body: None,
        };
        b.iter(|| engine.inspect(black_box(&req)))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_clean_request,
    bench_sqli_detection,
    bench_xss_detection,
    bench_path_traversal,
    bench_command_injection,
    bench_request_size_scaling,
    bench_header_inspection,
);

criterion_main!(benches);
