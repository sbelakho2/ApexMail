//! Black-box lifecycle tests for the deployed `outbound-mta` daemon binary.
//!
//! The daemon is spawned as a real child process against the local Postgres
//! (`TEST_DATABASE_URL`) on an ephemeral health port, its readiness
//! endpoints are polled over TCP, and the stop path is exercised with real
//! signals. A hung startup must fail the test on a deadline, never hang the
//! runner; children are always reaped.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const STARTUP_DEADLINE: Duration = Duration::from_secs(30);
const STOP_DEADLINE: Duration = Duration::from_secs(15);

fn test_database_url() -> Option<String> {
    migrator::test_support::assert_soft_skip_allowed("TEST_DATABASE_URL");
    match std::env::var("TEST_DATABASE_URL") {
        Ok(url) if !url.trim().is_empty() => Some(url),
        _ => None,
    }
}

/// Reserve an ephemeral port for the child's health listener.
fn reserve_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .expect("probe bind")
        .local_addr()
        .expect("addr")
}

fn spawn_daemon(database_url: &str, health_addr: SocketAddr) -> Child {
    Command::new(env!("CARGO_BIN_EXE_outbound-mta"))
        .env("DATABASE_URL", database_url)
        .env("OUTBOUND_MTA_HEALTH_ADDR", health_addr.to_string())
        .env("RUST_LOG", "error")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the outbound-mta binary")
}

/// Poll the daemon's health endpoint until it answers (or the deadline
/// expires — a hung bind fails here instead of hanging the runner).
fn wait_for_health(addr: SocketAddr) -> (u16, String) {
    let deadline = Instant::now() + STARTUP_DEADLINE;
    loop {
        if let Some(answer) = http_get(addr, "/healthz") {
            return answer;
        }
        if Instant::now() > deadline {
            panic!("the daemon never answered /healthz on {addr} within {STARTUP_DEADLINE:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Plain HTTP/1.0 GET over a raw socket; None on any connection failure.
fn http_get(addr: SocketAddr, path: &str) -> Option<(u16, String)> {
    let mut stream =
        TcpStream::connect_timeout(&addr, Duration::from_secs(2)).ok()?;
    stream
        .write_all(format!("GET {path} HTTP/1.0\r\n\r\n").as_bytes())
        .ok()?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status: u16 = text.split_whitespace().nth(1)?.parse().ok()?;
    Some((status, text))
}

/// Wait for the child to exit within the deadline, reaping it either way so
/// nextest never sees a leaked process.
fn reap(child: &mut Child, deadline: Duration) -> std::process::ExitStatus {
    let at = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            return status;
        }
        if at.elapsed() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the daemon did not exit within {deadline:?}");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn stderr_of(child: &mut Child) -> String {
    let mut text = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut text);
    }
    text
}

/// The deployed daemon serves its health contract against the real ledger
/// and drains to exit code 0 on SIGTERM — the container stop signal. Before
/// SIGTERM was handled, the default disposition killed the process
/// mid-sweep and the graceful drain never ran.
#[test]
fn daemon_serves_health_and_metrics_and_sigterm_exits_cleanly() {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping: set TEST_DATABASE_URL to drive the daemon against Postgres");
        return;
    };
    let addr = reserve_addr();
    let mut child = spawn_daemon(&database_url, addr);

    let (status, body) = wait_for_health(addr);
    assert_eq!(status, 200, "healthz: {body}");
    assert!(body.contains("\"status\":\"ok\""), "healthz: {body}");
    assert!(
        body.contains("\"service\":\"outbound-mta\""),
        "healthz: {body}"
    );

    // /readyz shares the same live-ledger contract.
    let (status, body) = http_get(addr, "/readyz").expect("readyz");
    assert_eq!(status, 200, "readyz: {body}");

    // /metrics exposes the queue gauges the SLO alert scrapes.
    let (status, metrics) = http_get(addr, "/metrics").expect("metrics");
    assert_eq!(status, 200, "metrics: {metrics}");
    assert!(
        metrics.contains("apexmail_outbound_mta_queue_pending"),
        "metrics: {metrics}"
    );
    assert!(
        metrics.contains("apexmail_outbound_mta_sweeps_total"),
        "metrics: {metrics}"
    );

    let _ = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .output()
        .expect("kill utility");
    let exit = reap(&mut child, STOP_DEADLINE);
    assert_eq!(
        exit.code(),
        Some(0),
        "SIGTERM must drain to a clean exit, got {exit}"
    );
}

/// A SIGINT (Ctrl-C) drains to exit code 0 as well.
#[test]
fn daemon_sigint_exits_cleanly() {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping: set TEST_DATABASE_URL to drive the daemon against Postgres");
        return;
    };
    let addr = reserve_addr();
    let mut child = spawn_daemon(&database_url, addr);
    wait_for_health(addr);

    let _ = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .output()
        .expect("kill utility");
    let exit = reap(&mut child, STOP_DEADLINE);
    assert_eq!(exit.code(), Some(0), "SIGINT must drain cleanly, got {exit}");
}

/// A malformed DATABASE_URL must fail fast with exit code 1 and an error
/// naming the variable — never serve "ok" health for a relay that cannot
/// reach its queue. (A well-formed URL to a dead server is retried for the
/// pool's 30s acquire_timeout by design; a parse error must not wait.)
#[test]
fn daemon_fails_fast_on_a_malformed_database_url() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_outbound-mta"))
        .env("DATABASE_URL", "definitely-not-a-postgres-url")
        .env("OUTBOUND_MTA_HEALTH_ADDR", reserve_addr().to_string())
        .env("RUST_LOG", "error")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the outbound-mta binary");
    let exit = reap(&mut child, STARTUP_DEADLINE);
    assert_eq!(exit.code(), Some(1), "expected an honest failure, got {exit}");
    let stderr = stderr_of(&mut child);
    assert!(
        stderr.contains("failed to connect to DATABASE_URL"),
        "stderr must name the failure: {stderr}"
    );
}

/// A duplicate instance on an already-bound health port must exit 1 with an
/// error naming the address, not run half-alive without its endpoints.
#[test]
fn daemon_refuses_a_taken_health_port() {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping: set TEST_DATABASE_URL to drive the daemon against Postgres");
        return;
    };
    let addr = reserve_addr();
    let _occupant = TcpListener::bind(addr).expect("occupy the port");
    let mut child = spawn_daemon(&database_url, addr);
    let exit = reap(&mut child, STARTUP_DEADLINE);
    assert_eq!(exit.code(), Some(1), "expected an honest failure, got {exit}");
    let stderr = stderr_of(&mut child);
    assert!(
        stderr.contains("failed to bind health listener") && stderr.contains(&addr.to_string()),
        "stderr must name the bind failure: {stderr}"
    );
}
