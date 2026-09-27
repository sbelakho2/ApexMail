//! Black-box lifecycle tests for the `observability-service` binary.
//!
//! The service is spawned as a real child process on an ephemeral port with
//! the local Redis as its dependency; readiness is polled over TCP and the
//! stop path is exercised with real signals. Every wait is deadline-bounded
//! so a hung startup fails the test instead of hanging the runner, and every
//! child is reaped.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const STARTUP_DEADLINE: Duration = Duration::from_secs(30);
const STOP_DEADLINE: Duration = Duration::from_secs(15);

fn reserve_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .expect("probe bind")
        .local_addr()
        .expect("addr")
}

/// Spawn the service with a fully explicit environment: no inherited OTEL
/// endpoint, no host-wide Redis overrides — the child's contract is exactly
/// what this test states.
fn spawn_service(health_addr: SocketAddr, extra_env: &[(&str, &str)]) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_observability-service"));
    command
        .env("OBSERVABILITY_PORT", health_addr.port().to_string())
        .env("METRICS_BIND_ADDR", "127.0.0.1")
        .env("INTERNAL_SERVICE_TOKEN", "lifecycle-test-token")
        .env("REDIS_HOST", "127.0.0.1")
        .env("REDIS_PORT", "6379")
        .env("DB_HOST", "127.0.0.1")
        .env("DB_PORT", "5432")
        .env("DB_NAME", "apexmail_scratch_base")
        .env("DB_USER", "apexmail")
        .env("DB_PASSWORD", "bebc8cefdc096e5247f8864e5c0edf78099df23058133321")
        .env("RUST_LOG", "error")
        .env_remove("OTEL_EXPORTER_OTLP_ENDPOINT")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in extra_env {
        command.env(key, value);
    }
    command.spawn().expect("spawn the observability-service binary")
}

fn wait_for_health(addr: SocketAddr) -> (u16, String) {
    let deadline = Instant::now() + STARTUP_DEADLINE;
    loop {
        if let Some(answer) = http_get(addr, "/health") {
            return answer;
        }
        if Instant::now() > deadline {
            panic!("the service never answered /health on {addr} within {STARTUP_DEADLINE:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn http_get(addr: SocketAddr, path: &str) -> Option<(u16, String)> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).ok()?;
    stream
        .write_all(format!("GET {path} HTTP/1.0\r\n\r\n").as_bytes())
        .ok()?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status: u16 = text.split_whitespace().nth(1)?.parse().ok()?;
    Some((status, text))
}

fn reap(child: &mut Child, deadline: Duration) -> std::process::ExitStatus {
    let at = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            return status;
        }
        if at.elapsed() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the service did not exit within {deadline:?}");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn output_of(child: &mut Child) -> String {
    let mut text = String::new();
    if let Some(mut pipe) = child.stdout.take() {
        let _ = pipe.read_to_string(&mut text);
    }
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut text);
    }
    text
}

/// The service serves its health and metrics contracts and drains to exit
/// code 0 on SIGTERM — the container stop signal.
#[test]
fn service_serves_health_and_metrics_and_sigterm_exits_cleanly() {
    let addr = reserve_addr();
    let mut child = spawn_service(addr, &[]);

    let (status, body) = wait_for_health(addr);
    assert_eq!(status, 200, "health: {body}");
    assert!(body.contains("ok"), "health: {body}");

    let (status, metrics) = http_get(addr, "/metrics").expect("metrics scrape");
    assert_eq!(status, 200, "metrics: {metrics}");
    assert!(
        metrics.contains("observability_uptime_seconds"),
        "the self-monitoring gauges must be rendered: {metrics}"
    );

    let _ = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .output()
        .expect("kill utility");
    let exit = reap(&mut child, STOP_DEADLINE);
    assert_eq!(exit.code(), Some(0), "SIGTERM must drain cleanly, got {exit}");
}

/// A SIGINT drains to exit code 0 as well.
#[test]
fn service_sigint_exits_cleanly() {
    let addr = reserve_addr();
    let mut child = spawn_service(addr, &[]);
    wait_for_health(addr);

    let _ = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .output()
        .expect("kill utility");
    let exit = reap(&mut child, STOP_DEADLINE);
    assert_eq!(exit.code(), Some(0), "SIGINT must drain cleanly, got {exit}");
}

/// A malformed environment (LOG_LEVEL=off fails validation) must refuse
/// startup with exit code 1 and a message on stderr — never a half-booted
/// service.
#[test]
fn service_refuses_an_invalid_configuration() {
    let addr = reserve_addr();
    let mut child = spawn_service(addr, &[("LOG_LEVEL", "off")]);
    let exit = reap(&mut child, STARTUP_DEADLINE);
    assert_eq!(exit.code(), Some(1), "expected an honest failure, got {exit}");
    let output = output_of(&mut child);
    assert!(
        output.contains("Invalid observability configuration"),
        "output must name the config failure: {output}"
    );
}

/// A duplicate instance on an already-bound port must exit 1 with a bind
/// error, not run half-alive.
#[test]
fn service_refuses_a_taken_port() {
    let addr = reserve_addr();
    let _occupant = TcpListener::bind(addr).expect("occupy the port");
    let mut child = spawn_service(addr, &[]);
    let exit = reap(&mut child, STARTUP_DEADLINE);
    assert_eq!(exit.code(), Some(1), "expected an honest failure, got {exit}");
    let output = output_of(&mut child);
    assert!(
        output.contains("failed to bind listener"),
        "output must name the bind failure: {output}"
    );
}
