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

/// The suite's Redis coordinates as `(host, port, password)`.
///
/// `TEST_REDIS_URL` is the CI/deploy endpoint (an ephemeral Redis on a
/// random port); 127.0.0.1:6379 is only the local dev default. The deploy
/// host runs no host-level Redis, so pinned coordinates would silently
/// disconnect every redis-backed assertion there (deploy 2026-10-11).
fn test_redis_coordinates() -> (String, String, Option<String>) {
    let raw = std::env::var("TEST_REDIS_URL").unwrap_or_default();
    let raw = raw.trim();
    if raw.is_empty() {
        return ("127.0.0.1".to_string(), "6379".to_string(), None);
    }
    let rest = raw.split_once("://").map(|(_, rest)| rest).unwrap_or(raw);
    let (auth, hostport) = match rest.rsplit_once('@') {
        Some((auth, hostport)) => (Some(auth), hostport),
        None => (None, rest),
    };
    let hostport = hostport.split('/').next().unwrap_or(hostport);
    let (host, port) = match hostport.rsplit_once(':') {
        Some((host, port)) => (host.to_string(), port.to_string()),
        None => (hostport.to_string(), "6379".to_string()),
    };
    let password = auth
        .and_then(|auth| auth.split_once(':').map(|(_, password)| password))
        .filter(|password| !password.is_empty())
        .map(str::to_string);
    (host, port, password)
}

/// The suite's Postgres coordinates parsed out of `TEST_DATABASE_URL`
/// (`(host, port, name, user, password)`), falling back to the local dev
/// defaults when the environment provides none.
fn test_db_coordinates() -> (String, String, String, String, String) {
    let dev = |value: &str| {
        (
            "127.0.0.1".to_string(),
            "5432".to_string(),
            "apexmail_scratch_base".to_string(),
            "apexmail".to_string(),
            value.to_string(),
        )
    };
    let raw = std::env::var("TEST_DATABASE_URL").unwrap_or_default();
    let raw = raw.trim();
    if raw.is_empty() {
        return dev("bebc8cefdc096e5247f8864e5c0edf78099df23058133321");
    }
    let rest = raw.split_once("://").map(|(_, rest)| rest).unwrap_or(raw);
    let (userinfo, hostpath) = match rest.rsplit_once('@') {
        Some((userinfo, hostpath)) => (userinfo, hostpath),
        None => ("", rest),
    };
    let (user, password) = match userinfo.split_once(':') {
        Some((user, password)) => (user.to_string(), password.to_string()),
        None => (userinfo.to_string(), String::new()),
    };
    // Strip any query string, then split host:port from the database name.
    let hostpath = hostpath.split('?').next().unwrap_or(hostpath);
    let (hostport, dbname) = match hostpath.split_once('/') {
        Some((hostport, dbname)) => (hostport, dbname.to_string()),
        None => (hostpath, "apexmail".to_string()),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((host, port)) => (host.to_string(), port.to_string()),
        None => (hostport.to_string(), "5432".to_string()),
    };
    (host, port, dbname, user, password)
}

/// Spawn the service with a fully explicit environment: no inherited OTEL
/// endpoint, no host-wide Redis overrides — the child's contract is exactly
/// what this test states.
fn spawn_service(health_addr: SocketAddr, extra_env: &[(&str, &str)]) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_observability-service"));
    let (redis_host, redis_port, redis_password) = test_redis_coordinates();
    let (db_host, db_port, db_name, db_user, db_password) = test_db_coordinates();
    command
        .env("OBSERVABILITY_PORT", health_addr.port().to_string())
        .env("METRICS_BIND_ADDR", "127.0.0.1")
        .env("INTERNAL_SERVICE_TOKEN", "lifecycle-test-token")
        .env("REDIS_HOST", redis_host)
        .env("REDIS_PORT", redis_port)
        .env("DB_HOST", db_host)
        .env("DB_PORT", db_port)
        .env("DB_NAME", db_name)
        .env("DB_USER", db_user)
        .env("DB_PASSWORD", db_password)
        .env("RUST_LOG", "error")
        .env_remove("OTEL_EXPORTER_OTLP_ENDPOINT")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(password) = redis_password {
        command.env("REDIS_PASSWORD", password);
    }
    for (key, value) in extra_env {
        command.env(key, value);
    }
    command
        .spawn()
        .expect("spawn the observability-service binary")
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
    assert_eq!(
        exit.code(),
        Some(0),
        "SIGTERM must drain cleanly, got {exit}"
    );
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
    assert_eq!(
        exit.code(),
        Some(0),
        "SIGINT must drain cleanly, got {exit}"
    );
}

/// A malformed environment (LOG_LEVEL=off fails validation) must refuse
/// startup with exit code 1 and a message on stderr — never a half-booted
/// service.
#[test]
fn service_refuses_an_invalid_configuration() {
    let addr = reserve_addr();
    let mut child = spawn_service(addr, &[("LOG_LEVEL", "off")]);
    let exit = reap(&mut child, STARTUP_DEADLINE);
    assert_eq!(
        exit.code(),
        Some(1),
        "expected an honest failure, got {exit}"
    );
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
    assert_eq!(
        exit.code(),
        Some(1),
        "expected an honest failure, got {exit}"
    );
    let output = output_of(&mut child);
    assert!(
        output.contains("failed to bind listener"),
        "output must name the bind failure: {output}"
    );
}
