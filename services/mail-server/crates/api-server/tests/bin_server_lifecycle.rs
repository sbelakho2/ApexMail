//! Black-box lifecycle tests for the deployed `api-server` binary.
//!
//! The server is spawned as a real child process against the local Postgres
//! and Redis on ephemeral ports; its health/readiness endpoints and the
//! Prometheus metrics listener are polled over TCP, and the stop path is
//! exercised with real signals. Every wait is deadline-bounded (a hung bind
//! fails the test instead of hanging the runner) and every child is reaped.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const STARTUP_DEADLINE: Duration = Duration::from_secs(60);
const STOP_DEADLINE: Duration = Duration::from_secs(30);

/// Deterministic 2048-bit RSA test pair (PKCS#8) — only ever used by the
/// spawned test server to boot its JWT wiring; no token is ever issued here.
const TEST_JWT_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCigFuI5W8l0h25
eV8Mnb339PtyHl/1S+UCC+6c14XY3J9PRKo1Wts+XSZcr4MFTRPQrvKGIeh9kiZI
z4dOO6OK2IvLyPuysVwlauazUnunFZn45j6OSZo338o3ndEJusGpWvLC9UmkGCJd
pZiy4xrhKxQSDbiykmZuWLQZUX38fASJKNPgBdKijdJso57FCV+hxAjLhlLbCytX
ey0yRaCpP0k0b5FLFIJdLvTd8xqwlUWx2aTQMuxX+hj0G1IvZoiXfxP3mFzpbyAb
77YjObiF9FwktCOh1+6qFFEoVjlq26YcvJKhOg0XT+KoFBDoB+jFSOifcUHV3wpd
5Qt3FodbAgMBAAECggEAF1I/kMKItI9Wp7809m0PDe5xRbv5Po2BVM1cldLSiUCE
do5etSCQdX9N2aBwt8qLjPgGo1xrbtYSO4HZI8+oVW1lhr4V7VvJ4y7X5CVyzJRr
kA6PLMGAagNqlJfIH9LXJ1R/oZ4tTukNyY3R/95bBbS2gS7J8orTO4PsePO6lokF
N1ldqM5JBLO00UukFGFiu7laFnOt62sd0J8D4OogUwGN8qg+XJYJZw1WpE4Rlx87
t4yVbjqCtPomhaF4RMBffxEKEjJN281nPs9theG/f4yq6vcay5H0Oq2S2/HRfqF1
wVqI/3BwU1/eb5Zu8MfKvvSt8CzNL8oCr97wKTT+/QKBgQDa0ncBqWX+15ATBiXV
CVEldQweaci2Q7mhmykbvW+FjhA8QikkUs2QiPtBUWtT1nRgJHbcWE55lK4xaHBz
7pnDSnuluheMm8CwA7xQpany7RgxvyvmmXDtHy/h55MVk73ZZHyCx2DpOekqIJYJ
uB+bJGR16HEnLvQxwMesxTFQnQKBgQC+HEG8mPcDAMuZBdPM+L5coTyi3x0YqYbF
M2QPMv7fQ3hLuB5OPsZaW5CQdfzwo+oxUeD+eWQW43HqIyLxkmxUhjKcBz9MVWCC
142TGYAccShrBbzGoRbXLIhQWKeqOyvjXso9HYqYUpjgF4w4t+IAY+0C1rdy+OuR
bY+vZIYKVwKBgEXGyxAKlm2XC2glk7bFC80n779a+Be2rODte0RPOdqanG66oifl
B4vJQmVnsxO+1Mk7l3NX7V4znQBAT2uIcBuoCpmkJ5I8sErwRgJpcTH3jLmAPl2A
HFRgl4Ivt+UvgWBq/JEvRqXYQ5OdZHqg7eMozagTgNF/1XpwALwE/V65AoGAWWZq
V2lLh6MBG3XNEy/KPT8ph6IKScW29ddj723Yw180G896mOsWVfmHMxf5GaTLhePu
PV0Sf1z3/dYGIbnsrZbqB8u0rY3cs8rv7cPpJfbkvedVzcaFOizb8YSvW/M1gVfb
HQBeY6E7+O256BY49lwHYfVdEXkTNjFih2VrT0MCgYBtjrmKzteI+YF0mulEyKYA
22hfU/9dH8xJjuQCObzEF8YJMAJSTF6wjLLrwZP2rQFb+PPHoEtVetKtihTbJlrd
ZdEbboOu+YEdq+lo3/J3IuBdxVruPh8w9YXbkSNsqHrAMwAkMQTda7Lo+sTm/Xih
0TvIrgOKJDUWFuetfTdPHw==
-----END PRIVATE KEY-----";

const TEST_JWT_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAooBbiOVvJdIduXlfDJ29
9/T7ch5f9UvlAgvunNeF2NyfT0SqNVrbPl0mXK+DBU0T0K7yhiHofZImSM+HTjuj
itiLy8j7srFcJWrms1J7pxWZ+OY+jkmaN9/KN53RCbrBqVrywvVJpBgiXaWYsuMa
4SsUEg24spJmbli0GVF9/HwEiSjT4AXSoo3SbKOexQlfocQIy4ZS2wsrV3stMkWg
qT9JNG+RSxSCXS703fMasJVFsdmk0DLsV/oY9BtSL2aIl38T95hc6W8gG++2Izm4
hfRcJLQjodfuqhRRKFY5atumHLySoToNF0/iqBQQ6AfoxUjon3FB1d8KXeULdxaH
WwIDAQAB
-----END PUBLIC KEY-----";

fn reserve_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .expect("probe bind")
        .local_addr()
        .expect("addr")
}

/// Spawn the API server with a fully explicit environment against the local
/// dependency stack. `extra_env` overrides individual variables; `omit_jwt`
/// leaves the required JWT private key unset (misconfiguration case).
fn spawn_api_server(
    port: u16,
    metrics_port: u16,
    omit_jwt: bool,
    extra_env: &[(&str, &str)],
) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_api-server"));
    command
        .env("HOST", "127.0.0.1")
        .env("PORT", port.to_string())
        .env("METRICS_PORT", metrics_port.to_string())
        .env("ENVIRONMENT", "development")
        .env("DB_HOST", "127.0.0.1")
        .env("DB_PORT", "5432")
        .env("DB_NAME", "apexmail_scratch_base")
        .env("DB_USER", "apexmail")
        .env(
            "DB_PASSWORD",
            "bebc8cefdc096e5247f8864e5c0edf78099df23058133321",
        )
        .env("REDIS_HOST", "127.0.0.1")
        .env("REDIS_PORT", "6379")
        .env("API_KEY_HASH_SECRET", "lifecycle-test-api-key-hash-secret")
        .env(
            "WEBHOOK_SIGNING_SECRET",
            "lifecycle-test-webhook-signing-secret",
        )
        .env("PLACEMENT_ENABLED", "false")
        .env("AWS_EC2_METADATA_DISABLED", "true")
        .env("RUST_LOG", "error")
        .env_remove("OTEL_EXPORTER_OTLP_ENDPOINT")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if !omit_jwt {
        command
            .env("JWT_PRIVATE_KEY_PEM", TEST_JWT_PRIVATE_KEY_PEM)
            .env("JWT_PUBLIC_KEY_PEM", TEST_JWT_PUBLIC_KEY_PEM);
    }
    for (key, value) in extra_env {
        command.env(key, value);
    }
    command.spawn().expect("spawn the api-server binary")
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

fn wait_for_health(addr: SocketAddr) -> (u16, String) {
    let deadline = Instant::now() + STARTUP_DEADLINE;
    loop {
        if let Some(answer) = http_get(addr, "/health/live") {
            return answer;
        }
        if Instant::now() > deadline {
            panic!(
                "the api-server never answered /health/live on {addr} within {STARTUP_DEADLINE:?}"
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
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
            panic!("the api-server did not exit within {deadline:?}");
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

/// The API server boots against the real Postgres + Redis, serves its
/// liveness and readiness endpoints plus the Prometheus listener, and drains
/// to exit code 0 on SIGTERM — the container stop signal.
#[test]
fn api_server_serves_health_and_metrics_and_sigterm_exits_cleanly() {
    let port = reserve_addr();
    let metrics_port = reserve_addr();
    let mut child = spawn_api_server(port.port(), metrics_port.port(), false, &[]);

    let (status, body) = wait_for_health(port);
    assert_eq!(status, 200, "liveness: {body}");
    assert!(body.contains("ok"), "liveness: {body}");

    // Readiness reflects the real dependencies (DB + Redis are up here).
    let deadline = Instant::now() + STARTUP_DEADLINE;
    let mut ready = None;
    while Instant::now() < deadline {
        if let Some((status, body)) = http_get(port, "/health/ready") {
            if status == 200 {
                ready = Some(body);
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let ready = ready.expect("readiness must report healthy dependencies");
    assert!(ready.to_lowercase().contains("ok"), "readiness: {ready}");

    // The Prometheus recorder listener answers on its own port.
    let (status, metrics) = http_get(metrics_port, "/metrics").expect("metrics scrape");
    assert_eq!(status, 200, "metrics: {metrics}");

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

/// A missing required variable (JWT private key) must refuse startup with
/// exit code 1 and an error naming the variable — never a half-booted API.
#[test]
fn api_server_refuses_an_incomplete_configuration() {
    let port = reserve_addr();
    let mut child = spawn_api_server(port.port(), 0, true, &[]);
    let exit = reap(&mut child, STARTUP_DEADLINE);
    assert_eq!(
        exit.code(),
        Some(1),
        "expected an honest failure, got {exit}"
    );
    let output = output_of(&mut child);
    assert!(
        output.contains("JWT_PRIVATE_KEY_PEM"),
        "output must name the missing variable: {output}"
    );
}

/// A duplicate instance on an already-bound port must exit 1, not run
/// half-alive.
#[test]
fn api_server_refuses_a_taken_port() {
    let addr = reserve_addr();
    let _occupant = TcpListener::bind(addr).expect("occupy the port");
    let mut child = spawn_api_server(addr.port(), 0, false, &[]);
    let exit = reap(&mut child, STARTUP_DEADLINE);
    assert_eq!(
        exit.code(),
        Some(1),
        "expected an honest failure, got {exit}"
    );
}
