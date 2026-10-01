//! Black-box lifecycle tests for the `analytics-worker` binary.
//!
//! The worker is spawned as a real child process against the local Postgres
//! and Redis; one-shot modes, the daemon signal path, and honest failure
//! codes are asserted. Every wait is deadline-bounded and every child is
//! reaped so the runner never hangs or leaks.

use std::io::Read;
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const STARTUP_DEADLINE: Duration = Duration::from_secs(30);
const STOP_DEADLINE: Duration = Duration::from_secs(15);

fn test_database_url() -> Option<String> {
    match std::env::var("TEST_DATABASE_URL") {
        Ok(url) if !url.trim().is_empty() => Some(url),
        _ => None,
    }
}

fn spawn_worker(database_url: &str, args: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_analytics-worker"))
        .args(args)
        .env("DATABASE_URL", database_url)
        .env("REDIS_URL", "redis://127.0.0.1:6379")
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the analytics-worker binary")
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
            panic!("the worker did not exit within {deadline:?}");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Probe helper (kept from the readiness contract of a listening daemon):
/// connects and immediately drops the socket.
fn can_connect(addr: SocketAddr) -> bool {
    TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok()
}

/// `--health` must verify its dependencies (Postgres + Redis pools are
/// created before the health check answers) and exit 0.
#[test]
fn health_mode_exits_zero_against_live_dependencies() {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping: set TEST_DATABASE_URL to drive the worker against Postgres");
        return;
    };
    let mut child = spawn_worker(&database_url, &["--health"]);
    let exit = reap(&mut child, STARTUP_DEADLINE);
    assert_eq!(exit.code(), Some(0), "health check must pass, got {exit}");
}

/// `--reconcile` is a read-only sweep over Postgres + ClickHouse and must
/// exit 0 against the live stack.
#[test]
fn reconcile_mode_exits_zero_against_live_dependencies() {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping: set TEST_DATABASE_URL to drive the worker against Postgres");
        return;
    };
    let mut child = spawn_worker(&database_url, &["--reconcile"]);
    let exit = reap(&mut child, STARTUP_DEADLINE);
    assert_eq!(exit.code(), Some(0), "reconcile must pass, got {exit}");
}

/// Daemon mode installs the SIGINT/SIGTERM handlers and waits; SIGTERM must
/// drain to exit code 0 after aborting the scheduled tasks (the container
/// stop path). The signal is only sent once the worker's own logs prove the
/// startup reached the signal wait — a signal racing an uninstalled handler
/// would kill the process with the default disposition.
#[test]
fn daemon_sigterm_exits_cleanly() {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping: set TEST_DATABASE_URL to drive the worker against Postgres");
        return;
    };
    let mut child = spawn_worker(&database_url, &[]);

    // The scheduled tasks log right after being spawned — at that point
    // main is at (or a few statements from) the signal await.
    let mut startup_log = String::new();
    let mut ready = false;
    let deadline = Instant::now() + STARTUP_DEADLINE;
    let mut stdout = child.stdout.take().expect("piped stdout");
    {
        let mut buf = [0u8; 4096];
        while Instant::now() < deadline {
            match stdout.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    startup_log.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if startup_log.contains("Next compaction in") {
                        ready = true;
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    }
    assert!(
        ready,
        "the worker never reached its signal wait within {STARTUP_DEADLINE:?}: {startup_log}"
    );
    // Signal now, then collect the remaining output.
    let _ = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .output()
        .expect("kill utility");
    let mut rest = String::new();
    let _ = stdout.read_to_string(&mut rest);
    let exit = reap(&mut child, STOP_DEADLINE);
    assert_eq!(
        exit.code(),
        Some(0),
        "SIGTERM must drain cleanly, got {exit}"
    );
    let output = format!("{startup_log}{rest}");
    assert!(
        output.contains("received SIGTERM") && output.contains("Shutting down analytics worker"),
        "the SIGTERM drain path must run: {output}"
    );
}

/// A dead database must produce an honest non-zero exit (the pool connect
/// fails after its acquire timeout), never a silent green daemon.
#[test]
fn daemon_fails_fast_on_an_unreachable_database() {
    let mut child = spawn_worker("postgres://apexmail:bad@127.0.0.1:1/none", &[]);
    let exit = reap(&mut child, STARTUP_DEADLINE);
    assert_ne!(
        exit.code(),
        Some(0),
        "expected an honest failure, got {exit}"
    );
}

/// The `can_connect` helper stays exercised: the local Redis answers.
#[test]
fn local_redis_is_reachable_for_the_worker() {
    let addr: SocketAddr = "127.0.0.1:6379".parse().expect("addr");
    assert!(can_connect(addr), "redis://127.0.0.1:6379 must be up");
}
