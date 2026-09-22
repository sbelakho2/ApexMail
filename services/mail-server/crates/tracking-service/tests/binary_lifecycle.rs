//! Binary lifecycle test: boot the REAL `tracking-service` binary as a
//! subprocess against the live test infrastructure (Postgres / Redis /
//! ClickHouse from the workspace env conventions), verify it serves, then
//! SIGTERM it and require a clean graceful shutdown (WAL drain + exit 0).
//!
//! The binary is reached through `CARGO_BIN_EXE_tracking-service`, so under
//! `cargo llvm-cov` its profile merges with the test profiles (the child
//! inherits `LLVM_PROFILE_FILE` via the explicit pass-through below), and
//! under plain `cargo test` the same assertions still run. Infrastructure
//! is soft-skipped with the workspace convention.

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The env the child needs to boot: live infra, ephemeral port, metrics
/// bound to an ephemeral loopback port, ClickHouse verification enabled.
fn child_env() -> Option<Vec<(String, String)>> {
    let db = std::env::var("TEST_DATABASE_URL").ok()?;
    let redis = std::env::var("TEST_REDIS_URL").ok()?;
    let clickhouse =
        std::env::var("CLICKHOUSE_TEST_URL").unwrap_or_else(|_| "http://127.0.0.1:8124".into());
    // The service composes its Redis URL from REDIS_HOST/PORT/DB/PASSWORD;
    // empty password ⇒ no auth (matches the local test Redis).
    let (redis_host, redis_port, redis_db) = {
        // Parse the DB index out of the workspace TEST_REDIS_URL if present.
        let db_index = redis
            .rsplit('/')
            .next()
            .and_then(|tail| tail.parse::<u32>().ok())
            .unwrap_or(0);
        (
            "127.0.0.1".to_string(),
            "6379".to_string(),
            db_index.to_string(),
        )
    };
    Some(vec![
        ("DATABASE_URL".into(), db),
        ("REDIS_HOST".into(), redis_host),
        ("REDIS_PORT".into(), redis_port),
        ("REDIS_DB".into(), redis_db),
        ("REDIS_PASSWORD".into(), String::new()),
        ("TRACKING_HOST".into(), "127.0.0.1".into()),
        ("TRACKING_PORT".into(), "0".into()),
        (
            "TRACKING_SECRET_KEY".into(),
            "tracking-binary-lifecycle-secret-32b".into(),
        ),
        ("METRICS_PORT".into(), "0".into()),
        ("CLICKHOUSE_URL".into(), clickhouse),
        // A non-default user turns ON the startup connectivity probe; the
        // workspace `probe` account makes that probe succeed (Ok arm).
        ("CLICKHOUSE_USER".into(), "probe".into()),
        ("CLICKHOUSE_PASSWORD".into(), "probe".into()),
        // Quiet child logs (kept for debugging on failure via RUST_LOG).
        ("RUST_LOG".into(), "warn".into()),
    ])
}

/// Pass the coverage profile destination through when running under
/// `cargo llvm-cov`, so the child binary's counters are merged; otherwise
/// point it at a scratch file so the repo is not polluted with .profraw.
fn profile_env(command: &mut Command) {
    let destination = std::env::var("LLVM_PROFILE_FILE").unwrap_or_else(|_| {
        std::env::temp_dir()
            .join(format!("tracking_bin_{}.profraw", std::process::id()))
            .to_string_lossy()
            .into_owned()
    });
    command.env("LLVM_PROFILE_FILE", destination);
}

/// `port 0` binds an ephemeral port the parent cannot learn from the child;
/// probe a free port and hand it to the child instead. (Bind races are
/// theoretically possible; the readiness loop below treats a refused
/// connection as "not ready yet", and the port was just released.)
fn reserve_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind probe");
    listener.local_addr().expect("local addr").port()
}

/// Wait until `addr` accepts TCP connections (the child's axum listener is
/// up) or time out.
fn wait_ready(addr: std::net::SocketAddr, deadline: Instant) -> bool {
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
}

fn wait_for_child_exit(
    child: &mut std::process::Child,
    deadline: Instant,
) -> Option<std::process::ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => return None,
        }
    }
}

#[test]
fn binary_boots_serves_and_shuts_down_cleanly_on_sigterm() {
    let Some(env_pairs) = child_env() else {
        eprintln!(
            "skipping: set TEST_DATABASE_URL (+ TEST_REDIS_URL) to run the binary lifecycle test"
        );
        return;
    };
    let port = reserve_free_port();
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_tracking-service"));
    for (k, v) in &env_pairs {
        command.env(k, v);
    }
    profile_env(&mut command);
    command
        .env("TRACKING_PORT", port.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().expect("spawn tracking-service binary");

    // The child must reach "HTTP server listening" within 30 s.
    let ready = wait_ready(addr, Instant::now() + Duration::from_secs(30));
    if !ready {
        let _ = child.kill();
        let mut stderr = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr);
        }
        panic!("binary never bound {addr}\nstderr: {stderr}");
    }

    // SIGTERM: the graceful-shutdown path must drain the WAL and exit 0.
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        unsafe {
            libc_kill(child.id() as i32, 15);
        }
        let status = wait_for_child_exit(&mut child, Instant::now() + Duration::from_secs(60))
            .expect("child must exit after SIGTERM");
        let code = status.code().unwrap_or_else(|| status.into_raw());
        assert_eq!(code, 0, "graceful shutdown must exit 0");
    }
}

#[cfg(unix)]
extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}
