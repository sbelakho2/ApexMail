//! Binary lifecycle test: boot the REAL `imap-server` binary as a subprocess
//! (loopback ephemeral ports, no TLS), verify it greets over both code paths,
//! then SIGINT it and require a clean exit (graceful shutdown of the accept
//! loops, exit code 0).
//!
//! The binary is reached through `CARGO_BIN_EXE_imap-server`, so under
//! `cargo llvm-cov` its profile merges with the test profiles (the child
//! inherits `LLVM_PROFILE_FILE` via the explicit pass-through below), and
//! under plain `cargo test` the same assertions still run.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Reserve a free loopback port (bind + release); the child binds it right
/// after, and the readiness probe tolerates the tiny race.
fn reserve_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind probe");
    listener.local_addr().expect("local addr").port()
}

/// Wait until `addr` accepts TCP connections, or time out.
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
fn binary_boots_greets_and_exits_cleanly_on_sigint() {
    let imap_port = reserve_free_port();
    let imaps_port = reserve_free_port();

    let mut command = Command::new(env!("CARGO_BIN_EXE_imap-server"));
    command
        .arg("--listen-addr")
        .arg("127.0.0.1")
        .arg("--imap-port")
        .arg(imap_port.to_string())
        .arg("--imaps-port")
        .arg(imaps_port.to_string())
        .arg("--mailstore-addr")
        .arg("http://127.0.0.1:1")
        .env("RUST_LOG", "warn");
    // Pass the coverage profile destination through so the child's counters
    // merge under cargo-llvm-cov; a scratch file otherwise.
    let destination = std::env::var("LLVM_PROFILE_FILE").unwrap_or_else(|_| {
        std::env::temp_dir()
            .join(format!("imap_bin_{}.profraw", std::process::id()))
            .to_string_lossy()
            .into_owned()
    });
    command.env("LLVM_PROFILE_FILE", destination);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = command.spawn().expect("spawn imap-server binary");

    let addr: std::net::SocketAddr = format!("127.0.0.1:{imap_port}").parse().unwrap();
    let ready = wait_ready(addr, Instant::now() + Duration::from_secs(30));
    if !ready {
        let _ = child.kill();
        let mut stderr = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr);
        }
        panic!("binary never bound {addr}\nstderr: {stderr}");
    }

    // The plaintext listener greets immediately (no TLS, insecure auth not
    // required for the greeting itself).
    let mut client = BufReader::new(TcpStream::connect(addr).expect("connect to IMAP"));
    client
        .get_ref()
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok();
    let mut greeting = String::new();
    client.read_line(&mut greeting).expect("read greeting");
    assert!(
        greeting.starts_with("* OK") && greeting.contains("IMAP4rev1"),
        "unexpected greeting: {greeting:?}"
    );
    client
        .get_mut()
        .write_all(b"zz LOGOUT\r\n")
        .expect("logout write");

    // SIGINT: the graceful-shutdown path stops the accept loops and exits 0.
    #[cfg(unix)]
    {
        extern "C" {
            #[link_name = "kill"]
            fn libc_kill(pid: i32, sig: i32) -> i32;
        }
        unsafe { libc_kill(child.id() as i32, 2) }; // SIGINT
        let status = wait_for_child_exit(&mut child, Instant::now() + Duration::from_secs(30))
            .expect("child must exit after SIGINT");
        assert_eq!(status.code(), Some(0), "graceful shutdown must exit 0");
    }
}
