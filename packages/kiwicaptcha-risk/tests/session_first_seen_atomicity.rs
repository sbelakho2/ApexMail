//! The first-seen session records must establish their lifetime atomically
//! with the write: one `SET key tag NX EX ttl`, never a `SET NX` followed
//! by a separate `EXPIRE`. A crash, connection drop or command timeout
//! between the two commands would leave a first-seen session record with
//! NO TTL at all — permanently retained evidence. The earlier Rust path
//! used exactly that two-command sequence.
//!
//! This suite runs the real store against a minimal in-process Redis
//! stand-in that records every command it receives, so the proof is
//! deterministic and needs no live server:
//!
//!   * a successful creation issues exactly one SET whose arguments carry
//!     `NX EX <ttl>` (the lifetime rides the write) and never an EXPIRE;
//!   * a connection interrupted immediately after the SET reply still
//!     shows the SET carried the TTL — there is no second command whose
//!     loss could strip the lifetime;
//!   * the TTL is the configured positive session TTL.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use kiwicaptcha_risk::redis::RedisRiskStateStore;
use kiwicaptcha_risk::store::SessionContextTagStore;

/// A minimal RESP server: records every command (as a vector of argument
/// strings) and replies +OK, except GET (nil) and hello (an error so the
/// client stays on RESP2). `drop_after_first_set` closes the socket
/// right after replying to the first SET, simulating a crash the instant
/// the write landed (handshake commands are replied to normally first).
struct FakeRedis {
    addr: String,
    commands: Arc<Mutex<Vec<Vec<String>>>>,
    _handle: thread::JoinHandle<()>,
}

impl FakeRedis {
    fn start(drop_after_first_set: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = format!("redis://{}", listener.local_addr().expect("addr"));
        let commands = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&commands);
        let handle = thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let recorder = Arc::clone(&recorder);
                thread::spawn(move || serve(stream, recorder, drop_after_first_set));
            }
        });

        Self {
            addr,
            commands,
            _handle: handle,
        }
    }

    fn recorded(&self) -> Vec<Vec<String>> {
        self.commands.lock().expect("recorded commands").clone()
    }
}

fn read_command(reader: &mut BufReader<TcpStream>) -> Option<Vec<String>> {
    let mut line = String::new();
    if reader.read_line(&mut line).ok()? == 0 {
        return None;
    }
    let line = line.trim_end();
    let count: usize = line.strip_prefix('*')?.parse().ok()?;
    let mut args = Vec::with_capacity(count);
    for _ in 0..count {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        let len: usize = header.trim_end().strip_prefix('$')?.parse().ok()?;
        let mut buf = vec![0u8; len + 2];
        use std::io::Read;
        reader.read_exact(&mut buf).ok()?;
        buf.truncate(len);
        args.push(String::from_utf8_lossy(&buf).to_string());
    }
    Some(args)
}

fn serve(stream: TcpStream, recorder: Arc<Mutex<Vec<Vec<String>>>>, drop_after_first_set: bool) {
    let mut writer = stream.try_clone().expect("clone");
    let mut reader = BufReader::new(stream);
    loop {
        let Some(args) = read_command(&mut reader) else {
            return;
        };
        let name = args.first().cloned().unwrap_or_default().to_uppercase();
        recorder.lock().expect("record").push(args);
        let reply: String = match name.as_str() {
            "GET" => "$-1\r\n".to_string(),
            "HELLO" => "-ERR unknown command 'HELLO'\r\n".to_string(),
            _ => "+OK\r\n".to_string(),
        };
        if writer.write_all(reply.as_bytes()).is_err() {
            return;
        }
        let _ = writer.flush();
        if drop_after_first_set && name == "SET" {
            // Simulate the process dying immediately after the write was
            // acknowledged: the client never gets to issue anything more.
            let _ = writer.shutdown(std::net::Shutdown::Both);
            return;
        }
    }
}

fn session_id() -> [u8; 16] {
    [0x42; 16]
}

#[test]
fn a_successful_first_seen_creation_carries_the_ttl_inside_the_single_set() {
    let fake = FakeRedis::start(false);
    let store = RedisRiskStateStore::with_options(
        redis_client(&fake.addr),
        "atomicity",
        1800,
        60,
        60_000,
        900,
        86_400,
        kiwicaptcha_risk::redis::DEFAULT_OUTCOME_TTL_SECS,
        kiwicaptcha_risk::redis::DEFAULT_SATURATIONS,
    );

    let tag = store
        .session_first_context_tag(&session_id(), "ctx-tag")
        .expect("the creation succeeds against the stand-in");
    assert_eq!(tag.as_deref(), Some("ctx-tag"));

    let commands = fake.recorded();
    let set = commands
        .iter()
        .find(|args| args.first().map(|a| a.to_uppercase()) == Some("SET".to_string()))
        .expect("the creation issues a SET");
    assert_eq!(set[0].to_uppercase(), "SET");
    assert_eq!(
        set[1],
        format!("{{kiwi:atomicity}}:risk:ctx:{}", hex::encode(session_id()))
    );
    assert_eq!(set[2], "ctx-tag");
    let upper: Vec<String> = set.iter().map(|a| a.to_uppercase()).collect();
    let nx = upper.iter().position(|a| a == "NX").expect("the SET is NX");
    let ex = upper
        .iter()
        .position(|a| a == "EX")
        .expect("the SET carries EX in the same command");
    assert_eq!(ex, nx + 1, "EX immediately follows NX");
    assert_eq!(
        upper[ex + 1],
        "900",
        "EX carries the configured positive session TTL"
    );
    assert!(
        !commands.iter().any(|args| args.first().map(|a| a.to_uppercase()) == Some("EXPIRE".to_string())),
        "the creation must never issue a separate EXPIRE whose loss could strip the lifetime: {commands:?}"
    );
}

#[test]
fn an_interrupted_first_seen_creation_cannot_leave_a_persistent_record() {
    // The connection is closed immediately after the SET is acknowledged,
    // the deterministic equivalent of the process dying mid-creation. The
    // lifetime rode the SET itself, so there is no window in which the
    // record exists without its expiry.
    let fake = FakeRedis::start(true);
    let store = RedisRiskStateStore::with_options(
        redis_client(&fake.addr),
        "atomicity",
        1800,
        60,
        60_000,
        900,
        86_400,
        kiwicaptcha_risk::redis::DEFAULT_OUTCOME_TTL_SECS,
        kiwicaptcha_risk::redis::DEFAULT_SATURATIONS,
    );

    // The call itself may observe the broken connection (no retry by
    // design); what matters is that the only write issued was the atomic
    // SET NX EX.
    let _ = store.session_first_context_tag(&session_id(), "ctx-tag");

    let commands = fake.recorded();
    let set = commands
        .iter()
        .find(|args| args.first().map(|a| a.to_uppercase()) == Some("SET".to_string()))
        .expect("the interrupted creation still issued exactly the atomic write");
    let upper: Vec<String> = set.iter().map(|a| a.to_uppercase()).collect();
    assert!(
        upper.iter().any(|a| a == "EX"),
        "the interrupted write already carried its lifetime: {set:?}"
    );
    assert!(
        !commands
            .iter()
            .any(|args| args.first().map(|a| a.to_uppercase()) == Some("EXPIRE".to_string())),
        "no separate EXPIRE existed to be interrupted: {commands:?}"
    );
    assert!(
        commands
            .iter()
            .filter(|args| args.first().map(|a| a.to_uppercase()) == Some("SET".to_string()))
            .count()
            == 1,
        "exactly one write was attempted"
    );
}

fn redis_client(url: &str) -> redis::Client {
    redis::Client::open(url).expect("the stand-in URL parses")
}
