#![allow(dead_code)] // shared test module: each binary uses a subset
//! Shared helpers of the hermetic fake-Redis integration tests.
//!
//! A miniature Redis-protocol TCP endpoint (no real Redis needed) that
//! records every command tagged with its connection, answers the
//! production verifier's exact command surface (GET, PING, the Lua
//! transitions by their ARGV shape, `SCRIPT` `LOAD`) from a tiny in-memory
//! record store, and drives the `NOSCRIPT`-then-load dance exactly once so
//! script-caching behavior is observable.
//!
//! This module is compiled into each integration test binary that
//! declares `mod common;` — it must stay dependency-free (std only plus
//! the crate and serde_json for the record seeding).

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

/// Minimal Redis-protocol command parser for the fake endpoint: returns
/// the command's argument strings and the number of bytes consumed, or
/// `None` while the buffer holds only a partial command.
pub fn parse_resp_command(buf: &[u8]) -> Option<(Vec<String>, usize)> {
    fn split_crlf(buf: &[u8]) -> Option<(&[u8], &[u8])> {
        let i = buf.windows(2).position(|w| w == b"\r\n")?;
        Some((&buf[..i], &buf[i + 2..]))
    }
    let rest = buf.strip_prefix(b"*")?;
    let (nline, mut rest) = split_crlf(rest)?;
    let count: usize = std::str::from_utf8(nline).ok()?.parse().ok()?;
    let mut args = Vec::with_capacity(count);
    for _ in 0..count {
        let rest2 = rest.strip_prefix(b"$")?;
        let (llen, rest3) = split_crlf(rest2)?;
        let len: usize = std::str::from_utf8(llen).ok()?.parse().ok()?;
        if rest3.len() < len + 2 {
            return None;
        }
        args.push(String::from_utf8_lossy(&rest3[..len]).into_owned());
        rest = &rest3[len + 2..];
    }
    let consumed = buf.len() - rest.len();
    Some((args, consumed))
}

/// The shared state of the miniature Redis-protocol endpoint: a tiny
/// string store (the runtime-envelope JSON of stored records), a full
/// command log tagged with the id of the TCP connection each command
/// arrived on, a TCP-connection counter and a script-cache flag (the
/// first `EVALSHA` misses with `NOSCRIPT`, the load warms it, exactly like a
/// real server).
#[derive(Default)]
pub struct FakeEndpoint {
    records: Mutex<HashMap<String, String>>,
    commands: Mutex<Vec<(usize, Vec<String>)>>,
    connections: AtomicUsize,
    script_loaded: AtomicUsize,
}

impl FakeEndpoint {
    /// Binds a listener on a random local port and serves the endpoint on
    /// it; returns the `redis://` URL and the shared state handle.
    pub fn spawn() -> (String, Arc<FakeEndpoint>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let endpoint = Arc::new(FakeEndpoint {
            records: Mutex::new(HashMap::new()),
            commands: Mutex::new(Vec::new()),
            connections: AtomicUsize::new(0),
            script_loaded: AtomicUsize::new(0),
        });
        let server = Arc::clone(&endpoint);
        thread::spawn(move || {
            use std::io::{Read, Write};
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let server = Arc::clone(&server);
                let conn_id = server.connections.fetch_add(1, Ordering::SeqCst);
                thread::spawn(move || {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    loop {
                        match stream.read(&mut tmp) {
                            Ok(0) => return,
                            Ok(n) => {
                                buf.extend_from_slice(&tmp[..n]);
                                while let Some((args, consumed)) = parse_resp_command(&buf) {
                                    buf.drain(..consumed);
                                    if let Some(reply) = server.handle(conn_id, &args) {
                                        if stream.write_all(reply.as_bytes()).is_err() {
                                            return;
                                        }
                                    }
                                }
                            }
                            Err(_) => return,
                        }
                    }
                });
            }
        });
        (format!("redis://127.0.0.1:{port}/"), endpoint)
    }

    /// Seeds a stored record exactly the way the real store writes it:
    /// the canonical record JSON plus the runtime envelope
    /// (`state: pending`, null result, null identity).
    pub fn seed(&self, prefix: &str, record: &kiwicaptcha::ChallengeRecord) {
        let mut json = serde_json::to_string(record).unwrap();
        json.truncate(json.len() - 1);
        json.push_str(
            ",\"state\":\"pending\",\"consumed_result\":null,\"operation_identity\":null}",
        );
        self.records
            .lock()
            .unwrap()
            .insert(format!("{prefix}{}", record.nonce), json);
    }

    /// The recorded command log: `(conn_id, args)` in arrival order.
    pub fn commands(&self) -> Vec<(usize, Vec<String>)> {
        self.commands.lock().unwrap().clone()
    }

    /// Clears the recorded command log (starts a fresh measurement
    /// window).
    pub fn clear_commands(&self) {
        self.commands.lock().unwrap().clear();
    }

    /// Whether a seeded/stored record still exists under its key.
    pub fn contains_record(&self, key: &str) -> bool {
        self.records.lock().unwrap().contains_key(key)
    }

    /// Handles one parsed command (tagged with its connection id); `None`
    /// closes nothing (every reply is written). Scripts are classified
    /// by their ARGV shape, not their sha: `EVALSHA sha 1 key` is the
    /// delete/cancel family, `EVALSHA sha 1 key <identity>` the consume
    /// transition (the empty identity of the no-identity call),
    /// `EVALSHA sha 1 key <0|1> <binding>` the outcome commit.
    fn handle(&self, conn_id: usize, args: &[String]) -> Option<String> {
        self.commands.lock().unwrap().push((conn_id, args.to_vec()));
        let bulk = |s: &str| format!("${}\r\n{}\r\n", s.len(), s);
        match args[0].as_str() {
            "PING" => Some("+PONG\r\n".to_string()),
            "GET" => Some(match self.records.lock().unwrap().get(&args[1]) {
                Some(v) => bulk(v),
                None => "$-1\r\n".to_string(),
            }),
            "EVALSHA" => {
                if self.script_loaded.load(Ordering::SeqCst) == 0 {
                    return Some("-NOSCRIPT No matching script. Use EVAL.\r\n".to_string());
                }
                let key = args.get(3).cloned().unwrap_or_default();
                let stored = self.records.lock().unwrap().get(&key).cloned();
                match args.len() {
                    // delete-if-pending / cancel family (no argv):
                    // [`EVALSHA`, sha, numkeys, key].
                    4 => Some(match stored {
                        Some(v) if v.contains("\"state\":\"pending\"") => {
                            self.records.lock().unwrap().remove(&key);
                            "*1\r\n$15\r\ndeleted-pending\r\n".to_string()
                        }
                        Some(v) if v.contains("\"state\":\"consumed\"") => {
                            format!("*2\r\n$8\r\nconsumed\r\n${}\r\n{}\r\n", v.len(), v)
                        }
                        _ => "*1\r\n$7\r\nmissing\r\n".to_string(),
                    }),
                    // consume ([`EVALSHA`, sha, numkeys, key, identity] —
                    // the empty identity of the no-identity call).
                    5 => Some(match stored {
                        Some(v) if v.contains("\"state\":\"pending\"") => {
                            let consumed =
                                v.replace("\"state\":\"pending\"", "\"state\":\"consumed\"");
                            self.records.lock().unwrap().insert(key, consumed.clone());
                            format!("*2\r\n${}\r\n{}\r\n:1\r\n", consumed.len(), consumed)
                        }
                        Some(v) if v.contains("\"state\":\"consumed\"") => {
                            format!("*2\r\n${}\r\n{}\r\n:0\r\n", v.len(), v)
                        }
                        _ => "$-1\r\n".to_string(),
                    }),
                    // commit ([`EVALSHA`, sha, numkeys, key, valid, binding]).
                    6 if args[4] == "0" || args[4] == "1" => Some(":1\r\n".to_string()),
                    _ => Some("-ERR unknown script shape\r\n".to_string()),
                }
            }
            "SCRIPT" => {
                // `SCRIPT` `LOAD` <source>: warm the cache (the source itself
                // identifies the script; the reply sha is never compared
                // by the client's invoke path).
                self.script_loaded.store(1, Ordering::SeqCst);
                Some(bulk(&"f".repeat(40)))
            }
            _ => Some("+OK\r\n".to_string()),
        }
    }
}
