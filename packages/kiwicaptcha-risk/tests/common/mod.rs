//! Shared helpers for the kiwicaptcha-risk integration tests.
//!
//! Every Redis-backed test here is hermetic: it skips (prints a notice and
//! returns) unless the Redis test URL is set, so the suite is green without
//! any infrastructure.
#![allow(dead_code)]

use kiwicaptcha_risk::event::{RiskEventKind, RiskObservation};
use kiwicaptcha_risk::signals::SignalVector;
use rand::RngCore;

/// Fixed clock (epoch ms): no decay between same-ts events.
pub const T0: u64 = 1_700_000_000_000;

/// Default source/subnet epoch window used by the helpers.
pub const RISK_EPOCH_SECS: i64 = 900;

/// Deterministic LCG matching the 10k parity stream (verified first value
/// 291): `x_{n+1} = (x_n * 6364136223846793005 + 1442695040888963407)
/// mod 2^64`, `value = (x >> 11) % 1001`.
pub fn lcg_next(state: &mut u64) -> u16 {
    *state = state
        .wrapping_mul(6364136223846793005u64)
        .wrapping_add(1442695040888963407u64);
    ((*state >> 11) % 1001) as u16
}

/// A full 13-field `SignalVector` from the LCG stream (contract order).
pub fn vector(state: &mut u64) -> SignalVector {
    SignalVector {
        source_fast: lcg_next(state),
        source_slow: lcg_next(state),
        subnet_fast: lcg_next(state),
        issue_debt: lcg_next(state),
        bad_proof: lcg_next(state),
        malformed: lcg_next(state),
        replay: lcg_next(state),
        action_failure: lcg_next(state),
        scope_switch: lcg_next(state),
        global_pressure: lcg_next(state),
        network_risk: lcg_next(state),
        trust_credit: lcg_next(state),
        principal_credit: lcg_next(state),
    }
}

/// event_id from a u64 (bytes 0..8 = big-endian n, rest zeroed), hex.
pub fn event_id(n: u64) -> String {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&n.to_be_bytes());
    hex::encode(out)
}

/// `tcp://` predis-style URLs are normalized to `redis://`; `None` when
/// the Redis test URL is unset or empty (the caller skips).
pub fn redis_url() -> Option<String> {
    match std::env::var("RISK_REDIS_URL") {
        Ok(url) if !url.is_empty() => Some(if let Some(rest) = url.strip_prefix("tcp://") {
            format!("redis://{rest}")
        } else {
            url
        }),
        _ => None,
    }
}

/// Fresh per-test namespace (the store's hash tag is `{kiwi:<ns>}`).
pub fn unique_namespace(prefix: &str) -> String {
    let mut suffix = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut suffix);
    format!("{prefix}{}", hex::encode(suffix))
}

/// 32-char hex id from a 16-byte pattern (per-epoch distinct variants).
fn epoch_id(pattern: u8, marker: u8) -> String {
    let mut out = [pattern; 16];
    out[15] = marker;
    hex::encode(out)
}

/// Epoch-scoped pseudonyms (prev/current/next) derived from one base
/// pattern, at the T0 epoch window. Each epoch id is distinct (the current
/// epoch's pseudonym is never reused for the ±1 keys).
pub fn epoch_ids(pattern: u8, now_ms: u64) -> (i64, String, String, String) {
    let epoch = ((now_ms / 1000) / RISK_EPOCH_SECS as u64) as i64;
    (
        epoch,
        epoch_id(pattern, 0x01),
        epoch_id(pattern, 0x02),
        epoch_id(pattern, 0x03),
    )
}

/// An observation with the given pseudonyms at the fixed clock. The
/// prev/next ids are the epoch-scoped variants of the same pattern, so the
/// ±1 keys never reuse the current pseudonym.
#[allow(clippy::too_many_arguments)]
pub fn observation(
    event: RiskEventKind,
    scope: u32,
    source_id: String,
    subnet_id: String,
    session_id: Option<[u8; 16]>,
    principal_id: Option<[u8; 16]>,
    event_id: String,
    now_ms: u64,
) -> RiskObservation {
    let (src_epoch, src_prev, _src_cur, src_next) = epoch_ids(0xAA, now_ms);
    let (net_epoch, net_prev, _net_cur, net_next) = epoch_ids(0xBB, now_ms);
    RiskObservation {
        event,
        scope,
        source_epoch: src_epoch,
        source_id_prev: src_prev,
        source_id,
        source_id_next: src_next,
        subnet_epoch: net_epoch,
        subnet_id_prev: net_prev,
        subnet_id,
        subnet_id_next: net_next,
        session_id,
        principal_id,
        event_id,
        network_risk: 0,
        now_ms,
        device_id: None,
    }
}

/// Free loopback ports for the spawn harnesses (distinct entries).
pub fn free_ports(count: usize) -> Vec<u16> {
    use std::collections::BTreeSet;
    use std::net::TcpListener;
    let mut ports = BTreeSet::new();
    while ports.len() < count {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        ports.insert(listener.local_addr().expect("addr").port());
    }
    ports.into_iter().collect()
}

/// One routed-slot stand-in endpoint of the sharded spawn harnesses: a
/// spawned throwaway redis-server (shut down with a nosave final write
/// on drop) or an env-provided endpoint (never touched on drop).
pub struct RedisStandin {
    url: String,
    child: Option<std::process::Child>,
}

/// `true` when the `redis-server` binary answers `--version` (the
/// binary exists and is executable).
fn redis_server_available() -> bool {
    std::process::Command::new("redis-server")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// The env-provided stand-in endpoints, normalized to the `redis://`
/// scheme the same way [`common::redis_url`] normalizes the single
/// test URL: `RISK_REDIS_URLS` (comma separated) is the list override,
/// `RISK_REDIS_URL` the single-endpoint override.
fn env_standin_urls() -> Vec<String> {
    let raw = std::env::var("RISK_REDIS_URLS")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| std::env::var("RISK_REDIS_URL").ok())
        .unwrap_or_default();
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            if let Some(rest) = s.strip_prefix("tcp://") {
                format!("redis://{rest}")
            } else {
                s.to_string()
            }
        })
        .collect()
}

impl RedisStandin {
    /// Spawns one throwaway `redis-server` on a free port and waits for
    /// its PING. `None` when the binary is missing (the caller skips).
    fn spawn_free() -> Option<RedisStandin> {
        let port = free_ports(1).into_iter().next()?;
        let url = format!("redis://127.0.0.1:{port}/");
        let child = std::process::Command::new("redis-server")
            .arg("--port")
            .arg(port.to_string())
            .arg("--save")
            .arg("")
            .arg("--appendonly")
            .arg("no")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        let standin = RedisStandin {
            url,
            child: Some(child),
        };
        standin.wait_ready();
        Some(standin)
    }

    /// An env-provided endpoint: reachable-check only, never owned.
    fn external(url: &str) -> RedisStandin {
        RedisStandin {
            url: url.to_string(),
            child: None,
        }
    }

    /// Blocks until the endpoint answers PING (bounded); `false` on a
    /// dead endpoint, so a bad env override fails loudly at the caller.
    fn wait_ready(&self) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Ok(client) = redis::Client::open(self.url.as_str()) {
                if let Ok(mut conn) = client.get_connection() {
                    let pong: Result<String, _> = redis::cmd("PING").query(&mut conn);
                    if pong.is_ok() {
                        return true;
                    }
                }
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// The stand-in's connection URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The `cmdstat_evalsha:calls=` counter of this stand-in.
    pub fn evalsha_calls(&self) -> u64 {
        let mut conn = redis::Client::open(self.url.as_str())
            .expect("url parses")
            .get_connection()
            .expect("connects");
        let info: String = redis::cmd("INFO")
            .arg("commandstats")
            .query(&mut conn)
            .expect("info");
        for line in info.lines() {
            if let Some(rest) = line.strip_prefix("cmdstat_evalsha:") {
                for field in rest.split(',') {
                    if let Some(calls) = field.strip_prefix("calls=") {
                        return calls.trim().parse().expect("calls is an integer");
                    }
                }
            }
        }
        0
    }

    pub fn reset_stats(&self) {
        let mut conn = redis::Client::open(self.url.as_str())
            .expect("url parses")
            .get_connection()
            .expect("connects");
        let _: Result<String, _> = redis::cmd("CONFIG").arg("RESETSTAT").query(&mut conn);
    }

    pub fn exists(&self, key: &str) -> bool {
        let mut conn = redis::Client::open(self.url.as_str())
            .expect("url parses")
            .get_connection()
            .expect("connects");
        let exists: i64 = redis::cmd("EXISTS")
            .arg(key)
            .query(&mut conn)
            .expect("exists");
        exists == 1
    }
}

impl Drop for RedisStandin {
    fn drop(&mut self) {
        // Only an owned spawn is shut down: the nosave shutdown leaves
        // no persistence artifacts. An env-provided endpoint is left
        // exactly as the operator handed it over.
        if self.child.is_some() {
            if let Ok(client) = redis::Client::open(self.url.as_str()) {
                if let Ok(mut conn) = client.get_connection() {
                    let _: Result<String, _> =
                        redis::cmd("SHUTDOWN").arg("NOSAVE").query(&mut conn);
                }
            }
        }
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// The `n` stand-in endpoints for a sharded spawn harness. The env
/// override is authoritative: `RISK_REDIS_URLS` (comma separated) when
/// it lists at least `n` endpoints, else `RISK_REDIS_URL` when `n == 1`.
/// Otherwise `n` throwaway `redis-server` processes are spawned on free
/// ports and shut down on drop. `None` (the caller prints the skip
/// notice) when the override is absent or too short and no local
/// `redis-server` binary is installed, so the suite stays green without
/// infrastructure.
pub fn shard_standins(n: usize) -> Option<Vec<RedisStandin>> {
    let urls = env_standin_urls();
    if urls.len() >= n {
        let standins: Vec<RedisStandin> = urls
            .into_iter()
            .take(n)
            .map(|u| RedisStandin::external(&u))
            .collect();
        if standins.iter().all(|s| s.wait_ready()) {
            return Some(standins);
        }
        return None;
    }
    if !redis_server_available() {
        return None;
    }
    let mut standins = Vec::with_capacity(n);
    for _ in 0..n {
        standins.push(RedisStandin::spawn_free()?);
    }
    Some(standins)
}
