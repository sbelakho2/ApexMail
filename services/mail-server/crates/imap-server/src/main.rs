//! IMAP4rev1 server for ApexMail.
//!
//! Listens on port 993 (IMAPS) with implicit TLS and port 143 (IMAP with STARTTLS).
//! Proxies all mailbox operations to the mailstore-core gRPC service.

use anyhow::{bail, Context, Result};
use base64::Engine;
use clap::Parser;
use futures::StreamExt;
use mail_proto::{
    CopyMessageRequest, CreateMailboxRequest, DeleteMailboxRequest, ExpungeRequest, FlagOperation,
    GetMailboxStatusRequest, GetMessageRequest, InternalServiceAuthInterceptor,
    ListMailboxesRequest, ListMessagesRequest, MailboxEvent, MailstoreServiceClient, MessageFlags,
    MoveMessageRequest, SearchMessagesRequest, SetFlagsRequest, StoreMessageRequest,
    SubscribeMailboxRequest,
};
use rustls::ServerConfig;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Duration;
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use tonic::transport::Channel;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "imap-server", about = "ApexMail IMAP4rev1 Server")]
struct Cli {
    #[arg(long, env = "IMAP_LISTEN_ADDR", default_value = "0.0.0.0")]
    listen_addr: String,
    #[arg(long, env = "IMAP_PORT", default_value = "143")]
    imap_port: u16,
    #[arg(long, env = "IMAPS_PORT", default_value = "993")]
    imaps_port: u16,
    #[arg(
        long,
        env = "MAILSTORE_GRPC_ADDR",
        default_value = "http://127.0.0.1:50051"
    )]
    mailstore_addr: String,
    #[arg(long, env = "INBOUND_CERT_PATH")]
    tls_cert_path: Option<String>,
    #[arg(long, env = "INBOUND_KEY_PATH")]
    tls_key_path: Option<String>,
    /// Allow LOGIN/AUTHENTICATE over a plaintext (non-TLS) connection.
    /// Defaults to false: authentication is only permitted over TLS.
    #[arg(long, env = "IMAP_ALLOW_INSECURE_AUTH", default_value_t = false)]
    allow_insecure_auth: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionState {
    NotAuthenticated,
    Authenticated,
    Selected,
    Logout,
}

struct ImapSession {
    state: SessionState,
    account_id: String,
    mailbox: String,
    uid_validity: u64,
    uid_next: u64,
    exists: u32,
    recent: u32,
    /// F6: session-scoped \Recent approximation — the UIDs this session
    /// considers \Recent (unseen when first observed via SELECT, plus unseen
    /// arrivals during the session). The store has no persistent
    /// first-delivery marker on the wire, so multi-session \Recent semantics
    /// are best-effort: without persistent state, two concurrent sessions can
    /// both see the same message as \Recent. Documented approximation, not a
    /// silent claim of RFC 3501 §2.3.2 fidelity.
    recent_uids: HashSet<u64>,
    permanent_flags: Vec<String>,
    uid_map: Vec<u64>,
    read_only: bool,
    client: MailstoreClient,
    tag: String,
    idle: bool,
    tls_active: bool,
    allow_insecure_auth: bool,
    /// Remote peer IP for brute-force throttling of LOGIN/AUTHENTICATE.
    peer_ip: String,
}

impl ImapSession {
    fn new(client: MailstoreClient) -> Self {
        Self {
            state: SessionState::NotAuthenticated,
            account_id: String::new(),
            mailbox: String::new(),
            uid_validity: 0,
            uid_next: 0,
            exists: 0,
            recent: 0,
            recent_uids: HashSet::new(),
            permanent_flags: vec![
                "\\Seen".into(),
                "\\Answered".into(),
                "\\Flagged".into(),
                "\\Deleted".into(),
                "\\Draft".into(),
            ],
            uid_map: Vec::new(),
            read_only: false,
            client,
            tag: String::new(),
            idle: false,
            tls_active: false,
            allow_insecure_auth: false,
            peer_ip: String::new(),
        }
    }

    fn seq_for_uid(&self, uid: u64) -> Option<u32> {
        self.uid_map
            .iter()
            .position(|&u| u == uid)
            .map(|i| i as u32 + 1)
    }

    /// Current \Recent count for this session: recent UIDs that are still in
    /// the mailbox view (expunged messages stop being \Recent).
    fn recent_count(&self) -> u32 {
        self.recent_uids
            .iter()
            .filter(|u| self.uid_map.contains(u))
            .count()
            .min(u32::MAX as usize) as u32
    }
}

// ── Subscription table ───────────────────────────────────────────────────────
//
// SUBSCRIBE/UNSUBSCRIBE state, keyed by account id. The mailstore gRPC API
// has no subscription endpoints and the DB schema has no subscriptions
// table (adding one needs a migration, out of scope here), so this in-memory
// table is the authoritative source for LSUB and the \Subscribed LIST
// attribute. KNOWN LIMITATION (documented deliberately): subscriptions do
// not survive a restart and are not shared between server replicas. LSUB at
// least reflects this table honestly — subscribed names are listed even
// when the mailbox no longer exists (with no attributes).

type SubscriptionTable = HashMap<String, HashSet<String>>;
static SUBSCRIPTIONS: LazyLock<Arc<Mutex<SubscriptionTable>>> =
    LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

type MailstoreClient = MailstoreServiceClient<
    tonic::service::interceptor::InterceptedService<Channel, InternalServiceAuthInterceptor>,
>;

/// Build the mailstore client with the validated internal service-token
/// interceptor configured at process startup.
fn build_mailstore_client(
    channel: Channel,
    interceptor: InternalServiceAuthInterceptor,
) -> MailstoreClient {
    MailstoreServiceClient::with_interceptor(channel, interceptor)
}

async fn subscribe_mailbox(account_id: &str, mailbox: &str) {
    let mut table = SUBSCRIPTIONS.lock().await;
    table
        .entry(account_id.to_string())
        .or_default()
        .insert(mailbox.to_string());
}

async fn unsubscribe_mailbox(account_id: &str, mailbox: &str) {
    let mut table = SUBSCRIPTIONS.lock().await;
    if let Some(set) = table.get_mut(account_id) {
        set.retain(|s| !s.eq_ignore_ascii_case(mailbox));
    }
}

async fn rename_subscription(account_id: &str, old_name: &str, new_name: &str) {
    let mut table = SUBSCRIPTIONS.lock().await;
    if let Some(set) = table.get_mut(account_id) {
        if set.iter().any(|s| s.eq_ignore_ascii_case(old_name)) {
            set.retain(|s| !s.eq_ignore_ascii_case(old_name));
            set.insert(new_name.to_string());
        }
    }
}

async fn remove_subscription(account_id: &str, mailbox: &str) {
    let mut table = SUBSCRIPTIONS.lock().await;
    if let Some(set) = table.get_mut(account_id) {
        set.retain(|s| !s.eq_ignore_ascii_case(mailbox));
    }
}

async fn subscribed_mailboxes(account_id: &str) -> HashSet<String> {
    let table = SUBSCRIPTIONS.lock().await;
    table.get(account_id).cloned().unwrap_or_default()
}

// ── LOGIN/AUTHENTICATE brute-force throttling ───────────────────────────────
//
// Tracks failed authentication attempts per (client IP, username). Once five
// failures accumulate inside the lockout window, further attempts for that
// pair are rejected immediately — before any credential check, with no
// artificial delay, so the response leaks nothing about the account.
//
// KNOWN LIMITATION (F12, documented deliberately): this state is
// PROCESS-LOCAL. Lockout counters are not shared between server replicas and
// do not survive a restart, so a distributed attacker rotating across
// replicas gets per-replica budgets. Moving the counters to a shared store
// needs a Redis client in this crate's dependency tree — none exists today
// (only other services in the workspace depend on redis) — and adding one is
// out of scope for this change.

const AUTH_FAILURE_LIMIT: usize = 5;
const AUTH_FAILURE_WINDOW: Duration = Duration::from_secs(5 * 60);
/// Aggregate cap on failed authentications per source IP across ALL
/// usernames, so an attacker spraying many username variants from one IP
/// cannot dodge the per-(ip, username) lockout.
const AUTH_IP_FAILURE_LIMIT: usize = 100;
/// Upper bound on DISTINCT IPs tracked in [`AUTH_IP_FAILURES`] (bounded
/// memory; see [`auth_evict_oldest_ips`]).
const AUTH_IP_MAX_TRACKED: usize = 10_000;

type AuthFailureTable = HashMap<(String, String), VecDeque<std::time::Instant>>;
static AUTH_FAILURES: LazyLock<Arc<Mutex<AuthFailureTable>>> =
    LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));
/// Per-IP failure history across all usernames.
type AuthIpFailureTable = HashMap<String, VecDeque<std::time::Instant>>;
static AUTH_IP_FAILURES: LazyLock<Arc<Mutex<AuthIpFailureTable>>> =
    LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

fn prune_stale(failures: &mut VecDeque<std::time::Instant>, now: std::time::Instant) {
    failures.retain(|t| now.duration_since(*t) < AUTH_FAILURE_WINDOW);
}

/// F12: bounded eviction for the per-IP table. When a NEW ip would push the
/// table past [`AUTH_IP_MAX_TRACKED`], drop the OLDEST HALF by last recorded
/// failure instead of keeping every key forever — the table stays bounded
/// without discarding the (recent, hostile) IPs that matter most.
fn auth_evict_oldest_ips(ip_table: &mut AuthIpFailureTable) {
    if ip_table.len() < AUTH_IP_MAX_TRACKED {
        return;
    }
    let mut by_age: Vec<String> = ip_table.keys().cloned().collect();
    by_age.sort_by_key(|ip| {
        ip_table
            .get(ip)
            .and_then(|failures| failures.back().copied())
            .unwrap_or_else(std::time::Instant::now)
    });
    let evict = by_age.len() / 2;
    for ip in by_age.into_iter().take(evict) {
        ip_table.remove(&ip);
    }
}

/// Returns `true` when (ip, username) is currently locked out, either via
/// its own failure history or via the per-IP aggregate cap.
async fn auth_is_locked(ip: &str, username: &str) -> bool {
    let mut table = AUTH_FAILURES.lock().await;
    let pair_locked = match table.get_mut(&(ip.to_string(), username.to_string())) {
        Some(failures) => {
            prune_stale(failures, std::time::Instant::now());
            failures.len() >= AUTH_FAILURE_LIMIT
        }
        None => false,
    };
    if pair_locked {
        return true;
    }
    drop(table);
    let mut ip_table = AUTH_IP_FAILURES.lock().await;
    match ip_table.get_mut(ip) {
        Some(failures) => {
            prune_stale(failures, std::time::Instant::now());
            failures.len() >= AUTH_IP_FAILURE_LIMIT
        }
        None => false,
    }
}

/// Record a failed attempt. Once the limit is reached within the window the
/// pair stays locked until the oldest failure ages out. Failures also count
/// towards the per-IP aggregate budget.
async fn auth_record_failure(ip: &str, username: &str) {
    let now = std::time::Instant::now();
    {
        let mut table = AUTH_FAILURES.lock().await;
        // Opportunistically drop fully-expired keys so the table cannot grow
        // without bound when an attacker sprays many username variants.
        table.retain(|_, failures| {
            prune_stale(failures, now);
            !failures.is_empty()
        });
        let failures = table
            .entry((ip.to_string(), username.to_string()))
            .or_default();
        failures.push_back(now);
    }
    // Per-IP aggregate accounting (bound the deque for safety).
    let mut ip_table = AUTH_IP_FAILURES.lock().await;
    ip_table.retain(|_, failures| {
        prune_stale(failures, now);
        !failures.is_empty()
    });
    // F12: bounded growth by DISTINCT IP — evict the oldest half before
    // inserting a brand-new key (existing keys just refresh in place).
    if !ip_table.contains_key(ip) {
        auth_evict_oldest_ips(&mut ip_table);
    }
    let failures = ip_table.entry(ip.to_string()).or_default();
    failures.push_back(now);
    // Hard cap the stored history so a hostile IP cannot grow it unboundedly.
    while failures.len() > AUTH_IP_FAILURE_LIMIT {
        failures.pop_front();
    }
}

/// Clear the failure history after a successful login.
///
/// F12: the per-IP AGGREGATE for this IP is cleared too — previously only the
/// (ip, username) pair was removed, so a legitimate user who finally logged
/// in still left their IP at the aggregate cap (one more sprayed failure away
/// from locking every other username from that IP, e.g. behind NAT).
async fn auth_clear_failures(ip: &str, username: &str) {
    {
        let mut table = AUTH_FAILURES.lock().await;
        table.remove(&(ip.to_string(), username.to_string()));
    }
    let mut ip_table = AUTH_IP_FAILURES.lock().await;
    ip_table.remove(ip);
}

// ── Sequence set parser ──────────────────────────────────────────────────────
//
// Sequence sets are parsed into inclusive (start, end) u64 intervals.
// `u64::MAX` represents the `*` wildcard and is resolved against actual
// mailbox contents at use time (never expanded blindly).

/// Maximum number of intervals accepted in one sequence set. A single
/// command carrying thousands of intervals is either hostile or broken;
/// expanding it is O(intervals x mailbox) work, so reject it up front.
const MAX_SEQ_INTERVALS: usize = 1_000;
/// Upper bound on resolved UIDs a single sequence set may expand to. Guards
/// the resolve step against pathological interval lists over huge mailboxes.
const MAX_RESOLVED_UIDS: usize = 100_000;

fn parse_sequence_set(input: &str) -> Result<Vec<(u64, u64)>> {
    let mut intervals = Vec::new();
    if input.trim().is_empty() {
        return Ok(intervals);
    }
    for part in input.split(',') {
        if intervals.len() >= MAX_SEQ_INTERVALS {
            bail!(
                "Too many intervals in sequence set (max {})",
                MAX_SEQ_INTERVALS
            );
        }
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(pos) = part.find(':') {
            let start_str = part[..pos].trim();
            let end_str = part[pos + 1..].trim();
            let start: u64 = if start_str == "*" {
                u64::MAX
            } else {
                start_str
                    .parse()
                    .with_context(|| format!("invalid sequence start: {}", start_str))?
            };
            let end: u64 = if end_str == "*" {
                u64::MAX
            } else {
                end_str
                    .parse()
                    .with_context(|| format!("invalid sequence end: {}", end_str))?
            };
            if start == u64::MAX && end == u64::MAX {
                intervals.push((u64::MAX, u64::MAX));
            } else {
                // RFC 3501 §9: a range may be given in either order
                // (5:2 == 2:5, *:4 == 4:*); normalize by swapping so the
                // range stays inclusive.
                intervals.push((start.min(end), start.max(end)));
            }
        } else if part == "*" {
            intervals.push((u64::MAX, u64::MAX));
        } else {
            let u: u64 = part
                .parse()
                .with_context(|| format!("invalid sequence number: {}", part))?;
            if u == 0 {
                continue;
            }
            intervals.push((u, u));
        }
    }
    Ok(intervals)
}

/// Resolve sequence-set intervals against an actual mailbox.
///
/// `uid_map` is the mailbox's UID list in ascending order (index + 1 = sequence
/// number). In UID mode, `max_uid` caps wildcard/large ranges so they are
/// expanded only over existing messages.
///
/// Bounds: intervals are sorted and merged first (dedup at the interval
/// level), the uid_map is then walked exactly once with a moving cursor, and
/// resolution fails once more than [`MAX_RESOLVED_UIDS`] messages would be
/// produced — a hostile set such as `1:*,1:*,...` can no longer materialize
/// billions of entries before dedup.
fn resolve_intervals(
    intervals: &[(u64, u64)],
    is_uid: bool,
    uid_map: &[u64],
    max_uid: u64,
) -> Result<Vec<u64>> {
    let mut merged: Vec<(u64, u64)> = intervals.to_vec();
    merged.sort_unstable();
    merged.dedup();
    // Merge overlapping/adjacent intervals so the single pass below never
    // revisits a UID and the output stays bounded by the mailbox size.
    let mut collapsed: Vec<(u64, u64)> = Vec::with_capacity(merged.len());
    for &(s, e) in &merged {
        match collapsed.last_mut() {
            Some(last) if s <= last.1.saturating_add(1) => {
                last.1 = last.1.max(e);
            }
            _ => collapsed.push((s, e)),
        }
    }

    let mut out: Vec<u64> = Vec::new();
    let len = uid_map.len() as u64;
    if collapsed.is_empty() || uid_map.is_empty() {
        return Ok(out);
    }

    let mut cursor = 0usize; // index into uid_map; never moves backwards
    for &(s, e) in &collapsed {
        let (lo, hi) = if is_uid {
            let lo = if s == u64::MAX { max_uid } else { s };
            let hi = if e == u64::MAX { max_uid } else { e };
            // RFC 3501 §9: `n:*` always includes the last message, even when
            // n exceeds the mailbox's maximum UID.
            let lo = if (s == u64::MAX || e == u64::MAX) && max_uid > 0 {
                lo.min(max_uid)
            } else {
                lo
            };
            (lo, hi)
        } else {
            // Sequence numbers beyond the mailbox size are ignored; a range's
            // upper bound is truncated to the last message (RFC 3501 §6.4.8).
            let lo = if s == u64::MAX { len } else { s };
            let hi = if e == u64::MAX { len } else { e.min(len) };
            // RFC 3501 §9: `n:*` always includes the last message, even when
            // n exceeds the number of messages in the mailbox.
            let lo = if (s == u64::MAX || e == u64::MAX) && lo > len {
                len
            } else {
                lo
            };
            (lo, hi)
        };
        if lo == 0 || lo > hi {
            continue;
        }

        if is_uid {
            while cursor < uid_map.len() && uid_map[cursor] < lo {
                cursor += 1;
            }
            while cursor < uid_map.len() && uid_map[cursor] <= hi {
                out.push(uid_map[cursor]);
                cursor += 1;
                if out.len() > MAX_RESOLVED_UIDS {
                    bail!(
                        "Sequence set resolves to too many messages (max {})",
                        MAX_RESOLVED_UIDS
                    );
                }
            }
        } else {
            // lo/hi are sequence numbers; clamp hi to the mailbox size.
            let hi = hi.min(len);
            let mut i = lo;
            while i <= hi && ((i as usize) <= uid_map.len()) {
                out.push(uid_map[(i - 1) as usize]);
                i += 1;
                if out.len() > MAX_RESOLVED_UIDS {
                    bail!(
                        "Sequence set resolves to too many messages (max {})",
                        MAX_RESOLVED_UIDS
                    );
                }
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// Resolve a sequence set against the session's current mailbox view.
fn resolve_sequence_set(session: &ImapSession, input: &str, is_uid: bool) -> Result<Vec<u64>> {
    let intervals = parse_sequence_set(input)?;
    let max_uid = session.uid_map.iter().copied().max().unwrap_or(0);
    resolve_intervals(&intervals, is_uid, &session.uid_map, max_uid)
}

// ── Response formatters ─────────────────────────────────────────────────────

fn tagged_ok(tag: &str, msg: &str) -> String {
    format!("{} OK {}\r\n", tag, msg)
}

fn tagged_no(tag: &str, msg: &str) -> String {
    format!("{} NO {}\r\n", tag, msg)
}

fn tagged_bad(tag: &str, msg: &str) -> String {
    format!("{} BAD {}\r\n", tag, msg)
}

fn bye(msg: &str) -> String {
    format!("* BYE {}\r\n", msg)
}

fn flags_response(flags: &[String]) -> String {
    let f = flags
        .iter()
        .map(|fl| format!("\\{}", fl))
        .collect::<Vec<_>>()
        .join(" ");
    format!("* FLAGS ({})\r\n", f)
}

fn permanent_flags_response(flags: &[String]) -> String {
    let mut all = flags.to_vec();
    all.push("\\*".to_string());
    format!(
        "* OK [PERMANENTFLAGS ({})] Permanent flags\r\n",
        all.join(" ")
    )
}

fn uid_validity_response(uidvalidity: u64) -> String {
    format!("* OK [UIDVALIDITY {}] UIDs valid\r\n", uidvalidity)
}

fn uid_next_response(uidnext: u64) -> String {
    format!("* OK [UIDNEXT {}] Predicted next UID\r\n", uidnext)
}

fn format_imap_flags(flags: &mail_proto::MessageFlags) -> String {
    let mut parts = Vec::new();
    if flags.seen {
        parts.push("\\Seen".to_string());
    }
    if flags.answered {
        parts.push("\\Answered".to_string());
    }
    if flags.flagged {
        parts.push("\\Flagged".to_string());
    }
    if flags.deleted {
        parts.push("\\Deleted".to_string());
    }
    if flags.draft {
        parts.push("\\Draft".to_string());
    }
    if flags.recent {
        parts.push("\\Recent".to_string());
    }
    for custom in &flags.custom {
        parts.push(custom.clone());
    }
    format!("({})", parts.join(" "))
}

fn format_internal_date(ts: i64) -> String {
    use chrono::DateTime;
    match DateTime::from_timestamp(ts, 0) {
        Some(dt) => format!("\"{}\"", dt.format("%d-%b-%Y %H:%M:%S %z")),
        None => "NIL".to_string(),
    }
}

fn format_envelope(env: &mail_proto::EmailEnvelope) -> String {
    let date = if env.date > 0 {
        format_internal_date(env.date)
    } else {
        "NIL".to_string()
    };
    let subject = if env.subject.is_empty() {
        "NIL".to_string()
    } else {
        encode_nstring(&env.subject)
    };
    let from = format_single_address(&env.from);
    let sender = format_single_address(&env.from);
    // RFC 3501 §7.4.2: the envelope's Reply-To defaults to the From address
    // when the message carries no Reply-To (the mailstore also defaults the
    // proto field; this covers envelopes from other producers).
    let reply_to = if env.reply_to.is_empty() {
        format_single_address(&env.from)
    } else {
        format_single_address(&env.reply_to)
    };
    let to = format_address_list(&env.to);
    let cc = format_address_list(&env.cc);
    let bcc = format_address_list(&env.bcc);
    let in_reply_to = if env.in_reply_to.is_empty() {
        "NIL".to_string()
    } else {
        encode_nstring(&env.in_reply_to)
    };
    let message_id = if env.message_id.is_empty() {
        "NIL".to_string()
    } else {
        encode_nstring(&env.message_id)
    };
    format!(
        "({} {} {} {} {} {} {} {} {} {})",
        date, subject, from, sender, reply_to, to, cc, bcc, in_reply_to, message_id
    )
}

fn format_single_address(addr: &str) -> String {
    if addr.is_empty() {
        return "NIL".to_string();
    }
    let (mbox, host) = match addr.find('@') {
        Some(pos) => (&addr[..pos], &addr[pos + 1..]),
        None => (addr, ""),
    };
    format!(
        "(NIL NIL {} {})",
        encode_nstring(mbox),
        encode_nstring(host)
    )
}

fn format_address_list(addrs: &[String]) -> String {
    if addrs.is_empty() || addrs.iter().all(|a| a.is_empty()) {
        return "NIL".to_string();
    }
    let list: Vec<String> = addrs.iter().map(|a| format_single_address(a)).collect();
    format!("({})", list.join(""))
}

fn encode_nstring(s: &str) -> String {
    // F10: a quoted string cannot carry CR, LF, NUL or other control bytes —
    // RFC 3501 §4.3 allows only `\"` and `\\` as escapes, so the old `\r`,
    // `\n` and `\xNN` output was an illegal quoted string. Values containing
    // such bytes are emitted as an IMAP literal (`{octets}\r\n<raw bytes>`)
    // instead, which the surrounding response format accepts wherever an
    // nstring is legal. The length is in OCTETS (UTF-8 bytes), not chars.
    let needs_literal = s
        .as_bytes()
        .iter()
        .any(|&b| b == b'\r' || b == b'\n' || b.is_ascii_control());
    if needs_literal {
        return format!("{{{}}}\r\n{}", s.len(), s);
    }
    let mut out = String::new();
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c => out.push(c),
        }
    }
    format!("\"{}\"", out)
}

// ── Tokenizing / small parsing helpers ──────────────────────────────────────

/// Tokenize a command argument string into whitespace-separated tokens,
/// keeping `"quoted strings"` and `(parenthesized lists)` intact as one token.
/// Backslash escapes inside quoted strings (`\"`, `\\`) are preserved in the
/// token and handled by `unquote` later.
fn tokenize_command_args(args: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    let mut paren_depth = 0usize;
    let mut has_token = false;
    let mut chars = args.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if !in_quote => {
                in_quote = true;
                cur.push(c);
                has_token = true;
            }
            '"' => {
                in_quote = false;
                cur.push(c);
            }
            '\\' if in_quote => {
                // Escaped character inside a quoted string: keep both chars
                // so unquote() can unescape them.
                cur.push(c);
                if let Some(&next) = chars.peek() {
                    cur.push(next);
                    chars.next();
                }
                has_token = true;
            }
            '(' if !in_quote => {
                paren_depth += 1;
                cur.push(c);
                has_token = true;
            }
            ')' if !in_quote => {
                paren_depth = paren_depth.saturating_sub(1);
                cur.push(c);
                has_token = true;
            }
            ' ' if !in_quote && paren_depth == 0 => {
                if has_token {
                    tokens.push(std::mem::take(&mut cur));
                    has_token = false;
                }
            }
            _ => {
                cur.push(c);
                has_token = true;
            }
        }
    }
    if has_token {
        tokens.push(cur);
    }
    tokens
}

/// Unquote an IMAP quoted string and process backslash escapes.
/// RFC 3501 §4.3: within a quoted string, `\"` and `\\` are the only escapes.
fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        let inner = &s[1..s.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(next) = chars.next() {
                    if next == '"' || next == '\\' {
                        out.push(next);
                    } else {
                        out.push('\\');
                        out.push(next);
                    }
                } else {
                    out.push('\\');
                }
            } else {
                out.push(c);
            }
        }
        out
    } else {
        s.to_string()
    }
}

// ── Literal handling ────────────────────────────────────────────────────────
//
// A literal is spliced into the command stream as the marker token
// `\x01LIT<k>\x01`, where `<k>` indexes into the literal byte buffers that
// were read with the command. Handlers resolve markers with `resolve_token`
// (text) or `token_literal_bytes` (raw APPEND payload).

fn literal_index(token: &str) -> Option<usize> {
    token
        .strip_prefix('\x01')
        .and_then(|t| t.strip_suffix('\x01'))
        .and_then(|t| t.strip_prefix("LIT"))
        .and_then(|k| k.parse().ok())
}

/// Resolve a token to text: literal markers become their UTF-8 content,
/// quoted strings are unquoted/unescaped, atoms pass through.
fn resolve_token(token: &str, literals: &[Vec<u8>]) -> String {
    if let Some(k) = literal_index(token) {
        if let Some(lit) = literals.get(k) {
            return String::from_utf8_lossy(lit).into_owned();
        }
    }
    unquote(token)
}

/// If the token is a literal marker, return the raw literal bytes.
fn token_literal_bytes<'a>(token: &str, literals: &'a [Vec<u8>]) -> Option<&'a [u8]> {
    literal_index(token)
        .and_then(|k| literals.get(k))
        .map(|v| v.as_slice())
}

/// Parse a literal spec: `{size}`, `{size+}` (LITERAL+ non-sync), or `~{size}`.
/// Returns (size, non_sync).
#[allow(dead_code)]
fn parse_literal_spec(s: &str) -> Result<(usize, bool)> {
    let s = s.trim().trim_start_matches('~');
    let inner = s
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .ok_or_else(|| anyhow::anyhow!("invalid literal spec: {}", s))?;
    let non_sync = inner.ends_with('+');
    let num = inner
        .trim_end_matches('+')
        .parse::<usize>()
        .with_context(|| format!("invalid literal size: {}", inner))?;
    Ok((num, non_sync))
}

// ── Modified UTF-7 (RFC 3501 §5.1.3) ───────────────────────────────────────
//
// Mailbox names are exchanged with clients in modified UTF-7: ASCII passes
// through unchanged, `&` is encoded as `&-`, and runs of non-ASCII characters
// are encoded as modified base64 (`,` instead of `/`, no padding) of their
// UTF-16BE representation, wrapped in `&...-`. Internally (and in the
// mailstore) mailbox names are plain UTF-8.

fn modified_b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b',' => 63,
            b'=' => break, // padding (not used by modified UTF-7, tolerate)
            _ => return None,
        };
        bits = (bits << 6) | v as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    Some(out)
}

fn modified_b64_encode(bytes: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";
    let mut out = String::with_capacity(bytes.len() / 3 * 4);
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    for &b in bytes {
        bits = (bits << 8) | b as u32;
        nbits += 8;
        while nbits >= 6 {
            nbits -= 6;
            out.push(CHARS[((bits >> nbits) & 0x3F) as usize] as char);
        }
    }
    if nbits > 0 {
        out.push(CHARS[((bits << (6 - nbits)) & 0x3F) as usize] as char);
    }
    out
}

/// Decode a modified UTF-7 mailbox name to UTF-8. Sequences that are not
/// valid modified UTF-7 (e.g. a plain UTF-8 name containing `&`) pass through
/// unchanged.
fn imap_utf7_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' {
            if let Some(rel_end) = s[i + 1..].find('-') {
                let b64 = &s[i + 1..i + 1 + rel_end];
                if b64.is_empty() {
                    // "&-" encodes a literal '&'
                    out.push(b'&');
                    i += 2;
                    continue;
                }
                if let Some(decoded) = modified_b64_decode(b64) {
                    let (pairs, _remainder) = decoded.as_chunks::<2>();
                    let mut utf16 = Vec::with_capacity(pairs.len());
                    for pair in pairs {
                        utf16.push(u16::from_be_bytes([pair[0], pair[1]]));
                    }
                    out.extend_from_slice(&String::from_utf16_lossy(&utf16).into_bytes());
                    i += 2 + rel_end;
                    continue;
                }
            }
            // Not valid modified UTF-7: keep the '&' literally.
            out.push(b'&');
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Encode a UTF-8 mailbox name as modified UTF-7.
fn imap_utf7_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut acc: Vec<u16> = Vec::new();
    let flush = |acc: &mut Vec<u16>, out: &mut String| {
        if acc.is_empty() {
            return;
        }
        let mut bytes = Vec::with_capacity(acc.len() * 2);
        for u in acc.drain(..) {
            bytes.extend_from_slice(&u.to_be_bytes());
        }
        out.push('&');
        out.push_str(&modified_b64_encode(&bytes));
        out.push('-');
    };
    for ch in s.chars() {
        if ch == '&' {
            flush(&mut acc, &mut out);
            out.push_str("&-");
        } else if ch.is_ascii() {
            flush(&mut acc, &mut out);
            out.push(ch);
        } else {
            let mut buf = [0u16; 2];
            for &u in ch.encode_utf16(&mut buf).iter() {
                acc.push(u);
            }
        }
    }
    flush(&mut acc, &mut out);
    out
}

/// IMAP LIST/LSUB pattern matching. `*` matches any sequence of characters,
/// `%` matches any sequence except the hierarchy delimiter `/` (it must not
/// consume a `/`).
/// Mailbox names are case-insensitive per RFC 3501, so ASCII case is folded.
///
/// Implemented as a dynamic-programming match so `%` backtracks correctly
/// (the previous single-backtrack-point scanner mis-evaluated patterns like
/// `%ab` against `aab`). Complexity is O(name x pattern), and inputs are
/// bounded mailbox names, so this is safe on hostile input.
fn imap_pattern_match(name: &str, pattern: &str) -> bool {
    if pattern.is_empty() {
        return name.is_empty();
    }
    let n: Vec<char> = name.chars().map(|c| c.to_ascii_lowercase()).collect();
    let p: Vec<char> = pattern.chars().map(|c| c.to_ascii_lowercase()).collect();
    let nlen = n.len();
    let plen = p.len();

    // dp[i][j] = does n[i..] match p[j..]?
    let mut dp = vec![vec![false; plen + 1]; nlen + 1];
    // Base case: the name is exhausted — only trailing wildcards may remain.
    dp[nlen][plen] = true;
    for j in (0..plen).rev() {
        dp[nlen][j] = matches!(p[j], '*' | '%') && dp[nlen][j + 1];
    }
    for i in (0..nlen).rev() {
        for j in (0..plen).rev() {
            dp[i][j] = match p[j] {
                '*' => dp[i + 1][j] || dp[i][j + 1],
                '%' => (n[i] != '/' && dp[i + 1][j]) || dp[i][j + 1],
                c => c == n[i] && dp[i + 1][j + 1],
            };
        }
    }
    dp[0][0]
}

/// Combine a LIST reference and pattern per RFC 3501 §6.3.8.
fn combine_list_pattern(reference: &str, pattern: &str) -> String {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return "*".to_string();
    }
    let reference = reference.trim();
    if reference.is_empty() || pattern.starts_with('/') {
        return pattern.to_string();
    }
    let ref_trimmed = reference.trim_end_matches('/');
    if ref_trimmed.is_empty() {
        return pattern.to_string();
    }
    format!("{}/{}", ref_trimmed, pattern)
}

/// Render a mailbox name as an IMAP quoted string (L7).
///
/// LIST/LSUB/STATUS interpolate mailbox names into quoted strings; a name
/// containing `"` (createable via literals) would terminate the quoted
/// string and a name containing CRLF would split the response line. The
/// backslash and double quote are escaped and CR/LF are stripped — mailbox
/// names are modified UTF-7, so raw CR/LF are never legitimate content.
fn mailbox_astring(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 2);
    out.push('"');
    for ch in name.chars() {
        match ch {
            '\r' | '\n' => {}
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

/// L12: the tagged response for a FETCH whose per-message body retrieval
/// failed. `ResourceExhausted` (the mailstore's rate/quota limiter) maps to
/// a `NO Server busy` so the client retries instead of silently missing
/// BODY attributes; any other error surfaces its reason.
fn fetch_body_failure_line(tag: &str, status: &tonic::Status) -> String {
    if status.code() == tonic::Code::ResourceExhausted {
        tagged_no(tag, "Server busy; try again later")
    } else {
        tagged_no(tag, &format!("FETCH failed: {}", status.message()))
    }
}

/// Extract the tonic gRPC status code from an anyhow error chain, if any.
fn tonic_code(e: &anyhow::Error) -> Option<tonic::Code> {
    e.root_cause()
        .downcast_ref::<tonic::Status>()
        .map(|s| s.code())
}

// ── Capability advertisement ─────────────────────────────────────────────────

fn capability_list(
    tls_active: bool,
    allow_insecure_auth: bool,
    starttls_available: bool,
) -> Vec<&'static str> {
    let mut caps = vec![
        "IMAP4rev1",
        "NAMESPACE",
        "MOVE",
        "UIDPLUS",
        "IDLE",
        "LITERAL+",
    ];
    if tls_active {
        caps.push("AUTH=PLAIN");
    } else {
        if starttls_available {
            caps.insert(0, "STARTTLS");
        }
        if allow_insecure_auth {
            caps.push("AUTH=PLAIN");
        } else {
            // RFC 3501 §6.2.3: LOGINDISABLED means LOGIN is not permitted.
            caps.push("LOGINDISABLED");
        }
    }
    caps
}

fn greeting_line(tls_active: bool, allow_insecure_auth: bool, starttls_available: bool) -> String {
    format!(
        "* OK [CAPABILITY {}] ApexMail IMAP4rev1 server ready\r\n",
        capability_list(tls_active, allow_insecure_auth, starttls_available).join(" ")
    )
}

// ── Command reader ──────────────────────────────────────────────────────────
//
// Commands are read line-by-line with full literal support: a literal spec
// (`{n}`, `{n+}`, `~{n}`) found at a token boundary, outside quoted strings,
// is consumed per RFC 3501 §4.3. Synchronizing literals get a continuation
// request; LITERAL+ literals are read immediately. The literal bytes are
// returned in order and the command text is spliced with `\x01LIT<k>\x01`
// marker tokens so the existing tokenizers see the literal as one token.

const MAX_COMMAND_LINE: usize = 1024 * 1024;
const MAX_LITERAL_SIZE: usize = 32 * 1024 * 1024;
/// Maximum number of literals accepted in a single command. A command
/// carrying hundreds of literal specs is hostile; each one would otherwise
/// receive a continuation and a read buffer.
const MAX_LITERALS_PER_COMMAND: usize = 64;
/// Maximum total literal bytes accepted in a single command. Bounds the
/// combined literal buffers (64 x 32 MB would otherwise be 2 GB).
const MAX_TOTAL_LITERAL_BYTES: usize = 64 * 1024 * 1024;
/// L1: maximum TOTAL literal bytes one connection may send across ALL its
/// commands. The per-command budget alone let a long-lived connection
/// stream an unbounded number of legal-sized literals; the per-connection
/// cumulative budget bounds the total read work per socket.
const MAX_TOTAL_LITERAL_BYTES_PER_CONNECTION: usize = 512 * 1024 * 1024;
/// L1: literal buffers grow in these increments. Memory tracks the bytes
/// that ACTUALLY arrived, not the client's declared size, so a hostile
/// `{33554432+}` followed by a stall pins only what was received.
const LITERAL_CHUNK: usize = 64 * 1024;
/// L1: how long a single command read may stall before the connection is
/// closed. Abandoned/slow sockets must die; this is independent of (and much
/// shorter than) the 29-minute IDLE deadline, which governs the IDLE loop.
const COMMAND_READ_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// L1: literal read limits for one command/connection.
#[derive(Debug, Clone, Copy)]
struct ReadLimits {
    max_literal_size: usize,
    max_literals_per_command: usize,
    max_total_per_command: usize,
    max_total_per_connection: usize,
}

impl Default for ReadLimits {
    fn default() -> Self {
        Self {
            max_literal_size: MAX_LITERAL_SIZE,
            max_literals_per_command: MAX_LITERALS_PER_COMMAND,
            max_total_per_command: MAX_TOTAL_LITERAL_BYTES,
            max_total_per_connection: MAX_TOTAL_LITERAL_BYTES_PER_CONNECTION,
        }
    }
}

/// L1: per-connection cumulative literal accounting.
#[derive(Debug, Default)]
struct ConnectionReadState {
    literal_bytes_total: usize,
}

/// Literal budget check for a command: given the literals already read
/// (count/total bytes), the next literal's declared size, and the
/// connection's cumulative total, decide whether reading it stays inside
/// every budget.
fn literal_within_budget(
    count_so_far: usize,
    total_so_far: usize,
    size: usize,
    limits: &ReadLimits,
    conn_total: usize,
) -> bool {
    if count_so_far >= limits.max_literals_per_command {
        return false;
    }
    if size > limits.max_literal_size {
        return false;
    }
    if total_so_far.saturating_add(size) > limits.max_total_per_command {
        return false;
    }
    conn_total.saturating_add(total_so_far).saturating_add(size) <= limits.max_total_per_connection
}

/// L1: read exactly `size` literal bytes INCREMENTALLY, in [`LITERAL_CHUNK`]
/// steps. Unlike the previous `vec![0u8; size]` + single `read_exact`, the
/// buffer only grows as data actually arrives — a client that declares a
/// 32 MiB literal and then stalls pins memory proportional to what it sent,
/// not to what it promised.
async fn read_literal_chunked<R: AsyncRead + Unpin>(
    reader: &mut R,
    size: usize,
) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    if size == 0 {
        return Ok(buf);
    }
    let mut chunk = vec![0u8; LITERAL_CHUNK.min(size)];
    let mut remaining = size;
    while remaining > 0 {
        let want = remaining.min(chunk.len());
        reader
            .read_exact(&mut chunk[..want])
            .await
            .with_context(|| "Literal data truncated")?;
        buf.extend_from_slice(&chunk[..want]);
        remaining -= want;
    }
    Ok(buf)
}

/// Read one physical line (bounded) as lossy UTF-8. Returns None on EOF.
async fn read_line_limited<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Result<Option<String>> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let consumed = {
            let available = reader.fill_buf().await?;

            if available.is_empty() {
                return Ok(None);
            }
            if let Some(pos) = available.iter().position(|&b| b == b'\n') {
                buf.extend_from_slice(&available[..=pos]);
                pos + 1
            } else {
                if buf.len() + available.len() > MAX_COMMAND_LINE {
                    bail!("Command line too long");
                }
                buf.extend_from_slice(available);
                available.len()
            }
        };
        reader.consume(consumed);
        if buf.last() == Some(&b'\n') {
            break;
        }
    }
    if buf.len() > MAX_COMMAND_LINE {
        bail!("Command line too long");
    }
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

/// Find the first literal spec at a token boundary in `line`.
/// Returns (spec_start, spec_end, size, non_sync).
fn find_literal_spec(line: &str) -> Option<(usize, usize, usize, bool)> {
    let bytes = line.as_bytes();
    let mut i = 0;
    let mut in_quote = false;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                in_quote = !in_quote;
                i += 1;
            }
            b'\\' if in_quote => i += 2,
            b'{' if !in_quote => {
                let prev_ok = i == 0 || matches!(bytes[i - 1], b' ' | b'(' | b'\t');
                if prev_ok {
                    let mut j = i + 1;
                    let mut size: usize = 0;
                    let mut digits = false;
                    while j < bytes.len() && bytes[j].is_ascii_digit() {
                        size = size
                            .saturating_mul(10)
                            .saturating_add((bytes[j] - b'0') as usize);
                        j += 1;
                        digits = true;
                    }
                    if digits {
                        let non_sync = j < bytes.len() && bytes[j] == b'+';
                        if non_sync {
                            j += 1;
                        }
                        if j < bytes.len() && bytes[j] == b'}' {
                            return Some((i, j + 1, size, non_sync));
                        }
                    }
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

/// Read a complete command (tag, command name, args) including any literals.
/// Returns None when the client closes the connection cleanly at a command
/// boundary. Errors indicate the stream is no longer synchronized (e.g. a
/// literal was truncated) and the connection must be closed.
/// Test-facing wrapper: production paths use [`read_command_bounded`] (with
/// the read deadline) over [`read_command_limited`].
#[cfg(test)]
async fn read_command<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut BufReader<R>,
    writer: &mut W,
) -> Result<Option<(String, String, String, Vec<Vec<u8>>)>> {
    read_command_limited(
        reader,
        writer,
        &ReadLimits::default(),
        &mut ConnectionReadState::default(),
    )
    .await
}

/// The real command reader: [`ReadLimits`] bounds literals per command and
/// per connection (L1), and the literal bytes are read incrementally.
async fn read_command_limited<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    limits: &ReadLimits,
    conn: &mut ConnectionReadState,
) -> Result<Option<(String, String, String, Vec<Vec<u8>>)>> {
    let mut assembled = String::new();
    let mut literals: Vec<Vec<u8>> = Vec::new();
    let mut pending = String::new();

    loop {
        if pending.is_empty() {
            let line = match read_line_limited(reader).await? {
                None => return Ok(None),
                Some(l) => l,
            };
            let line = line.trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                continue; // ignore blank lines between commands
            }
            pending = line.to_string();
        }

        match find_literal_spec(&pending) {
            Some((start, end, size, non_sync)) => {
                assembled.push_str(&pending[..start]);
                assembled.push_str(&format!("\x01LIT{}\x01", literals.len()));
                let total_so_far: usize = literals.iter().map(|l| l.len()).sum();
                if !literal_within_budget(
                    literals.len(),
                    total_so_far,
                    size,
                    limits,
                    conn.literal_bytes_total,
                ) {
                    bail!("Literal data exceeds per-command or per-connection budget");
                }
                if !non_sync {
                    write_line(writer, "+ Ready for literal data\r\n").await?;
                }
                // L1: incremental read — memory follows the bytes that
                // actually arrive, never the declared size up front.
                let buf = read_literal_chunked(reader, size).await?;
                conn.literal_bytes_total = conn.literal_bytes_total.saturating_add(buf.len());

                literals.push(buf);
                // The text after the literal spec is sent after the literal
                // data, followed by CRLF; the next physical line continues it.
                let rest = pending[end..].to_string();
                let line = match read_line_limited(reader).await? {
                    None => return Ok(None),
                    Some(l) => l,
                };
                pending = rest + line.trim_end_matches(['\r', '\n']);
                if pending.is_empty() {
                    break; // literal ended the command
                }
                // Otherwise keep scanning for further literals in `pending`.
            }
            None => {
                assembled.push_str(&pending);
                break;
            }
        }
    }

    let assembled = assembled.trim_end_matches(['\r', '\n']).to_string();
    let (tag, cmd, args) = parse_imap_line(&assembled).unwrap_or_else(|_| {
        // Commands starting with a literal (e.g. `{5}\r\nLOGIN ...`) have no
        // tag; treat the whole thing as the command with a generic tag.
        ("*".to_string(), assembled.clone(), String::new())
    });
    Ok(Some((tag, cmd, args, literals)))
}

/// L1: `read_command_limited` with a stall deadline: a client that stops
/// sending mid-command gets a BYE and the connection is closed instead of
/// pinning its buffers forever. Distinct from the IDLE deadline (29 min),
/// which governs the IDLE wait loop, not command reads.
async fn read_command_bounded<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    limits: &ReadLimits,
    conn: &mut ConnectionReadState,
    timeout: Duration,
) -> Result<Option<(String, String, String, Vec<Vec<u8>>)>> {
    match tokio::time::timeout(timeout, read_command_limited(reader, writer, limits, conn)).await {
        Ok(inner) => inner,
        Err(_elapsed) => {
            write_line(writer, &bye("Command read timeout, closing connection")).await?;
            bail!("command read timed out after {:?}", timeout)
        }
    }
}
// ── Command dispatcher ──────────────────────────────────────────────────────
//
// Handlers write their responses directly to `writer` and read continuation
// data (AUTHENTICATE payloads, APPEND literals) from `reader`.

async fn write_line<W: AsyncWrite + Unpin>(writer: &mut W, s: &str) -> Result<()> {
    writer.write_all(s.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

async fn handle_command<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    cmd: &str,
    args: &str,
    reader: &mut BufReader<R>,
    writer: &mut W,
    literals: &[Vec<u8>],
) -> Result<()> {
    session.tag = tag.to_string();

    match cmd.to_uppercase().as_str() {
        "CAPABILITY" => handle_capability(session, tag, writer).await,
        "LOGIN" => handle_login(session, tag, args, literals, writer).await,
        "LOGOUT" => handle_logout(session, tag, writer).await,
        "AUTHENTICATE" => handle_authenticate(session, tag, args, literals, reader, writer).await,
        "NAMESPACE" => handle_namespace(session, tag, writer).await,
        "SELECT" => handle_select(session, tag, args, false, literals, writer).await,
        "EXAMINE" => handle_select(session, tag, args, true, literals, writer).await,
        "FETCH" => handle_fetch(session, tag, args, false, writer).await,
        "UID" => handle_uid_command(session, tag, args, literals, writer).await,
        "STORE" => handle_store(session, tag, args, false, literals, writer).await,
        "SEARCH" => handle_search(session, tag, args, false, literals, writer).await,
        "COPY" => handle_copy(session, tag, args, false, literals, writer).await,
        "MOVE" => handle_move(session, tag, args, false, literals, writer).await,
        "CREATE" => handle_create(session, tag, args, literals, writer).await,
        "DELETE" => handle_delete(session, tag, args, literals, writer).await,
        "RENAME" => handle_rename(session, tag, args, literals, writer).await,
        "LIST" => handle_list(session, tag, args, literals, writer).await,
        "LSUB" => handle_lsub(session, tag, args, literals, writer).await,
        "SUBSCRIBE" => handle_subscribe(session, tag, args, literals, writer).await,
        "UNSUBSCRIBE" => handle_unsubscribe(session, tag, args, literals, writer).await,
        "STATUS" => handle_status(session, tag, args, literals, writer).await,
        "APPEND" => handle_append(session, tag, args, literals, writer).await,
        "EXPUNGE" => handle_expunge(session, tag, None, writer).await,
        "IDLE" => handle_idle(session, tag, writer).await,
        "NOOP" => handle_noop(session, tag, writer).await,
        "CHECK" => handle_noop(session, tag, writer).await,
        "CLOSE" => handle_close(session, tag, writer).await,
        // STARTTLS is handled at the connection level; if it reaches this
        // dispatcher we are already on a TLS connection where it is forbidden.
        "STARTTLS" => {
            write_line(
                writer,
                &tagged_bad(tag, "STARTTLS not available on TLS connection"),
            )
            .await
        }
        _ => write_line(writer, &tagged_bad(tag, "Unknown command")).await,
    }
}

async fn handle_uid_command<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    let args = args.trim();
    let space_pos = args.find(' ').unwrap_or(args.len());
    let sub_cmd = &args[..space_pos];
    let sub_args = args[space_pos..].trim();
    let sub_args = resolve_token(sub_args, literals);

    match sub_cmd.to_uppercase().as_str() {
        "FETCH" => handle_fetch(session, tag, &sub_args, true, writer).await,
        "STORE" => handle_store(session, tag, &sub_args, true, literals, writer).await,
        "SEARCH" => handle_search(session, tag, &sub_args, true, literals, writer).await,
        "COPY" => handle_copy(session, tag, &sub_args, true, literals, writer).await,
        "MOVE" => handle_move(session, tag, &sub_args, true, literals, writer).await,
        "EXPUNGE" => handle_expunge(session, tag, Some(&sub_args), writer).await,
        _ => {
            write_line(
                writer,
                &tagged_bad(tag, &format!("Unknown UID sub-command: {}", sub_cmd)),
            )
            .await
        }
    }
}

fn auth_required(session: &ImapSession) -> bool {
    session.state != SessionState::NotAuthenticated
}

/// Re-list the selected mailbox so the session's UID map (and thus sequence
/// numbers) stays correct even when other sessions modify the mailbox.
///
/// F7: returns the untagged view diff (EXPUNGEs in descending sequence order,
/// then EXISTS — the same `view_update_lines` NOOP/IDLE emit) between the old
/// and the refreshed view. Command handlers that compute their own untagged
/// responses against the refreshed view MUST write this diff FIRST, so the
/// client's sequence numbers are corrected before the command's responses
/// reference them; the previous silent refresh made e.g. a STORE's
/// `* n FETCH (FLAGS ...)` point at the wrong message after another session
/// had expunged. (RFC 3501 §5.2 discourages unsolicited EXPUNGEs during
/// FETCH/STORE/SEARCH responses; the alternative — silently shifted sequence
/// numbers — is strictly worse, and RFC 9051 removes the restriction.)
async fn refresh_session_view(session: &mut ImapSession) -> String {
    if !mailbox_selected(session) {
        return String::new();
    }
    let old_uid_map = session.uid_map.clone();
    let mut client = session.client.clone();
    let req = ListMessagesRequest {
        account_id: session.account_id.clone(),
        mailbox: session.mailbox.clone(),
        uid_min: 1,
        uid_max: u64::MAX,
        limit: 100_000,
    };
    if let Ok(resp) = client.list_messages(req).await {
        let mut msgs = resp.into_inner().messages;
        msgs.sort_by_key(|m| m.uid);
        let new_uid_map: Vec<u64> = msgs.iter().map(|m| m.uid).collect();
        let diff = view_update_lines(&old_uid_map, &new_uid_map);
        session.uid_map = new_uid_map;
        session.exists = session.uid_map.len().min(u32::MAX as usize) as u32;
        // F6: prune \Recent for messages that left the view (expunged by
        // another session).
        let live: HashSet<u64> = session.uid_map.iter().copied().collect();
        session.recent_uids.retain(|u| live.contains(u));
        if let Some(&last) = session.uid_map.last() {
            session.uid_next = session.uid_next.max(last.saturating_add(1));
        }
        return diff;
    }
    String::new()
}

/// F8 (RFC 9051 §6.3.4): a failed SELECT/EXAMINE leaves the connection in
/// the Authenticated state with NO mailbox selected — the previously
/// selected mailbox is deselected. The old code kept the previous mailbox
/// selected on failure, so a client that SELECTed a bad name kept operating
/// on a stale view it believes it left.
fn deselect_mailbox(session: &mut ImapSession) {
    session.state = SessionState::Authenticated;
    session.mailbox.clear();
    session.uid_validity = 0;
    session.uid_next = 0;
    session.exists = 0;
    session.recent = 0;
    session.recent_uids.clear();
    session.uid_map.clear();
    session.read_only = false;
}

fn mailbox_selected(session: &ImapSession) -> bool {
    session.state == SessionState::Selected
}

fn auth_allowed(session: &ImapSession) -> bool {
    session.tls_active || session.allow_insecure_auth
}

// ── CAPABILITY ──────────────────────────────────────────────────────────────

async fn handle_capability<W: AsyncWrite + Unpin>(
    session: &ImapSession,
    tag: &str,
    writer: &mut W,
) -> Result<()> {
    let caps = capability_list(session.tls_active, session.allow_insecure_auth, true);
    write_line(
        writer,
        &format!(
            "* CAPABILITY {}\r\n{}",
            caps.join(" "),
            tagged_ok(tag, "CAPABILITY completed")
        ),
    )
    .await
}

// ── NAMESPACE (RFC 2342) ────────────────────────────────────────────────────

async fn handle_namespace<W: AsyncWrite + Unpin>(
    session: &ImapSession,
    tag: &str,
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    write_line(
        writer,
        &format!(
            "* NAMESPACE ((\"\" \"/\")) NIL NIL\r\n{}",
            tagged_ok(tag, "NAMESPACE completed")
        ),
    )
    .await
}

// ── LOGIN ───────────────────────────────────────────────────────────────────

async fn handle_login<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if session.state != SessionState::NotAuthenticated {
        return write_line(
            writer,
            &tagged_bad(tag, "Already authenticated; LOGIN not permitted"),
        )
        .await;
    }
    if !auth_allowed(session) {
        return write_line(
            writer,
            &tagged_no(
                tag,
                "[PRIVACYREQUIRED] LOGIN requires a TLS connection (use STARTTLS)",
            ),
        )
        .await;
    }

    let (user, password) = match parse_login_args(args, literals) {
        Ok(v) => v,
        Err(e) => {
            return write_line(writer, &tagged_bad(tag, &format!("{}", e))).await;
        }
    };

    // Brute-force throttling: locked-out pairs are rejected immediately,
    // before any credential work (no timing leak).
    if auth_is_locked(&session.peer_ip, &user).await {
        warn!(
            "LOGIN throttled for {} from {} (too many failures)",
            user, session.peer_ip
        );
        return write_line(
            writer,
            &tagged_no(
                tag,
                "[AUTHORIZATIONFAILED] Too many failed attempts; try again later",
            ),
        )
        .await;
    }

    let mut client = session.client.clone();
    let request = mail_proto::AuthenticateRequest {
        email: user.clone(),
        password: password.clone(),
    };

    let resp = client
        .authenticate_account(request)
        .await
        .with_context(|| "gRPC authenticate_account failed")?;
    let resp = resp.into_inner();

    if resp.success {
        auth_clear_failures(&session.peer_ip, &user).await;
        session.state = SessionState::Authenticated;
        session.account_id = resp.account_id.clone();
        info!("User {} authenticated via LOGIN", user);
        write_line(writer, &tagged_ok(tag, "LOGIN succeeded")).await
    } else {
        auth_record_failure(&session.peer_ip, &user).await;
        let error_msg = resp.error;
        warn!("LOGIN failed for {}: {}", user, error_msg);
        write_line(
            writer,
            &tagged_no(tag, &format!("LOGIN failed: {}", error_msg)),
        )
        .await
    }
}

fn parse_login_args(args: &str, literals: &[Vec<u8>]) -> Result<(String, String)> {
    let tokens = tokenize_command_args(args.trim());
    if tokens.is_empty() {
        bail!("LOGIN requires username and password");
    }
    let user = resolve_token(&tokens[0], literals);
    let password = if tokens.len() > 1 {
        resolve_token(&tokens[1], literals)
    } else {
        String::new()
    };
    if tokens.len() > 2 {
        bail!("LOGIN takes exactly username and password");
    }
    if user.is_empty() || password.is_empty() {
        bail!("LOGIN requires username and password");
    }
    Ok((user, password))
}

// ── AUTHENTICATE PLAIN (RFC 4616) ───────────────────────────────────────────

/// L13: parse AUTHENTICATE arguments into (mechanism, optional
/// initial-response). RFC 4959 SASL-IR: `AUTHENTICATE PLAIN <base64>` (or a
/// literal) carries the initial client response inline; "=" encodes the
/// empty initial response.
fn parse_authenticate_args(args: &str, literals: &[Vec<u8>]) -> (String, Option<String>) {
    let tokens = tokenize_command_args(args.trim());
    let mech = tokens
        .first()
        .map(|t| resolve_token(t, literals))
        .unwrap_or_default();
    let initial_response = tokens.get(1).map(|t| {
        let raw = resolve_token(t, literals);
        if raw == "=" {
            String::new()
        } else {
            raw
        }
    });
    (mech, initial_response)
}

async fn handle_authenticate<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    literals: &[Vec<u8>],
    reader: &mut BufReader<R>,
    writer: &mut W,
) -> Result<()> {
    let args = args.trim();
    if session.state != SessionState::NotAuthenticated {
        return write_line(
            writer,
            &tagged_bad(tag, "Already authenticated; AUTHENTICATE not permitted"),
        )
        .await;
    }
    if !auth_allowed(session) {
        return write_line(
            writer,
            &tagged_no(
                tag,
                "[PRIVACYREQUIRED] AUTHENTICATE requires a TLS connection (use STARTTLS)",
            ),
        )
        .await;
    }
    // L13: accept the SASL initial-response form (RFC 4959); without it,
    // run the classic continuation exchange.
    let (mechanism, initial_response) = parse_authenticate_args(args, literals);
    if !mechanism.eq_ignore_ascii_case("PLAIN") {
        return write_line(
            writer,
            &tagged_no(tag, &format!("Unsupported AUTH mechanism: {}", mechanism)),
        )
        .await;
    }

    // Step 1: the initial response, either inline (SASL-IR) or via the
    // continuation exchange.
    let line = match initial_response {
        Some(ir) => ir,
        None => {
            // Send the continuation prompt, then read the base64 line from
            // the client (bounded so a client that never sends a newline
            // cannot exhaust memory; L1: also bounded in time).
            write_line(writer, "+ \r\n").await?;
            match tokio::time::timeout(COMMAND_READ_TIMEOUT, read_line_limited(reader)).await {
                Ok(Ok(None)) => bail!("Client disconnected during AUTHENTICATE"),
                Ok(Ok(Some(l))) => l.trim().to_string(),
                Ok(Err(e)) => bail!("Read error during AUTHENTICATE: {}", e),
                Err(_) => {
                    write_line(
                        writer,
                        &bye("Authentication read timeout, closing connection"),
                    )
                    .await?;
                    bail!("AUTHENTICATE continuation timed out");
                }
            }
        }
    };

    if line.is_empty() || line == "*" {
        // RFC 3501: "*" cancels the authentication exchange.
        return write_line(writer, &tagged_bad(tag, "AUTHENTICATE cancelled")).await;
    }

    let decoded = match base64::engine::general_purpose::STANDARD.decode(line) {
        Ok(d) => d,
        Err(e) => {
            return write_line(
                writer,
                &tagged_bad(tag, &format!("Invalid base64 in AUTHENTICATE: {}", e)),
            )
            .await;
        }
    };

    // RFC 4616: [authzid] \0 authcid \0 passwd
    let mut parts = decoded.split(|&b| b == 0);
    let _authzid = parts.next();
    let authcid = parts.next().unwrap_or(&[]);
    let passwd = parts.next().unwrap_or(&[]);
    if authcid.is_empty() || passwd.is_empty() {
        return write_line(writer, &tagged_bad(tag, "Invalid AUTHENTICATE payload")).await;
    }
    let user = String::from_utf8_lossy(authcid).to_string();
    let password = String::from_utf8_lossy(passwd).to_string();

    // Brute-force throttling: locked-out pairs are rejected immediately,
    // before any credential work (no timing leak).
    if auth_is_locked(&session.peer_ip, &user).await {
        warn!(
            "AUTHENTICATE throttled for {} from {} (too many failures)",
            user, session.peer_ip
        );
        return write_line(
            writer,
            &tagged_no(
                tag,
                "[AUTHORIZATIONFAILED] Too many failed attempts; try again later",
            ),
        )
        .await;
    }

    let mut client = session.client.clone();
    let request = mail_proto::AuthenticateRequest {
        email: user.clone(),
        password: password.clone(),
    };

    let resp = client
        .authenticate_account(request)
        .await
        .with_context(|| "gRPC authenticate_account failed")?;
    let resp = resp.into_inner();

    if resp.success {
        auth_clear_failures(&session.peer_ip, &user).await;
        session.state = SessionState::Authenticated;
        session.account_id = resp.account_id.clone();
        info!("User {} authenticated via AUTHENTICATE PLAIN", user);
        write_line(writer, &tagged_ok(tag, "AUTHENTICATE succeeded")).await
    } else {
        auth_record_failure(&session.peer_ip, &user).await;
        let error_msg = resp.error;
        warn!("AUTHENTICATE PLAIN failed for {}: {}", user, error_msg);
        write_line(
            writer,
            &tagged_no(tag, &format!("AUTHENTICATE failed: {}", error_msg)),
        )
        .await
    }
}

// ── LOGOUT ──────────────────────────────────────────────────────────────────

async fn handle_logout<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    writer: &mut W,
) -> Result<()> {
    session.state = SessionState::Logout;
    write_line(
        writer,
        &format!(
            "{}{}",
            bye("Logging out"),
            tagged_ok(tag, "LOGOUT completed")
        ),
    )
    .await
}

// ── SELECT / EXAMINE ────────────────────────────────────────────────────────

async fn handle_select<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    read_only: bool,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    let tokens = tokenize_command_args(args.trim());
    let mailbox = tokens
        .first()
        .map(|t| imap_utf7_decode(&resolve_token(t, literals)))
        .unwrap_or_default();
    if mailbox.is_empty() {
        return write_line(writer, &tagged_bad(tag, "Mailbox name required")).await;
    }

    // F8 (RFC 9051 §6.3.4): a failed SELECT deselects the previous mailbox.
    let status = match get_mailbox_status(&mut session.client, &session.account_id, &mailbox).await
    {
        Ok(s) => s.into_inner(),
        Err(e) => {
            deselect_mailbox(session);
            if tonic_code(&e) == Some(tonic::Code::NotFound) {
                return write_line(writer, &tagged_no(tag, "[NONEXISTENT] Mailbox not found"))
                    .await;
            }
            return write_line(
                writer,
                &tagged_no(tag, &format!("Failed to open mailbox: {}", e)),
            )
            .await;
        }
    };
    let mb = status.mailbox.unwrap_or_default();

    // L6: perform EVERY fallible step before touching the session. The old
    // order marked the session Selected before the message listing; if that
    // RPC failed, the client was left with a half-selected phantom mailbox
    // (state Selected, empty uid_map). On any failure below the session is
    // deselected entirely (F8): no mailbox remains selected.
    let mut client = session.client.clone();
    let list_req = ListMessagesRequest {
        account_id: session.account_id.clone(),
        mailbox: mailbox.clone(),
        uid_min: 1,
        uid_max: u64::MAX,
        limit: 100_000,
    };
    let list_resp = match client.list_messages(list_req).await {
        Ok(r) => r.into_inner(),
        Err(e) => {
            deselect_mailbox(session);
            return write_line(
                writer,
                &tagged_no(tag, &format!("Failed to list messages: {}", e)),
            )
            .await;
        }
    };

    let mut msgs = list_resp.messages;
    msgs.sort_by_key(|m| m.uid);
    let new_uid_map: Vec<u64> = msgs.iter().map(|m| m.uid).collect();
    // The session's message view is capped at the list limit, so EXISTS must
    // report the size of the resolvable view (uid_map), not the store's total
    // count — otherwise EXISTS > highest usable sequence number and clients
    // desync when fetching the phantom tail.
    let new_exists = new_uid_map.len().min(u32::MAX as usize) as u32;

    // RFC 3501 §6.3.1: [UNSEEN n] is the sequence number of the FIRST unseen
    // message, sent only when the mailbox contains unseen messages.
    let first_unseen = msgs
        .iter()
        .position(|m| !m.flags.clone().unwrap_or_default().seen)
        .map(|i| i as u32 + 1);

    // F6: session-scoped \Recent baseline. Without a persistent
    // first-delivery marker in the store, the closest honest approximation is
    // "unseen when this session first observed the mailbox" — those UIDs stay
    // \Recent for this session's lifetime (and unseen arrivals during the
    // session join the set). Multi-session semantics are best-effort; see the
    // field docs on `ImapSession::recent_uids`.
    let new_recent_uids: HashSet<u64> = msgs
        .iter()
        .filter(|m| !m.flags.clone().unwrap_or_default().seen)
        .map(|m| m.uid)
        .collect();

    // All fallible work succeeded — NOW switch the session to the new view.
    session.mailbox = mailbox.clone();
    session.read_only = read_only;
    session.uid_validity = mb.uidvalidity.max(1);
    session.uid_next = mb.uidnext.max(1);
    session.exists = new_exists;
    session.recent_uids = new_recent_uids;
    session.state = SessionState::Selected;
    session.uid_map = new_uid_map;
    // F6: after the view is switched, report this session's recent count.
    session.recent = session.recent_count();

    let mut responses = String::new();
    responses.push_str(&format!("* {} EXISTS\r\n", session.exists));
    responses.push_str(&format!("* {} RECENT\r\n", session.recent));
    responses.push_str(&flags_response(&session.permanent_flags));
    if let Some(seq) = first_unseen {
        responses.push_str(&format!("* OK [UNSEEN {}] First unseen message\r\n", seq));
    }
    responses.push_str(&permanent_flags_response(&session.permanent_flags));
    responses.push_str(&uid_validity_response(session.uid_validity));
    responses.push_str(&uid_next_response(session.uid_next));
    // L14(e): when the store holds more messages than the session's capped
    // view can resolve, say so — STATUS still reports the true count, and
    // the mismatch would otherwise confuse clients silently.
    if let Some(notice) = view_capped_notice(session.exists, mb.exists) {
        responses.push_str(&notice);
    }

    if read_only {
        responses.push_str(&tagged_ok(
            tag,
            &format!("[READ-ONLY] EXAMINE completed, {} messages", session.exists),
        ));
    } else {
        responses.push_str(&tagged_ok(
            tag,
            &format!("[READ-WRITE] SELECT completed, {} messages", session.exists),
        ));
    }

    write_line(writer, &responses).await
}
// ── FETCH ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum BodySection {
    Full,
    Header,
    /// BODY[HEADER.FIELDS (a b c)] (+ the .NOT variant).
    HeaderFields {
        fields: Vec<String>,
        not: bool,
    },
    Text,
    /// BODY[n] or BODY[n.MIME] (dot-separated part path, e.g. "1.2").
    Part {
        number: String,
        mime: bool,
    },
}

impl BodySection {
    /// Response attribute name for a `BODY[...]` fetch of this section
    /// (RFC 3501 §7.4.2: the response echoes the requested section spec).
    fn response_name(&self) -> String {
        match self {
            BodySection::Full => "BODY[]".to_string(),
            BodySection::Header => "BODY[HEADER]".to_string(),
            BodySection::HeaderFields { fields, not } => format!(
                "BODY[HEADER.FIELDS{} ({})]",
                if *not { ".NOT" } else { "" },
                fields.join(" ")
            ),
            BodySection::Text => "BODY[TEXT]".to_string(),
            BodySection::Part { number, mime } => {
                format!("BODY[{}{}]", number, if *mime { ".MIME" } else { "" })
            }
        }
    }
}

/// Parse the section spec between `BODY[` and `]` (L2). Returns an error for
/// unsupported/malformed specs so they surface as a tagged BAD instead of
/// being silently dropped.
fn parse_body_section(spec: &str) -> Result<BodySection> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Ok(BodySection::Full);
    }
    if spec.eq_ignore_ascii_case("HEADER") {
        return Ok(BodySection::Header);
    }
    if spec.eq_ignore_ascii_case("TEXT") {
        return Ok(BodySection::Text);
    }
    let upper = spec.to_uppercase();
    if let Some(list) = upper
        .strip_prefix("HEADER.FIELDS.NOT")
        .or_else(|| upper.strip_prefix("HEADER.FIELDS"))
    {
        let list = list.trim();
        let inner = list
            .strip_prefix('(')
            .and_then(|l| l.strip_suffix(')'))
            .ok_or_else(|| anyhow::anyhow!("HEADER.FIELDS requires a (field list)"))?;
        let fields: Vec<String> = inner.split_whitespace().map(str::to_string).collect();
        if fields.is_empty() {
            bail!("HEADER.FIELDS requires at least one field name");
        }
        return Ok(BodySection::HeaderFields {
            fields,
            not: upper.starts_with("HEADER.FIELDS.NOT"),
        });
    }
    // Part spec: digits dotted with digits, optional .MIME suffix.
    let (number, mime) = match upper.strip_suffix(".MIME") {
        Some(num) => (num.to_string(), true),
        None => (upper.clone(), false),
    };
    let valid_part = !number.is_empty()
        && number.split('.').all(|component| {
            !component.is_empty() && component.chars().all(|c| c.is_ascii_digit())
        });
    if valid_part {
        return Ok(BodySection::Part { number, mime });
    }
    bail!("Unsupported BODY section: {}", spec)
}

#[derive(Debug, Clone, PartialEq)]
enum FetchItem {
    Flags,
    InternalDate,
    Rfc822Size,
    Envelope,
    Uid,
    Fast,
    All,
    Full,
    /// F5: BODY / BODYSTRUCTURE — the derived MIME structure
    /// (RFC 3501 §7.4.2). `extended` selects BODYSTRUCTURE (extension data)
    /// over bare BODY. Structure items are inherently peek-only: they
    /// describe the content, they do not deliver it, so they never set
    /// \Seen (this is what makes the FULL macro peek: true).
    BodyStructure {
        extended: bool,
    },
    /// BODY[...] or RFC822[...] with its response name and whether it peeks.
    Body {
        section: BodySection,
        peek: bool,
        name: String,
        partial: Option<(usize, usize)>,
    },
}

fn resolve_macro_item(item: &FetchItem) -> Vec<FetchItem> {
    match item {
        FetchItem::Fast => vec![
            FetchItem::Flags,
            FetchItem::InternalDate,
            FetchItem::Rfc822Size,
        ],
        FetchItem::All => vec![
            FetchItem::Flags,
            FetchItem::InternalDate,
            FetchItem::Envelope,
        ],
        // F5: RFC 3501 §6.4.5 — the FULL macro is ALL + BODY (the structure).
        // The old expansion returned BODY[] CONTENT and set \Seen on every
        // FULL FETCH; the structure is a peek-only derived view instead.
        FetchItem::Full => vec![
            FetchItem::Flags,
            FetchItem::InternalDate,
            FetchItem::Envelope,
            FetchItem::BodyStructure { extended: true },
        ],
        other => vec![other.clone()],
    }
}

fn body_item_needs_content(item: &FetchItem) -> bool {
    matches!(
        item,
        FetchItem::Body { .. } | FetchItem::BodyStructure { .. } | FetchItem::Full
    )
}

fn body_item_sets_seen(item: &FetchItem) -> bool {
    // F5: FULL expands to ALL + BODYSTRUCTURE, which never sets \Seen.
    matches!(item, FetchItem::Body { peek: false, .. })
}

/// Split a raw message into header / text sections.
fn header_and_text(raw: &[u8]) -> (&[u8], &[u8]) {
    if let Some(pos) = find_subslice(raw, b"\r\n\r\n") {
        return (&raw[..pos + 4], &raw[pos + 4..]);
    }
    if let Some(pos) = find_subslice(raw, b"\n\n") {
        return (&raw[..pos + 2], &raw[pos + 2..]);
    }
    (raw, &[])
}

/// L2: filter a raw header block down to the named fields (BODY[HEADER.FIELDS
/// (...)]); with `not`, everything EXCEPT the named fields. Folded
/// continuation lines stay attached to their field. The result always ends
/// with the terminating blank line (RFC 3501 §6.4.5).
fn filter_header_fields(header: &[u8], fields: &[String], not: bool) -> Vec<u8> {
    let text = String::from_utf8_lossy(header);
    let mut out = String::new();
    let mut current_matches = false;
    for line in text.lines() {
        let trimmed = line.trim_end_matches('\r');
        if trimmed.is_empty() {
            continue; // the terminating blank line is re-added below
        }
        let is_continuation = trimmed.starts_with(' ') || trimmed.starts_with('\t');
        if !is_continuation {
            let name = trimmed.split(':').next().unwrap_or("").trim();
            current_matches = fields.iter().any(|f| f.eq_ignore_ascii_case(name));
        }
        let include = if not {
            !current_matches
        } else {
            current_matches
        };
        if include {
            out.push_str(trimmed);
            out.push_str("\r\n");
        }
    }
    // The header block always ends with the terminating empty line
    // (RFC 3501 §6.4.5).
    out.push_str("\r\n");
    out.into_bytes()
}

/// Parse the boundary parameter of a multipart Content-Type header value.
fn multipart_boundary(content_type: &str) -> Option<String> {
    let lower = content_type.to_lowercase();
    if !lower.trim_start().starts_with("multipart") {
        return None;
    }
    let idx = lower.find("boundary=")?;
    let after = &content_type[idx + "boundary=".len()..];
    let after = after.trim();
    let boundary = if let Some(stripped) = after.strip_prefix('"') {
        let end = stripped.find('"')?;
        &stripped[..end]
    } else {
        let end = after.find(';').unwrap_or(after.len());
        &after[..end]
    };
    let boundary = boundary.trim();
    if boundary.is_empty() {
        None
    } else {
        Some(boundary.to_string())
    }
}

/// Find a header field's value in a raw header block (first match,
/// case-insensitive name), with lines joined by single spaces.
fn raw_header_value(header: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(header);
    let mut value: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim_end_matches('\r');
        if trimmed.starts_with(' ') || trimmed.starts_with('\t') {
            if let Some(v) = value.as_mut() {
                v.push(' ');
                v.push_str(trimmed.trim());
            }
            continue;
        }
        let mut parts = trimmed.splitn(2, ':');
        let key = parts.next().unwrap_or("").trim();
        if key.eq_ignore_ascii_case(name) {
            value = Some(parts.next().unwrap_or("").trim().to_string());
        }
    }
    value
}

/// One MIME part found between boundary delimiters.
struct MimePart<'a> {
    /// The part's MIME header block, including the terminating blank line.
    header: &'a [u8],
    /// The part's content (after the header blank line, before the CRLF that
    /// belongs to the next boundary delimiter).
    content: &'a [u8],
}

/// Split a header block from its content at the first blank line; the header
/// return value includes the terminating blank line.
fn split_part_header(part: &[u8]) -> (&[u8], &[u8]) {
    if let Some(p) = find_subslice(part, b"\r\n\r\n") {
        (&part[..p + 4], &part[p + 4..])
    } else if let Some(p) = find_subslice(part, b"\n\n") {
        (&part[..p + 2], &part[p + 2..])
    } else {
        (part, &[])
    }
}

/// Split a multipart body into its parts using `boundary` (RFC 2046):
/// the preamble before the first `--boundary` line and the epilogue after
/// `--boundary--` are discarded. The CRLF preceding each delimiter belongs
/// to the delimiter, not to the part content (so BODY[n] round-trips what
/// the sender wrote).
fn split_multipart<'a>(body: &'a [u8], boundary: &str) -> Vec<MimePart<'a>> {
    let delim = format!("--{}", boundary);
    let close = format!("{}--", delim);

    // Collect (line_start, line_end_incl_newline) offsets.
    let mut lines: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < body.len() {
        let nl = body[i..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|p| i + p + 1)
            .unwrap_or(body.len());
        lines.push((i, nl));
        i = nl;
    }

    let mut parts = Vec::new();
    let mut part_start: Option<usize> = None;
    for &(start, end) in &lines {
        let line = String::from_utf8_lossy(&body[start..end]);
        let trimmed = line.trim_end_matches(['\r', '\n']);
        let is_delim = trimmed == delim;
        let is_close = trimmed == close;
        if is_delim || is_close {
            if let Some(ps) = part_start.take() {
                // Strip the CRLF that belongs to this delimiter line.
                let mut content_end = start;
                if content_end > ps && body.get(content_end - 1) == Some(&b'\n') {
                    content_end -= 1;
                    if content_end > ps && body.get(content_end - 1) == Some(&b'\r') {
                        content_end -= 1;
                    }
                }
                let part = &body[ps..content_end.max(ps)];
                let (header, content) = split_part_header(part);
                parts.push(MimePart { header, content });
            }
            if is_delim {
                part_start = Some(end);
            } else {
                break;
            }
        }
    }
    parts
}

/// L2: extract BODY[n] / BODY[n.MIME] content from a raw MIME message.
///
/// `number` is a dot-separated part path ("1", "2.1", ...). A non-existent
/// part yields empty bytes (RFC 3501 §6.4.5: a non-existent section returns
/// an empty string, not an error). For non-multipart content part 1 is the
/// body itself (for message/rfc822 parts that is the encapsulated message,
/// headers included, per RFC 3501 §6.4.5).
fn extract_body_part(raw: &[u8], number: &str, mime: bool) -> Vec<u8> {
    let components: Vec<&str> = number.split('.').collect();
    let mut region: Vec<u8> = raw.to_vec();
    for (i, comp) in components.iter().enumerate() {
        let Ok(idx) = comp.parse::<usize>() else {
            return Vec::new();
        };
        if idx == 0 {
            return Vec::new();
        }
        let (header, body) = split_part_header(&region);
        let is_last = i + 1 == components.len();
        let content_type = raw_header_value(header, "Content-Type").unwrap_or_default();
        if let Some(boundary) = multipart_boundary(&content_type) {
            let parts = split_multipart(body, &boundary);
            let Some(part) = parts.get(idx - 1) else {
                return Vec::new();
            };
            if is_last {
                return if mime {
                    part.header.to_vec()
                } else {
                    part.content.to_vec()
                };
            }
            // Descend with the ENTIRE part (its MIME header block + its
            // content): the next component indexes the sub-multipart whose
            // Content-Type lives in THIS part's headers.
            region = [part.header, part.content].concat();
        } else {
            // Not multipart at this level: part 1 is the body; a higher
            // part number does not exist.
            if idx != 1 {
                return Vec::new();
            }
            if is_last {
                return if mime { header.to_vec() } else { body.to_vec() };
            }
            region = body.to_vec();
        }
    }
    Vec::new()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ── F5: BODY/BODYSTRUCTURE rendering ────────────────────────────────────────
//
// The MIME structure is derived on demand from the raw message (there is no
// persisted structure metadata), reusing the same header/multipart helpers
// the BODY[n] section extraction uses.

/// Split one `key=value` parameter token (`charset="utf-8"` → `("charset",
/// "utf-8")`); surrounding double quotes on the value are stripped. RFC 2231
/// extended/continued parameters are not reassembled (documented
/// approximation).
fn parse_header_param(segment: &str) -> (String, String) {
    let (key, value) = segment.split_once('=').unwrap_or((segment, ""));
    (
        key.trim().to_string(),
        value.trim().trim_matches('"').to_string(),
    )
}

/// Split a Content-Type-style value into (type, subtype, parameters):
/// `text/plain; charset="utf-8"` → ("text", "plain", [("charset", "utf-8")]).
/// A `;` inside a quoted parameter value would split early — accepted
/// approximation for structure rendering.
fn parse_type_params(value: &str) -> (String, String, Vec<(String, String)>) {
    let mut segments = value.split(';');
    let media = segments.next().unwrap_or("").trim().to_string();
    let (media_type, subtype) = match media.split_once('/') {
        Some((t, s)) => (t.trim().to_string(), s.trim().to_string()),
        None => (media, String::new()),
    };
    let params = segments.map(parse_header_param).collect();
    (media_type, subtype, params)
}

/// Render a parameter list as the body-fielddata parenthesized list of
/// strings (`("CHARSET" "utf-8")`), or NIL when empty.
fn format_body_params(params: &[(String, String)]) -> String {
    if params.is_empty() {
        return "NIL".to_string();
    }
    let inner: Vec<String> = params
        .iter()
        .map(|(k, v)| {
            format!(
                "{} {}",
                encode_nstring(&k.to_uppercase()),
                encode_nstring(v)
            )
        })
        .collect();
    format!("({})", inner.join(" "))
}

/// Render an optional header value as an nstring (NIL when absent).
fn opt_body_nstring(value: Option<&str>) -> String {
    match value {
        None => "NIL".to_string(),
        Some(s) => encode_nstring(s),
    }
}

/// The body-fld-dsp field shared by the 1part and mpart extension data:
/// `("TYPE" (params))` from Content-Disposition, or NIL when absent.
fn format_disposition_field(header: &[u8]) -> String {
    match raw_header_value(header, "Content-Disposition") {
        None => "NIL".to_string(),
        Some(value) => {
            let (dtype, _, params) = parse_type_params(&value);
            let dtype = if dtype.is_empty() {
                "INLINE".to_string()
            } else {
                dtype.to_uppercase()
            };
            format!(
                "({} {})",
                encode_nstring(&dtype),
                format_body_params(&params)
            )
        }
    }
}

/// Extension data for a non-multipart part (BODYSTRUCTURE only):
/// body-fld-md5, body-fld-dsp, body-fld-lang, body-fld-loc per RFC 3501
/// §7.4.2. MD5/language/location are not tracked and render NIL; the
/// disposition comes from Content-Disposition.
fn format_extension_fields(header: &[u8]) -> String {
    format!("NIL {} NIL NIL", format_disposition_field(header))
}

/// Extension data for a multipart part (BODYSTRUCTURE only):
/// body-fld-param, body-fld-dsp, body-fld-lang, body-fld-loc — note the
/// multipart's extension starts with ITS OWN Content-Type parameters
/// (boundary included), not an MD5 field.
fn format_multipart_extension(params: &[(String, String)], header: &[u8]) -> String {
    format!(
        "{} {} NIL NIL",
        format_body_params(params),
        format_disposition_field(header)
    )
}

/// Build a minimal ENVELOPE for an embedded message (the BODYSTRUCTURE of a
/// message/rfc822 part carries the encapsulated message's envelope). Header
/// values are taken verbatim; address lists are split on commas — a
/// documented approximation of real address parsing for structure rendering.
fn embedded_envelope(content: &[u8]) -> mail_proto::EmailEnvelope {
    let (header, _) = split_part_header(content);
    let get = |name: &str| raw_header_value(header, name);
    let addr_list = |name: &str| -> Vec<String> {
        match get(name) {
            Some(v) if !v.trim().is_empty() => v
                .split(',')
                .map(|a| a.trim().to_string())
                .filter(|a| !a.is_empty())
                .collect(),
            _ => Vec::new(),
        }
    };
    mail_proto::EmailEnvelope {
        from: get("From").unwrap_or_default(),
        to: addr_list("To"),
        cc: addr_list("Cc"),
        bcc: addr_list("Bcc"),
        reply_to: addr_list("Reply-To").first().cloned().unwrap_or_default(),
        subject: get("Subject").unwrap_or_default(),
        message_id: get("Message-ID").unwrap_or_default(),
        in_reply_to: get("In-Reply-To").unwrap_or_default(),
        references: vec![],
        date: get("Date")
            .and_then(|d| chrono::DateTime::parse_from_rfc2822(&d).ok())
            .map(|dt| dt.timestamp())
            .unwrap_or(0),
    }
}

/// Render the BODY/BODYSTRUCTURE of one MIME region (its header block plus
/// content) per RFC 3501 §7.4.2. `region` for a part is header+content
/// concatenated; for the top-level message it is the whole raw message.
fn format_structure_region(region: &[u8], extended: bool) -> String {
    let (header, content) = split_part_header(region);
    let content_type = raw_header_value(header, "Content-Type");
    let (media_type, subtype, params) = match &content_type {
        Some(ct) => {
            let (t, s, p) = parse_type_params(ct);
            (t.to_uppercase(), s.to_uppercase(), p)
        }
        None => ("TEXT".to_string(), "PLAIN".to_string(), Vec::new()),
    };

    if media_type == "MULTIPART" {
        let boundary =
            multipart_boundary(content_type.as_deref().unwrap_or("")).unwrap_or_default();
        let parts = split_multipart(content, &boundary);
        let substructures: Vec<String> = parts
            .iter()
            .map(|p| format_structure_region(&[p.header, p.content].concat(), extended))
            .collect();
        let mut out = format!("(\"{}\" {}", subtype, substructures.join(" "));
        if extended {
            out.push(' ');
            out.push_str(&format_multipart_extension(&params, header));
        }
        out.push(')');
        return out;
    }

    let encoding = raw_header_value(header, "Content-Transfer-Encoding")
        .map(|e| e.to_uppercase())
        .unwrap_or_else(|| "7BIT".to_string());
    let size = content.len();
    let lines = content.iter().filter(|&&b| b == b'\n').count();

    let mut fields = vec![
        encode_nstring(&media_type),
        encode_nstring(&subtype),
        format_body_params(&params),
        opt_body_nstring(raw_header_value(header, "Content-ID").as_deref()),
        opt_body_nstring(raw_header_value(header, "Content-Description").as_deref()),
        encode_nstring(&encoding),
        size.to_string(),
    ];
    if media_type == "MESSAGE" && subtype == "RFC822" {
        fields.push(format_envelope(&embedded_envelope(content)));
        fields.push(format_structure_region(content, extended));
        fields.push(lines.to_string());
    } else if media_type == "TEXT" {
        fields.push(lines.to_string());
    }
    if extended {
        fields.push(format_extension_fields(header));
    }
    format!("({})", fields.join(" "))
}

/// F5: render the top-level BODY (`extended == false`) or BODYSTRUCTURE
/// (`extended == true`) response data for a raw message.
fn format_body_structure(raw: &[u8], extended: bool) -> String {
    format_structure_region(raw, extended)
}

struct GetMessageBody {
    body: Vec<u8>,
}

async fn handle_fetch<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    is_uid: bool,
    writer: &mut W,
) -> Result<()> {
    if !mailbox_selected(session) {
        return write_line(writer, &tagged_bad(tag, "No mailbox selected")).await;
    }

    let (seq_part, items_str) = match parse_fetch_args(args) {
        Ok(v) => v,
        Err(e) => return write_line(writer, &tagged_bad(tag, &format!("{}", e))).await,
    };
    // L2/L13: unsupported or malformed fetch items must surface as a tagged
    // BAD (RFC 3501) — never a silent substitution or drop.
    let items = match parse_fetch_items(&items_str) {
        Ok(items) => items,
        Err(e) => return write_line(writer, &tagged_bad(tag, &format!("{}", e))).await,
    };
    let intervals = match parse_sequence_set(&seq_part) {
        Ok(v) => v,
        Err(e) => return write_line(writer, &tagged_bad(tag, &format!("{}", e))).await,
    };
    // Fetch the full mailbox listing so sequence numbers are correct and
    // wildcards resolve against actual contents.
    let mut client = session.client.clone();
    let list_req = ListMessagesRequest {
        account_id: session.account_id.clone(),
        mailbox: session.mailbox.clone(),
        uid_min: 1,
        uid_max: u64::MAX,
        limit: 100_000,
    };
    let list_resp = client
        .list_messages(list_req)
        .await
        .with_context(|| "gRPC list_messages failed")?;
    let mut all_msgs = list_resp.into_inner().messages;
    all_msgs.sort_by_key(|m| m.uid);
    let uid_map: Vec<u64> = all_msgs.iter().map(|m| m.uid).collect();
    let max_uid = uid_map.last().copied().unwrap_or(0);

    let uids = resolve_intervals(&intervals, is_uid, &uid_map, max_uid)?;
    if uids.is_empty() {
        return write_line(writer, &tagged_ok(tag, "FETCH completed")).await;
    }

    let meta_map: HashMap<u64, mail_proto::MessageMeta> =
        all_msgs.into_iter().map(|m| (m.uid, m)).collect();

    let need_body = items.iter().any(body_item_needs_content);
    let sets_seen = !session.read_only && items.iter().any(body_item_sets_seen);

    // Stream bodies in bounded chunks instead of buffering every matching
    // body up front: the previous collect()-into-HashMap held ALL bodies in
    // memory at once, so `FETCH 1:* BODY[]` on a large mailbox was an OOM
    // vector. With chunks of FETCH_CONCURRENCY, at most 8 bodies (and their
    // responses) are resident at any time; each response is written to the
    // socket as its chunk completes, so no additional per-command cap on
    // body FETCHes is needed.
    //
    // Deliberate (documented) bound: the mailbox view itself is capped at
    // MAX_RESOLVED_UIDS (100k) messages per sequence set by the resolver,
    // and each chunk's bodies stream; there is no CHANGEDSINCE-style paging.
    // A full FETCH range therefore costs one bounded metadata pass plus the
    // streamed body fetches — accepted for an IMAP4rev1 server of this
    // scale rather than implementing QRESYNC-style paging.
    const FETCH_CONCURRENCY: usize = 8;
    for chunk in uids.chunks(FETCH_CONCURRENCY) {
        let mut body_futures = Vec::new();
        if need_body {
            for &uid in chunk {
                if !meta_map.contains_key(&uid) {
                    continue;
                }
                let req = GetMessageRequest {
                    account_id: session.account_id.clone(),
                    mailbox: session.mailbox.clone(),
                    uid,
                    include_body: true,
                };
                let mut c = session.client.clone();
                body_futures.push(async move {
                    let resp = c.get_message(req).await;
                    (uid, resp)
                });
            }
        }
        // Fetch this chunk's bodies with bounded concurrency. Results are
        // keyed by UID; responses are emitted in sequence-number order, so
        // completing out of order does not affect the FETCH response.
        // L12: the tonic Status is preserved so a failed per-message body
        // fetch can fail the whole command (NO) instead of silently
        // stripping the BODY attributes from an OK response.
        let body_results: HashMap<u64, Result<GetMessageBody, tonic::Status>> =
            futures::stream::iter(body_futures)
                .buffer_unordered(FETCH_CONCURRENCY)
                .map(|(uid, r)| {
                    let parsed = r.map(|resp| {
                        let resp = resp.into_inner();
                        GetMessageBody { body: resp.body }
                    });
                    (uid, parsed)
                })
                .collect()
                .await;

        // Emit responses in sequence-number order for this chunk.
        for &uid in chunk {
            // L12: surface body-fetch failures. ResourceExhausted (the
            // mailstore's per-account limiter) answers NO Server busy so the
            // client retries later; other errors answer NO with the reason.
            // Returning partial OK-with-missing-bodies desynced clients that
            // rely on the requested attributes being present.
            if need_body && matches!(body_results.get(&uid), Some(Err(_))) {
                let status = body_results.get(&uid).and_then(|r| r.as_ref().err());
                if let Some(status) = status {
                    return write_line(writer, &fetch_body_failure_line(tag, status)).await;
                }
            }
            let meta = match meta_map.get(&uid) {
                Some(m) => m,
                None => continue,
            };
            let seq = match uid_map.iter().position(|&u| u == uid) {
                Some(i) => i as u32 + 1,
                None => continue,
            };
            // F6: \Recent is a per-session property of the message.
            let is_recent = session.recent_uids.contains(&uid);
            emit_fetch_response(
                writer,
                uid,
                seq,
                meta,
                &items,
                body_results.get(&uid),
                is_uid,
                sets_seen,
                is_recent,
            )
            .await?;
        }

        // Fire \Seen flag updates for non-peek BODY fetches on unread
        // messages in this chunk.
        let mut seen_futures = Vec::new();
        for &uid in chunk {
            let meta = match meta_map.get(&uid) {
                Some(m) => m,
                None => continue,
            };
            let was_seen = meta.flags.clone().unwrap_or_default().seen;
            if sets_seen && !was_seen {
                let req = SetFlagsRequest {
                    account_id: session.account_id.clone(),
                    mailbox: session.mailbox.clone(),
                    uids: vec![uid],
                    flags: Some(MessageFlags {
                        seen: true,
                        ..Default::default()
                    }),
                    operation: FlagOperation::Add as i32,
                };
                let mut c = session.client.clone();
                seen_futures.push(async move {
                    let _ = c.set_flags(req).await;
                });
            }
        }
        futures::stream::iter(seen_futures)
            .for_each_concurrent(FETCH_CONCURRENCY, |fut| fut)
            .await;
    }

    writer.flush().await?;
    write_line(writer, &tagged_ok(tag, "FETCH completed")).await
}

/// Emit one `* <seq> FETCH (...)` response, including any literal body
/// payloads, for a single message. Split out of `handle_fetch` so the
/// chunked streaming path can write each response as soon as its chunk's
/// bodies have arrived.
#[allow(clippy::too_many_arguments)]
async fn emit_fetch_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    uid: u64,
    seq: u32,
    meta: &mail_proto::MessageMeta,
    items: &[FetchItem],
    body: Option<&Result<GetMessageBody, tonic::Status>>,
    is_uid: bool,
    sets_seen: bool,
    recent: bool,
) -> Result<()> {
    let mut flags = meta.flags.clone().unwrap_or_default();
    if sets_seen && !flags.seen {
        flags.seen = true;
    }
    // F6: \Recent is session-scoped; it is reported, never stored.
    flags.recent = recent;

    let mut attrs: Vec<String> = Vec::new();
    let mut body_payloads: Vec<(String, Vec<u8>)> = Vec::new();

    for item in items {
        for ritem in resolve_macro_item(item) {
            match ritem {
                // L11: in UID mode the UID attribute is prepended exactly
                // once below; an explicit UID item must not add a second.
                FetchItem::Uid if !is_uid => {
                    attrs.push(format!("UID {}", uid));
                }
                FetchItem::Uid => {}
                FetchItem::Flags => {
                    attrs.push(format!("FLAGS {}", format_imap_flags(&flags)));
                }
                FetchItem::InternalDate => {
                    attrs.push(format!(
                        "INTERNALDATE {}",
                        format_internal_date(meta.internal_date)
                    ));
                }
                FetchItem::Rfc822Size => {
                    attrs.push(format!("RFC822.SIZE {}", meta.size));
                }
                FetchItem::Envelope => {
                    let env = meta.envelope.clone().unwrap_or_default();
                    attrs.push(format!("ENVELOPE {}", format_envelope(&env)));
                }
                // F5: BODY (bare) / BODYSTRUCTURE — the derived structure.
                FetchItem::BodyStructure { extended } => {
                    let raw = match body {
                        Some(Ok(b)) => &b.body,
                        Some(Err(e)) => {
                            warn!("Failed to get message body for UID {}: {}", uid, e);
                            continue;
                        }
                        None => continue,
                    };
                    attrs.push(format!(
                        "{} {}",
                        if extended { "BODYSTRUCTURE" } else { "BODY" },
                        format_body_structure(raw, extended)
                    ));
                }
                FetchItem::Body {
                    section,
                    peek: _,
                    name,
                    partial,
                } => {
                    let raw = match body {
                        Some(Ok(b)) => &b.body,
                        Some(Err(e)) => {
                            warn!("Failed to get message body for UID {}: {}", uid, e);
                            continue;
                        }
                        None => continue,
                    };
                    let (header, text) = header_and_text(raw);
                    // L2: resolve the requested section to its bytes,
                    // including HEADER.FIELDS filtering and MIME part
                    // extraction.
                    let section_bytes: Vec<u8> = match &section {
                        BodySection::Full => raw.to_vec(),
                        BodySection::Header => header.to_vec(),
                        BodySection::Text => text.to_vec(),
                        BodySection::HeaderFields { fields, not } => {
                            filter_header_fields(header, fields, *not)
                        }
                        BodySection::Part { number, mime } => extract_body_part(raw, number, *mime),
                    };
                    let mut payload = section_bytes;
                    // RFC 3501 §7.4.2: a partial fetch response names the
                    // section with its origin, e.g. BODY[HEADER]<0>.
                    let resp_name = match partial {
                        Some((offset, _)) => format!("{}<{}>", name, offset),
                        None => name.clone(),
                    };
                    if let Some((offset, octets)) = partial {
                        // octets > 0 is guaranteed by split_partial_spec.
                        let end = offset.saturating_add(octets).min(payload.len());
                        if offset < payload.len() {
                            payload = payload[offset..end].to_vec();
                        } else {
                            payload.clear();
                        }
                    }
                    body_payloads.push((resp_name, payload));
                }
                FetchItem::Fast | FetchItem::All | FetchItem::Full => {}
            }
        }
    }

    if is_uid {
        attrs.insert(0, format!("UID {}", uid));
    }

    // Write `* seq FETCH (attr1 attr2 BODY[] {n}` then the literal bytes
    // then `) CRLF`.
    let mut out = format!("* {} FETCH (", seq);
    let mut first = true;
    for a in &attrs {
        if !first {
            out.push(' ');
        }
        out.push_str(a);
        first = false;
    }
    for (name, payload) in &body_payloads {
        if !first {
            out.push(' ');
        }
        out.push_str(&format!("{} {{{}}}", name, payload.len()));
        first = false;
    }
    writer.write_all(out.as_bytes()).await?;
    if !body_payloads.is_empty() {
        // RFC 3501 §7.4.2: after the last literal the closing paren
        // follows immediately (no trailing space).
        writer.write_all(b"\r\n").await?;
        for (i, (_, payload)) in body_payloads.iter().enumerate() {
            if i > 0 {
                writer.write_all(b" ").await?;
            }
            writer.write_all(payload).await?;
        }
    }
    writer.write_all(b")\r\n").await?;
    Ok(())
}

fn parse_fetch_args(args: &str) -> Result<(String, String)> {
    // The sequence set never contains whitespace, so tokenizing yields the
    // sequence set as the first token and the (possibly parenthesized) item
    // list as the remainder.
    let tokens = tokenize_command_args(args.trim());
    if tokens.is_empty() {
        bail!("FETCH requires a sequence set");
    }
    let seq_part = resolve_token(&tokens[0], &[]);
    let items_str = tokens[1..].join(" ");
    Ok((seq_part, items_str))
}

/// Split a `<offset.octets>` partial-fetch suffix off a fetch item name.
/// L13: the spec must be well formed and `octets` must be > 0 — RFC 3501
/// §6.4.5 has no zero-length partial; the old code silently treated a
/// malformed/zero-octets spec as "return the whole tail".
fn split_partial_spec(item: &str) -> Result<(String, Option<(usize, usize)>)> {
    let Some(pos) = item.find('<') else {
        return Ok((item.trim().to_string(), None));
    };
    let name = item[..pos].trim().to_string();
    let spec = item[pos + 1..].trim().trim_end_matches('>');
    let parts: Vec<&str> = spec.splitn(2, '.').collect();
    if parts.len() != 2 {
        bail!("Invalid partial spec <{}>: expected <offset.octets>", spec);
    }
    let offset: usize = parts[0]
        .trim()
        .parse()
        .with_context(|| format!("Invalid partial offset in <{}>", spec))?;
    let octets: usize = parts[1]
        .trim()
        .parse()
        .with_context(|| format!("Invalid partial octet count in <{}>", spec))?;
    if octets == 0 {
        bail!(
            "Invalid partial spec <{}>: octet count must be greater than zero",
            spec
        );
    }
    Ok((name, Some((offset, octets))))
}

fn parse_fetch_items(items_str: &str) -> Result<Vec<FetchItem>> {
    let s = items_str.trim();
    let inner = if s.starts_with('(') && s.ends_with(')') {
        &s[1..s.len() - 1]
    } else {
        s
    };

    let mut items = Vec::new();
    let tokens = tokenize_fetch_items(inner);

    for token in tokens {
        let upper = token.to_uppercase();
        let (name, partial) = split_partial_spec(&upper)?;
        match name.as_str() {
            "FLAGS" => items.push(FetchItem::Flags),
            "INTERNALDATE" => items.push(FetchItem::InternalDate),
            "RFC822.SIZE" => items.push(FetchItem::Rfc822Size),
            "ENVELOPE" => items.push(FetchItem::Envelope),
            "UID" => items.push(FetchItem::Uid),
            "FAST" => items.push(FetchItem::Fast),
            "FULL" => items.push(FetchItem::Full),
            "ALL" => items.push(FetchItem::All),
            // F5: BODY/BODYSTRUCTURE are now implemented (derived from the
            // raw message on demand) — the old L2 rejection is superseded;
            // the FULL macro needs them (ALL + BODYSTRUCTURE, peek).
            "BODYSTRUCTURE" => items.push(FetchItem::BodyStructure { extended: true }),
            "BODY" => items.push(FetchItem::BodyStructure { extended: false }),
            "RFC822" => items.push(FetchItem::Body {
                section: BodySection::Full,
                peek: false,
                name: "RFC822".to_string(),
                partial,
            }),
            "RFC822.HEADER" => items.push(FetchItem::Body {
                section: BodySection::Header,
                peek: false,
                name: "RFC822.HEADER".to_string(),
                partial,
            }),
            "RFC822.TEXT" => items.push(FetchItem::Body {
                section: BodySection::Text,
                peek: false,
                name: "RFC822.TEXT".to_string(),
                partial,
            }),
            _ => {
                // `name` already has any `<partial>` suffix stripped (and is
                // uppercased), so the `[section]` suffix can be split safely.
                if let Some(section_spec) = name
                    .strip_prefix("BODY.PEEK[")
                    .and_then(|rest| rest.strip_suffix(']'))
                {
                    let section = parse_body_section(section_spec)?;
                    items.push(FetchItem::Body {
                        name: BodySection::response_name(&section),
                        section,
                        peek: true,
                        partial,
                    });
                } else if let Some(section_spec) = name
                    .strip_prefix("BODY[")
                    .and_then(|rest| rest.strip_suffix(']'))
                {
                    let section = parse_body_section(section_spec)?;
                    items.push(FetchItem::Body {
                        name: BodySection::response_name(&section),
                        section,
                        peek: false,
                        partial,
                    });
                } else {
                    bail!("Unknown FETCH item: {}", token);
                }
            }
        }
    }
    // L2: an empty item list is a client syntax error (RFC 3501 requires at
    // least one item) — BAD, not a silent ALL substitution.
    if items.is_empty() {
        bail!("FETCH requires at least one item");
    }
    Ok(items)
}

fn tokenize_fetch_items(s: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;
    for c in s.chars() {
        match c {
            '[' => {
                depth += 1;
                current.push(c);
            }
            ']' => {
                depth = depth.saturating_sub(1);
                current.push(c);
            }
            // Parenthesized lists inside a BODY[...] section (e.g.
            // HEADER.FIELDS (DATE FROM)) stay inside the token; parens
            // outside brackets delimit the item list itself.
            '(' if depth == 0 => {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    tokens.push(trimmed);
                }
                current.clear();
            }
            ')' if depth == 0 => {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    tokens.push(trimmed);
                }
                current.clear();
            }
            ' ' if depth == 0 => {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    tokens.push(trimmed);
                }
                current.clear();
            }
            _ => current.push(c),
        }
    }
    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        tokens.push(trimmed);
    }
    tokens
}
// ── STORE ───────────────────────────────────────────────────────────────────

/// The five storable IMAP system flags (RFC 3501 §2.3.2). `\Recent is
/// deliberately absent: it is session-scoped and not client-settable.
const STORE_SYSTEM_FLAGS: [&str; 5] = ["\\Seen", "\\Answered", "\\Flagged", "\\Deleted", "\\Draft"];

fn is_store_system_flag(token: &str) -> bool {
    STORE_SYSTEM_FLAGS
        .iter()
        .any(|f| token.eq_ignore_ascii_case(f))
}

/// F4: map a STORE/APPEND flag token list to proto flags.
///
/// System flags match CASE-INSENSITIVELY (RFC 3501 flags are
/// case-insensitive; APPEND already did this inline — `STORE +FLAGS
/// (\seen)` silently no-opped before). Unknown backslash tokens are NOT
/// dropped silently: they round-trip as custom keywords via the labels
/// column, mirroring APPEND's custom-keyword handling. `\Recent` is ignored
/// entirely (not client-settable, not storable as a keyword).
fn store_flags_from_tokens(tokens: &[String]) -> MessageFlags {
    let has = |name: &str| tokens.iter().any(|t| t.eq_ignore_ascii_case(name));
    MessageFlags {
        seen: has("\\Seen"),
        answered: has("\\Answered"),
        flagged: has("\\Flagged"),
        deleted: has("\\Deleted"),
        draft: has("\\Draft"),
        recent: false,
        custom: tokens
            .iter()
            .filter(|t| {
                !is_store_system_flag(t) && !t.eq_ignore_ascii_case("\\Recent") && !t.is_empty()
            })
            .cloned()
            .collect(),
    }
}

#[derive(Debug)]
enum StoreOp {
    Set(Vec<String>, bool),
    Add(Vec<String>, bool),
    Remove(Vec<String>, bool),
}

async fn handle_store<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    is_uid: bool,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if !mailbox_selected(session) {
        return write_line(writer, &tagged_bad(tag, "No mailbox selected")).await;
    }
    if session.read_only {
        return write_line(writer, &tagged_no(tag, "[READ-ONLY] STORE not permitted")).await;
    }

    let (seq_part, store_op) = match parse_store_args(args, literals) {
        Ok(v) => v,
        Err(e) => {
            return write_line(writer, &tagged_bad(tag, &format!("{}", e))).await;
        }
    };
    // F7: refresh the view and capture the diff — it is emitted BEFORE the
    // command's own untagged responses so the client's sequence numbers are
    // corrected first (see refresh_session_view).
    let view_diff = refresh_session_view(session).await;
    let uids = resolve_sequence_set(session, &seq_part, is_uid)?;
    if uids.is_empty() {
        // F7: the view may still have shifted; emit the diff with the OK.
        return write_line(
            writer,
            &format!("{}{}", view_diff, tagged_ok(tag, "STORE completed")),
        )
        .await;
    }

    let (operation, flags, silent) = match store_op {
        StoreOp::Set(f, silent) => (FlagOperation::Set, f, silent),
        StoreOp::Add(f, silent) => (FlagOperation::Add, f, silent),
        StoreOp::Remove(f, silent) => (FlagOperation::Remove, f, silent),
    };

    let mut client = session.client.clone();
    let req = SetFlagsRequest {
        account_id: session.account_id.clone(),
        mailbox: session.mailbox.clone(),
        uids: uids.clone(),
        // F4: case-insensitive system-flag matching; unknown backslash tokens
        // survive as custom keywords instead of being dropped silently.
        flags: Some(store_flags_from_tokens(&flags)),
        operation: operation as i32,
    };

    let resp = match client.set_flags(req).await {
        Ok(r) => r.into_inner(),
        Err(e) => {
            return write_line(writer, &tagged_no(tag, &format!("STORE failed: {}", e))).await;
        }
    };

    // Echo the resulting flags per message (accurate post-operation state).
    // F7: the view diff precedes the FETCH responses; F6: \Recent is
    // session-scoped and reported on the echoed flags.
    let mut responses = view_diff;
    if !silent {
        let flags_req = mail_proto::GetFlagsRequest {
            account_id: session.account_id.clone(),
            mailbox: session.mailbox.clone(),
            uids: uids.clone(),
        };
        if let Ok(flags_resp) = client.get_flags(flags_req).await {
            let flag_map = flags_resp.into_inner().flags;
            for &uid in &uids {
                if let Some(seq) = session.seq_for_uid(uid) {
                    let mut f = flag_map.get(&uid).cloned().unwrap_or_default();
                    f.recent = session.recent_uids.contains(&uid);
                    responses.push_str(&format!(
                        "* {} FETCH (FLAGS {})\r\n",
                        seq,
                        format_imap_flags(&f)
                    ));
                }
            }
        }
    }
    responses.push_str(&tagged_ok(
        tag,
        &format!("STORE completed, {} updated", resp.updated_count),
    ));
    write_line(writer, &responses).await
}

fn parse_store_args(args: &str, literals: &[Vec<u8>]) -> Result<(String, StoreOp)> {
    let args = args.trim();
    let tokens: Vec<&str> = args.splitn(3, ' ').collect();
    if tokens.len() < 3 {
        bail!("STORE requires sequence set, operation, and flags");
    }
    let seq_part = resolve_token(tokens[0], literals);
    let op_prefix = tokens[1];
    let flags_str = tokens[2];

    let flags: Vec<String> = flags_str
        .trim_matches(|c| c == '(' || c == ')')
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    let silent = op_prefix.to_uppercase().ends_with(".SILENT");
    let op_base = op_prefix
        .rfind(".SILENT")
        .map(|p| &op_prefix[..p])
        .unwrap_or(op_prefix);

    let op = if op_base.starts_with('+') {
        StoreOp::Add(flags, silent)
    } else if op_base.starts_with('-') {
        StoreOp::Remove(flags, silent)
    } else {
        StoreOp::Set(flags, silent)
    };

    Ok((seq_part, op))
}

// ── SEARCH ──────────────────────────────────────────────────────────────────

/// Maximum SEARCH criteria tokens per command. Without a cap, every token
/// triggers a full retain() pass over the mailbox — 100k tokens x 100k
/// messages is 10^10 predicate evaluations.
const MAX_SEARCH_TOKENS: usize = 64;

/// Tokenize SEARCH arguments (resolving literal/quoted tokens) with a hard
/// cap on the criteria count; hostile SEARCHes are rejected before any
/// per-message evaluation begins.
fn collect_search_tokens(args: &str, literals: &[Vec<u8>]) -> Result<Vec<String>> {
    let tokens: Vec<String> = tokenize_command_args(args.trim())
        .iter()
        .map(|t| resolve_token(t, literals))
        .collect();
    if tokens.len() > MAX_SEARCH_TOKENS {
        bail!("Too many SEARCH criteria (max {})", MAX_SEARCH_TOKENS);
    }
    Ok(tokens)
}

async fn handle_search<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    is_uid: bool,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if !mailbox_selected(session) {
        return write_line(writer, &tagged_bad(tag, "No mailbox selected")).await;
    }

    refresh_session_view(session).await;

    let mut client = session.client.clone();
    let list_req = ListMessagesRequest {
        account_id: session.account_id.clone(),
        mailbox: session.mailbox.clone(),
        uid_min: 1,
        uid_max: u64::MAX,
        limit: 100_000,
    };
    let all = match client.list_messages(list_req).await {
        Ok(r) => r.into_inner().messages,
        Err(e) => {
            return write_line(writer, &tagged_no(tag, &format!("SEARCH failed: {}", e))).await;
        }
    };
    let mut all = all;
    all.sort_by_key(|m| m.uid);
    let uid_to_seq: HashMap<u64, u32> = all
        .iter()
        .enumerate()
        .map(|(i, m)| (m.uid, i as u32 + 1))
        .collect();

    let mut keep: Vec<&mail_proto::MessageMeta> = all.iter().collect();
    let mut fulltext_terms: Vec<String> = Vec::new();
    // L8: (field, value) pairs collected from HEADER criteria; each runs as
    // its own headers-JSONB search and ANDs into the result set.
    let mut header_criteria: Vec<(String, String)> = Vec::new();

    let tokens = match collect_search_tokens(args, literals) {
        Ok(t) => t,
        Err(e) => {
            return write_line(writer, &tagged_bad(tag, &format!("{}", e))).await;
        }
    };
    let mut i = 0;
    while i < tokens.len() {
        let tok = tokens[i].to_uppercase();
        let flags_of = |m: &mail_proto::MessageMeta| m.flags.clone().unwrap_or_default();
        match tok.as_str() {
            "ALL" => {}
            "UNSEEN" => keep.retain(|m| !flags_of(m).seen),
            "SEEN" => keep.retain(|m| flags_of(m).seen),
            "DELETED" => keep.retain(|m| flags_of(m).deleted),
            "UNDELETED" => keep.retain(|m| !flags_of(m).deleted),
            "FLAGGED" => keep.retain(|m| flags_of(m).flagged),
            "UNFLAGGED" => keep.retain(|m| !flags_of(m).flagged),
            "ANSWERED" => keep.retain(|m| flags_of(m).answered),
            "UNANSWERED" => keep.retain(|m| !flags_of(m).answered),
            "DRAFT" => keep.retain(|m| flags_of(m).draft),
            "UNDRAFT" => keep.retain(|m| !flags_of(m).draft),
            // F6: session-scoped \Recent (see ImapSession::recent_uids).
            // RECENT  = in this session's recent set;
            // NEW     = RECENT and still UNSEEN (RFC 3501 §6.4.4);
            // OLD     = not RECENT.
            // "UNRECENT" stays a BAD — it is not an IMAP criterion.
            "RECENT" => keep.retain(|m| session.recent_uids.contains(&m.uid)),
            "NEW" => keep.retain(|m| session.recent_uids.contains(&m.uid) && !flags_of(m).seen),
            "OLD" => keep.retain(|m| !session.recent_uids.contains(&m.uid)),
            "UNRECENT" => {
                return write_line(
                    writer,
                    &tagged_bad(tag, "UNRECENT is not a valid SEARCH criterion"),
                )
                .await;
            }
            "SUBJECT" | "FROM" | "TO" | "CC" | "BCC" => {
                i += 1;
                if i < tokens.len() {
                    let term = tokens[i].to_lowercase();
                    match tok.as_str() {
                        "SUBJECT" => keep.retain(|m| {
                            m.envelope
                                .as_ref()
                                .map(|e| e.subject.to_lowercase().contains(&term))
                                .unwrap_or(false)
                        }),
                        "FROM" => keep.retain(|m| {
                            m.envelope
                                .as_ref()
                                .map(|e| e.from.to_lowercase().contains(&term))
                                .unwrap_or(false)
                        }),
                        "TO" => keep.retain(|m| {
                            m.envelope
                                .as_ref()
                                .map(|e| e.to.iter().any(|a| a.to_lowercase().contains(&term)))
                                .unwrap_or(false)
                        }),
                        "CC" => keep.retain(|m| {
                            m.envelope
                                .as_ref()
                                .map(|e| e.cc.iter().any(|a| a.to_lowercase().contains(&term)))
                                .unwrap_or(false)
                        }),
                        "BCC" => keep.retain(|m| {
                            m.envelope
                                .as_ref()
                                .map(|e| e.bcc.iter().any(|a| a.to_lowercase().contains(&term)))
                                .unwrap_or(false)
                        }),
                        _ => {}
                    }
                }
            }
            "SINCE" | "BEFORE" | "ON" => {
                i += 1;
                if i < tokens.len() {
                    let date = match parse_imap_date(&tokens[i]) {
                        Some(d) => d,
                        None => {
                            return write_line(
                                writer,
                                &tagged_bad(tag, &format!("Invalid date: {}", tokens[i])),
                            )
                            .await;
                        }
                    };
                    let day_start = date.and_hms_opt(0, 0, 0).map(|d| d.and_utc().timestamp());
                    let day_end = date
                        .and_hms_opt(23, 59, 59)
                        .map(|d| d.and_utc().timestamp());
                    match tok.as_str() {
                        "SINCE" => {
                            keep.retain(|m| day_start.map(|t| m.internal_date >= t).unwrap_or(true))
                        }
                        "BEFORE" => {
                            keep.retain(|m| day_start.map(|t| m.internal_date < t).unwrap_or(true))
                        }
                        "ON" => keep.retain(|m| {
                            day_start
                                .zip(day_end)
                                .map(|(s, e)| m.internal_date >= s && m.internal_date <= e)
                                .unwrap_or(true)
                        }),
                        _ => {}
                    }
                }
            }
            "BODY" | "TEXT" => {
                i += 1;
                if i < tokens.len() {
                    fulltext_terms.push(tokens[i].clone());
                }
            }
            // L8: HEADER <field> <value> filters on the named header field
            // via the mailstore's headers-JSONB containment search — the old
            // code ignored the field name and searched the subject/body
            // fulltext index on the value alone, so `HEADER Message-ID x`
            // could be satisfied by a subject containing x.
            "HEADER" => {
                i += 1;
                let field = tokens.get(i).cloned().unwrap_or_default();
                i += 1;
                let value = tokens.get(i).cloned().unwrap_or_default();
                if field.is_empty() || value.is_empty() {
                    return write_line(
                        writer,
                        &tagged_bad(tag, "HEADER requires a field name and a value"),
                    )
                    .await;
                }
                header_criteria.push((field, value));
            }
            other => {
                return write_line(
                    writer,
                    &tagged_bad(tag, &format!("Unsupported SEARCH criterion: {}", other)),
                )
                .await;
            }
        }
        i += 1;
    }

    // L8: each HEADER criterion runs as its own mailstore headers-JSONB
    // search (field name honored; see header_search_query for the wire
    // convention) and intersects the accumulated set — AND semantics, one
    // RPC per criterion.
    for (field, value) in &header_criteria {
        let req = SearchMessagesRequest {
            account_id: session.account_id.clone(),
            mailbox: session.mailbox.clone(),
            query: header_search_query(field, value),
            limit: 100_000,
            offset: 0,
        };
        match client.search_messages(req).await {
            Ok(resp) => {
                let found: HashSet<u64> =
                    resp.into_inner().messages.iter().map(|m| m.uid).collect();
                keep.retain(|m| found.contains(&m.uid));
            }
            Err(e) => {
                warn!("mailstore header search failed: {}", e);
                return write_line(writer, &tagged_no(tag, &format!("SEARCH failed: {}", e))).await;
            }
        }
    }

    if !fulltext_terms.is_empty() {
        // Deliberate, documented semantics: multiple BODY/TEXT terms are
        // joined and sent as ONE fulltext query, which the mailstore
        // evaluates as a stemmed AND (`plainto_tsquery`). This is not a
        // literal substring match and we do not pretend otherwise.
        let joined = fulltext_terms.join(" ");
        let req = SearchMessagesRequest {
            account_id: session.account_id.clone(),
            mailbox: session.mailbox.clone(),
            query: joined,
            limit: 100_000,
            offset: 0,
        };
        match client.search_messages(req).await {
            Ok(resp) => {
                let found: HashSet<u64> =
                    resp.into_inner().messages.iter().map(|m| m.uid).collect();
                keep.retain(|m| found.contains(&m.uid));
            }
            Err(e) => {
                // Fail closed: silently ignoring a failing search backend
                // would return UNFILTERED results as matches. Return NO so
                // the client knows the search could not be executed (e.g.
                // encrypted stores cannot search over ciphertext).
                warn!("mailstore search failed: {}", e);
                return write_line(writer, &tagged_no(tag, &format!("SEARCH failed: {}", e))).await;
            }
        }
    }

    let ids: Vec<String> = keep
        .iter()
        .map(|m| {
            if is_uid {
                m.uid.to_string()
            } else {
                uid_to_seq
                    .get(&m.uid)
                    .map(|s| s.to_string())
                    .unwrap_or_default()
            }
        })
        .filter(|s| !s.is_empty())
        .collect();

    let mut responses = String::new();
    if ids.is_empty() {
        responses.push_str("* SEARCH\r\n");
    } else {
        responses.push_str(&format!("* SEARCH {}\r\n", ids.join(" ")));
    }
    responses.push_str(&tagged_ok(tag, "SEARCH completed"));
    write_line(writer, &responses).await
}

fn parse_imap_date(s: &str) -> Option<chrono::NaiveDate> {
    chrono::NaiveDate::parse_from_str(s.trim(), "%d-%b-%Y").ok()
}

/// L8: encode an IMAP `SEARCH HEADER <field> <value>` as a mailstore search
/// query. The proto's SearchMessagesRequest has a single `query` string, so
/// the two crates share this wire convention: `header:<field>\x01<value>`.
/// The separator is the first \x01, and the convention only triggers with
/// BOTH the prefix and the separator, so ordinary fulltext queries (even one
/// starting with "header:") are unaffected. See mailstore-core's
/// `parse_header_query` (the decoding side).
fn header_search_query(field: &str, value: &str) -> String {
    format!("header:{}\x01{}", field, value)
}

/// L14(e): notice emitted on SELECT when the session's resolvable view is
/// smaller than the store's true message count (mailbox larger than the
/// 100k list cap). STATUS keeps reporting the true count, so the client is
/// told explicitly instead of silently observing EXISTS < STATUS MESSAGES.
fn view_capped_notice(view_exists: u32, store_exists: u32) -> Option<String> {
    if store_exists > view_exists {
        Some(format!(
            "* OK [ALERT] Mailbox has {} messages; only the first {} are visible in this session\r\n",
            store_exists, view_exists
        ))
    } else {
        None
    }
}

// ── COPY / MOVE ─────────────────────────────────────────────────────────────

async fn handle_copy<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    is_uid: bool,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if !mailbox_selected(session) {
        return write_line(writer, &tagged_bad(tag, "No mailbox selected")).await;
    }

    let (seq_part, dest) = match parse_copy_args(args, literals) {
        Ok(v) => v,
        Err(e) => {
            return write_line(writer, &tagged_bad(tag, &format!("{}", e))).await;
        }
    };
    // F7: view diff (EXPUNGEs/EXISTS from other sessions) is emitted before
    // the command's own tagged response so sequence numbers are corrected.
    let view_diff = refresh_session_view(session).await;
    let uids = resolve_sequence_set(session, &seq_part, is_uid)?;
    if uids.is_empty() {
        // F7: the view may still have shifted; emit the diff with the OK.
        return write_line(
            writer,
            &format!("{}{}", view_diff, tagged_ok(tag, "COPY completed")),
        )
        .await;
    }

    let mut client = session.client.clone();
    let req = CopyMessageRequest {
        account_id: session.account_id.clone(),
        source_mailbox: session.mailbox.clone(),
        dest_mailbox: dest.clone(),
        uids: uids.clone(),
    };

    let resp = match client.copy_message(req).await {
        Ok(r) => r.into_inner(),
        Err(e) => {
            // F9 (RFC 3501 §6.4.7): a NO for a nonexistent destination
            // carries [TRYCREATE] so the client knows it may CREATE the
            // mailbox and retry.
            if e.code() == tonic::Code::NotFound {
                return write_line(
                    writer,
                    &tagged_no(tag, "[TRYCREATE] Destination mailbox does not exist"),
                )
                .await;
            }
            return write_line(writer, &tagged_no(tag, &format!("COPY failed: {}", e))).await;
        }
    };

    // RFC 4315: [COPYUID <uidvalidity> <src uid-set> <dst uid-set>]
    // The uidvalidity is the DESTINATION mailbox's.
    let dest_uidvalidity = match get_mailbox_status(&mut client, &session.account_id, &dest).await {
        Ok(s) => s
            .into_inner()
            .mailbox
            .unwrap_or_default()
            .uidvalidity
            .max(1),
        Err(_) => session.uid_validity.max(1),
    };
    let mut pairs: Vec<(u64, u64)> = resp
        .uid_mapping
        .iter()
        .map(|(from, to)| (*from, *to))
        .collect();
    pairs.sort_unstable();
    let srcs: Vec<String> = pairs.iter().map(|(s, _)| s.to_string()).collect();
    let dsts: Vec<String> = pairs.iter().map(|(_, d)| d.to_string()).collect();

    write_line(
        writer,
        &format!(
            "{}{}",
            view_diff,
            tagged_ok(
                tag,
                &format!(
                    "[COPYUID {} {} {}] COPY completed",
                    dest_uidvalidity,
                    srcs.join(","),
                    dsts.join(",")
                ),
            ),
        ),
    )
    .await
}

async fn handle_move<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    is_uid: bool,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if !mailbox_selected(session) {
        return write_line(writer, &tagged_bad(tag, "No mailbox selected")).await;
    }

    let (seq_part, dest) = match parse_copy_args(args, literals) {
        Ok(v) => v,
        Err(e) => {
            return write_line(writer, &tagged_bad(tag, &format!("{}", e))).await;
        }
    };
    // F7: view diff first, so the EXPUNGE responses below (and the tagged
    // response) reference sequence numbers the client has already corrected.
    let view_diff = refresh_session_view(session).await;
    let uids = resolve_sequence_set(session, &seq_part, is_uid)?;
    if uids.is_empty() {
        // F7: the view may still have shifted; emit the diff with the OK.
        return write_line(
            writer,
            &format!("{}{}", view_diff, tagged_ok(tag, "MOVE completed")),
        )
        .await;
    }

    let mut client = session.client.clone();
    let req = MoveMessageRequest {
        account_id: session.account_id.clone(),
        source_mailbox: session.mailbox.clone(),
        dest_mailbox: dest.clone(),
        uids: uids.clone(),
    };

    let resp = match client.move_message(req).await {
        Ok(r) => r.into_inner(),
        Err(e) => {
            // F9 (RFC 6851 §4.3 / RFC 3501 §6.4.7): [TRYCREATE] on a
            // nonexistent destination.
            if e.code() == tonic::Code::NotFound {
                return write_line(
                    writer,
                    &tagged_no(tag, "[TRYCREATE] Destination mailbox does not exist"),
                )
                .await;
            }
            return write_line(writer, &tagged_no(tag, &format!("MOVE failed: {}", e))).await;
        }
    };

    // RFC 4315: [COPYUID <uidvalidity> <src uid-set> <dst uid-set>]
    // The uidvalidity is the DESTINATION mailbox's.
    let dest_uidvalidity = match get_mailbox_status(&mut client, &session.account_id, &dest).await {
        Ok(s) => s
            .into_inner()
            .mailbox
            .unwrap_or_default()
            .uidvalidity
            .max(1),
        Err(_) => session.uid_validity.max(1),
    };
    let mut pairs: Vec<(u64, u64)> = resp
        .uid_mapping
        .iter()
        .map(|(from, to)| (*from, *to))
        .collect();
    pairs.sort_unstable();
    let srcs: Vec<String> = pairs.iter().map(|(s, _)| s.to_string()).collect();
    let dsts: Vec<String> = pairs.iter().map(|(_, d)| d.to_string()).collect();

    // RFC 6851 §4.3: MOVE MUST send an untagged EXPUNGE response for each
    // message removed from the source mailbox, using sequence numbers of the
    // source mailbox. Emitting them in descending order keeps the original
    // numbering valid as each removal renumbers later messages.
    let expunge_seqs = expunge_seqs_descending(&session.uid_map, &uids);

    // Update the session's view: moved messages are gone from this mailbox.
    retain_except(&mut session.uid_map, &uids);
    session.exists = session.uid_map.len().min(u32::MAX as usize) as u32;
    // F6: moved messages stop being \Recent for this session.
    let moved: HashSet<u64> = uids.iter().copied().collect();
    session.recent_uids.retain(|u| !moved.contains(u));
    session.recent = session.recent_count();

    let mut responses = view_diff;
    responses.push_str(&expunge_response_lines(&expunge_seqs));
    responses.push_str(&tagged_ok(
        tag,
        &format!(
            "[COPYUID {} {} {}] MOVE completed",
            dest_uidvalidity,
            srcs.join(","),
            dsts.join(",")
        ),
    ));
    write_line(writer, &responses).await
}

/// Sequence numbers (in the CURRENT session view) of the given UIDs, in
/// descending order — the order in which untagged `* n EXPUNGE` responses
/// must be emitted so earlier numbers stay valid as later ones are removed.
fn expunge_seqs_descending(uid_map: &[u64], removed: &[u64]) -> Vec<u32> {
    let removed_set: HashSet<u64> = removed.iter().copied().collect();
    let mut seqs: Vec<u32> = uid_map
        .iter()
        .enumerate()
        .filter(|(_, &u)| removed_set.contains(&u))
        .map(|(i, _)| i as u32 + 1)
        .collect();
    seqs.sort_unstable_by(|a, b| b.cmp(a));
    seqs
}

/// Remove `removed` UIDs from `uid_map` in O(n) (a naive
/// `retain(|u| !removed.contains(u))` is O(n*m) and quadratic on big moves).
fn retain_except(uid_map: &mut Vec<u64>, removed: &[u64]) {
    let removed_set: HashSet<u64> = removed.iter().copied().collect();
    uid_map.retain(|u| !removed_set.contains(u));
}

/// Untagged EXPUNGE response lines for pre-computed (descending) sequences.
fn expunge_response_lines(seqs: &[u32]) -> String {
    let mut out = String::new();
    for &s in seqs {
        out.push_str(&format!("* {} EXPUNGE\r\n", s));
    }
    out
}

/// L5: untagged lines describing a session-view transition from
/// `old_uid_map` to `new_uids`: an EXPUNGE (descending sequence order, per
/// RFC 3501 §7.4.1) for every message that disappeared, then EXISTS when
/// the view gained messages or changed size. Shared by NOOP/CHECK and the
/// IDLE event path so polling clients learn about removals by other
/// sessions, not just arrivals.
fn view_update_lines(old_uid_map: &[u64], new_uids: &[u64]) -> String {
    let new_set: HashSet<u64> = new_uids.iter().copied().collect();
    let old_set: HashSet<u64> = old_uid_map.iter().copied().collect();
    let removed: Vec<u64> = old_uid_map
        .iter()
        .copied()
        .filter(|u| !new_set.contains(u))
        .collect();
    let added_any = new_uids.iter().any(|u| !old_set.contains(u));

    let mut out = expunge_response_lines(&expunge_seqs_descending(old_uid_map, &removed));
    if added_any || new_uids.len() != old_uid_map.len() {
        out.push_str(&format!(
            "* {} EXISTS\r\n",
            new_uids.len().min(u32::MAX as usize) as u32
        ));
    }
    out
}

fn parse_copy_args(args: &str, literals: &[Vec<u8>]) -> Result<(String, String)> {
    let tokens = tokenize_command_args(args.trim());
    if tokens.len() < 2 {
        bail!("COPY/MOVE requires sequence set and destination");
    }
    let seq_part = resolve_token(&tokens[0], literals);
    let dest = imap_utf7_decode(&resolve_token(&tokens[tokens.len() - 1], literals));
    Ok((seq_part, dest))
}

// ── CREATE / DELETE / RENAME ────────────────────────────────────────────────

async fn handle_create<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    let tokens = tokenize_command_args(args.trim());
    let name = tokens
        .first()
        .map(|t| imap_utf7_decode(&resolve_token(t, literals)))
        .unwrap_or_default();
    if name.is_empty() {
        return write_line(writer, &tagged_bad(tag, "Mailbox name required")).await;
    }

    let mut client = session.client.clone();
    let req = CreateMailboxRequest {
        account_id: session.account_id.clone(),
        name: name.clone(),
        special_use: String::new(),
    };

    match client.create_mailbox(req).await {
        Ok(_) => {
            write_line(
                writer,
                &tagged_ok(tag, &format!("CREATE completed, mailbox {}", name)),
            )
            .await
        }
        Err(e) => write_line(writer, &tagged_no(tag, &format!("CREATE failed: {}", e))).await,
    }
}

async fn handle_delete<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    let tokens = tokenize_command_args(args.trim());
    let name = tokens
        .first()
        .map(|t| imap_utf7_decode(&resolve_token(t, literals)))
        .unwrap_or_default();
    if name.is_empty() {
        return write_line(writer, &tagged_bad(tag, "Mailbox name required")).await;
    }

    let mut client = session.client.clone();
    let req = DeleteMailboxRequest {
        account_id: session.account_id.clone(),
        name: name.clone(),
    };

    match client.delete_mailbox(req).await {
        Ok(_) => {
            remove_subscription(&session.account_id, &name).await;
            write_line(
                writer,
                &tagged_ok(tag, &format!("DELETE completed, mailbox {}", name)),
            )
            .await
        }
        Err(e) => write_line(writer, &tagged_no(tag, &format!("DELETE failed: {}", e))).await,
    }
}

// ── RENAME ──────────────────────────────────────────────────────────────────
//
// RENAME is implemented as create-new -> move every message -> delete-old.
// The mailstore has no atomic rename, so the flow must be defensive: errors
// are propagated (never swallowed), messages are moved in pages so
// mailboxes larger than one list page survive, and the source mailbox is
// only deleted once it is verifiably empty. The old implementation listed
// one page, ignored move errors, and unconditionally deleted the source —
// with the DB's ON DELETE CASCADE that destroyed every unmoved message.

/// Page size used when moving messages during RENAME. Matches the
/// mailstore's list cap.
const RENAME_PAGE_SIZE: u32 = 100_000;
/// Hard limit on pages per RENAME (guards against a pathological mailbox).
const RENAME_MAX_PAGES: usize = 10_000;

/// The mailstore operations RENAME needs, as a trait so the flow is unit
/// testable against a mock (the real gRPC client cannot be instantiated in
/// tests).
trait RenameApi: Send {
    fn create_mailbox(
        &mut self,
        account_id: &str,
        name: &str,
    ) -> futures::future::BoxFuture<'_, anyhow::Result<()>>;
    fn list_page(
        &mut self,
        account_id: &str,
        mailbox: &str,
        uid_min: u64,
        uid_max: u64,
        limit: u32,
    ) -> futures::future::BoxFuture<'_, anyhow::Result<Vec<u64>>>;
    fn move_messages(
        &mut self,
        account_id: &str,
        source: &str,
        dest: &str,
        uids: Vec<u64>,
    ) -> futures::future::BoxFuture<'_, anyhow::Result<()>>;
    fn delete_mailbox(
        &mut self,
        account_id: &str,
        name: &str,
    ) -> futures::future::BoxFuture<'_, anyhow::Result<()>>;
}

impl RenameApi for MailstoreClient {
    fn create_mailbox(
        &mut self,
        account_id: &str,
        name: &str,
    ) -> futures::future::BoxFuture<'_, anyhow::Result<()>> {
        let req = CreateMailboxRequest {
            account_id: account_id.to_string(),
            name: name.to_string(),
            special_use: String::new(),
        };
        Box::pin(async move {
            self.create_mailbox(req).await?;
            Ok(())
        })
    }

    fn list_page(
        &mut self,
        account_id: &str,
        mailbox: &str,
        uid_min: u64,
        uid_max: u64,
        limit: u32,
    ) -> futures::future::BoxFuture<'_, anyhow::Result<Vec<u64>>> {
        let req = ListMessagesRequest {
            account_id: account_id.to_string(),
            mailbox: mailbox.to_string(),
            uid_min,
            uid_max,
            limit: limit as i32,
        };
        Box::pin(async move {
            let resp = self.list_messages(req).await?;
            let mut uids: Vec<u64> = resp.into_inner().messages.iter().map(|m| m.uid).collect();
            uids.sort_unstable();
            uids.dedup();
            Ok(uids)
        })
    }

    fn move_messages(
        &mut self,
        account_id: &str,
        source: &str,
        dest: &str,
        uids: Vec<u64>,
    ) -> futures::future::BoxFuture<'_, anyhow::Result<()>> {
        let req = MoveMessageRequest {
            account_id: account_id.to_string(),
            source_mailbox: source.to_string(),
            dest_mailbox: dest.to_string(),
            uids,
        };
        Box::pin(async move {
            self.move_message(req).await?;
            Ok(())
        })
    }

    fn delete_mailbox(
        &mut self,
        account_id: &str,
        name: &str,
    ) -> futures::future::BoxFuture<'_, anyhow::Result<()>> {
        let req = DeleteMailboxRequest {
            account_id: account_id.to_string(),
            name: name.to_string(),
        };
        Box::pin(async move {
            self.delete_mailbox(req).await?;
            Ok(())
        })
    }
}

/// Core RENAME flow. Returns Ok(()) on success; Err(msg) maps to a tagged NO
/// and guarantees the source mailbox was NOT deleted.
///
/// L9: RFC 3501 §6.3.5 — RENAME INBOX moves all messages to the new mailbox
/// and leaves INBOX empty but existing. INBOX is never deleted (the
/// mailstore refuses to delete the system mailbox anyway); the old flow
/// emptied it and THEN failed on the delete, reporting an error after the
/// damage was done.
async fn rename_mailbox_flow(
    api: &mut dyn RenameApi,
    account_id: &str,
    old_name: &str,
    new_name: &str,
) -> Result<(), String> {
    let is_inbox = old_name.eq_ignore_ascii_case("INBOX");

    api.create_mailbox(account_id, new_name)
        .await
        .map_err(|e| format!("RENAME failed: {}", e))?;

    // Move messages in pages, walking the UID space downwards (the mailstore
    // lists newest-first under its LIMIT), so mailboxes larger than one list
    // page are renamed completely.
    let mut uid_max = u64::MAX;
    let mut pages = 0usize;
    loop {
        pages += 1;
        if pages > RENAME_MAX_PAGES {
            return Err("RENAME failed: too many pages".to_string());
        }
        let page = api
            .list_page(account_id, old_name, 1, uid_max, RENAME_PAGE_SIZE)
            .await
            .map_err(|e| format!("RENAME failed: could not list source mailbox: {}", e))?;
        if page.is_empty() {
            break;
        }
        api.move_messages(account_id, old_name, new_name, page.clone())
            .await
            .map_err(|e| format!("RENAME failed: could not move messages: {}", e))?;
        if page.len() < RENAME_PAGE_SIZE as usize {
            break;
        }
        // Continue with the UIDs strictly below this page's oldest UID.
        let oldest = page[0];
        if oldest == 0 {
            break;
        }
        uid_max = oldest - 1;
    }

    // Completeness check: only finish when the source is verifiably empty.
    // Anything left (move failure swallowed upstream, concurrent delivery,
    // ...) is an error; the mailbox — and its messages — stay intact.
    let remaining = api
        .list_page(account_id, old_name, 1, u64::MAX, 1)
        .await
        .map_err(|e| format!("RENAME failed: could not verify source mailbox: {}", e))?;
    if !remaining.is_empty() {
        return Err(
            "RENAME failed: rename incomplete, source mailbox still has messages".to_string(),
        );
    }

    // L9: INBOX stays — empty but existing (RFC 3501 §6.3.5). Only regular
    // mailboxes are deleted after a rename.
    if !is_inbox {
        api.delete_mailbox(account_id, old_name)
            .await
            .map_err(|e| format!("RENAME failed: could not delete source mailbox: {}", e))?;
    }
    Ok(())
}

async fn handle_rename<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    let tokens = tokenize_command_args(args.trim());
    if tokens.len() < 2 {
        return write_line(writer, &tagged_bad(tag, "RENAME requires old and new name")).await;
    }
    let old_name = imap_utf7_decode(&resolve_token(&tokens[0], literals));
    let new_name = imap_utf7_decode(&resolve_token(&tokens[1], literals));
    if old_name.is_empty() || new_name.is_empty() {
        return write_line(writer, &tagged_bad(tag, "RENAME requires old and new name")).await;
    }

    let mut client = session.client.clone();
    if let Err(msg) =
        rename_mailbox_flow(&mut client, &session.account_id, &old_name, &new_name).await
    {
        warn!("RENAME {} -> {}: {}", old_name, new_name, msg);
        return write_line(writer, &tagged_no(tag, &msg)).await;
    }

    rename_subscription(&session.account_id, &old_name, &new_name).await;

    write_line(
        writer,
        &tagged_ok(
            tag,
            &format!("RENAME completed {} -> {}", old_name, new_name),
        ),
    )
    .await
}
// ── LIST / LSUB ─────────────────────────────────────────────────────────────

async fn handle_list<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    let (reference, pattern) = parse_list_args(args, literals);
    let pattern = imap_utf7_decode(&combine_list_pattern(&reference, &pattern));

    let mut client = session.client.clone();
    let req = ListMailboxesRequest {
        account_id: session.account_id.clone(),
        pattern: "*".to_string(),
    };

    let resp = match client.list_mailboxes(req).await {
        Ok(r) => r.into_inner(),
        Err(e) => {
            return write_line(writer, &tagged_no(tag, &format!("LIST failed: {}", e))).await;
        }
    };

    let mut responses = String::new();
    for mb in resp.mailboxes {
        if !imap_pattern_match(&mb.name, &pattern) {
            continue;
        }
        let delim = if mb.delimiter.is_empty() {
            "NIL".to_string()
        } else {
            mailbox_astring(&mb.delimiter)
        };
        let mut attrs = mb.attributes.clone();
        if is_subscribed(&session.account_id, &mb.name).await {
            attrs.push("\\Subscribed".to_string());
        }
        // L7: the (client-controlled) name is escaped/stripped by
        // mailbox_astring so it cannot terminate the quoted string or split
        // the response line.
        responses.push_str(&format!(
            "* LIST ({}) {} {}\r\n",
            attrs.join(" "),
            delim,
            mailbox_astring(&imap_utf7_encode(&mb.name))
        ));
    }
    responses.push_str(&tagged_ok(tag, "LIST completed"));
    write_line(writer, &responses).await
}

async fn handle_lsub<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    let (reference, pattern) = parse_list_args(args, literals);
    let pattern = imap_utf7_decode(&combine_list_pattern(&reference, &pattern));

    // L13: the subscription table (see its module comment) is the
    // authoritative source for LSUB — reflect it honestly: every subscribed
    // name matching the pattern is listed, even when the mailbox no longer
    // exists in the mailstore (reported with no attributes).
    let mut subscribed: Vec<String> = subscribed_mailboxes(&session.account_id)
        .await
        .into_iter()
        .collect();
    subscribed.sort();

    let mut client = session.client.clone();
    let req = ListMailboxesRequest {
        account_id: session.account_id.clone(),
        pattern: "*".to_string(),
    };

    let resp = match client.list_mailboxes(req).await {
        Ok(r) => r.into_inner(),
        Err(e) => {
            return write_line(writer, &tagged_no(tag, &format!("LSUB failed: {}", e))).await;
        }
    };

    let mut responses = String::new();
    for name in &subscribed {
        if !imap_pattern_match(name, &pattern) {
            continue;
        }
        let existing = resp
            .mailboxes
            .iter()
            .find(|mb| mb.name.eq_ignore_ascii_case(name));
        let (attrs, delim) = match existing {
            Some(mb) => (
                mb.attributes.join(" "),
                if mb.delimiter.is_empty() {
                    "NIL".to_string()
                } else {
                    mailbox_astring(&mb.delimiter)
                },
            ),
            None => (String::new(), "\"/\"".to_string()),
        };
        // L7: escape the name — it may contain quotes (via literals).
        responses.push_str(&format!(
            "* LSUB ({}) {} {}\r\n",
            attrs,
            delim,
            mailbox_astring(&imap_utf7_encode(name))
        ));
    }
    responses.push_str(&tagged_ok(tag, "LSUB completed"));
    write_line(writer, &responses).await
}

async fn is_subscribed(account_id: &str, mailbox: &str) -> bool {
    subscribed_mailboxes(account_id)
        .await
        .iter()
        .any(|s| s.eq_ignore_ascii_case(mailbox))
}

fn parse_list_args(args: &str, literals: &[Vec<u8>]) -> (String, String) {
    let tokens = tokenize_command_args(args.trim());
    let reference = tokens
        .first()
        .map(|t| resolve_token(t, literals))
        .unwrap_or_default();
    let pattern = tokens
        .get(1)
        .map(|t| resolve_token(t, literals))
        .unwrap_or_else(|| "*".to_string());
    (reference, pattern)
}

// ── SUBSCRIBE / UNSUBSCRIBE ─────────────────────────────────────────────────

async fn handle_subscribe<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    let name = imap_utf7_decode(&resolve_token(args.trim(), literals));
    if name.is_empty() {
        return write_line(writer, &tagged_bad(tag, "Mailbox name required")).await;
    }
    subscribe_mailbox(&session.account_id, &name).await;
    write_line(
        writer,
        &tagged_ok(tag, &format!("SUBSCRIBE completed, {}", name)),
    )
    .await
}

async fn handle_unsubscribe<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    let name = imap_utf7_decode(&resolve_token(args.trim(), literals));
    if name.is_empty() {
        return write_line(writer, &tagged_bad(tag, "Mailbox name required")).await;
    }
    unsubscribe_mailbox(&session.account_id, &name).await;
    write_line(
        writer,
        &tagged_ok(tag, &format!("UNSUBSCRIBE completed, {}", name)),
    )
    .await
}

// ── STATUS ──────────────────────────────────────────────────────────────────

async fn handle_status<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }
    let tokens = tokenize_command_args(args.trim());
    if tokens.is_empty() {
        return write_line(writer, &tagged_bad(tag, "Mailbox name required")).await;
    }
    let mailbox = imap_utf7_decode(&resolve_token(&tokens[0], literals));
    if mailbox.is_empty() {
        return write_line(writer, &tagged_bad(tag, "Mailbox name required")).await;
    }

    let status = match get_mailbox_status(&mut session.client, &session.account_id, &mailbox).await
    {
        Ok(s) => s.into_inner(),
        Err(e) => {
            if tonic_code(&e) == Some(tonic::Code::NotFound) {
                return write_line(writer, &tagged_no(tag, "[NONEXISTENT] Mailbox not found"))
                    .await;
            }
            return write_line(writer, &tagged_no(tag, &format!("STATUS failed: {}", e))).await;
        }
    };
    let mb = status.mailbox.unwrap_or_default();

    let items_str = tokens[1..].join(" ");
    let mut parts = Vec::new();
    let items_lower = items_str.to_lowercase();

    if items_lower.contains("messages") {
        parts.push(format!("MESSAGES {}", mb.exists));
    }
    if items_lower.contains("recent") {
        // F6: recency is session-scoped; only the currently selected mailbox
        // has a meaningful count for THIS session. Other mailboxes honestly
        // report the store's zero (no persistent first-delivery marker).
        let recent = if mailbox_selected(session) && session.mailbox.eq_ignore_ascii_case(&mailbox)
        {
            session.recent_count()
        } else {
            mb.recent
        };
        parts.push(format!("RECENT {}", recent));
    }
    if items_lower.contains("uidnext") {
        parts.push(format!("UIDNEXT {}", mb.uidnext.max(1)));
    }
    if items_lower.contains("uidvalidity") {
        parts.push(format!("UIDVALIDITY {}", mb.uidvalidity));
    }
    if items_lower.contains("unseen") {
        parts.push(format!("UNSEEN {}", mb.unseen));
    }

    let mut responses = String::new();
    responses.push_str(&format!(
        "* STATUS {} ({})\r\n",
        mailbox_astring(&imap_utf7_encode(&mailbox)),
        parts.join(" ")
    ));
    responses.push_str(&tagged_ok(tag, "STATUS completed"));
    write_line(writer, &responses).await
}

/// Parse an IMAP date-time (APPEND internal date, RFC 3501 date-time
/// format) into a Unix timestamp.
fn parse_append_datetime(date_str: &str) -> Result<i64> {
    chrono::DateTime::parse_from_str(date_str.trim(), "%d-%b-%Y %H:%M:%S %z")
        .map(|dt| dt.timestamp())
        .with_context(|| format!("Invalid date-time: {}", date_str))
}

/// L3: the APPEND internal-date decision — NOW when the client omitted the
/// date-time token (proto 0 used to stamp 1970-01-01), the exact parsed
/// timestamp when present.
fn append_internal_date(tokens: &[String], idx: usize, literals: &[Vec<u8>]) -> Result<i64> {
    if idx < tokens.len() && tokens[idx].starts_with('"') {
        parse_append_datetime(&resolve_token(&tokens[idx], literals))
    } else {
        Ok(chrono::Utc::now().timestamp())
    }
}

// ── APPEND ──────────────────────────────────────────────────────────────────

async fn handle_append<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    args: &str,
    literals: &[Vec<u8>],
    writer: &mut W,
) -> Result<()> {
    if !auth_required(session) {
        return write_line(writer, &tagged_no(tag, "Not authenticated")).await;
    }

    let tokens = tokenize_command_args(args.trim());
    if tokens.is_empty() {
        return write_line(writer, &tagged_bad(tag, "APPEND requires a mailbox")).await;
    }
    let mailbox = imap_utf7_decode(&resolve_token(&tokens[0], literals));
    if mailbox.is_empty() {
        return write_line(writer, &tagged_bad(tag, "APPEND requires a mailbox")).await;
    }

    let mut idx = 1;
    let mut flags = MessageFlags::default();
    if idx < tokens.len() && tokens[idx].starts_with('(') {
        let flag_tokens: Vec<String> = tokens[idx]
            .trim_matches(|c| c == '(' || c == ')')
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        // F4: shared flag-token mapping — case-insensitive system flags and
        // unknown backslash tokens kept as custom keywords (previously
        // APPEND matched case-insensitively but silently DROPPED unknown
        // backslash tokens).
        flags = store_flags_from_tokens(&flag_tokens);
        idx += 1;
    }

    // L3: an omitted APPEND date-time means "now", not epoch 0 (see
    // append_internal_date). The mailstore also maps proto 0 to now, but
    // this layer sends the real timestamp so the two agree. (No caller
    // legitimately sends epoch 0: the SMTP path sends Utc::now().)
    let internal_date = match append_internal_date(&tokens, idx, literals) {
        Ok(ts) => ts,
        Err(_) => {
            return write_line(
                writer,
                &tagged_bad(tag, "Invalid date-time: command rejected"),
            )
            .await;
        }
    };
    // Advance past the date token when one was consumed.
    if idx < tokens.len() && tokens[idx].starts_with('"') {
        idx += 1;
    }

    if idx >= tokens.len() {
        return write_line(
            writer,
            &tagged_bad(tag, "APPEND requires a literal message"),
        )
        .await;
    }
    // The message literal was consumed by the command reader (sync literals
    // got a continuation request there). The literal token is the message.
    let raw_message = match token_literal_bytes(&tokens[idx], literals) {
        Some(b) => b.to_vec(),
        None => {
            return write_line(
                writer,
                &tagged_bad(tag, "APPEND requires a literal message"),
            )
            .await;
        }
    };
    if idx + 1 < tokens.len() {
        return write_line(
            writer,
            &tagged_bad(tag, "Unexpected extra argument after message literal"),
        )
        .await;
    }

    // Verify the target mailbox exists and get its UIDVALIDITY.
    let uidvalidity =
        match get_mailbox_status(&mut session.client, &session.account_id, &mailbox).await {
            Ok(s) => s
                .into_inner()
                .mailbox
                .unwrap_or_default()
                .uidvalidity
                .max(1),
            Err(e) => {
                if tonic_code(&e) == Some(tonic::Code::NotFound) {
                    // F9 (RFC 3501 §6.3.11): the NO for a nonexistent APPEND
                    // target carries [TRYCREATE].
                    return write_line(
                        writer,
                        &tagged_no(tag, "[TRYCREATE] Mailbox does not exist"),
                    )
                    .await;
                }
                return write_line(writer, &tagged_no(tag, &format!("APPEND failed: {}", e))).await;
            }
        };

    // Store the message via mailstore gRPC.
    let append_sets_seen = flags.seen;
    let mut client = session.client.clone();
    let req = StoreMessageRequest {
        account_id: session.account_id.clone(),
        mailbox: mailbox.clone(),
        raw_message: raw_message.into(),
        flags: Some(flags),
        internal_date,
        // IMAP APPEND is an explicit client request for this copy: exempt it
        // from per-mailbox Message-ID dedup (RFC 3501 APPEND semantics).
        dedup_exempt: true,
    };

    let resp = match client.store_message(req).await {
        Ok(r) => r.into_inner(),
        Err(e) if e.code() == tonic::Code::ResourceExhausted => {
            // RFC 3501 §6.3.11: quota violations are reported with NO and an
            // [ALERT] response code so the client surfaces them to the user.
            warn!(
                "APPEND rejected: quota exceeded for account {}",
                session.account_id
            );
            return write_line(
                writer,
                &tagged_no(tag, "[ALERT] Quota exceeded: APPEND failed"),
            )
            .await;
        }
        Err(e) => {
            return write_line(writer, &tagged_no(tag, &format!("APPEND failed: {}", e))).await;
        }
    };

    // If we appended into the currently selected mailbox, keep the session
    // view in sync and advertise the new message count.
    let mut responses = String::new();
    if session.mailbox.eq_ignore_ascii_case(&mailbox) && mailbox_selected(session) {
        session.exists = session.exists.saturating_add(1);
        session.uid_map.push(resp.uid);
        session.uid_map.sort_unstable();
        session.uid_next = session.uid_next.max(resp.uid.saturating_add(1));
        // F6: an unseen message that arrives (here: is APPENDED) during the
        // session joins this session's \Recent set.
        if !append_sets_seen {
            session.recent_uids.insert(resp.uid);
            session.recent = session.recent_count();
        }
        responses.push_str(&format!("* {} EXISTS\r\n", session.exists));
    }

    responses.push_str(&tagged_ok(
        tag,
        &format!("[APPENDUID {} {}] APPEND completed", uidvalidity, resp.uid),
    ));
    write_line(writer, &responses).await
}

// ── EXPUNGE ─────────────────────────────────────────────────────────────────

async fn handle_expunge<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    uid_set: Option<&str>,
    writer: &mut W,
) -> Result<()> {
    if !mailbox_selected(session) {
        return write_line(writer, &tagged_bad(tag, "No mailbox selected")).await;
    }
    if session.read_only {
        return write_line(writer, &tagged_no(tag, "[READ-ONLY] EXPUNGE not permitted")).await;
    }

    // F7: capture the view diff from the refresh; it is emitted BEFORE this
    // command's own EXPUNGE responses so the client's sequence numbers are
    // corrected for removals by other sessions first.
    let view_diff = refresh_session_view(session).await;

    // UID EXPUNGE (RFC 4315 §2.2.2) restricts the expunge to the given UID
    // set: only the intersection of \Deleted and the set is removed. An empty
    // resolved set (e.g. every UID is out of range) expunges nothing.
    let uids: Vec<u64> = match uid_set {
        Some(set) => {
            let resolved = match resolve_sequence_set(session, set, true) {
                Ok(v) => v,
                Err(e) => {
                    return write_line(writer, &tagged_bad(tag, &format!("{}", e))).await;
                }
            };
            if resolved.is_empty() {
                // F7: nothing to expunge, but the refreshed view may still
                // have shifted — emit the diff with the OK.
                return write_line(
                    writer,
                    &format!("{}{}", view_diff, tagged_ok(tag, "EXPUNGE completed")),
                )
                .await;
            }
            resolved
        }
        None => Vec::new(),
    };

    let mut client = session.client.clone();
    let req = ExpungeRequest {
        account_id: session.account_id.clone(),
        mailbox: session.mailbox.clone(),
        uids,
    };

    let resp = match client.expunge(req).await {
        Ok(r) => r.into_inner(),
        Err(e) => {
            return write_line(writer, &tagged_no(tag, &format!("EXPUNGE failed: {}", e))).await;
        }
    };

    let mut responses = view_diff;
    let mut expunged_seqs: Vec<u32> = Vec::new();
    for uid in &resp.expunged_uids {
        if let Some(seq) = session.seq_for_uid(*uid) {
            let adjusted = seq - expunged_seqs.iter().filter(|&&s| s < seq).count() as u32;
            responses.push_str(&format!("* {} EXPUNGE\r\n", adjusted));
            expunged_seqs.push(adjusted);
        }
    }

    retain_except(&mut session.uid_map, &resp.expunged_uids);
    session.exists = session.uid_map.len().min(u32::MAX as usize) as u32;
    // F6: expunged messages stop being \Recent.
    let expunged: HashSet<u64> = resp.expunged_uids.iter().copied().collect();
    session.recent_uids.retain(|u| !expunged.contains(u));
    session.recent = session.recent_count();

    if !resp.expunged_uids.is_empty() {
        responses.push_str(&format!("* {} EXISTS\r\n", session.exists));
    }

    responses.push_str(&tagged_ok(tag, "EXPUNGE completed"));
    write_line(writer, &responses).await
}

// ── NOOP / CHECK ────────────────────────────────────────────────────────────

async fn handle_noop<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    writer: &mut W,
) -> Result<()> {
    let mut responses = String::new();
    if mailbox_selected(session) && !session.mailbox.is_empty() {
        let old_uid_map = session.uid_map.clone();
        let mut client = session.client.clone();
        if let Ok(status) =
            get_mailbox_status(&mut client, &session.account_id, &session.mailbox).await
        {
            let mb = status.into_inner().mailbox.unwrap_or_default();

            // L5: re-list the mailbox so polling clients learn about messages
            // REMOVED by other sessions (EXPUNGE), not just about arrivals.
            // The diff shares the IDLE path's logic via view_update_lines.
            let list_req = ListMessagesRequest {
                account_id: session.account_id.clone(),
                mailbox: session.mailbox.clone(),
                uid_min: 1,
                uid_max: u64::MAX,
                limit: 100_000,
            };
            if let Ok(resp) = client.list_messages(list_req).await {
                let mut msgs = resp.into_inner().messages;
                msgs.sort_by_key(|m| m.uid);
                msgs.dedup_by_key(|m| m.uid);
                let new_uids: Vec<u64> = msgs.iter().map(|m| m.uid).collect();
                responses.push_str(&view_update_lines(&old_uid_map, &new_uids));
                // F6: unseen arrivals since the last poll join this session's
                // \Recent set; messages that left the view drop out of it.
                let known: HashSet<u64> = old_uid_map.iter().copied().collect();
                for m in &msgs {
                    if !known.contains(&m.uid) && !m.flags.as_ref().map(|f| f.seen).unwrap_or(false)
                    {
                        session.recent_uids.insert(m.uid);
                    }
                }
                let live: HashSet<u64> = new_uids.iter().copied().collect();
                session.recent_uids.retain(|u| live.contains(u));
                session.uid_map = new_uids;
                // EXISTS reports the size of the session's resolvable view
                // (the capped uid_map), keeping sequence numbers consistent.
                session.exists = session.uid_map.len().min(u32::MAX as usize) as u32;
                if let Some(&last) = session.uid_map.last() {
                    session.uid_next = session.uid_next.max(last.saturating_add(1));
                }
            }
            // F6: RECENT reports this session's (approximated) recent count,
            // not the store's always-zero counter.
            let recent_now = session.recent_count();
            if recent_now != session.recent {
                responses.push_str(&format!("* {} RECENT\r\n", recent_now));
                session.recent = recent_now;
            }
            if mb.uidnext.max(1) != session.uid_next {
                responses.push_str(&uid_next_response(mb.uidnext.max(1)));
                session.uid_next = mb.uidnext.max(1);
            }
        }
    }
    responses.push_str(&tagged_ok(tag, "NOOP completed"));
    write_line(writer, &responses).await
}

// ── CLOSE ───────────────────────────────────────────────────────────────────

async fn handle_close<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    writer: &mut W,
) -> Result<()> {
    if !mailbox_selected(session) {
        return write_line(writer, &tagged_bad(tag, "No mailbox selected")).await;
    }

    // CLOSE = EXPUNGE (silently) + deselect (RFC 3501 §6.4.2).
    // L13: an expunge failure is reported (NO) and the session stays
    // selected — the old code swallowed the error and deselected anyway,
    // leaving the client with silently-unexpunged \Deleted messages.
    if !session.read_only {
        let mut client = session.client.clone();
        let req = ExpungeRequest {
            account_id: session.account_id.clone(),
            mailbox: session.mailbox.clone(),
            // CLOSE expunges every \Deleted message (no UID set).
            uids: Vec::new(),
        };
        if let Err(e) = client.expunge(req).await {
            warn!("CLOSE expunge failed for {}: {}", session.mailbox, e);
            return write_line(
                writer,
                &tagged_no(tag, &format!("CLOSE failed: expunge error: {}", e)),
            )
            .await;
        }
    }

    session.state = SessionState::Authenticated;
    session.mailbox.clear();
    session.uid_map.clear();
    session.exists = 0;
    session.recent = 0;
    session.recent_uids.clear();
    session.uid_next = 0;
    session.uid_validity = 0;

    write_line(writer, &tagged_ok(tag, "CLOSE completed")).await
}

// ── IDLE ────────────────────────────────────────────────────────────────────

async fn handle_idle<W: AsyncWrite + Unpin>(
    session: &mut ImapSession,
    tag: &str,
    writer: &mut W,
) -> Result<()> {
    if !mailbox_selected(session) {
        return write_line(writer, &tagged_bad(tag, "No mailbox selected")).await;
    }
    session.idle = true;
    write_line(writer, "+ idling\r\n").await
}
// ── Helpers ─────────────────────────────────────────────────────────────────

async fn get_mailbox_status(
    client: &mut MailstoreClient,
    account_id: &str,
    mailbox: &str,
) -> Result<tonic::Response<mail_proto::GetMailboxStatusResponse>> {
    let req = GetMailboxStatusRequest {
        account_id: account_id.to_string(),
        mailbox: mailbox.to_string(),
    };
    client
        .get_mailbox_status(req)
        .await
        .with_context(|| format!("gRPC get_mailbox_status failed for {}", mailbox))
}

// ── TLS configuration ───────────────────────────────────────────────────────

fn configure_tls(cert_path: Option<&str>, key_path: Option<&str>) -> Result<Option<TlsAcceptor>> {
    let cert_path = match cert_path {
        Some(p) => p.to_string(),
        None => {
            let default = "/opt/apexmail/certs/apexmail.crt".to_string();
            if std::path::Path::new(&default).exists() {
                default
            } else {
                warn!("No TLS cert found at {} — running without IMAPS", default);
                return Ok(None);
            }
        }
    };

    let key_path = match key_path {
        Some(p) => p.to_string(),
        None => {
            let default = "/opt/apexmail/certs/apexmail.key".to_string();
            if std::path::Path::new(&default).exists() {
                default
            } else {
                warn!("No TLS key found — running without IMAPS");
                return Ok(None);
            }
        }
    };

    let certs = {
        let cert_file = std::fs::File::open(&cert_path)
            .with_context(|| format!("Failed to open cert file: {}", cert_path))?;
        let mut reader = std::io::BufReader::new(cert_file);
        rustls_pemfile::certs(&mut reader)
            .collect::<std::io::Result<Vec<_>>>()
            .with_context(|| format!("Failed to read certs from {}", cert_path))?
    };

    let key = {
        let key_file = std::fs::File::open(&key_path)
            .with_context(|| format!("Failed to open key file: {}", key_path))?;
        let mut reader = std::io::BufReader::new(key_file);
        match rustls_pemfile::private_key(&mut reader) {
            Ok(Some(key)) => key,
            Ok(None) => bail!("No private key found in {}", key_path),
            Err(e) => bail!("Failed to read key from {}: {}", key_path, e),
        }
    };

    let mut config = ServerConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS12,
        &rustls::version::TLS13,
    ])
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .with_context(|| "Failed to build TLS server config")?;

    // Enable TLS session tickets — some mobile clients hang during TLS
    // post-handshake if no NewSessionTicket message is sent.
    config.session_storage = rustls::server::ServerSessionMemoryCache::new(256);

    Ok(Some(TlsAcceptor::from(Arc::new(config))))
}

// ── IDLE runtime loop ───────────────────────────────────────────────────────
//
// While a session is idling, subscribe to the mailstore mailbox event stream
// and emit unsolicited EXISTS/RECENT/UIDNEXT/EXPUNGE updates when the mailbox
// changes. RFC 2177: if the client does not send DONE within a reasonable
// time (30 minutes), the server may close the connection — we use 29 minutes.

async fn process_mailbox_event<W: AsyncWrite + Unpin>(
    session: &Arc<Mutex<ImapSession>>,
    writer: &mut W,
    _event: &MailboxEvent,
) -> Result<()> {
    let (account_id, mailbox, old_exists, old_recent, old_uidnext, old_uid_map) = {
        let g = session.lock().await;
        (
            g.account_id.clone(),
            g.mailbox.clone(),
            g.exists,
            g.recent,
            g.uid_next,
            g.uid_map.clone(),
        )
    };
    if mailbox.is_empty() {
        return Ok(());
    }

    let mut client = session.lock().await.client.clone();

    let status = match get_mailbox_status(&mut client, &account_id, &mailbox).await {
        Ok(s) => s.into_inner(),
        Err(_) => return Ok(()),
    };
    let mb = status.mailbox.unwrap_or_default();

    let list_req = ListMessagesRequest {
        account_id: account_id.clone(),
        mailbox: mailbox.clone(),
        uid_min: 1,
        uid_max: u64::MAX,
        limit: 100_000,
    };
    let msgs = match client.list_messages(list_req).await {
        Ok(r) => {
            let mut m = r.into_inner().messages;
            m.sort_by_key(|x| x.uid);
            m.dedup_by_key(|x| x.uid);
            m
        }
        Err(_) => return Ok(()),
    };
    let new_uids: Vec<u64> = msgs.iter().map(|m| m.uid).collect();

    let old_set: HashSet<u64> = old_uid_map.iter().copied().collect();
    let new_set: HashSet<u64> = new_uids.iter().copied().collect();
    let removed: Vec<u64> = old_uid_map
        .iter()
        .copied()
        .filter(|u| !new_set.contains(u))
        .collect();
    let added: Vec<u64> = new_uids
        .iter()
        .copied()
        .filter(|u| !old_set.contains(u))
        .collect();

    // F6: unseen arrivals join this session's \Recent set; departures drop
    // out. Computed on a clone so the check below stays lock-free.
    let mut recent_uids = session.lock().await.recent_uids.clone();
    for m in &msgs {
        if added.contains(&m.uid) && !m.flags.as_ref().map(|f| f.seen).unwrap_or(false) {
            recent_uids.insert(m.uid);
        }
    }
    recent_uids.retain(|u| new_set.contains(u));
    let recent_now = recent_uids.len().min(u32::MAX as usize) as u32;

    let exists_changed = mb.exists != old_exists;
    let uidnext_changed = mb.uidnext.max(1) != old_uidnext;
    let recent_changed = recent_now != old_recent;

    if removed.is_empty()
        && added.is_empty()
        && !exists_changed
        && !uidnext_changed
        && !recent_changed
    {
        return Ok(());
    }

    let mut out = String::new();
    // EXPUNGE responses must be sent in decreasing sequence-number order.
    let mut rem_seqs: Vec<u32> = removed
        .iter()
        .filter_map(|u| {
            old_uid_map
                .iter()
                .position(|x| x == u)
                .map(|i| i as u32 + 1)
        })
        .collect();
    rem_seqs.sort_unstable_by(|a, b| b.cmp(a));
    for s in rem_seqs {
        out.push_str(&format!("* {} EXPUNGE\r\n", s));
    }
    // EXISTS reports the size of the session's resolvable view (the capped
    // uid_map), keeping sequence numbers and EXISTS consistent.
    let view_exists = new_uids.len().min(u32::MAX as usize) as u32;
    if !added.is_empty() || exists_changed {
        out.push_str(&format!("* {} EXISTS\r\n", view_exists));
    }
    if recent_changed {
        // F6: this session's \Recent count, not the store's zero.
        out.push_str(&format!("* {} RECENT\r\n", recent_now));
    }
    if uidnext_changed {
        out.push_str(&uid_next_response(mb.uidnext.max(1)));
    }

    let new_uidnext = new_uids
        .last()
        .copied()
        .unwrap_or(0)
        .saturating_add(1)
        .max(mb.uidnext);
    {
        let mut g = session.lock().await;
        g.exists = view_exists;
        g.recent = recent_now;
        g.recent_uids = recent_uids;
        g.uid_next = new_uidnext;
        g.uid_map = new_uids;
    }

    if !out.is_empty() {
        write_line(writer, &out).await?;
    }
    Ok(())
}

async fn run_idle<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    session: &Arc<Mutex<ImapSession>>,
    reader: &mut BufReader<R>,
    writer: &mut W,
    tag: &str,
) -> Result<()> {
    let (account_id, mailbox) = {
        let g = session.lock().await;
        (g.account_id.clone(), g.mailbox.clone())
    };
    let mut client = session.lock().await.client.clone();

    let mut stream = match client
        .subscribe_mailbox(SubscribeMailboxRequest {
            account_id,
            mailbox,
        })
        .await
    {
        Ok(resp) => Some(resp.into_inner()),
        Err(e) => {
            warn!("IDLE subscribe_mailbox failed: {}", e);
            None
        }
    };
    // Without a live event stream we must never reach for `stream.message()`
    // below: mark it dead up front so the select only waits on DONE.
    let mut stream_dead = stream.is_none();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(29 * 60);

    loop {
        // Build the event-stream future on each iteration: a pending future
        // once the stream has ended so the select keeps waiting on DONE.
        let event_fut: std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<Option<MailboxEvent>, tonic::Status>>
                    + Send,
            >,
        > = if stream_dead {
            Box::pin(std::future::pending())
        } else {
            Box::pin(stream.as_mut().expect("live stream").message())
        };

        tokio::select! {
            // Bounded read: a client that never sends a newline cannot grow
            // the buffer indefinitely (MAX_COMMAND_LINE applies).
            read_res = read_line_limited(reader) => {
                match read_res {
                    Ok(None) => {
                        let mut g = session.lock().await;
                        g.state = SessionState::Logout;
                        return Ok(());
                    }
                    Ok(Some(line)) => {
                        let tokens: Vec<&str> = line.split_whitespace().collect();
                        if tokens.is_empty() {
                            continue;
                        }
                        let is_done = tokens
                            .last()
                            .map(|t| t.eq_ignore_ascii_case("DONE"))
                            .unwrap_or(false);
                        if is_done {
                            let mut g = session.lock().await;
                            g.idle = false;
                            drop(g);
                            write_line(writer, &tagged_ok(tag, "IDLE terminated")).await?;
                            return Ok(());
                        }
                        // RFC 2177: only DONE is permitted while idling. A
                        // LOGOUT ends the session cleanly; anything else gets
                        // a BAD and IDLE continues.
                        let is_logout = tokens
                            .get(1)
                            .map(|t| t.eq_ignore_ascii_case("LOGOUT"))
                            .unwrap_or(false);
                        if is_logout {
                            let mut g = session.lock().await;
                            g.idle = false;
                            g.state = SessionState::Logout;
                            drop(g);
                            write_line(
                                writer,
                                &format!("{}{}", bye("Logging out"), tagged_ok(tokens[0], "LOGOUT completed")),
                            )
                            .await?;
                            return Ok(());
                        }
                        let cmd_tag = tokens.first().map(|s| s.to_string()).unwrap_or_default();
                        write_line(writer, &tagged_bad(&cmd_tag, "Command not allowed during IDLE")).await?;
                    }
                    Err(e) => {
                        warn!("IDLE read error: {}", e);
                        let mut g = session.lock().await;
                        g.state = SessionState::Logout;
                        return Ok(());
                    }
                }
            }
            event = event_fut => {
                match event {
                    Ok(Some(ev)) => {
                        if let Err(e) = process_mailbox_event(session, writer, &ev).await {
                            warn!("Failed to process IDLE mailbox event: {}", e);
                        }
                    }
                    Ok(None) => {
                        stream_dead = true;
                    }
                    Err(e) => {
                        warn!("IDLE stream error: {}", e);
                        stream_dead = true;
                    }
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                // RFC 2177: terminate the IDLE after a reasonable timeout.
                let mut g = session.lock().await;
                g.idle = false;
                g.state = SessionState::Logout;
                drop(g);
                write_line(writer, &bye("IDLE timeout, closing connection")).await?;
                return Ok(());
            }
        }
    }
}

// ── Connection handling ─────────────────────────────────────────────────────

async fn handle_connection(
    stream: TcpStream,
    tls: Option<TlsAcceptor>,
    mailstore_addr: String,
    mailstore_auth: InternalServiceAuthInterceptor,
    is_tls: bool,
    allow_insecure_auth: bool,
) -> Result<()> {
    let peer = stream.peer_addr()?;
    info!("New connection from {} (TLS: {})", peer, is_tls);

    // Connect to mailstore with a timeout so mobile clients don't hang waiting
    // for the IMAP greeting while gRPC connects. A lazy channel is used so the
    // greeting is sent immediately without waiting for mailstore to be up.
    // Limits are raised to 64 MiB so large messages (e.g. 5 MB APPENDs) pass.
    let uri: tonic::transport::Uri = mailstore_addr
        .parse()
        .with_context(|| "Invalid mailstore address")?;
    let channel = Channel::builder(uri)
        .timeout(Duration::from_secs(30))
        .connect_lazy();

    let client = build_mailstore_client(channel, mailstore_auth)
        .max_decoding_message_size(64 * 1024 * 1024)
        .max_encoding_message_size(64 * 1024 * 1024);
    let session = Arc::new(Mutex::new({
        let mut s = ImapSession::new(client);
        s.tls_active = is_tls;
        s.allow_insecure_auth = allow_insecure_auth;
        s.peer_ip = peer.ip().to_string();
        s
    }));

    if is_tls {
        // IMAPS (993): implicit TLS — accept then serve.
        if let Some(acceptor) = tls {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let (reader, writer) = tokio::io::split(tls_stream);
                    serve(session, reader, writer, true).await?;
                }
                Err(e) => {
                    warn!("TLS handshake failed: {}", e);
                }
            }
        }
    } else if let Some(acceptor) = tls {
        // IMAP (143): plaintext with STARTTLS upgrade.
        handle_plaintext_with_starttls(stream, acceptor, session, allow_insecure_auth).await?;
    } else {
        // IMAP (143) without TLS configured: serve plaintext directly but keep
        // the auth policy (LOGIN/AUTHENTICATE only when insecure auth allowed)
        // and do not advertise STARTTLS since there is no certificate.
        let (reader, writer) = tokio::io::split(stream);
        let greeting = {
            let g = session.lock().await;
            greeting_line(g.tls_active, g.allow_insecure_auth, false)
        };
        let mut writer = writer;
        writer.write_all(greeting.as_bytes()).await?;
        writer.flush().await?;
        serve(session, reader, writer, false).await?;
    }

    Ok(())
}

/// Handle a plaintext IMAP connection (port 143) with STARTTLS upgrade support.
///
/// Reads commands line-by-line. When the client sends STARTTLS, responds with
/// an OK, upgrades the TCP stream to TLS, then delegates to `serve()` for the
/// rest of the session. Before STARTTLS, only CAPABILITY/NOOP/STARTTLS are
/// allowed per RFC 3501 §6.2.1 — except that LOGIN/AUTHENTICATE are routed
/// through the normal handlers so they are refused with `[PRIVACYREQUIRED]`
/// on a plaintext connection (unless IMAP_ALLOW_INSECURE_AUTH=true, in which
/// case the session continues in plaintext).
async fn handle_plaintext_with_starttls(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    session: Arc<Mutex<ImapSession>>,
    allow_insecure_auth: bool,
) -> Result<()> {
    use tokio::io::ReadHalf;
    use tokio::io::WriteHalf;

    let (read_half, write_half): (ReadHalf<TcpStream>, WriteHalf<TcpStream>) =
        tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let mut writer = write_half;

    // Send greeting
    let greeting = greeting_line(false, allow_insecure_auth, true);
    writer.write_all(greeting.as_bytes()).await?;
    writer.flush().await?;

    // L1: per-connection literal budget for the pre-STARTTLS reads.
    let mut conn_state = ConnectionReadState::default();

    loop {
        // Re-read commands with literal support in case a client uses a
        // literal for its username. L1: bounded read — a client that stalls
        // before STARTTLS gets a BYE and is dropped.
        let command = match read_command_bounded(
            &mut reader,
            &mut writer,
            &ReadLimits::default(),
            &mut conn_state,
            COMMAND_READ_TIMEOUT,
        )
        .await
        {
            Ok(Some(c)) => c,
            Ok(None) => return Ok(()),
            Err(e) => {
                warn!("Error reading command before STARTTLS: {}", e);
                return Ok(());
            }
        };
        let (tag, cmd, args, literals) = command;

        match cmd.to_uppercase().as_str() {
            "STARTTLS" => {
                let resp = format!("{tag} OK Begin TLS negotiation now\r\n");
                writer.write_all(resp.as_bytes()).await?;
                writer.flush().await?;

                let stream = reader.into_inner().unsplit(writer);
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        info!("STARTTLS upgrade successful");
                        // The connection is now encrypted: mark the session as
                        // TLS so auth is permitted and STARTTLS is no longer
                        // advertised. No second greeting is sent.
                        session.lock().await.tls_active = true;
                        let (tls_reader, tls_writer) = tokio::io::split(tls_stream);
                        serve(session, tls_reader, tls_writer, false).await?;
                        return Ok(());
                    }
                    Err(e) => {
                        warn!("STARTTLS handshake failed: {}", e);
                        return Ok(());
                    }
                }
            }
            "CAPABILITY" => {
                let caps = capability_list(false, allow_insecure_auth, true);
                let resp = format!(
                    "* CAPABILITY {}\r\n{tag} OK CAPABILITY completed\r\n",
                    caps.join(" ")
                );
                writer.write_all(resp.as_bytes()).await?;
                writer.flush().await?;
            }
            "NOOP" => {
                let resp = format!("{tag} OK NOOP completed\r\n");
                writer.write_all(resp.as_bytes()).await?;
                writer.flush().await?;
            }
            "LOGOUT" => {
                let resp = format!("* BYE Logging out\r\n{tag} OK LOGOUT completed\r\n");
                writer.write_all(resp.as_bytes()).await?;
                writer.flush().await?;
                return Ok(());
            }
            "LOGIN" | "AUTHENTICATE" => {
                // Route through the real handlers so the security policy
                // ([PRIVACYREQUIRED] unless insecure auth is enabled) and the
                // AUTHENTICATE PLAIN exchange work exactly as on TLS.
                let mut g = session.lock().await;
                let result = handle_command(
                    &mut g,
                    &tag,
                    &cmd,
                    &args,
                    &mut reader,
                    &mut writer,
                    &literals,
                )
                .await;
                let state = g.state;
                drop(g);
                if let Err(e) = result {
                    let resp = tagged_bad(&tag, &format!("Error: {}", e));
                    writer.write_all(resp.as_bytes()).await?;
                    writer.flush().await?;
                }
                if state != SessionState::NotAuthenticated {
                    // Authenticated over plaintext (only possible when
                    // IMAP_ALLOW_INSECURE_AUTH=true): continue the session.
                    return serve(session, reader, writer, false).await;
                }
            }
            _ => {
                // Per RFC 3501, before STARTTLS only CAPABILITY, NOOP, and
                // STARTTLS are allowed. Reject everything else.
                let resp = format!("{tag} BAD Command not allowed before STARTTLS\r\n");
                writer.write_all(resp.as_bytes()).await?;
                writer.flush().await?;
            }
        }
    }
}

async fn serve<R: tokio::io::AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin>(
    session: Arc<Mutex<ImapSession>>,
    reader: R,
    writer: W,
    send_greeting: bool,
) -> Result<()> {
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);

    if send_greeting {
        // RFC 3501 §6.2.1 forbids advertising STARTTLS on an already-TLS
        // connection. The greeting is only sent once per connection: on the
        // plaintext path the pre-STARTTLS loop sends it before delegating here.
        let (tls_active, allow_insecure_auth) = {
            let g = session.lock().await;
            (g.tls_active, g.allow_insecure_auth)
        };
        let greeting = greeting_line(tls_active, allow_insecure_auth, true);
        writer.write_all(greeting.as_bytes()).await?;
        writer.flush().await?;
    }

    // L1: per-connection literal budget shared by every command read below.
    let mut conn_state = ConnectionReadState::default();
    let limits = ReadLimits::default();

    loop {
        // If the session is idling, wait for DONE / mailbox updates / timeout.
        let idle_tag = {
            let g = session.lock().await;
            if g.idle {
                Some(g.tag.clone())
            } else {
                None
            }
        };
        if let Some(tag) = idle_tag {
            run_idle(&session, &mut reader, &mut writer, &tag).await?;
            continue;
        }

        // Read the next command with full literal support. Errors here mean
        // the stream is desynchronized (e.g. a truncated literal): close the
        // connection rather than trying to resync. L1: the read is bounded by
        // COMMAND_READ_TIMEOUT (plus the per-connection literal budget held
        // in `conn_state`) so abandoned or stalling sockets die with a BYE.
        let command = match read_command_bounded(
            &mut reader,
            &mut writer,
            &limits,
            &mut conn_state,
            COMMAND_READ_TIMEOUT,
        )
        .await
        {
            Ok(Some(c)) => c,
            Ok(None) => break,
            Err(e) => {
                warn!("Error reading command: {}", e);
                break;
            }
        };
        let (cmd_tag, cmd_name, cmd_args, literals) = command;

        let mut session_guard = session.lock().await;

        let result = handle_command(
            &mut session_guard,
            &cmd_tag,
            &cmd_name,
            &cmd_args,
            &mut reader,
            &mut writer,
            &literals,
        )
        .await;
        drop(session_guard);

        if let Err(e) = result {
            let resp = tagged_bad(&cmd_tag, &format!("Error: {}", e));
            writer.write_all(resp.as_bytes()).await?;
            writer.flush().await?;
        } else {
            writer.flush().await?;
        }

        let logout = session.lock().await.state == SessionState::Logout;
        if logout {
            break;
        }
    }

    Ok(())
}

fn parse_imap_line(line: &str) -> Result<(String, String, String)> {
    let line = line.trim_end();
    let first_space = line
        .find(' ')
        .ok_or_else(|| anyhow::anyhow!("No tag in command"))?;
    let tag = &line[..first_space];
    let rest = line[first_space..].trim();

    let second_space = rest.find(' ').unwrap_or(rest.len());
    let cmd = &rest[..second_space];
    let args = rest[second_space..].trim();

    Ok((tag.to_string(), cmd.to_string(), args.to_string()))
}

// ── Connection admission control (L1) ───────────────────────────────────────
//
// Without a cap, an unauthenticated client can open thousands of sockets and
// each one holds a session, buffers and a mailstore gRPC channel. The caps
// below are enforced at the accept loops (both 143 and 993 share one
// limiter). Connections beyond the cap are closed immediately with an
// untagged BYE; the slot is released when the connection task finishes.

/// Maximum simultaneous IMAP connections server-wide (both ports combined).
const MAX_TOTAL_CONNECTIONS: usize = 500;
/// Maximum simultaneous connections from a single source IP.
const MAX_CONNECTIONS_PER_IP: usize = 50;

/// Admission state for the accept loops. Guarded by a tokio Mutex; the
/// critical section is two integer comparisons, so contention is negligible.
#[derive(Debug, Default)]
struct ConnectionLimiter {
    total: usize,
    per_ip: HashMap<std::net::IpAddr, usize>,
}

impl ConnectionLimiter {
    /// Try to reserve one slot for `ip`; `false` when a cap would be exceeded.
    fn try_acquire(&mut self, ip: std::net::IpAddr) -> bool {
        if self.total >= MAX_TOTAL_CONNECTIONS {
            return false;
        }
        let slot = self.per_ip.entry(ip).or_insert(0);
        if *slot >= MAX_CONNECTIONS_PER_IP {
            return false;
        }
        *slot += 1;
        self.total += 1;
        true
    }

    /// Release the slot held for `ip`.
    fn release(&mut self, ip: std::net::IpAddr) {
        self.total = self.total.saturating_sub(1);
        if let Some(slot) = self.per_ip.get_mut(&ip) {
            *slot = slot.saturating_sub(1);
            if *slot == 0 {
                self.per_ip.remove(&ip);
            }
        }
    }
}

/// Reject an over-cap connection: say BYE and close. The write is
/// best-effort — the socket may already be gone.
async fn reject_connection(mut stream: TcpStream, reason: &str) {
    let _ = stream.write_all(bye(reason).as_bytes()).await;
    let _ = stream.shutdown().await;
}

// ── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "imap_server=info".to_string()),
        )
        .init();

    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let cli = Cli::parse();
    let mailstore_auth = InternalServiceAuthInterceptor::from_env()
        .map_err(|error| anyhow::anyhow!("invalid internal mailstore authentication: {error}"))?;

    info!(
        "IMAP server starting on {}:{} / {}:{} (mailstore={}, allow_insecure_auth={})",
        cli.listen_addr,
        cli.imap_port,
        cli.listen_addr,
        cli.imaps_port,
        cli.mailstore_addr,
        cli.allow_insecure_auth
    );

    let tls_acceptor = configure_tls(cli.tls_cert_path.as_deref(), cli.tls_key_path.as_deref())?;

    // L1: one admission limiter shared by both accept loops.
    let conn_limiter = Arc::new(Mutex::new(ConnectionLimiter::default()));

    let imap_addr = format!("{}:{}", cli.listen_addr, cli.imap_port);
    let imap_listener = TcpListener::bind(&imap_addr)
        .await
        .with_context(|| format!("Failed to bind IMAP on {}", imap_addr))?;
    info!("IMAP listener on {}", imap_addr);

    // Clone the acceptor so both the IMAPS (993) and IMAP (143) paths can use it.
    // The plaintext IMAP path needs it for STARTTLS upgrade.
    let plaintext_tls_acceptor = tls_acceptor.clone();

    let _imaps = if let Some(acceptor) = tls_acceptor {
        let imaps_addr = format!("{}:{}", cli.listen_addr, cli.imaps_port);
        let imaps_listener = TcpListener::bind(&imaps_addr)
            .await
            .with_context(|| format!("Failed to bind IMAPS on {}", imaps_addr))?;
        info!("IMAPS listener on {}", imaps_addr);

        let acceptor = acceptor.clone();
        let mailstore = cli.mailstore_addr.clone();
        let mailstore_auth = mailstore_auth.clone();
        let conn_limiter = Arc::clone(&conn_limiter);
        Some(tokio::spawn(async move {
            loop {
                match imaps_listener.accept().await {
                    Ok((stream, addr)) => {
                        if !conn_limiter.lock().await.try_acquire(addr.ip()) {
                            warn!("IMAPS connection from {} rejected: connection cap", addr);
                            let stream = stream;
                            tokio::spawn(reject_connection(
                                stream,
                                "Too many connections; try again later",
                            ));
                            continue;
                        }
                        let acceptor = acceptor.clone();
                        let mailstore = mailstore.clone();
                        let mailstore_auth = mailstore_auth.clone();
                        let limiter = Arc::clone(&conn_limiter);
                        let ip = addr.ip();
                        tokio::spawn(async move {
                            let result = handle_connection(
                                stream,
                                Some(acceptor),
                                mailstore,
                                mailstore_auth,
                                true,
                                false,
                            )
                            .await;
                            limiter.lock().await.release(ip);
                            if let Err(e) = result {
                                error!("Connection error from {}: {}", addr, e);
                            }
                        });
                    }
                    Err(e) => error!("IMAPS accept error: {}", e),
                }
            }
        }))
    } else {
        None
    };

    let mailstore = cli.mailstore_addr.clone();
    let mailstore_auth = mailstore_auth.clone();
    let allow_insecure_auth = cli.allow_insecure_auth;
    loop {
        match imap_listener.accept().await {
            Ok((stream, addr)) => {
                if !conn_limiter.lock().await.try_acquire(addr.ip()) {
                    warn!("IMAP connection from {} rejected: connection cap", addr);
                    tokio::spawn(reject_connection(
                        stream,
                        "Too many connections; try again later",
                    ));
                    continue;
                }
                let mailstore = mailstore.clone();
                let mailstore_auth = mailstore_auth.clone();
                let tls_for_plaintext = plaintext_tls_acceptor.clone();
                let limiter = Arc::clone(&conn_limiter);
                let ip = addr.ip();
                tokio::spawn(async move {
                    let result = handle_connection(
                        stream,
                        tls_for_plaintext,
                        mailstore,
                        mailstore_auth,
                        false,
                        allow_insecure_auth,
                    )
                    .await;
                    limiter.lock().await.release(ip);
                    if let Err(e) = result {
                        error!("Connection error from {}: {}", addr, e);
                    }
                });
            }
            Err(e) => error!("IMAP accept error: {}", e),
        }
    }

    #[allow(unreachable_code)]
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn auth_failure_tracker_locks_after_limit_and_clears_on_success() {
        // Unique keys so parallel tests cannot interfere via the global table.
        let ip = format!("10.9.8.7:{}", std::process::id());
        let user = "throttle-test@example.com";

        assert!(!auth_is_locked(&ip, user).await);
        for _ in 0..AUTH_FAILURE_LIMIT {
            assert!(
                !auth_is_locked(&ip, user).await,
                "must not lock before the limit is reached"
            );
            auth_record_failure(&ip, user).await;
        }
        assert!(auth_is_locked(&ip, user).await, "locked after 5 failures");

        // A successful login clears the history immediately.
        auth_clear_failures(&ip, user).await;
        assert!(!auth_is_locked(&ip, user).await);
    }

    #[test]
    fn seq_set_parses_singles_and_ranges() {
        assert_eq!(parse_sequence_set("1").unwrap(), vec![(1, 1)]);
        assert_eq!(
            parse_sequence_set("1,3,5").unwrap(),
            vec![(1, 1), (3, 3), (5, 5)]
        );
        assert_eq!(parse_sequence_set("1:5").unwrap(), vec![(1, 5)]);
        assert_eq!(parse_sequence_set("1:*").unwrap(), vec![(1, u64::MAX)]);
        assert_eq!(parse_sequence_set("*").unwrap(), vec![(u64::MAX, u64::MAX)]);
        // RFC 3501 §9: descending ranges are inclusive and normalized.
        assert_eq!(parse_sequence_set("5:2").unwrap(), vec![(2, 5)]);
        assert_eq!(parse_sequence_set("*:4").unwrap(), vec![(4, u64::MAX)]);
        assert_eq!(parse_sequence_set("0").unwrap(), vec![]);
    }

    #[test]
    fn seq_mode_resolves_against_uid_map() {
        let uid_map = vec![10, 20, 30, 40];
        let max_uid = 40;
        // seq 1:3 → uids 10,20,30
        assert_eq!(
            resolve_intervals(
                &parse_sequence_set("1:3").unwrap(),
                false,
                &uid_map,
                max_uid
            )
            .unwrap(),
            vec![10, 20, 30]
        );
        // seq * → last message
        assert_eq!(
            resolve_intervals(&parse_sequence_set("*").unwrap(), false, &uid_map, max_uid).unwrap(),
            vec![40]
        );
        // seq 2:* → 20,30,40
        assert_eq!(
            resolve_intervals(
                &parse_sequence_set("2:*").unwrap(),
                false,
                &uid_map,
                max_uid
            )
            .unwrap(),
            vec![20, 30, 40]
        );
        // out of range → empty
        assert_eq!(
            resolve_intervals(&parse_sequence_set("5").unwrap(), false, &uid_map, max_uid).unwrap(),
            Vec::<u64>::new()
        );
        // overlapping ranges dedup
        assert_eq!(
            resolve_intervals(
                &parse_sequence_set("1:3,2:4").unwrap(),
                false,
                &uid_map,
                max_uid
            )
            .unwrap(),
            vec![10, 20, 30, 40]
        );
    }

    #[test]
    fn uid_mode_resolves_against_max_uid() {
        let uid_map = vec![10, 20, 30, 40];
        let max_uid = 40;
        // UID 20:30 → 20,30
        assert_eq!(
            resolve_intervals(
                &parse_sequence_set("20:30").unwrap(),
                true,
                &uid_map,
                max_uid
            )
            .unwrap(),
            vec![20, 30]
        );
        // UID * → max uid
        assert_eq!(
            resolve_intervals(&parse_sequence_set("*").unwrap(), true, &uid_map, max_uid).unwrap(),
            vec![40]
        );
        // UID 15:* → 20,30,40
        assert_eq!(
            resolve_intervals(
                &parse_sequence_set("15:*").unwrap(),
                true,
                &uid_map,
                max_uid
            )
            .unwrap(),
            vec![20, 30, 40]
        );
        // sparse: only existing uids in range
        assert_eq!(
            resolve_intervals(
                &parse_sequence_set("10:25").unwrap(),
                true,
                &uid_map,
                max_uid
            )
            .unwrap(),
            vec![10, 20]
        );
        // empty mailbox
        assert_eq!(
            resolve_intervals(&parse_sequence_set("1:*").unwrap(), true, &[], 0).unwrap(),
            Vec::<u64>::new()
        );
    }

    #[test]
    fn star_ranges_always_include_last_message() {
        let uid_map = vec![10, 20, 30, 40];
        let max_uid = 40;
        // UID 100:* with max UID 40 → RFC 3501 §9: always includes the last.
        assert_eq!(
            resolve_intervals(
                &parse_sequence_set("100:*").unwrap(),
                true,
                &uid_map,
                max_uid
            )
            .unwrap(),
            vec![40]
        );
        // Descending wildcard range *:30 → 30..max
        assert_eq!(
            resolve_intervals(
                &parse_sequence_set("*:30").unwrap(),
                true,
                &uid_map,
                max_uid
            )
            .unwrap(),
            vec![30, 40]
        );
        // Sequence mode: seq 5:* on a 4-message mailbox → the last message.
        assert_eq!(
            resolve_intervals(
                &parse_sequence_set("5:*").unwrap(),
                false,
                &uid_map,
                max_uid
            )
            .unwrap(),
            vec![40]
        );
        // Sequence mode descending: *:2 → messages 2..=4
        assert_eq!(
            resolve_intervals(
                &parse_sequence_set("*:2").unwrap(),
                false,
                &uid_map,
                max_uid
            )
            .unwrap(),
            vec![20, 30, 40]
        );
        // Ranges entirely above the mailbox without a wildcard stay empty.
        assert_eq!(
            resolve_intervals(
                &parse_sequence_set("100:200").unwrap(),
                true,
                &uid_map,
                max_uid
            )
            .unwrap(),
            Vec::<u64>::new()
        );
    }

    #[test]
    fn literal_spec_parses_sync_async_and_binary() {
        assert_eq!(parse_literal_spec("{1234}").unwrap(), (1234, false));
        assert_eq!(parse_literal_spec("{1234+}").unwrap(), (1234, true));
        assert_eq!(parse_literal_spec("~{42}").unwrap(), (42, false));
        assert!(parse_literal_spec("nope").is_err());
        assert!(parse_literal_spec("{abc}").is_err());
    }

    #[test]
    fn pattern_matching_supports_star_and_percent() {
        assert!(imap_pattern_match("INBOX", "*"));
        assert!(imap_pattern_match("INBOX", "INBOX"));
        assert!(imap_pattern_match("INBOX.Archive", "INBOX*"));
        assert!(imap_pattern_match("Archive", "*"));
        assert!(!imap_pattern_match("Trash", "INBOX*"));
        // % does not cross the hierarchy delimiter
        assert!(imap_pattern_match("Work", "%"));
        assert!(imap_pattern_match("Work/Project", "Work/*"));
        assert!(imap_pattern_match("Work/Project", "Work/%"));
        assert!(!imap_pattern_match("Work/Project/Sub", "Work/%"));
        assert!(imap_pattern_match("", "*"));
        assert!(!imap_pattern_match("x", ""));
    }

    #[test]
    fn tokenizer_keeps_quoted_and_parenthesized_tokens() {
        let toks = tokenize_command_args("\"My Folder\" (\\Seen \\Flagged) {1234}");
        assert_eq!(toks.len(), 3);
        assert_eq!(toks[0], "\"My Folder\"");
        assert_eq!(toks[1], "(\\Seen \\Flagged)");
        assert_eq!(toks[2], "{1234}");
        let toks = tokenize_command_args("INBOX {100+}");
        assert_eq!(toks, vec!["INBOX", "{100+}"]);
    }

    #[test]
    fn header_text_splitting() {
        let raw = b"From: a@b\r\nSubject: hi\r\n\r\nbody line\r\n";
        let (h, t) = header_and_text(raw);
        assert_eq!(h, b"From: a@b\r\nSubject: hi\r\n\r\n");
        assert_eq!(t, b"body line\r\n");
        // No blank line: everything is header.
        let (h, _) = header_and_text(b"From: a@b\r\nSubject: hi\r\n");
        assert_eq!(h, b"From: a@b\r\nSubject: hi\r\n");
    }

    #[test]
    fn capability_advertisement_respects_security_policy() {
        let tls = capability_list(true, false, true);
        assert!(tls.contains(&"AUTH=PLAIN"));
        assert!(!tls.contains(&"STARTTLS"));
        let plain = capability_list(false, false, true);
        assert!(plain.contains(&"STARTTLS"));
        assert!(plain.contains(&"LOGINDISABLED"));
        assert!(!plain.contains(&"AUTH=PLAIN"));
        let plain_allow = capability_list(false, true, true);
        assert!(plain_allow.contains(&"STARTTLS"));
        assert!(plain_allow.contains(&"AUTH=PLAIN"));
        assert!(!plain_allow.contains(&"LOGINDISABLED"));
        // No TLS cert configured: STARTTLS must not be advertised.
        let no_starttls = capability_list(false, false, false);
        assert!(!no_starttls.contains(&"STARTTLS"));
        assert!(no_starttls.contains(&"LOGINDISABLED"));
    }

    #[test]
    fn unquote_processes_backslash_escapes() {
        assert_eq!(unquote("\"plain\""), "plain");
        assert_eq!(unquote("\"a\\\"b\""), "a\"b");
        assert_eq!(unquote("\"a\\\\b\""), "a\\b");
        assert_eq!(unquote("\"INBOX/\\\\Sent\""), "INBOX/\\Sent");
        assert_eq!(unquote("atom"), "atom");
        assert_eq!(unquote("\"trailing\\\\\""), "trailing\\");
    }

    #[test]
    fn tokenizer_keeps_escaped_quotes_inside_quoted_strings() {
        let toks = tokenize_command_args("\"a\\\"b\" c");
        assert_eq!(toks.len(), 2);
        assert_eq!(toks[0], "\"a\\\"b\"");
        assert_eq!(toks[1], "c");
        let toks = tokenize_command_args("\"My Folder\" (\\Seen \\Flagged) {1234}");
        assert_eq!(toks.len(), 3);
        assert_eq!(toks[0], "\"My Folder\"");
        assert_eq!(toks[1], "(\\Seen \\Flagged)");
        assert_eq!(toks[2], "{1234}");
        let toks = tokenize_command_args("INBOX {100+}");
        assert_eq!(toks, vec!["INBOX", "{100+}"]);
    }

    #[test]
    fn utf7_round_trips_mailbox_names() {
        assert_eq!(imap_utf7_decode("&g0l6Pw-"), "草稿");
        assert_eq!(imap_utf7_encode("草稿"), "&g0l6Pw-");
        assert_eq!(imap_utf7_encode("Sent"), "Sent");
        assert_eq!(imap_utf7_decode("Sent"), "Sent");
        assert_eq!(imap_utf7_encode("a&b"), "a&-b");
        assert_eq!(imap_utf7_decode("a&-b"), "a&b");
        assert_eq!(imap_utf7_encode("已发送"), "&XfJT0ZAB-");
        assert_eq!(imap_utf7_decode("&XfJT0ZAB-"), "已发送");
        // ASCII mixed with non-ASCII
        let mixed = "Work/项目";
        assert_eq!(imap_utf7_decode(&imap_utf7_encode(mixed)), mixed);
        // Invalid sequences pass through
        assert_eq!(imap_utf7_decode("plain&name"), "plain&name");
    }

    #[test]
    fn literal_spec_scanner_finds_token_boundary_literals() {
        assert_eq!(
            find_literal_spec("SEARCH HEADER Subject {5}"),
            Some((22, 25, 5, false))
        );
        assert_eq!(find_literal_spec("LOGIN {5} {6}"), Some((6, 9, 5, false)));
        assert_eq!(
            find_literal_spec("APPEND INBOX {100+}"),
            Some((13, 19, 100, true))
        );
        // Inside quoted strings literals are not specs
        assert_eq!(find_literal_spec("SEARCH SUBJECT \"{5}\""), None);
        // Not at a token boundary
        assert_eq!(find_literal_spec("BODY[]{5}"), None);
        // No closing brace
        assert_eq!(find_literal_spec("SEARCH {5"), None);
        assert_eq!(find_literal_spec("SEARCH {abc}"), None);
    }

    #[test]
    fn literal_markers_resolve() {
        let literals = vec![b"hello".to_vec(), b"world".to_vec()];
        assert_eq!(resolve_token("\x01LIT0\x01", &literals), "hello");
        assert_eq!(resolve_token("\x01LIT1\x01", &literals), "world");
        assert_eq!(resolve_token("\"quoted\"", &literals), "quoted");
        assert_eq!(literal_index("\x01LIT0\x01"), Some(0));
        assert_eq!(literal_index("plain"), None);
        assert_eq!(
            token_literal_bytes("\x01LIT1\x01", &literals),
            Some(b"world".as_slice())
        );
        assert_eq!(token_literal_bytes("plain", &literals), None);
    }

    #[tokio::test]
    async fn read_command_handles_sync_literal_in_login() {
        use tokio::io::AsyncWriteExt;
        let (mut client_io, server_io) = tokio::io::duplex(1 << 16);
        let (server_r, mut server_w) = tokio::io::split(server_io);
        let mut reader = BufReader::new(server_r);

        let client_task = tokio::spawn(async move {
            client_io.write_all(b"a1 LOGIN {5}\r\n").await.unwrap();
            let mut buf = [0u8; 64];
            let n = client_io.read(&mut buf).await.unwrap();
            assert!(
                String::from_utf8_lossy(&buf[..n]).starts_with('+'),
                "expected continuation prompt, got {:?}",
                String::from_utf8_lossy(&buf[..n])
            );
            client_io
                .write_all(b"admin {6}\r\nsecret\r\n")
                .await
                .unwrap();
            // Keep the stream open until the server side is dropped below.
            let mut sink = [0u8; 8];
            let _ = client_io.read(&mut sink).await;
        });

        let (tag, cmd, args, literals) = read_command(&mut reader, &mut server_w)
            .await
            .unwrap()
            .unwrap();
        drop(reader);
        drop(server_w);
        client_task.await.unwrap();

        assert_eq!(tag, "a1");
        assert_eq!(cmd, "LOGIN");
        let tokens = tokenize_command_args(&args);
        assert_eq!(resolve_token(&tokens[0], &literals), "admin");
        assert_eq!(resolve_token(&tokens[1], &literals), "secret");
    }

    #[tokio::test]
    async fn read_command_handles_literal_plus_and_crlf_inside_data() {
        use tokio::io::AsyncWriteExt;
        let (mut client_io, server_io) = tokio::io::duplex(1 << 16);
        let (server_r, mut server_w) = tokio::io::split(server_io);
        let mut reader = BufReader::new(server_r);

        // LITERAL+ (no continuation) with embedded CRLF in the data.
        let client_task = tokio::spawn(async move {
            client_io
                .write_all(b"a2 APPEND INBOX {6+}\r\nab\r\ncd\r\n")
                .await
                .unwrap();
            // No continuation prompt should arrive for {8+}: a read returns
            // EOF once the server side of the duplex is dropped below.
            let mut buf = [0u8; 16];
            let n = client_io.read(&mut buf).await.unwrap();
            assert_eq!(
                n,
                0,
                "unexpected data: {:?}",
                String::from_utf8_lossy(&buf[..n])
            );
        });

        let (tag, cmd, args, literals) = read_command(&mut reader, &mut server_w)
            .await
            .unwrap()
            .unwrap();
        drop(reader);
        drop(server_w);
        client_task.await.unwrap();

        assert_eq!(tag, "a2");
        assert_eq!(cmd, "APPEND");
        let tokens = tokenize_command_args(&args);
        assert_eq!(resolve_token(&tokens[0], &literals), "INBOX");
        assert_eq!(
            token_literal_bytes(&tokens[1], &literals),
            Some(b"ab\r\ncd".as_slice())
        );
    }

    #[tokio::test]
    async fn read_command_reports_truncated_literal() {
        use tokio::io::AsyncWriteExt;
        let (mut client_io, server_io) = tokio::io::duplex(1 << 16);
        let (server_r, mut server_w) = tokio::io::split(server_io);
        let mut reader = BufReader::new(server_r);

        // Client declares {10} but sends only 3 bytes, then closes.
        let client_task = tokio::spawn(async move {
            client_io
                .write_all(b"a3 SEARCH HEADER Subject {10}\r\nabc")
                .await
                .unwrap();
            let mut buf = [0u8; 16];
            let n = client_io.read(&mut buf).await.unwrap();
            assert!(String::from_utf8_lossy(&buf[..n]).starts_with('+'));
            drop(client_io);
        });

        let result = read_command(&mut reader, &mut server_w).await;
        client_task.await.unwrap();
        assert!(
            result.is_err(),
            "truncated literal must be an error, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn read_command_ignores_blank_lines_between_commands() {
        use tokio::io::AsyncWriteExt;
        let (mut client_io, server_io) = tokio::io::duplex(1 << 16);
        let (server_r, mut server_w) = tokio::io::split(server_io);
        let mut reader = BufReader::new(server_r);

        let client_task = tokio::spawn(async move {
            client_io.write_all(b"\r\n\r\na4 NOOP\r\n").await.unwrap();
        });

        let (tag, cmd, args, _) = read_command(&mut reader, &mut server_w)
            .await
            .unwrap()
            .unwrap();
        client_task.await.unwrap();
        assert_eq!(tag, "a4");
        assert_eq!(cmd, "NOOP");
        assert_eq!(args, "");
    }

    // ── N(1): per-IP aggregate lockout ─────────────────────────────────────

    #[tokio::test]
    async fn auth_ip_aggregate_lockout_blocks_username_spraying() {
        // Unique IPs so parallel tests cannot interfere via the global table.
        let ip = format!("10.44.44.44:{}", std::process::id());
        let other_ip = format!("10.44.44.45:{}", std::process::id());

        // Each individual (ip, username) pair stays below the per-pair limit.
        for i in 0..AUTH_IP_FAILURE_LIMIT {
            let user = format!("spray-{}@example.com", i);
            assert!(
                !auth_is_locked(&ip, &user).await,
                "per-pair limit must not trigger with one failure each"
            );
            auth_record_failure(&ip, &user).await;
        }

        // ...but the per-IP aggregate now locks every user from that IP,
        // including brand-new ones.
        assert!(auth_is_locked(&ip, "fresh-victim@example.com").await);

        // A different source IP is unaffected (no cross-tenant lockout).
        assert!(!auth_is_locked(&other_ip, "fresh-victim@example.com").await);
    }

    // ── A: sequence-set bombs ──────────────────────────────────────────────

    #[test]
    fn seq_set_interval_count_is_bounded() {
        // 50k `1:*` intervals in one command must be rejected at parse time,
        // before any mailbox expansion happens.
        let bomb = "1:*,".repeat(50_000);
        let started = std::time::Instant::now();
        let res = parse_sequence_set(&bomb);
        let elapsed = started.elapsed();
        assert!(res.is_err(), "50k intervals must be BAD");
        assert!(
            elapsed < Duration::from_secs(1),
            "parse took too long: {:?}",
            elapsed
        );
        assert!(res.unwrap_err().to_string().contains("Too many intervals"));

        // Exactly at the cap is still accepted.
        let at_cap = "1,".repeat(MAX_SEQ_INTERVALS);
        assert!(parse_sequence_set(at_cap.trim_end_matches(',')).is_ok());
    }

    #[test]
    fn seq_set_resolution_bomb_is_rejected_fast() {
        // A view LARGER than the resolution cap: resolving everything must
        // fail fast at the cap instead of materializing an unbounded set.
        let big_map: Vec<u64> = (1..=(MAX_RESOLVED_UIDS as u64 + 1)).collect();
        let started = std::time::Instant::now();
        let res = resolve_intervals(&[(1, u64::MAX)], true, &big_map, big_map.len() as u64);
        let elapsed = started.elapsed();
        assert!(res.is_err(), "resolving past the cap must fail");
        assert!(
            elapsed < Duration::from_secs(2),
            "resolution took too long: {:?}",
            elapsed
        );
        // Repeated hostile ranges do not multiply the work: they collapse.
        let dupes = vec![(1u64, u64::MAX); MAX_SEQ_INTERVALS];
        let started = std::time::Instant::now();
        let res2 = resolve_intervals(&dupes, true, &big_map, big_map.len() as u64);
        assert!(res2.is_err());
        assert!(started.elapsed() < Duration::from_secs(2));

        // Exactly AT the cap passes: 1000 x 1:* over a 50k view resolves once.
        let uid_map: Vec<u64> = (1..=50_000u64).collect();
        let dupes = vec![(1u64, u64::MAX); 1_000];
        let resolved = resolve_intervals(&dupes, true, &uid_map, 50_000).unwrap();
        assert_eq!(resolved.len(), 50_000);
    }

    // ── I(1): wildcard matching with proper % backtracking ────────────────

    #[test]
    fn percent_backtracking_cases() {
        // The classic case the old single-backtrack scanner got wrong.
        assert!(imap_pattern_match("aab", "%ab"));
        assert!(imap_pattern_match("aaab", "%ab"));
        assert!(imap_pattern_match("ab", "%ab")); // % matches empty
        assert!(!imap_pattern_match("ba", "%ab"));
        assert!(!imap_pattern_match("ab", "%aab"));
        // Multiple wildcards requiring backtracking.
        assert!(imap_pattern_match("xaybz", "x%y%z"));
        assert!(!imap_pattern_match("xayz", "x%y%w"));
        // Delimiter semantics: % never crosses '/'.
        assert!(!imap_pattern_match("Work/Project", "%"));
        assert!(imap_pattern_match("Work", "%"));
        assert!(imap_pattern_match("Work/Project", "%/%"));
        assert!(!imap_pattern_match("Work/Project/Sub", "%/%"));
        assert!(!imap_pattern_match("a/b", "a%"));
        assert!(imap_pattern_match("ab", "a%"));
        assert!(imap_pattern_match("", "%"));
        assert!(imap_pattern_match("", "*"));
        // * still crosses the delimiter.
        assert!(imap_pattern_match("Work/Project", "*"));
        assert!(imap_pattern_match("Work/Project", "Work/*"));
        // Case folding.
        assert!(imap_pattern_match("InBoX", "inbox%"));
    }

    // ── I(2)/(3): MOVE EXPUNGE wire output + O(n) retain ──────────────────

    #[test]
    fn expunge_seqs_descending_and_retain_except() {
        let mut uid_map = vec![10, 20, 30, 40, 50];
        let seqs = expunge_seqs_descending(&uid_map, &[20, 50]);
        assert_eq!(seqs, vec![5, 2]);
        assert_eq!(
            expunge_response_lines(&seqs),
            "* 5 EXPUNGE\r\n* 2 EXPUNGE\r\n"
        );
        retain_except(&mut uid_map, &[20, 50]);
        assert_eq!(uid_map, vec![10, 30, 40]);
        // UIDs not present are ignored.
        assert_eq!(expunge_seqs_descending(&uid_map, &[999]), Vec::<u32>::new());
    }

    #[test]
    fn retain_except_handles_large_sets_fast() {
        // Loose performance assertion: 100k view x 50k removals must finish
        // quickly with the HashSet implementation (the naive contains() loop
        // is quadratic).
        let mut big: Vec<u64> = (0..100_000u64).map(|i| i * 2).collect();
        let to_remove: Vec<u64> = (0..50_000u64).map(|i| i * 4).collect();
        let started = std::time::Instant::now();
        retain_except(&mut big, &to_remove);
        let elapsed = started.elapsed();
        assert_eq!(big.len(), 50_000);
        assert!(elapsed < Duration::from_secs(2), "took {:?}", elapsed);
    }

    // ── E: SEARCH criteria token cap ───────────────────────────────────────

    #[test]
    fn search_token_cap_rejects_criteria_bomb() {
        let bomb = "SEEN ".repeat(100_000);
        let started = std::time::Instant::now();
        let res = collect_search_tokens(&bomb, &[]);
        let elapsed = started.elapsed();
        assert!(res.is_err(), "100k criteria tokens must be BAD");
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("Too many SEARCH criteria"));
        assert!(elapsed < Duration::from_secs(1));

        // Normal searches pass through unchanged.
        let ok = collect_search_tokens("SEEN UNSEEN SUBJECT \"hello world\"", &[]).unwrap();
        assert_eq!(ok.len(), 4);
        assert_eq!(ok[3], "hello world");
    }

    // ── H: literal budget ──────────────────────────────────────────────────

    #[test]
    fn literal_budget_unit_matrix() {
        const MB: usize = 1024 * 1024;
        let limits = ReadLimits::default();
        // Single literal within per-literal and total caps.
        assert!(literal_within_budget(0, 0, 32 * MB, &limits, 0));
        // A single literal over MAX_LITERAL_SIZE fails.
        assert!(!literal_within_budget(0, 0, 32 * MB + 1, &limits, 0));
        // The "100 x 32MB" scenario: two 32MB literals total exactly 64MB
        // (allowed at the cap), one byte more is refused.
        assert!(literal_within_budget(1, 32 * MB, 32 * MB, &limits, 0));
        assert!(!literal_within_budget(1, 32 * MB, 32 * MB + 1, &limits, 0));
        // Count cap: the 65th literal is refused regardless of size.
        assert!(!literal_within_budget(
            limits.max_literals_per_command,
            0,
            1,
            &limits,
            0
        ));
        assert!(literal_within_budget(
            limits.max_literals_per_command - 1,
            0,
            1,
            &limits,
            0
        ));
        // Total saturates instead of overflowing.
        assert!(!literal_within_budget(0, usize::MAX, 1, &limits, 0));
        // L1: the per-connection cumulative cap refuses literals that are
        // individually legal once the connection's budget is spent.
        assert!(!literal_within_budget(
            0,
            0,
            32 * MB,
            &limits,
            limits.max_total_per_connection
        ));
        assert!(literal_within_budget(0, 0, 32 * MB, &limits, 0));
    }

    #[tokio::test]
    async fn read_command_rejects_literal_count_bomb() {
        use tokio::io::AsyncWriteExt;
        let (mut client_io, server_io) = tokio::io::duplex(1 << 16);
        let (server_r, mut server_w) = tokio::io::split(server_io);
        let mut reader = BufReader::new(server_r);

        let client_task = tokio::spawn(async move {
            client_io
                .write_all(b"a5 APPEND INBOX {1+}\r\n")
                .await
                .unwrap();
            client_io.write_all(b"x").await.unwrap();
            // 63 more one-byte LITERAL+ literals.
            for _ in 1..MAX_LITERALS_PER_COMMAND {
                client_io.write_all(b"x {1+}\r\n").await.unwrap();
                client_io.write_all(b"x").await.unwrap();
            }
            // The (MAX+1)-th literal spec must be rejected before any data
            // is read for it.
            client_io.write_all(b"x {1+}\r\n").await.unwrap();
            let mut sink = [0u8; 8];
            let _ = client_io.read(&mut sink).await;
        });

        let result = read_command(&mut reader, &mut server_w).await;
        // Drop the server halves so the client's trailing read sees EOF.
        drop(reader);
        drop(server_w);
        client_task.await.unwrap();
        assert!(
            result.is_err(),
            "literal count bomb must be an error, got {:?}",
            result
        );
        assert!(result.unwrap_err().to_string().contains("budget"));
    }

    // ── D: FETCH response emission ─────────────────────────────────────────

    /// Minimal synchronous AsyncWrite sink for capturing wire output.
    struct VecWriter(Vec<u8>);

    impl VecWriter {
        fn new() -> Self {
            Self(Vec::new())
        }

        fn output(&self) -> String {
            String::from_utf8_lossy(&self.0).into_owned()
        }
    }

    impl AsyncWrite for VecWriter {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.0.extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn emit_fetch_response_writes_body_literal() {
        let mut w = VecWriter::new();
        let meta = mail_proto::MessageMeta {
            uid: 7,
            size: 25,
            internal_date: 0,
            flags: Some(MessageFlags::default()),
            envelope: Some(mail_proto::EmailEnvelope {
                subject: "hi".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        // (is_uid=true below prepends the UID attribute, so the item list
        // mirrors a real `UID FETCH ... FLAGS BODY.PEEK[TEXT]` command.)
        let items = vec![
            FetchItem::Flags,
            FetchItem::Body {
                section: BodySection::Text,
                peek: true,
                name: "BODY[TEXT]".to_string(),
                partial: None,
            },
        ];
        let body = Ok(GetMessageBody {
            body: b"From: a\r\n\r\nhello world".to_vec(),
        });
        emit_fetch_response(&mut w, 7, 2, &meta, &items, Some(&body), true, false, false)
            .await
            .unwrap();
        let out = w.output();
        assert!(
            out.starts_with("* 2 FETCH (UID 7 FLAGS () BODY[TEXT] {11}\r\n"),
            "unexpected wire output: {:?}",
            out
        );
        assert!(out.ends_with("hello world)\r\n"), "got {:?}", out);
    }

    #[tokio::test]
    async fn emit_fetch_response_body_error_skips_only_body() {
        let mut w = VecWriter::new();
        let meta = mail_proto::MessageMeta {
            uid: 9,
            size: 0,
            ..Default::default()
        };
        let items = vec![
            FetchItem::Uid,
            FetchItem::Body {
                section: BodySection::Full,
                peek: true,
                name: "BODY[]".to_string(),
                partial: None,
            },
        ];
        // L12: with a Status-typed error the handler aborts with NO before
        // emitting; emit still degrades gracefully if reached directly.
        let body: Result<GetMessageBody, tonic::Status> =
            Err(tonic::Status::internal("backend down"));
        emit_fetch_response(
            &mut w,
            9,
            1,
            &meta,
            &items,
            Some(&body),
            false,
            false,
            false,
        )
        .await
        .unwrap();
        let out = w.output();
        // Metadata attrs still emitted; only the failed BODY attribute is
        // omitted rather than failing the whole FETCH.
        assert_eq!(out, "* 1 FETCH (UID 9)\r\n");
    }

    // ── B: RENAME flow against a mock mailstore ────────────────────────────

    struct MockRenameApi {
        /// Current source mailbox contents (UIDs).
        uids: Vec<u64>,
        created: Vec<String>,
        moved: Vec<u64>,
        deleted: Vec<String>,
        list_calls: usize,
        /// Fail the move when it contains this UID.
        fail_move_for: Option<u64>,
        /// Simulate a swallowed/failed removal: move "succeeds" but this UID
        /// stays in the source.
        keep_in_source: Option<u64>,
    }

    impl MockRenameApi {
        fn new(uids: Vec<u64>) -> Self {
            Self {
                uids,
                created: Vec::new(),
                moved: Vec::new(),
                deleted: Vec::new(),
                list_calls: 0,
                fail_move_for: None,
                keep_in_source: None,
            }
        }
    }

    impl RenameApi for MockRenameApi {
        fn create_mailbox(
            &mut self,
            _account_id: &str,
            name: &str,
        ) -> futures::future::BoxFuture<'_, anyhow::Result<()>> {
            self.created.push(name.to_string());
            Box::pin(std::future::ready(Ok(())))
        }

        fn list_page(
            &mut self,
            _account_id: &str,
            _mailbox: &str,
            uid_min: u64,
            uid_max: u64,
            limit: u32,
        ) -> futures::future::BoxFuture<'_, anyhow::Result<Vec<u64>>> {
            self.list_calls += 1;
            // Mimic the real backend: the NEWEST `limit` UIDs within
            // [uid_min, uid_max], returned ascending.
            let in_range: Vec<u64> = self
                .uids
                .iter()
                .copied()
                .filter(|&u| u >= uid_min && u <= uid_max)
                .collect();
            let take = (limit as usize).min(in_range.len());
            let mut page: Vec<u64> = in_range[in_range.len() - take..].to_vec();
            page.sort_unstable();
            Box::pin(std::future::ready(Ok(page)))
        }

        fn move_messages(
            &mut self,
            _account_id: &str,
            _source: &str,
            _dest: &str,
            uids: Vec<u64>,
        ) -> futures::future::BoxFuture<'_, anyhow::Result<()>> {
            if let Some(doomed) = self.fail_move_for {
                if uids.contains(&doomed) {
                    return Box::pin(std::future::ready(Err(anyhow::anyhow!(
                        "move failed for uid {}",
                        doomed
                    ))));
                }
            }
            self.moved.extend(uids.iter().copied());
            let keep = self.keep_in_source;
            let page: HashSet<u64> = uids.iter().copied().collect();
            self.uids.retain(|u| !page.contains(u) || keep == Some(*u));
            Box::pin(std::future::ready(Ok(())))
        }

        fn delete_mailbox(
            &mut self,
            _account_id: &str,
            name: &str,
        ) -> futures::future::BoxFuture<'_, anyhow::Result<()>> {
            self.deleted.push(name.to_string());
            Box::pin(std::future::ready(Ok(())))
        }
    }

    #[tokio::test]
    async fn rename_success_moves_everything_and_deletes_source() {
        let mut api = MockRenameApi::new((1..=1000).collect());
        let res = rename_mailbox_flow(&mut api, "acct", "Old", "New").await;
        assert!(res.is_ok(), "got {:?}", res);
        assert_eq!(api.moved.len(), 1000);
        assert!(api.created == vec!["New".to_string()]);
        assert_eq!(api.deleted, vec!["Old".to_string()]);
    }

    #[tokio::test]
    async fn rename_move_failure_returns_error_and_never_deletes_source() {
        let mut api = MockRenameApi::new(vec![1, 2, 3]);
        api.fail_move_for = Some(2);
        let res = rename_mailbox_flow(&mut api, "acct", "Old", "New").await;
        assert!(res.is_err());
        assert!(
            res.unwrap_err().contains("could not move messages"),
            "must surface the move failure"
        );
        assert!(api.deleted.is_empty(), "source mailbox must survive");
        // Untouched messages still live in the source.
        assert!(api.uids.contains(&1) && api.uids.contains(&3));
    }

    #[tokio::test]
    async fn rename_pages_mailboxes_larger_than_one_page() {
        // 2.5 pages worth of messages: every one must be moved.
        let total = (RENAME_PAGE_SIZE as usize * 5) / 2;
        let mut api = MockRenameApi::new((1..=total as u64).collect());
        let res = rename_mailbox_flow(&mut api, "acct", "Old", "New").await;
        assert!(res.is_ok(), "got {:?}", res);
        assert_eq!(api.moved.len(), total, "overflow beyond one page moved too");
        assert!(api.list_calls >= 3, "expected multiple pages");
        assert_eq!(api.deleted, vec!["Old".to_string()]);
    }

    #[tokio::test]
    async fn rename_refuses_to_delete_nonempty_source() {
        // A message that "fails to move" silently (or arrives concurrently)
        // must prevent the source deletion — the old code cascade-deleted it.
        let mut api = MockRenameApi::new((1..=10).collect());
        api.keep_in_source = Some(7);
        let res = rename_mailbox_flow(&mut api, "acct", "Old", "New").await;
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("rename incomplete"));
        assert!(api.deleted.is_empty(), "source mailbox must survive");
    }

    // ── F5: BODY/BODYSTRUCTURE now parse to structure items ───────────────

    #[test]
    fn fetch_bodystructure_and_bare_body_parse_to_structure_items() {
        // F5: both used to be a tagged BAD ("not implemented"); the FULL
        // macro requires them (ALL + BODYSTRUCTURE, peek), so they are real
        // items now — NOT the old silent ALL substitution.
        assert_eq!(
            parse_fetch_items("BODYSTRUCTURE").unwrap(),
            vec![FetchItem::BodyStructure { extended: true }]
        );
        assert_eq!(
            parse_fetch_items("BODY").unwrap(),
            vec![FetchItem::BodyStructure { extended: false }]
        );
        // An empty item list is still a syntax error, not ALL.
        assert!(parse_fetch_items("").is_err());
        assert!(parse_fetch_items("()").is_err());
        // Unknown items are still BAD.
        assert!(parse_fetch_items("MADEUP").is_err());
    }

    // ── F5: the FULL macro expands to ALL + BODYSTRUCTURE and peeks ───────

    #[test]
    fn full_macro_expands_to_all_plus_bodystructure_peek() {
        let expanded = resolve_macro_item(&FetchItem::Full);
        assert_eq!(
            expanded,
            vec![
                FetchItem::Flags,
                FetchItem::InternalDate,
                FetchItem::Envelope,
                FetchItem::BodyStructure { extended: true },
            ]
        );
        // FULL needs the raw message to derive the structure, but it must
        // NOT set \Seen (peek semantics).
        assert!(body_item_needs_content(&FetchItem::Full));
        assert!(!body_item_sets_seen(&FetchItem::Full));
        assert!(!body_item_sets_seen(&FetchItem::BodyStructure {
            extended: true
        }));
        // Non-peek BODY[] still sets \Seen.
        assert!(body_item_sets_seen(&FetchItem::Body {
            section: BodySection::Full,
            peek: false,
            name: "BODY[]".to_string(),
            partial: None,
        }));
    }

    // ── F5: BODYSTRUCTURE rendering ────────────────────────────────────────

    #[test]
    fn body_structure_renders_text_and_multipart() {
        let raw = b"Content-Type: text/plain; charset=us-ascii\r\n\
                    Content-Transfer-Encoding: 8BIT\r\n\
                    Subject: hi\r\n\
                    \r\n\
                    line1\r\nline2\r\n";
        // Non-extended BODY: type, subtype, params, id, description,
        // encoding, size, lines.
        assert_eq!(
            format_body_structure(raw, false),
            "(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"us-ascii\") NIL NIL \"8BIT\" 14 2)"
        );
        // Extended adds the extension data (md5, disposition, language,
        // location); a part without Content-Disposition renders NIL.
        assert!(
            format_body_structure(raw, true)
                .starts_with("(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"us-ascii\") NIL NIL \"8BIT\" 14 2 NIL NIL NIL NIL)"),
            "got: {}",
            format_body_structure(raw, true)
        );

        let multipart = concat!(
            "Content-Type: multipart/mixed; boundary=\"XX\"\r\n",
            "\r\n",
            "preamble\r\n",
            "--XX\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "part one\r\n",
            "--XX\r\n",
            "Content-Type: application/octet-stream; name=\"a.bin\"\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "Content-Disposition: attachment; filename=\"a.bin\"\r\n",
            "\r\n",
            "AAAA\r\n",
            "--XX--\r\n",
            "epilogue\r\n"
        );
        let structure = format_body_structure(multipart.as_bytes(), true);
        // Multipart: ("MIXED" part part ext...) — no size/lines fields for
        // the container; "part one" is 8 octets / 0 lines. The multipart's
        // extension data starts with ITS OWN Content-Type params (boundary).
        assert!(
            structure.starts_with("(\"MIXED\" (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 8 0 "),
            "got: {}",
            structure
        );
        assert!(
            structure.ends_with("(\"BOUNDARY\" \"XX\") NIL NIL NIL)"),
            "multipart extension must be params/disp/lang/loc, got: {}",
            structure
        );
        assert!(
            structure.contains(
                "(\"APPLICATION\" \"OCTET-STREAM\" (\"NAME\" \"a.bin\") NIL NIL \"BASE64\" 4"
            ),
            "got: {}",
            structure
        );
        // The extended part carries the disposition from Content-Disposition.
        assert!(
            structure
                .contains("\"BASE64\" 4 NIL (\"ATTACHMENT\" (\"FILENAME\" \"a.bin\")) NIL NIL)"),
            "extended fields with disposition expected, got: {}",
            structure
        );
    }

    // ── F4: STORE/APPEND flag-token matching ──────────────────────────────

    #[test]
    fn store_flags_match_system_flags_case_insensitively() {
        let flags = store_flags_from_tokens(&[
            "\\seen".to_string(),
            "\\ANSWERED".to_string(),
            "\\Flagged".to_string(),
            "\\draft".to_string(),
        ]);
        assert!(flags.seen && flags.answered && flags.flagged && flags.draft);
        assert!(!flags.deleted);
        assert!(flags.custom.is_empty());
    }

    #[test]
    fn store_flags_keep_unknown_backslash_tokens_as_keywords() {
        let flags = store_flags_from_tokens(&[
            "\\Seen".to_string(),
            "MyKeyword".to_string(),
            "\\CustomThing".to_string(),
            "\\RECENT".to_string(),
        ]);
        assert!(flags.seen);
        assert!(!flags.recent, "\\Recent is not client-settable");
        // Unknown backslash tokens survive as keywords (round-trip via
        // labels) instead of being dropped silently; \Recent is dropped.
        assert_eq!(flags.custom, vec!["MyKeyword", "\\CustomThing"]);
    }

    // ── F10: nstring encoding ──────────────────────────────────────────────

    #[test]
    fn nstring_quoting_escapes_only_quote_and_backslash() {
        assert_eq!(encode_nstring("plain"), "\"plain\"");
        assert_eq!(encode_nstring(""), "\"\"");
        assert_eq!(encode_nstring("a\"b"), "\"a\\\"b\"");
        assert_eq!(encode_nstring("a\\b"), "\"a\\\\b\"");
        // Non-control UTF-8 stays in the quoted string.
        assert_eq!(encode_nstring("Grüße"), "\"Grüße\"");
    }

    #[test]
    fn nstring_with_control_bytes_becomes_a_literal() {
        // CR/LF/NUL/control bytes cannot appear in a quoted string (RFC 3501
        // §4.3); the value is emitted as an IMAP literal with an OCTET count.
        assert_eq!(encode_nstring("a\r\nb"), "{4}\r\na\r\nb");
        assert_eq!(encode_nstring("x\0y"), "{3}\r\nx\0y");
        assert_eq!(encode_nstring("\x01"), "{1}\r\n\x01");
        // The octet count counts UTF-8 bytes, not chars.
        assert_eq!(encode_nstring("é\tx"), "{4}\r\né\tx");
    }

    // ── L13: partial spec with zero octets is invalid ──────────────────────

    #[test]
    fn partial_fetch_with_zero_octets_is_rejected() {
        assert!(parse_fetch_items("BODY[]<0.0>").is_err());
        assert!(parse_fetch_items("BODY[TEXT]<10.0>").is_err());
        // Valid partials still parse.
        assert!(parse_fetch_items("BODY[]<0.100>").is_ok());
    }

    // ── L11: UID FETCH must emit exactly one UID attribute ─────────────────

    #[tokio::test]
    async fn uid_fetch_emits_exactly_one_uid_attribute() {
        let mut w = VecWriter::new();
        let meta = mail_proto::MessageMeta {
            uid: 7,
            ..Default::default()
        };
        // `UID FETCH 1 (UID FLAGS)`
        let items = vec![FetchItem::Uid, FetchItem::Flags];
        emit_fetch_response(&mut w, 7, 1, &meta, &items, None, true, false, false)
            .await
            .unwrap();
        let out = w.output();
        assert_eq!(
            out.matches("UID 7").count(),
            1,
            "UID FETCH must not duplicate the UID attribute, got {:?}",
            out
        );
        assert!(out.starts_with("* 1 FETCH (UID 7"), "got {:?}", out);
    }

    // ── L4: ENVELOPE Reply-To defaults to From ─────────────────────────────

    #[test]
    fn envelope_reply_to_defaults_to_from() {
        let env = mail_proto::EmailEnvelope {
            from: "someone@example.com".to_string(),
            reply_to: String::new(),
            ..Default::default()
        };
        let s = format_envelope(&env);
        // from, sender AND reply_to positions must all render the From
        // address (the address is split into mbox/host inside the envelope).
        let addr = "(NIL NIL \"someone\" \"example.com\")";
        assert_eq!(
            s.matches(addr).count(),
            3,
            "reply_to must default to from, got {:?}",
            s
        );
        // An explicit Reply-To is honored.
        let env2 = mail_proto::EmailEnvelope {
            from: "someone@example.com".to_string(),
            reply_to: "other@example.com".to_string(),
            ..Default::default()
        };
        let s2 = format_envelope(&env2);
        assert!(
            s2.contains("(NIL NIL \"other\" \"example.com\")"),
            "explicit reply_to must win, got {:?}",
            s2
        );
        assert_eq!(
            s2.matches("(NIL NIL \"someone\" \"example.com\")").count(),
            2
        );
    }

    // ── L9: RENAME INBOX moves messages but never deletes INBOX ────────────

    #[tokio::test]
    async fn rename_inbox_moves_messages_and_keeps_inbox() {
        let mut api = MockRenameApi::new((1..=5).collect());
        let res = rename_mailbox_flow(&mut api, "acct", "INBOX", "Target").await;
        assert!(res.is_ok(), "got {:?}", res);
        assert_eq!(api.moved.len(), 5, "messages must move to the new mailbox");
        assert!(
            api.deleted.is_empty(),
            "INBOX must never be deleted (RFC 3501 §6.3.5)"
        );
        assert!(api.created == vec!["Target".to_string()]);
    }

    // ── L12: body-fetch failure must surface as NO, not a silent skip ──────

    #[test]
    fn body_fetch_failure_maps_to_no_response() {
        let exhausted = fetch_body_failure_line("a1", &tonic::Status::resource_exhausted("lim"));
        assert!(exhausted.starts_with("a1 NO "), "got {:?}", exhausted);
        assert!(exhausted.contains("Server busy"), "got {:?}", exhausted);

        let other = fetch_body_failure_line("a2", &tonic::Status::internal("backend exploded"));
        assert!(other.starts_with("a2 NO "), "got {:?}", other);
        assert!(other.contains("backend exploded"), "got {:?}", other);
    }

    // ── L7: mailbox names cannot break out of the quoted string ────────────

    #[test]
    fn mailbox_astring_escapes_quotes_and_strips_crlf() {
        let hostile = "x\" * 1 EXPUNGE\r\nz";
        let rendered = mailbox_astring(hostile);
        assert!(
            !rendered.contains("\r") && !rendered.contains("\n"),
            "CRLF must be stripped, got {:?}",
            rendered
        );
        assert!(rendered.starts_with('"') && rendered.ends_with('"'));
        // Unescaping the quoted form recovers the name (minus stripped CRLF),
        // proving every embedded quote is escaped.
        assert_eq!(unquote(&rendered), "x\" * 1 EXPUNGEz");
        // Ordinary names pass through quoted.
        assert_eq!(mailbox_astring("INBOX"), "\"INBOX\"");
    }

    // ── L1: connection admission control ───────────────────────────────────

    #[test]
    fn connection_limiter_enforces_total_and_per_ip_caps() {
        use std::net::{IpAddr, Ipv4Addr};
        let ip = |n: u8| IpAddr::V4(Ipv4Addr::new(10, 0, 0, n));
        let mut limiter = ConnectionLimiter::default();

        // Per-IP cap: MAX_CONNECTIONS_PER_IP from one address...
        for _ in 0..MAX_CONNECTIONS_PER_IP {
            assert!(limiter.try_acquire(ip(1)));
        }
        // ...then refused, while another IP still gets in.
        assert!(!limiter.try_acquire(ip(1)), "per-IP cap must hold");
        assert!(limiter.try_acquire(ip(2)));

        // Release restores the slot.
        limiter.release(ip(1));
        assert!(limiter.try_acquire(ip(1)));

        // Global cap: fill up to the total from distinct IPs.
        let mut limiter = ConnectionLimiter::default();
        let mut acquired = 0;
        'outer: for n in 1..=254u8 {
            for _ in 0..MAX_CONNECTIONS_PER_IP {
                if !limiter.try_acquire(ip(n)) {
                    break 'outer;
                }
                acquired += 1;
                if acquired == MAX_TOTAL_CONNECTIONS {
                    break 'outer;
                }
            }
        }
        assert_eq!(acquired, MAX_TOTAL_CONNECTIONS);
        // Any further connection from ANY IP is refused.
        assert!(!limiter.try_acquire(ip(254)));
        // Releasing one makes room for exactly one more.
        limiter.release(ip(1));
        assert!(limiter.try_acquire(ip(200)));
    }

    // ── L1: read timeout + incremental literal + cumulative budget ─────────

    #[tokio::test]
    async fn read_command_times_out_and_says_bye() {
        use tokio::io::AsyncWriteExt;
        let (mut client_io, server_io) = tokio::io::duplex(1 << 16);
        let (server_r, mut server_w) = tokio::io::split(server_io);
        let mut reader = BufReader::new(server_r);

        // Client sends a partial command then stalls forever.
        client_io.write_all(b"a1 NOOP").await.unwrap();
        client_io.flush().await.unwrap();

        let result = read_command_bounded(
            &mut reader,
            &mut server_w,
            &ReadLimits::default(),
            &mut ConnectionReadState::default(),
            Duration::from_millis(100),
        )
        .await;
        assert!(result.is_err(), "stalled read must time out");

        // The server must have said BYE before dropping the connection.
        let mut buf = [0u8; 256];
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let n = client_io.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                let text = String::from_utf8_lossy(&buf[..n]).to_string();
                if text.contains("* BYE") {
                    assert!(text.contains("timeout"), "got {:?}", text);
                    return;
                }
            }
            panic!("no BYE received before EOF");
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn read_command_large_declared_literal_stall_does_not_block() {
        use tokio::io::AsyncWriteExt;
        let (mut client_io, server_io) = tokio::io::duplex(1 << 16);
        let (server_r, mut server_w) = tokio::io::split(server_io);
        let mut reader = BufReader::new(server_r);

        // Declare a 32 MiB literal, send a few bytes, then stall. The old
        // code pre-allocated 32 MiB and blocked in read_exact; now the read
        // is incremental AND deadline-bounded, so the connection dies.
        let client_task = tokio::spawn(async move {
            client_io
                .write_all(b"a1 APPEND INBOX {33554432+}\r\n")
                .await
                .unwrap();
            client_io.write_all(&[b'x'; 4096]).await.unwrap();
            let mut sink = [0u8; 16];
            let _ = client_io.read(&mut sink).await;
        });

        let started = std::time::Instant::now();
        let result = read_command_bounded(
            &mut reader,
            &mut server_w,
            &ReadLimits::default(),
            &mut ConnectionReadState::default(),
            Duration::from_millis(150),
        )
        .await;
        assert!(
            result.is_err(),
            "declared-but-stalled literal must time out"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "timeout must fire promptly"
        );
        client_task.abort();
    }

    #[tokio::test]
    async fn read_command_cumulative_literal_budget_is_enforced() {
        use tokio::io::AsyncWriteExt;
        let (client_io, server_io) = tokio::io::duplex(1 << 16);
        let (server_r, mut server_w) = tokio::io::split(server_io);
        let mut reader = BufReader::new(server_r);

        // Tiny per-connection budget: one 6-byte literal fits per command,
        // but the SECOND command exceeds the cumulative cap.
        let limits = ReadLimits {
            max_total_per_connection: 8,
            ..ReadLimits::default()
        };
        let mut conn = ConnectionReadState::default();

        let client_task = tokio::spawn(async move {
            let mut client_io = client_io;
            client_io
                .write_all(b"a1 NOOP {6+}\r\nabcdef\r\n")
                .await
                .unwrap();
            // Block until the server side closes (EOF) so the task returns.
            let mut sink = [0u8; 64];
            let _ = client_io.read(&mut sink).await;
        });

        let first = read_command_limited(&mut reader, &mut server_w, &limits, &mut conn).await;
        assert!(first.is_ok(), "first literal is within budget");
        drop(first);

        // EOF the duplex so the client task's trailing read finishes, then
        // join it. The budget accounting on the connection state must now
        // refuse even a legal-sized literal for the NEXT command.
        drop(reader);
        drop(server_w);
        let _ = client_task.await;

        assert!(!literal_within_budget(
            0,
            0,
            6,
            &limits,
            conn.literal_bytes_total
        ));
        assert_eq!(conn.literal_bytes_total, 6);
    }

    #[tokio::test]
    async fn read_literal_chunked_reads_exact_bytes() {
        let (mut client_io, server_io) = tokio::io::duplex(4096);
        let (server_r, _server_w) = tokio::io::split(server_io);
        let mut reader = BufReader::new(server_r);

        let payload: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        let expected = payload.clone();
        let writer_task = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            client_io.write_all(&payload).await.unwrap();
        });

        // Small chunk size via a short read: 1000 bytes fed through the
        // default 64 KiB chunk path.
        let read = read_literal_chunked(&mut reader, 1000).await.unwrap();
        writer_task.await.unwrap();
        assert_eq!(read, expected);
        // Zero-size literal is an immediate empty buffer.
        assert!(read_literal_chunked(&mut reader, 0)
            .await
            .unwrap()
            .is_empty());
    }

    // ── L2: fetch body sections ────────────────────────────────────────────

    #[test]
    fn fetch_items_parse_header_fields_and_parts() {
        // HEADER.FIELDS with a parenthesized list stays one token.
        let toks = tokenize_fetch_items("BODY[HEADER.FIELDS (DATE FROM)]");
        assert_eq!(toks, vec!["BODY[HEADER.FIELDS (DATE FROM)]".to_string()]);

        let items = parse_fetch_items("BODY[HEADER.FIELDS (DATE FROM)]").unwrap();
        assert_eq!(
            items,
            vec![FetchItem::Body {
                section: BodySection::HeaderFields {
                    fields: vec!["DATE".to_string(), "FROM".to_string()],
                    not: false,
                },
                peek: false,
                name: "BODY[HEADER.FIELDS (DATE FROM)]".to_string(),
                partial: None,
            }]
        );

        let items = parse_fetch_items("BODY.PEEK[HEADER.FIELDS.NOT (X-Spam)]").unwrap();
        assert_eq!(
            items[0],
            FetchItem::Body {
                section: BodySection::HeaderFields {
                    fields: vec!["X-SPAM".to_string()],
                    not: true,
                },
                peek: true,
                name: "BODY[HEADER.FIELDS.NOT (X-SPAM)]".to_string(),
                partial: None,
            }
        );

        // Part numbers and .MIME.
        assert_eq!(
            parse_fetch_items("BODY[1]").unwrap()[0],
            FetchItem::Body {
                section: BodySection::Part {
                    number: "1".to_string(),
                    mime: false,
                },
                peek: false,
                name: "BODY[1]".to_string(),
                partial: None,
            }
        );
        assert_eq!(
            parse_fetch_items("BODY.PEEK[4.2.MIME]").unwrap()[0],
            FetchItem::Body {
                section: BodySection::Part {
                    number: "4.2".to_string(),
                    mime: true,
                },
                peek: true,
                name: "BODY[4.2.MIME]".to_string(),
                partial: None,
            }
        );

        // Unknown tokens and malformed sections are BAD, not dropped.
        assert!(parse_fetch_items("BODY[NOTASECTION]").is_err());
        assert!(parse_fetch_items("BODY[1.2.HEADER.FIELDS (X)]").is_err());
        assert!(parse_fetch_items("BOGUS").is_err());

        // Legacy simple sections still work.
        assert_eq!(
            parse_fetch_items("BODY.PEEK[TEXT]<0.50>").unwrap()[0],
            FetchItem::Body {
                section: BodySection::Text,
                peek: true,
                name: "BODY[TEXT]".to_string(),
                partial: Some((0, 50)),
            }
        );
    }

    #[test]
    fn header_fields_filter_returns_only_requested_fields() {
        let raw = b"From: a@b.c\r\nSubject: folded\r\n subject-continued\r\nDate: Tue, 1 Jan 2030 00:00:00 +0000\r\nX-Junk: nope\r\n\r\nbody";
        let (header, _) = header_and_text(raw);

        let out = filter_header_fields(header, &["DATE".to_string(), "from".into()], false);
        let text = String::from_utf8_lossy(&out).to_string();
        assert_eq!(
            text, "From: a@b.c\r\nDate: Tue, 1 Jan 2030 00:00:00 +0000\r\n\r\n",
            "exactly the requested fields + terminating blank line, in message order"
        );

        // The .NOT variant keeps everything else; folded continuation lines
        // stay attached to their field (original bytes preserved).
        let out = filter_header_fields(header, &["X-Junk".to_string()], true);
        let text = String::from_utf8_lossy(&out).to_string();
        assert!(text.contains("Subject: folded\r\n subject-continued"));
        assert!(text.contains("From: a@b.c"));
        assert!(!text.contains("X-Junk"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    const MULTIPART_RAW: &[u8] = b"Content-Type: multipart/mixed; boundary=\"BB\"\r\nSubject: outer\r\n\r\npreamble is ignored\r\n--BB\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\nfirst part body\r\n--BB\r\nContent-Type: text/html\r\n\r\n<p>second</p>\r\n--BB--\r\nepilogue";

    #[test]
    fn body_part_extraction_returns_part_content() {
        // Part 1 content excludes the part's MIME header and the boundary.
        assert_eq!(
            extract_body_part(MULTIPART_RAW, "1", false),
            b"first part body".to_vec()
        );
        assert_eq!(
            extract_body_part(MULTIPART_RAW, "2", false),
            b"<p>second</p>".to_vec()
        );
        // .MIME returns the part's MIME header block (blank line included).
        assert_eq!(
            extract_body_part(MULTIPART_RAW, "1", true),
            b"Content-Type: text/plain; charset=us-ascii\r\n\r\n".to_vec()
        );
        // A non-existent part is an empty string, not an error.
        assert_eq!(
            extract_body_part(MULTIPART_RAW, "3", false),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn body_part_extraction_non_multipart_part_one_is_body() {
        let raw = b"From: a@b\r\nSubject: s\r\n\r\nplain body";
        assert_eq!(extract_body_part(raw, "1", false), b"plain body".to_vec());
        assert_eq!(extract_body_part(raw, "2", false), Vec::<u8>::new());
        // .MIME of part 1 on a non-multipart message is the message header.
        assert!(extract_body_part(raw, "1", true).starts_with(b"From: a@b\r\n"));
    }

    const NESTED_RAW: &[u8] = b"Content-Type: multipart/mixed; boundary=OUTER\r\n\r\n--OUTER\r\nContent-Type: multipart/alternative; boundary=INNER\r\n\r\n--INNER\r\nContent-Type: text/plain\r\n\r\ninner text\r\n--INNER--\r\n--OUTER\r\nContent-Type: text/plain\r\n\r\nouter second\r\n--OUTER--\r\n";

    #[test]
    fn body_part_extraction_supports_nested_numbering() {
        assert_eq!(
            extract_body_part(NESTED_RAW, "1.1", false),
            b"inner text".to_vec()
        );
        assert_eq!(
            extract_body_part(NESTED_RAW, "2", false),
            b"outer second".to_vec()
        );
        // The nested part's MIME header is addressable as 1.1.MIME (the
        // ".MIME" suffix is stripped by the fetch-item parser before it
        // reaches here: number "1.1", mime=true).
        assert_eq!(
            extract_body_part(NESTED_RAW, "1.1", true),
            b"Content-Type: text/plain\r\n\r\n".to_vec()
        );
        // The sub-multipart's own header is 1.MIME.
        assert!(extract_body_part(NESTED_RAW, "1", true)
            .starts_with(b"Content-Type: multipart/alternative"));
    }

    #[tokio::test]
    async fn emit_fetch_response_header_fields_end_to_end() {
        let mut w = VecWriter::new();
        let meta = mail_proto::MessageMeta {
            uid: 3,
            ..Default::default()
        };
        let raw = b"From: a@b.c\r\nTo: x@y.z\r\nSubject: sub\r\n\r\nthe body";
        let items = parse_fetch_items("BODY.PEEK[HEADER.FIELDS (FROM SUBJECT)]").unwrap();
        let body = Ok(GetMessageBody { body: raw.to_vec() });
        emit_fetch_response(
            &mut w,
            3,
            1,
            &meta,
            &items,
            Some(&body),
            false,
            false,
            false,
        )
        .await
        .unwrap();
        let out = w.output();
        // Exactly the requested headers (plus the terminating blank line) as
        // a literal; NOT the whole message, NOT ALL-substituted flags.
        let expected_payload = "From: a@b.c\r\nSubject: sub\r\n\r\n";
        assert!(
            out.contains(&format!(
                "BODY[HEADER.FIELDS (FROM SUBJECT)] {{{}}}\r\n",
                expected_payload.len()
            )),
            "unexpected response: {:?}",
            out
        );
        // The literal ends with the blank line immediately before the paren.
        assert!(
            out.contains("From: a@b.c\r\nSubject: sub\r\n\r\n)"),
            "got {:?}",
            out
        );
        assert!(!out.contains("the body"));
    }

    #[tokio::test]
    async fn emit_fetch_response_part_section_end_to_end() {
        let mut w = VecWriter::new();
        let meta = mail_proto::MessageMeta {
            uid: 4,
            ..Default::default()
        };
        let items = parse_fetch_items("BODY[1]").unwrap();
        let body = Ok(GetMessageBody {
            body: MULTIPART_RAW.to_vec(),
        });
        emit_fetch_response(&mut w, 4, 2, &meta, &items, Some(&body), true, false, false)
            .await
            .unwrap();
        let out = w.output();
        let expected = "first part body";
        assert!(
            out.contains(&format!(
                "* 2 FETCH (UID 4 BODY[1] {{{}}}\r\n{})\r\n",
                expected.len(),
                expected
            )),
            "unexpected response: {:?}",
            out
        );
    }

    // ── L3: APPEND internal date ───────────────────────────────────────────

    #[test]
    fn append_internal_date_defaults_to_now_and_parses_explicit() {
        let none_tokens: Vec<String> = vec![];
        let before = chrono::Utc::now().timestamp();
        let ts = append_internal_date(&none_tokens, 0, &[]).unwrap();
        let after = chrono::Utc::now().timestamp();
        assert!(
            ts >= before && ts <= after,
            "omitted date must be now, got {} ({}..{})",
            ts,
            before,
            after
        );

        let explicit = vec!["\"01-Jan-2020 10:00:00 +0000\"".to_string()];
        let ts = append_internal_date(&explicit, 0, &[]).unwrap();
        assert_eq!(
            ts,
            chrono::DateTime::parse_from_rfc2822("Wed, 1 Jan 2020 10:00:00 +0000")
                .unwrap()
                .timestamp()
        );

        let bad = vec!["\"not a date\"".to_string()];
        assert!(append_internal_date(&bad, 0, &[]).is_err());
    }

    // ── L5: NOOP EXPUNGE via view_update_lines ─────────────────────────────

    #[test]
    fn view_update_lines_emit_descending_expunges_then_exists() {
        // UIDs 10,20,30 removed by another session; view goes 5 -> 2.
        let old = vec![10u64, 20, 30, 40, 50];
        let new = vec![40u64, 50];
        let lines = view_update_lines(&old, &new);
        assert_eq!(
            lines,
            "* 3 EXPUNGE\r\n* 2 EXPUNGE\r\n* 1 EXPUNGE\r\n* 2 EXISTS\r\n"
        );

        // Addition only: no EXPUNGE, one EXISTS.
        let lines = view_update_lines(&[10], &[10, 20]);
        assert_eq!(lines, "* 2 EXISTS\r\n");

        // No change: silence (RFC 3501 §7.4.1 allows unsolicited updates but
        // sending nothing is correct for an unchanged view).
        assert_eq!(view_update_lines(&[10, 20], &[10, 20]), "");
    }

    // ── L6: SELECT leaves the session untouched on failure ────────────────

    #[tokio::test]
    async fn select_failure_keeps_session_authenticated() {
        // A mailstore client on a definitely-unreachable endpoint: every RPC
        // fails with a transport error, exercising the fallible path of
        // SELECT without needing a real mailstore.
        let channel = tonic::transport::Channel::builder("http://127.0.0.1:1".parse().unwrap())
            .connect_lazy();
        let interceptor = mail_proto::InternalServiceAuthInterceptor::new(None).unwrap();
        let client = build_mailstore_client(channel, interceptor);
        let mut session = ImapSession::new(client);
        session.state = SessionState::Authenticated;
        session.account_id = "11111111-1111-1111-1111-111111111111".to_string();

        let mut w = VecWriter::new();
        handle_select(&mut session, "a1", "INBOX", false, &[], &mut w)
            .await
            .unwrap();
        let out = w.output();
        assert!(
            out.starts_with("a1 NO "),
            "failure must be NO, got {:?}",
            out
        );
        assert_eq!(
            session.state,
            SessionState::Authenticated,
            "a failed SELECT must not half-select the session"
        );
        assert!(session.uid_map.is_empty());
        assert!(session.mailbox.is_empty());
    }

    // ── L8: header search query convention ─────────────────────────────────

    #[test]
    fn header_search_query_matches_the_wire_convention() {
        // Mirrors mailstore-core's parse_header_query — first \x01 separates
        // field from value; prefix + separator required.
        assert_eq!(
            header_search_query("Message-ID", "<a@b>"),
            "header:Message-ID\x01<a@b>"
        );
    }

    // ── L13: SASL-IR parsing ───────────────────────────────────────────────

    #[test]
    fn authenticate_args_parse_mechanism_and_optional_initial_response() {
        let (mech, ir) = parse_authenticate_args("PLAIN", &[]);
        assert_eq!(mech, "PLAIN");
        assert!(ir.is_none());

        let (mech, ir) = parse_authenticate_args("PLAIN AGFyZQBwYXNz", &[]);
        assert_eq!(mech, "PLAIN");
        assert_eq!(ir.as_deref(), Some("AGFyZQBwYXNz"));

        // RFC 4959: "=" encodes the empty initial response.
        let (_, ir) = parse_authenticate_args("PLAIN =", &[]);
        assert_eq!(ir.as_deref(), Some(""));

        // A literal initial response resolves too.
        let literals = vec![b"literal-ir".to_vec()];
        let (_, ir) = parse_authenticate_args("PLAIN \x01LIT0\x01", &literals);
        assert_eq!(ir.as_deref(), Some("literal-ir"));
    }

    // ── L14(e): capped-view notice ─────────────────────────────────────────

    #[test]
    fn view_capped_notice_emitted_only_when_store_exceeds_view() {
        assert!(view_capped_notice(100_000, 100_001).is_some());
        let notice = view_capped_notice(100_000, 100_001).unwrap();
        assert!(notice.starts_with("* OK [ALERT]"));
        assert!(notice.contains("100001"));
        assert!(notice.contains("100000"));
        assert!(view_capped_notice(100, 100).is_none());
        assert!(view_capped_notice(100, 99).is_none());
    }
}
